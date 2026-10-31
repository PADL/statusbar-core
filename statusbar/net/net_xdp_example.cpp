// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// XDP Packet Monitor and Bridge Example
/// Demonstrates AF_XDP packet capture with optional TAP bridging.
/// Uses poll_once() as the canonical XDP polling pattern.
///
/// Usage: net_example_xdp --interface=<name> [options]
/// Monitor: net_example_xdp --interface=eth0
/// Bridge:  net_example_xdp --interface=eth0 --tap=xdp_tap0 --bridge

#if defined(__linux__)

#    include "statusbar/config/config.hpp"
#    include "statusbar/ieee/ieee.hpp"
#    include "statusbar/itc/itc_stop_token.hpp"
#    include "statusbar/net/net.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cerrno>
#    include <cstdint>
#    include <cstdio>
#    include <cstdlib>
#    include <cstring>
#    include <expected>
#    include <format>
#    include <iterator>
#    include <optional>
#    include <print>
#    include <span>
#    include <string>
#    include <string_view>
#    include <system_error>
#    include <vector>

#    if defined(__linux__)
#        include <poll.h>
#        include <unistd.h>
#    endif

using namespace statusbar::net;

namespace {

struct Config
{
    std::string interface_name;
    std::string tap_name;
    bool bridge_mode{false};
    bool verbose{false};
    uint32_t queue_id{0};
    std::string default_action;
    std::vector<int64_t> ethertypes;
    std::vector<int64_t> udp_ports;
};

auto build_arg_specs(Config& config) -> statusbar::args::ArgumentSpecs
{
    statusbar::args::ArgumentSpecs specs;

    specs.add_device("interface", "Network interface (required)", "", [&](auto v) { config.interface_name = std::string{v}; });
    specs.add<std::string_view>(
        "tap", "TAP device name (enables TAP creation)", "", [&](auto v) { config.tap_name = std::string{v}; });
    specs.add_flag("bridge", "Enable bidirectional XDP<->TAP bridging", [&](auto v) { config.bridge_mode = v; });
    specs.add_flag("verbose", "Print hex dump of each packet", [&](auto v) { config.verbose = v; });
    specs.add<uint32_t>("queue", "RX queue index", 0, [&](auto v) { config.queue_id = v; });
    specs.add_choice("default-action", "Default filter action", {"xsk", "pass", "tap"}, "", [&](auto v) {
        config.default_action = std::string{v};
    });
    specs.add_list<int64_t>("ethertype", "Ethertype filter (hex or decimal, comma-separated)", [&](std::vector<int64_t> const& v) {
        config.ethertypes = v;
    });
    specs.add_list<int64_t>(
        "udp-port", "UDP port filter (comma-separated)", [&](std::vector<int64_t> const& v) { config.udp_ports = v; });

    return specs;
}

void print_usage(char const* program_name, statusbar::args::ArgumentSpecs const& specs)
{
    std::println(stderr, "Usage: {} --interface=<name> [options]", program_name);
    std::println(stderr, "");
    std::println(stderr, "XDP packet monitor and bridge example.");
    std::println(stderr, "Demonstrates AF_XDP packet capture with optional TAP bridging.");
    std::println(stderr, "");
    std::println(stderr, "Options:");

    std::string help;
    specs.format_help_to(std::back_inserter(help));
    std::print(stderr, "{}", help);

    std::println(stderr, "Examples:");
    std::println(stderr, "  sudo {} --interface=eth0", program_name);
    std::println(stderr, "  sudo {} --interface=eth0 --ethertype=0x0806,0x0800", program_name);
    std::println(stderr, "  sudo {} --interface=eth0 --udp-port=319", program_name);
    std::println(stderr, "  sudo {} --interface=eth0 --tap=xdp_tap0 --bridge", program_name);
    std::println(stderr, "  sudo {} --interface=eth0 --verbose", program_name);
    std::println(stderr, "  sudo {} --config-load=my_xdp.toml", program_name);
}

/// Map action string to XdpAction enum
[[nodiscard]] auto parse_action(std::string_view str) -> std::optional<XdpAction>
{
    if (str == "xsk") {
        return XdpAction::redirect_xsk;
    }
    if (str == "pass") {
        return XdpAction::pass_kernel;
    }
    if (str == "tap") {
        return XdpAction::redirect_tap;
    }
    return std::nullopt;
}

/// Map an XdpAction to the per-rule result flags the BPF program reads.
[[nodiscard]] auto result_flags_for(XdpAction action) -> std::uint64_t
{
    switch (action) {
        case XdpAction::redirect_xsk:
            return flag::process;
        case XdpAction::redirect_tap:
            return flag::forward_tap;
        case XdpAction::pass_kernel:
            return flag::none;
    }
    return flag::none;
}

/// Build a single ethertype-match rule (any VLAN framing).
[[nodiscard]] auto make_ethertype_rule(std::uint16_t ethertype, XdpAction action) -> CompiledRule<32>
{
    auto const built = ClassifierRuleBuilder<32>{}.ethertype(ethertype).vlan_any().result(result_flags_for(action)).build();
    // vlan_any() produces a 2-rule fan-out (untagged + tagged). For the
    // example, take the untagged variant; a future enhancement could
    // push both into the TCAM map.
    return built[0];
}

/// Build an IPv4/UDP port-match rule (untagged only).
[[nodiscard]] auto make_udp_port_rule(std::uint16_t port, XdpAction action) -> CompiledRule<32>
{
    // UDP destination port lives past the 32-byte TCAM window, so we
    // can't match it here. Keep the old example behaviour shape by
    // matching only IPv4+UDP protocol; userspace classifiers (or a
    // wider TCAM window) can refine to a specific port.
    (void)port;
    auto const built = ClassifierRuleBuilder<32>{}
                           .ethertype(0x0800)  // IPv4
                           .ipv4_protocol(17)  // UDP
                           .vlan_untagged()
                           .result(result_flags_for(action))
                           .build();
    return built[0];
}

/// Parse [[filter]] array-of-tables from a TOML config into filter rules
auto parse_toml_filter_tables(statusbar::config::Config const& toml_config, std::vector<CompiledRule<32>>& rules) -> void
{
    auto const* filter_array = toml_config.get_array("filter");
    if (filter_array == nullptr) {
        return;
    }

    for (size_t i = 0; i < filter_array->size(); ++i) {
        auto const& entry = (*filter_array)[i];
        auto const* tbl = entry.as_table();
        if (tbl == nullptr) {
            continue;
        }

        XdpAction action = XdpAction::pass_kernel;
        if (auto const* v = tbl->get("action"); v) {
            if (auto str = v->as_string(); str) {
                if (auto act = parse_action(*str); act) {
                    action = *act;
                }
            }
        }

        if (auto const* v = tbl->get("udp-port"); v) {
            if (auto int_val = v->as_integer(); int_val) {
                rules.push_back(make_udp_port_rule(static_cast<std::uint16_t>(*int_val), action));
                continue;
            }
        }
        if (auto const* v = tbl->get("ethertype"); v) {
            if (auto int_val = v->as_integer(); int_val) {
                rules.push_back(make_ethertype_rule(static_cast<std::uint16_t>(*int_val), action));
            }
        }
    }
}

/// Build filter rules from CLI flags and TOML [[filter]] tables
[[nodiscard]] auto build_filter_rules(Config const& config, int argc, char** argv) -> std::vector<CompiledRule<32>>
{
    std::vector<CompiledRule<32>> rules;
    rules.reserve(config.ethertypes.size() + config.udp_ports.size());

    // Build rules from typed ethertype vector
    for (auto val : config.ethertypes) {
        rules.push_back(make_ethertype_rule(static_cast<std::uint16_t>(val), XdpAction::redirect_xsk));
    }

    // Build rules from typed UDP port vector
    if (!config.udp_ports.empty()) {
        std::println(
            stderr,
            "Note: --udp-port matches every IPv4/UDP frame; the port lies past the {}-byte TCAM window",
            static_cast<int>(TCAM_WINDOW_BYTES));
    }
    for (auto val : config.udp_ports) {
        rules.push_back(make_udp_port_rule(static_cast<std::uint16_t>(val), XdpAction::redirect_xsk));
    }

    // Re-parse --config-load files to extract [[filter]] array-of-tables
    for (int i = 1; i < argc; ++i) {
        std::string_view const arg{argv[i]};
        std::string file;

        if (arg.starts_with("--config-load=")) {
            file = std::string{arg.substr(14)};
        } else if (arg == "--config-load" && i + 1 < argc) {
            file = argv[++i];
        } else {
            continue;
        }

        statusbar::config::Config toml_config;
        if (auto status = toml_config.load_file(file); status) {
            parse_toml_filter_tables(toml_config, rules);
        }
    }

    return rules;
}

/// Log a one-line packet summary, optionally with hex dump
auto log_packet(std::span<uint8_t const> data, int64_t timestamp_ns, int64_t& first_timestamp_ns, bool verbose) -> void
{
    // Relative timestamp
    if (first_timestamp_ns == 0) {
        first_timestamp_ns = timestamp_ns;
    }
    double rel_sec = static_cast<double>(timestamp_ns - first_timestamp_ns) / 1'000'000'000.0;

    // Need at least 14 bytes for Ethernet header
    if (data.size() < 14) {
        std::println(stderr, "[{:10.6f}] <short frame {} bytes>", rel_sec, data.size());
        return;
    }

    // Parse Ethernet header: dst[6] src[6] ethertype[2]
    auto const* dst = data.data();
    auto const* src = data.data() + 6;
    uint16_t const ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);

    std::println(
        stderr,
        "[{:10.6f}] {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> "
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {:6s}  {} bytes",
        rel_sec,
        src[0],
        src[1],
        src[2],
        src[3],
        src[4],
        src[5],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        dst[4],
        dst[5],
        statusbar::ieee::ethertype_name(ethertype).view(),
        data.size());

    if (verbose) {
        size_t const dump_len = std::min(data.size(), size_t{64});
        for (size_t i = 0; i < dump_len; i += 16) {
            std::print(stderr, "  {:04x}: ", i);
            for (size_t j = i; j < i + 16 && j < dump_len; ++j) {
                std::print(stderr, "{:02x} ", data[j]);
            }
            std::println(stderr, "");
        }
    }
}

/// One complete XDP polling cycle. This is the canonical usage pattern.
/// Call in a loop with poll() gating for non-busy-wait operation.
[[nodiscard]] auto poll_once(XdpContext& xdp, TapBridge& tap, bool bridge_mode, bool verbose, int64_t& first_timestamp_ns)
    -> statusbar::Status
{
    using namespace statusbar;

    xdp.begin_cycle();

    if (auto s = xdp.fill_replenish(); !s) {
        return s;
    }
    if (auto s = xdp.tx_complete(); !s) {
        return s;
    }

    // RX: drain packets from XDP socket
    while (true) {
        auto guard_result = rx_guard(xdp);
        if (!guard_result) {
            return failure(guard_result.error());
        }
        auto& maybe_guard = *guard_result;
        if (!maybe_guard) {
            break;  // budget hit or ring empty
        }

        log_packet(maybe_guard->buffer(), maybe_guard->timestamp_ns(), first_timestamp_ns, verbose);

        // In bridge mode, forward XDP -> TAP.
        // IMPORTANT: must access buffer BEFORE release, which frees
        // the UMEM frame (frame memory becomes invalid after release).
        if (bridge_mode && tap.valid()) {
            (void)tap.forward_to_tap(maybe_guard->buffer());
        }

        // Guard auto-releases UMEM frame on scope exit
    }

    // TAP -> XDP (bridge mode only)
    if (bridge_mode && tap.valid()) {
        if (auto result = tap.drain_to_wire(xdp); !result) {
            return failure(result.error());
        }
    }

    if (auto s = xdp.tx_flush(); !s) {
        return s;
    }

    return success();
}

auto print_stats(XdpSocketStats const& stats) -> void
{
    std::println(
        stderr,
        "Stats: rx={} tx={} tx_ring_full={} umem_exhausted={} rx_budget_hits={}",
        stats.rx_count,
        stats.tx_count,
        stats.tx_ring_full_count,
        stats.umem_exhausted_count,
        stats.rx_budget_hit_count);
    // A healthy sender skips most kicks, so a low skip ratio here is itself
    // worth looking at. transient and failed are deliberately separate: the
    // first passes, the second does not.
    std::println(
        stderr,
        "       tx_kicks={} skipped={} transient={} failed={} last_errno={} rx_wakeups={}",
        stats.tx_flush_count,
        stats.tx_flush_skipped,
        stats.tx_flush_transient,
        stats.tx_flush_failed,
        stats.tx_flush_errno,
        stats.rx_wakeup_count);
}

}  // namespace

auto main(int argc, char** argv) -> int
{
    // Build config and specs with bindings
    Config config;
    auto specs = build_arg_specs(config);

    // Parse CLI arguments, handle --completion, --help, --config-load, --config-save, apply bindings
    auto cli_result = statusbar::config::parse_cli_args(argc, argv, specs, print_usage);
    if (!cli_result) {
        return statusbar::config::handled_builtin_command(cli_result) ? 0 : 1;
    }

    // Validate required options
    if (config.interface_name.empty()) {
        std::println(stderr, "Error: --interface is required");
        print_usage(argv[0], specs);
        return 1;
    }

    if (config.bridge_mode && config.tap_name.empty()) {
        std::println(stderr, "Error: --bridge requires --tap=NAME");
        return 1;
    }

    // Build filter rules from CLI and TOML config
    auto rules = build_filter_rules(config, argc, argv);

    // Determine default action
    XdpAction default_action = rules.empty() ? XdpAction::redirect_xsk  // No rules: capture everything
                                             : XdpAction::pass_kernel;  // Rules specified: only matched traffic
    if (!config.default_action.empty()) {
        if (auto act = parse_action(config.default_action); act) {
            default_action = *act;
        } else {
            std::println(stderr, "Error: invalid --default-action '{}'", config.default_action);
            return 1;
        }
    }

    // Set up signal handling
    auto& stop = statusbar::itc::install_stop_signal();

    // Create TAP bridge if requested
    TapBridge tap;
    if (!config.tap_name.empty()) {
        if (auto status = tap.open(TapBridgeConfig{.device_name = config.tap_name}); !status) {
            std::println(stderr, "Error: Failed to open TAP device '{}': {}", config.tap_name, status.error().message());
            return 1;
        }
    }

    // Configure and open XDP context
    XdpConfig const xdp_config{
        .interface_name = config.interface_name,
        .filter_rules = rules,
        .default_action = default_action,
        .queue_id = config.queue_id,
        .tap_ifindex = tap.ifindex(),
    };

    XdpContext xdp;
    if (auto status = xdp.open(xdp_config); !status) {
        std::println(stderr, "Error: Failed to open XDP context: {}", status.error().message());
        return 1;
    }

    // Print startup info
    std::println(
        stderr,
        "XDP monitor on interface '{}' (MAC: {})",
        config.interface_name,
        statusbar::ieee::to_string(xdp.hardware_address()).view());
    std::println(stderr, "Mode: {}", config.bridge_mode ? "bridge" : "monitor");
    // What the open actually got, which on a NIC without native XDP (the
    // Pi 5's macb, say) is generic attach and a copy-mode bind.
    std::println(
        stderr,
        "Attach: {}, bind: {}{}, bind retries: {}, program: {}",
        xdp.attach_mode() == XdpAttachMode::native ? "native" : "generic",
        xdp.zero_copy() ? "zero-copy" : "copy",
        xdp.bind_mode() == XdpBindMode::copy ? " (requested copy)" : "",
        xdp.bind_retries(),
        xdp.adopted()      ? "adopted"
            : xdp.pinned() ? "pinned"
                           : "attached");
    if (tap.valid()) {
        std::println(stderr, "TAP device: {}", config.tap_name);
    }
    std::println(
        stderr,
        "Filter rules: {}, default action: {}",
        rules.size(),
        default_action == XdpAction::redirect_xsk      ? "xsk"
            : default_action == XdpAction::pass_kernel ? "pass"
                                                       : "tap");
    std::println(stderr, "Press Ctrl+C to stop");

    // Main event loop
    int64_t first_timestamp_ns = 0;

    // Set up poll fds
    std::array<struct pollfd, 2> fds{};
    int nfds = 0;
    fds[nfds++] = {.fd = xdp.fd(), .events = POLLIN, .revents = 0};
    if (tap.fd() >= 0) {
        fds[nfds++] = {.fd = tap.fd(), .events = POLLIN, .revents = 0};
    }

    while (!stop.stop_requested()) {
        int const ret = ::poll(fds.data(), static_cast<nfds_t>(nfds), 100);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::println(stderr, "Error: poll() failed: {}", std::strerror(errno));
            break;
        }

        if (auto status = poll_once(xdp, tap, config.bridge_mode, config.verbose, first_timestamp_ns); !status) {
            std::println(stderr, "Error: poll_once() failed: {}", status.error().message());
            break;
        }
    }

    std::println(stderr, "\nShutting down...");
    print_stats(xdp.stats());
    if (auto const kernel = xdp.kernel_stats(); kernel) {
        std::println(
            stderr,
            "Kernel: rx_dropped={} rx_invalid_descs={} tx_invalid_descs={} rx_ring_full={} rx_fill_ring_empty={} tx_ring_empty={}",
            kernel->rx_dropped,
            kernel->rx_invalid_descs,
            kernel->tx_invalid_descs,
            kernel->rx_ring_full,
            kernel->rx_fill_ring_empty_descs,
            kernel->tx_ring_empty_descs);
    }

    return 0;
}
#endif  // defined(__linux__)
