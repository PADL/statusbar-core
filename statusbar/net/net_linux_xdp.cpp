// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_linux_xdp.hpp"

#include "statusbar/net/net_posix_util.hpp"

namespace statusbar::net {

auto XdpErrorCategory::message(int ev) const -> std::string
{
    switch (static_cast<XdpError>(ev)) {
        case XdpError::socket_creation_failed:
            return "Socket creation failed";
        case XdpError::interface_not_found:
            return "Network interface not found";
        case XdpError::get_hwaddr_failed:
            return "Failed to get hardware address";
        case XdpError::umem_creation_failed:
            return "UMEM creation failed";
        case XdpError::xsk_creation_failed:
            return "XSK socket creation failed";
        case XdpError::bpf_load_failed:
            return "BPF program load failed";
        case XdpError::bpf_attach_failed:
            return "BPF program attach failed";
        case XdpError::bpf_map_update_failed:
            return "BPF map update failed";
        case XdpError::tap_creation_failed:
            return "TAP device creation failed";
        case XdpError::tap_configure_failed:
            return "TAP device configuration failed";
        case XdpError::not_open:
            return "Context not open";
        case XdpError::tx_ring_full:
            return "TX ring buffer full";
        case XdpError::rx_ring_empty:
            return "RX ring buffer empty";
        case XdpError::fill_ring_full:
            return "Fill ring full";
        case XdpError::free_list_empty:
            return "UMEM free list empty";
        case XdpError::invalid_addr:
            return "Invalid UMEM frame address";
        case XdpError::frame_too_large:
            return "Frame exceeds maximum size";
        case XdpError::tx_flush_failed:
            return "TX flush sendto failed";
        case XdpError::join_multicast_failed:
            return "Failed to join multicast group";
        case XdpError::not_supported_on_platform:
            return "AF_XDP not supported on this platform";
        case XdpError::invalid_bpf_program:
            return "Embedded BPF program is empty or invalid";
        case XdpError::too_many_filter_rules:
            return "Filter rule count exceeds TCAM_MAX_RULES";
        default:
            return "Unknown XDP error";
    }
}

#if defined(__linux__) && defined(HAVE_XDP)

auto detail::UmemRegion::allocate(
    size_t frame_count, size_t frame_size, size_t headroom, size_t fill_ring_size, size_t comp_ring_size, RingSet& rings)
    -> StatusValue<struct xsk_umem*>
{
    close();

    frame_size_ = frame_size;
    headroom_ = headroom;

    size_t const total_size = frame_count * frame_size;
    area_ = static_cast<uint8_t*>(
        ::mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0));
    if (area_ == MAP_FAILED) {
        area_ = nullptr;
        frame_size_ = 0;
        headroom_ = 0;
        return failure(XdpError::umem_creation_failed);
    }
    area_size_ = total_size;

    (void)::madvise(area_, total_size, MADV_DONTFORK);
    {
        size_t const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
        uint8_t volatile* p = area_;
        for (size_t i = 0; i < total_size; i += page_size) {
            (void)p[i];
        }
    }

    struct xsk_umem_config umem_cfg{};
    umem_cfg.fill_size = static_cast<__u32>(fill_ring_size);
    umem_cfg.comp_size = static_cast<__u32>(comp_ring_size);
    umem_cfg.frame_size = static_cast<__u32>(frame_size);
    umem_cfg.frame_headroom = static_cast<__u32>(headroom);
    umem_cfg.flags = 0;

    int const ret = xsk_umem__create(&umem_, area_, total_size, &rings.fill, &rings.comp, &umem_cfg);
    if (ret != 0) {
        close();
        return failure(XdpError::umem_creation_failed);
    }

    free_list_ = UmemFreeList(frame_count, frame_size);

    return umem_;
}

void detail::UmemRegion::close() noexcept
{
    if (umem_ != nullptr) {
        (void)xsk_umem__delete(umem_);
        umem_ = nullptr;
    }
    if (area_ != nullptr) {
        ::munmap(area_, area_size_);
        area_ = nullptr;
        area_size_ = 0;
    }
    frame_size_ = 0;
    headroom_ = 0;
    free_list_ = {};
}

auto detail::BpfState::load(std::span<CompiledRule<32> const> rules, XdpAction default_action) -> Status
{
    close();
    default_action_ = default_action;

    if (xdp_filter_bpf_o_len == 0) {
        return failure(XdpError::invalid_bpf_program);
    }

    BpfObject obj;
    if (auto status = obj.open_and_load(xdp_filter_bpf_o, xdp_filter_bpf_o_len); !status) {
        return status;
    }

    struct bpf_map* rules_map = bpf_object__find_map_by_name(obj.get(), "rules_map");
    struct bpf_map* xsk_map = bpf_object__find_map_by_name(obj.get(), "xsk_map");
    struct bpf_map* devmap = bpf_object__find_map_by_name(obj.get(), "devmap");

    auto are_xdp_maps_valid = [](bpf_map* rm, bpf_map* xsk, bpf_map* dev) -> bool {
        return rm != nullptr && xsk != nullptr && dev != nullptr;
    };
    if (!are_xdp_maps_valid(rules_map, xsk_map, devmap)) {
        return failure(XdpError::bpf_load_failed);
    }

    rules_map_fd_ = bpf_map__fd(rules_map);
    xsk_map_fd_ = bpf_map__fd(xsk_map);
    devmap_fd_ = bpf_map__fd(devmap);

    // The loaded BPF object starts with all rule slots zero-initialized
    // (array map default), so any pre-existing stale entries from the
    // previous loader run are already cleared. install_tcam_rules() fills
    // slots 0..rules.size()-1 and re-zeroes the tail to keep that
    // guarantee on subsequent set_rules() calls.
    if (auto status = install_tcam_rules(rules); !status) {
        return status;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj.get(), "xdp_filter_prog");
    if (prog == nullptr) {
        return failure(XdpError::bpf_load_failed);
    }
    prog_fd_ = bpf_program__fd(prog);

    obj_ = std::move(obj);
    return success();
}

namespace {

/// Derive the catch-all rule the BPF program needs when the user wants a
/// non-pass default. The mask is all-zero, so the rule matches every
/// frame, but `min_frame_size` is set to the full TCAM window so the
/// slot also passes the "active rule" gate in the BPF loop.
[[nodiscard]] auto catch_all_rule_for(XdpAction action) -> std::optional<CompiledRule<32>>
{
    CompiledRule<32> rule{};
    rule.min_frame_size = static_cast<std::uint16_t>(TCAM_WINDOW_BYTES);
    rule.priority = 255;  // Ordered last; irrelevant for the BPF engine but documents intent.
    switch (action) {
        case XdpAction::redirect_xsk:
            rule.result_flags = flag::process;
            return rule;
        case XdpAction::redirect_tap:
            rule.result_flags = flag::forward_tap;
            return rule;
        case XdpAction::pass_kernel:
            return std::nullopt;  // Falls through to XDP_PASS naturally.
    }
    return std::nullopt;
}

}  // namespace

auto detail::BpfState::install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status
{
    auto catch_all = catch_all_rule_for(default_action_);
    std::size_t const extra = catch_all.has_value() ? 1U : 0U;
    if (rules.size() + extra > TCAM_MAX_RULES) {
        return failure(XdpError::too_many_filter_rules);
    }

    auto write_slot = [this](std::uint32_t index, CompiledRule<32> const& rule) -> Status {
        if (bpf_map_update_elem(rules_map_fd_, &index, &rule, BPF_ANY) != 0) {
            return failure(XdpError::bpf_map_update_failed);
        }
        return success();
    };

    std::uint32_t slot = 0;
    for (auto const& rule : rules) {
        if (auto s = write_slot(slot, rule); !s) {
            return s;
        }
        ++slot;
    }
    if (catch_all.has_value()) {
        if (auto s = write_slot(slot, *catch_all); !s) {
            return s;
        }
        ++slot;
    }

    CompiledRule<32> const empty{};
    for (std::uint32_t i = slot; i < TCAM_MAX_RULES; ++i) {
        if (auto s = write_slot(i, empty); !s) {
            return s;
        }
    }

    return success();
}

auto XdpContext::open(XdpConfig const& config) -> Status
{
    close();

    // Step 1: Look up interface index and MAC address
    int sock_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return failure(XdpError::socket_creation_failed);
    }
    auto close_sock = detail::scopeguard([&]() noexcept { ::close(sock_fd); });

    struct ifreq ifr{};
    auto const name_len = config.interface_name.size() < IFNAMSIZ ? config.interface_name.size() : IFNAMSIZ - 1;
    span_copy(ifname_bytes(ifr).first(name_len), make_const_span(config.interface_name).first(name_len));
    ifr.ifr_name[name_len] = '\0';

    if (::ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        return failure(XdpError::interface_not_found);
    }
    interface_.index = static_cast<unsigned int>(ifr.ifr_ifindex);

    if (::ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        close();
        return failure(XdpError::get_hwaddr_failed);
    }
    span_copy(interface_.hardware_address.value, hwaddr_bytes(ifr));

    // Step 2: Allocate UMEM
    auto umem_result = umem_.allocate(
        config.umem_frame_count,
        config.umem_frame_size,
        config.umem_headroom,
        config.fill_ring_size,
        config.completion_ring_size,
        rings_);
    if (!umem_result) {
        close();
        return failure(umem_result.error());
    }

    // Step 3: Load BPF
    if (auto status = bpf_.load(config.filter_rules, config.default_action); !status) {
        close();
        return status;
    }

    // Step 4: Create XSK socket
    struct xsk_socket_config xsk_cfg{};
    xsk_cfg.rx_size = static_cast<__u32>(config.rx_ring_size);
    xsk_cfg.tx_size = static_cast<__u32>(config.tx_ring_size);
    xsk_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = 0;
    xsk_cfg.bind_flags = detail::xdp_bind_flags(config.bind_mode);

    std::string const ifname_str(config.interface_name);
    int const ret = xsk_socket__create(&xsk_, ifname_str.c_str(), config.queue_id, *umem_result, &rings_.rx, &rings_.tx, &xsk_cfg);
    if (ret != 0) {
        close();
        return failure(XdpError::xsk_creation_failed);
    }
    bind_mode_ = config.bind_mode;

    // Report the mode the bind obtained: with auto_ the kernel picks zero-copy
    // only when the driver offers it.
    struct xdp_options opts{};
    socklen_t opts_len = sizeof(opts);
    if (::getsockopt(xsk_socket__fd(xsk_), SOL_XDP, XDP_OPTIONS, &opts, &opts_len) == 0) {
        zero_copy_ = (opts.flags & XDP_OPTIONS_ZEROCOPY) != 0;
    }

    // Step 5: Attach BPF + register socket
    if (auto status = bpf_.attach(interface_.index, config.queue_id, xsk_socket__fd(xsk_)); !status) {
        close();
        return status;
    }

    // Step 6: Register TAP device if requested
    if (config.tap_ifindex != 0) {
        if (auto status = bpf_.register_tap(config.tap_ifindex); !status) {
            close();
            return status;
        }
    }

    // Step 7: Store budget config + initial fill
    budget_.rx_drain_max = config.rx_drain_max;
    budget_.completion_drain_max = config.completion_drain_max;
    budget_.rx_clock_id = config.rx_clock_id;

    auto fill_status = fill_replenish();
    if (!fill_status) {
        close();
        return fill_status;
    }

    return success();
}

void XdpContext::close() noexcept
{
    if (xsk_ != nullptr) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }

    bpf_.close();
    umem_.close();

    interface_ = {};
    rings_ = {};
    budget_ = {};
    stats_ = {};
    bind_mode_ = XdpBindMode::auto_;
    zero_copy_ = false;
}

auto XdpContext::tx_commit(uint64_t handle, size_t frame_length) -> Status
{
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&rings_.tx, 1, &idx) == 0) {
        // The TX ring is full. Return the caller's UMEM frame to the free
        // list so we do not leak it — without this, every tx_ring_full
        // event consumed one UMEM frame permanently until umem_exhausted
        // saturated.
        umem_.free_frame(handle);
        ++stats_.tx_ring_full_count;
        return failure(XdpError::tx_ring_full);
    }
    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&rings_.tx, idx);
    desc->addr = handle + umem_.headroom();
    desc->len = static_cast<uint32_t>(frame_length);
    xsk_ring_prod__submit(&rings_.tx, 1);
    ++stats_.tx_count;
    return success();
}

auto XdpContext::tx_complete() -> Status
{
    uint32_t idx = 0;
    auto completed = xsk_ring_cons__peek(&rings_.comp, static_cast<uint32_t>(budget_.completion_drain_max), &idx);
    for (uint32_t i = 0; i < completed; ++i) {
        auto addr = *xsk_ring_cons__comp_addr(&rings_.comp, idx + i);
        umem_.free_frame(addr);
    }
    if (completed > 0) {
        xsk_ring_cons__release(&rings_.comp, completed);
    }
    return success();
}

auto XdpContext::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (budget_.rx_drain_max > 0 && budget_.rx_cycle_count >= budget_.rx_drain_max) {
        ++stats_.rx_budget_hit_count;
        return std::optional<EthernetRxSlot>{};
    }

    uint32_t idx = 0;
    if (xsk_ring_cons__peek(&rings_.rx, 1, &idx) == 0) {
        return std::optional<EthernetRxSlot>{};
    }

    auto const* desc = xsk_ring_cons__rx_desc(&rings_.rx, idx);

    struct timespec ts{};
    (void)::clock_gettime(budget_.rx_clock_id, &ts);
    int64_t const timestamp_ns = (static_cast<int64_t>(ts.tv_sec) * 1'000'000'000) + ts.tv_nsec;

    EthernetRxSlot slot{
        .handle = desc->addr,
        .buffer = umem_.readable_span(desc->addr, desc->len),
        .timestamp_ns = timestamp_ns,
    };

    // Release ring slot — UMEM frame remains valid until rx_release(handle)
    xsk_ring_cons__release(&rings_.rx, 1);
    ++budget_.rx_cycle_count;
    ++stats_.rx_count;

    return std::optional<EthernetRxSlot>{slot};
}

auto XdpContext::fill_replenish() -> Status
{
    auto available = umem_.available_frames();
    if (available == 0) {
        return success();
    }

    auto const count = detail::fill_reserve_count(available, xsk_prod_nb_free(&rings_.fill, static_cast<uint32_t>(available)));
    if (count == 0) {
        return success();
    }

    uint32_t idx = 0;
    auto reserved = xsk_ring_prod__reserve(&rings_.fill, count, &idx);
    uint32_t filled = 0;
    for (uint32_t i = 0; i < reserved; ++i) {
        auto addr = umem_.alloc_frame();
        if (!addr) {
            break;
        }
        *xsk_ring_prod__fill_addr(&rings_.fill, idx + i) = *addr;
        ++filled;
    }
    if (filled > 0) {
        xsk_ring_prod__submit(&rings_.fill, filled);
    }
    return success();
}

auto XdpContext::join_multicast(ieee::Eui48 const& addr) -> Status
{
    if (xsk_ == nullptr) {
        return failure(XdpError::not_open);
    }

    struct ifreq ifr{};
    if (::if_indextoname(interface_.index, ifr.ifr_name) == nullptr) {
        return failure(XdpError::interface_not_found);
    }
    span_copy(hwaddr_bytes(ifr), make_const_span(addr.value));
    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;

    int sock_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return failure(XdpError::socket_creation_failed);
    }
    auto close_sock = detail::scopeguard([&]() noexcept { ::close(sock_fd); });

    if (::ioctl(sock_fd, SIOCADDMULTI, &ifr) < 0) {
        return failure(XdpError::join_multicast_failed);
    }

    return success();
}

#endif  // __linux__ && HAVE_XDP

}  // namespace statusbar::net
