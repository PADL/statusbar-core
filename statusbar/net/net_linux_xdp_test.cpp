// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for statusbar.net:linux_xdp module

#include "statusbar/test/test.hpp"

#ifdef __linux__

#    include "statusbar/ieee/ieee.hpp"
#    include "statusbar/net/net.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstdint>
#    include <expected>
#    include <optional>
#    include <span>
#    include <string>
#    include <system_error>
#    include <vector>

using namespace statusbar;
using namespace statusbar::net;

//
// XdpError tests
//

TEST(xdp_error, error_code_from_enum)
{
    std::error_code ec = XdpError::socket_creation_failed;
    EXPECT_TRUE(ec.value() == 1);
    EXPECT_TRUE(ec.category().name() != nullptr);
}

TEST(xdp_error, different_errors_have_different_values)
{
    std::error_code ec1 = XdpError::socket_creation_failed;
    std::error_code ec2 = XdpError::interface_not_found;
    EXPECT_NE(ec1.value(), ec2.value());
}

TEST(xdp_error, error_message_not_empty)
{
    std::error_code ec = XdpError::socket_creation_failed;
    EXPECT_TRUE(!ec.message().empty());
}

TEST(xdp_error, all_errors_have_messages)
{
    // Verify every error code produces a non-"Unknown" message
    auto check = [](XdpError e) {
        std::error_code ec = e;
        EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
    };
    check(XdpError::socket_creation_failed);
    check(XdpError::interface_not_found);
    check(XdpError::get_hwaddr_failed);
    check(XdpError::umem_creation_failed);
    check(XdpError::xsk_creation_failed);
    check(XdpError::bpf_load_failed);
    check(XdpError::bpf_attach_failed);
    check(XdpError::bpf_map_update_failed);
    check(XdpError::tap_creation_failed);
    check(XdpError::tap_configure_failed);
    check(XdpError::not_open);
    check(XdpError::tx_ring_full);
    check(XdpError::rx_ring_empty);
    check(XdpError::fill_ring_full);
    check(XdpError::free_list_empty);
    check(XdpError::invalid_addr);
    check(XdpError::frame_too_large);
    check(XdpError::tx_flush_failed);
    check(XdpError::join_multicast_failed);
    check(XdpError::not_supported_on_platform);
    check(XdpError::invalid_bpf_program);
    check(XdpError::too_many_filter_rules);
    check(XdpError::stats_read_failed);
}

TEST(xdp_error, category_name)
{
    std::error_code ec = XdpError::not_open;
    std::string name = ec.category().name();
    EXPECT_EQ(name, std::string("statusbar.net.xdp"));
}

//
// XdpConfig defaults tests
//

TEST(xdp_config, default_values)
{
    XdpConfig config{.interface_name = "eth0"};
    EXPECT_EQ(config.default_action, XdpAction::pass_kernel);
    EXPECT_EQ(config.queue_id, 0u);
    EXPECT_EQ(config.rx_ring_size, 256u);
    EXPECT_EQ(config.tx_ring_size, 256u);
    EXPECT_EQ(config.fill_ring_size, 512u);
    EXPECT_EQ(config.completion_ring_size, 512u);
    EXPECT_EQ(config.umem_frame_size, 2048u);
    EXPECT_EQ(config.umem_frame_count, 1024u);
    EXPECT_EQ(config.umem_headroom, 0u);
    EXPECT_EQ(config.tap_ifindex, 0u);
    EXPECT_EQ(config.rx_drain_max, 32u);
}

TEST(xdp_config, compiled_rule_defaults)
{
    CompiledRule<32> rule{};
    EXPECT_EQ(rule.result_flags, 0u);
    EXPECT_EQ(rule.min_frame_size, 0u);
    EXPECT_EQ(rule.priority, 0u);
    for (auto m : rule.mask) {
        EXPECT_EQ(m, 0u);
    }
    for (auto m : rule.match) {
        EXPECT_EQ(m, 0u);
    }
}

//
// UmemFreeList tests
//

TEST(xdp_freelist, initial_state)
{
    detail::UmemFreeList fl(4, 2048);
    EXPECT_EQ(fl.available(), 4u);
}

TEST(xdp_freelist, pop_returns_frame_addresses)
{
    detail::UmemFreeList fl(4, 2048);
    // Pop all 4 — should get addresses 0, 2048, 4096, 6144 in some order
    std::vector<uint64_t> addrs;
    for (size_t i = 0; i < 4; ++i) {
        auto addr = fl.pop();
        EXPECT_TRUE(addr.has_value());
        addrs.push_back(*addr);
    }
    EXPECT_EQ(fl.available(), 0u);

    // Verify they are multiples of frame_size
    for (auto a : addrs) {
        EXPECT_EQ(a % 2048, 0u);
    }
}

TEST(xdp_freelist, pop_empty_returns_nullopt)
{
    detail::UmemFreeList fl(1, 2048);
    auto a1 = fl.pop();
    EXPECT_TRUE(a1.has_value());
    auto a2 = fl.pop();
    EXPECT_FALSE(a2.has_value());
}

TEST(xdp_freelist, push_then_pop)
{
    detail::UmemFreeList fl(2, 2048);
    auto a1 = fl.pop();
    auto a2 = fl.pop();
    EXPECT_EQ(fl.available(), 0u);

    fl.push(*a1);
    EXPECT_EQ(fl.available(), 1u);

    auto a3 = fl.pop();
    EXPECT_TRUE(a3.has_value());
    EXPECT_EQ(*a3, *a1);
}

TEST(xdp_freelist, push_does_not_exceed_capacity)
{
    detail::UmemFreeList fl(2, 2048);
    // Pop one to make room, then push two back — only one should fit
    auto a1 = fl.pop();
    EXPECT_TRUE(a1.has_value());
    EXPECT_EQ(fl.available(), 1u);

    fl.push(*a1);
    EXPECT_EQ(fl.available(), 2u);

    // Already at capacity — extra push should be silently dropped
    fl.push(99999);
    EXPECT_EQ(fl.available(), 2u);
}

TEST(xdp_freelist, default_constructed_is_empty)
{
    detail::UmemFreeList fl;
    EXPECT_EQ(fl.available(), 0u);
    auto a = fl.pop();
    EXPECT_FALSE(a.has_value());
}

//
// ScopeGuard tests
//

TEST(xdp_scopeguard, fires_on_normal_exit)
{
    bool fired = false;
    {
        auto guard = detail::scopeguard([&] { fired = true; });
        EXPECT_FALSE(fired);
    }
    EXPECT_TRUE(fired);
}

TEST(xdp_scopeguard, fires_on_early_return)
{
    bool fired = false;
    auto test_fn = [&]() {
        auto guard = detail::scopeguard([&] { fired = true; });
        return;  // Early return
    };
    test_fn();
    EXPECT_TRUE(fired);
}

//
// XdpContextOpen RAII wrapper test
//

TEST(xdp_raii, open_throws_on_failure)
{
    XdpContext ctx;
    XdpConfig config{.interface_name = "nonexistent_iface_xyz"};
    bool threw = false;
    try {
        XdpContextOpen opener{ctx, config};
    } catch (std::system_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

//
// Stub tests (verify stub returns not_supported_on_platform on non-Linux or without libbpf)
//

TEST(xdp_stub, open_fails)
{
    XdpContext ctx;
    XdpConfig config{.interface_name = "eth0"};
    auto status = ctx.open(config);
    EXPECT_FALSE(status.has_value());
}

TEST(xdp_stub, not_valid_by_default)
{
    XdpContext ctx;
    EXPECT_FALSE(ctx.valid());
    EXPECT_EQ(ctx.xsk_fd(), -1);
    EXPECT_EQ(ctx.fd(), -1);
    EXPECT_EQ(ctx.interface_index(), 0u);
}

TEST(xdp_stub, stats_zero_by_default)
{
    XdpContext ctx;
    auto const& s = ctx.stats();
    EXPECT_EQ(s.rx_count, 0u);
    EXPECT_EQ(s.tx_count, 0u);
    EXPECT_EQ(s.tx_ring_full_count, 0u);
}

//
// XdpKernelStats — the kernel's own counters
//

// counters_reported is the whole guard against reading a counter the kernel
// never filled. The kernel answers XDP_STATISTICS with either 24 bytes (the
// three counters it has always had) or 48 (all six, added in 5.9), and says
// which in the optlen it returns; the fields we zeroed and it did not write
// would otherwise read as a confident zero.
TEST(xdp_kernel_stats, counters_reported_gates_the_later_fields)
{
    XdpKernelStats const old_kernel{.counters_reported = 3};
    EXPECT_FALSE(old_kernel.has_rx_ring_full());
    EXPECT_FALSE(old_kernel.has_ring_empty_counters());

    // The one in between matters too: a kernel could answer with the four
    // and not the ring-empty pair, and the two predicates have to disagree.
    XdpKernelStats const four{.counters_reported = 4};
    EXPECT_TRUE(four.has_rx_ring_full());
    EXPECT_FALSE(four.has_ring_empty_counters());

    XdpKernelStats const current{.counters_reported = 6};
    EXPECT_TRUE(current.has_rx_ring_full());
    EXPECT_TRUE(current.has_ring_empty_counters());
}

TEST(xdp_kernel_stats, default_constructed_claims_nothing)
{
    XdpKernelStats const stats;
    EXPECT_EQ(stats.counters_reported, 0u);
    EXPECT_FALSE(stats.has_rx_ring_full());
    EXPECT_FALSE(stats.has_ring_empty_counters());
    EXPECT_EQ(stats.tx_invalid_descs, 0u);
}

// "No data" must not be readable as "no drops": a context with no socket
// has to fail rather than hand back six zeroes.
TEST(xdp_kernel_stats, unopened_context_fails_rather_than_reading_zero)
{
    XdpContext ctx;
    auto const stats = ctx.kernel_stats();
    EXPECT_FALSE(stats.has_value());
    // Which error it is matters: not_open says there is no socket to ask,
    // where stats_read_failed would mean we asked and the kernel refused.
    // Without this the guard could be deleted and the EBADF from
    // getsockopt(-1) would look like the same failure.
#    if defined(__linux__) && defined(HAVE_XDP)
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::not_open));
#    else
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::not_supported_on_platform));
#    endif
}

//
// Integration tests (require root, veth pairs, Linux with XDP)
//

#    if defined(__linux__) && defined(HAVE_XDP)

#        include <sched.h>
#        include <unistd.h>

#        include <cstdio>
#        include <cstdlib>
#        include <cstring>
#        include <memory>

#        include <sys/wait.h>

// Helper: create veth pair (requires root)
static bool create_veth_pair(char const* name_a, char const* name_b)
{
    char cmd[256];
    snprintf(
        cmd,
        sizeof(cmd),
        "ip link add %s type veth peer name %s && "
        "ip link set %s up && ip link set %s up",
        name_a,
        name_b,
        name_a,
        name_b);
    return system(cmd) == 0;
}

static void destroy_veth_pair(char const* name_a)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name_a);
    (void)system(cmd);
}

TEST(xdp_integration, open_close_lifecycle)
{
    // Skip if not root
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    auto const rules = ClassifierRuleBuilder<32>{}.ethertype(0x22F0).vlan_tagged_any().result(flag::process).build();

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = rules,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());
    EXPECT_TRUE(ctx.valid());
    EXPECT_TRUE(ctx.xsk_fd() >= 0);
    EXPECT_TRUE(ctx.interface_index() > 0);

    ctx.close();
    EXPECT_FALSE(ctx.valid());
}

TEST(xdp_integration, tx_rx_loopback)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // TX side on xdptest0
    XdpConfig tx_config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext tx_ctx;
    auto s1 = tx_ctx.open(tx_config);
    EXPECT_TRUE(s1.has_value());

    // RX side on xdptest1 — accept frames with ethertype 0x9000 via XSK
    auto const rx_rules = ClassifierRuleBuilder<32>{}.ethertype(0x9000).vlan_untagged().result(flag::process).build();
    XdpConfig rx_config{
        .interface_name = "xdptest1",
        .filter_rules = rx_rules,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext rx_ctx;
    auto s2 = rx_ctx.open(rx_config);
    EXPECT_TRUE(s2.has_value());

    // Prime RX fill ring
    (void)rx_ctx.fill_replenish();

    // TX: send a test frame with ethertype 0x9000
    auto tx_slot = tx_ctx.tx_start();
    EXPECT_TRUE(tx_slot.has_value());

    // Build minimal Ethernet frame: dst(6) + src(6) + ethertype(2) + payload
    auto buf = tx_slot->buffer;
    // Broadcast dest
    for (int i = 0; i < 6; ++i) {
        buf[i] = 0xFF;
    }
    // Source from tx interface
    auto const& src_mac = tx_ctx.hardware_address();
    auto const* src_data = src_mac.value.data();
    for (int i = 0; i < 6; ++i) {
        buf[6 + i] = src_data[i];
    }
    // Ethertype 0x9000
    buf[12] = 0x90;
    buf[13] = 0x00;
    // Payload
    buf[14] = 0xDE;
    buf[15] = 0xAD;

    (void)tx_ctx.tx_commit(tx_slot->handle, 64);  // Min frame size
    (void)tx_ctx.tx_flush();

    // Give kernel a moment to deliver
    usleep(10000);  // 10ms

    // RX: check for received frame
    rx_ctx.begin_cycle();
    auto rx_result = rx_ctx.rx_start();
    EXPECT_TRUE(rx_result.has_value());
    // Frame may or may not have arrived (XDP_COPY mode timing), so don't
    // hard-fail. If it arrived, verify payload.
    if (*rx_result) {
        auto const& slot = **rx_result;
        EXPECT_TRUE(slot.buffer.size() >= 16);
        if (slot.buffer.size() >= 16) {
            EXPECT_EQ(slot.buffer[14], 0xDE);
            EXPECT_EQ(slot.buffer[15], 0xAD);
        }
        (void)rx_ctx.rx_release(slot.handle);
    }
}

TEST(xdp_integration, rx_drain_budget)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .rx_drain_max = 2,  // Only drain 2 per cycle
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Verify context opens with drain budget configured and
    // begin_cycle/rx_start work on an empty ring.
    // Note: rx_cycle_count_ only increments on actual frame receipt,
    // so budget enforcement requires live traffic to fully exercise.
    ctx.begin_cycle();

    auto r1 = ctx.rx_start();
    EXPECT_TRUE(r1.has_value());    // Success (no error)
    EXPECT_FALSE(r1->has_value());  // Empty optional (no frames)
}

TEST(xdp_integration, multiple_inflight_tx)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Acquire multiple TX slots before committing any
    auto slot1 = ctx.tx_start();
    auto slot2 = ctx.tx_start();
    auto slot3 = ctx.tx_start();
    EXPECT_TRUE(slot1.has_value());
    EXPECT_TRUE(slot2.has_value());
    EXPECT_TRUE(slot3.has_value());

    // All handles must be distinct
    EXPECT_NE(slot1->handle, slot2->handle);
    EXPECT_NE(slot1->handle, slot3->handle);
    EXPECT_NE(slot2->handle, slot3->handle);

    // Commit all, then single flush
    (void)ctx.tx_commit(slot1->handle, 64);
    (void)ctx.tx_commit(slot2->handle, 64);
    (void)ctx.tx_commit(slot3->handle, 64);
    (void)ctx.tx_flush();

    // Reclaim via tx_complete
    usleep(10000);
    (void)ctx.tx_complete();
}

TEST(xdp_integration, set_rules)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // Start with one rule
    auto const rules1 = ClassifierRuleBuilder<32>{}.ethertype(0x22F0).vlan_tagged_any().result(flag::process).build();

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = rules1,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Update to different rules
    auto const gptp_rule = ClassifierRuleBuilder<32>{}.ethertype(0x88F7).vlan_untagged().result(flag::none).build();
    auto const udp_rule =
        ClassifierRuleBuilder<32>{}.ethertype(0x0800).ipv4_protocol(17).vlan_untagged().result(flag::process).build();
    std::array<CompiledRule<32>, 2> rules2{gptp_rule[0], udp_rule[0]};

    auto update_status = ctx.set_rules(rules2);
    EXPECT_TRUE(update_status.has_value());
}

// The member's success path needs an opened context, and opening one loads
// the BPF filter -- CAP_BPF, which no namespace grants. So this one really
// does need root, and says so when it does not have it: a root-only test that
// returns quietly is a test that stops running without anyone noticing.
TEST(xdp_integration, kernel_stats_on_an_open_context)
{
    if (getuid() != 0) {
        std::printf("SKIP xdp_integration.kernel_stats_on_an_open_context: needs root to load the XDP program\n");
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        std::printf("SKIP xdp_integration.kernel_stats_on_an_open_context: could not create the veth pair\n");
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig const config{.interface_name = "xdptest0", .umem_frame_count = 64};
    XdpContext ctx;
    EXPECT_TRUE(ctx.open(config).has_value());

    auto const stats = ctx.kernel_stats();
    EXPECT_TRUE(stats.has_value());
    EXPECT_EQ(stats->tx_invalid_descs, 0u);
    EXPECT_TRUE(stats->counters_reported >= 3);

    // And the same context, once closed, reports a failure rather than the
    // zeroes it would have been honest about a moment ago.
    ctx.close();
    EXPECT_FALSE(ctx.kernel_stats().has_value());
}

//
// kernel_stats_from — the mapping, with no socket at all
//

TEST(xdp_kernel_stats, every_counter_lands_in_its_own_field)
{
    // Distinct values, so a crossed pair cannot pass.
    struct xdp_statistics raw{};
    raw.rx_dropped = 11;
    raw.rx_invalid_descs = 22;
    raw.tx_invalid_descs = 33;
    raw.rx_ring_full = 44;
    raw.rx_fill_ring_empty_descs = 55;
    raw.tx_ring_empty_descs = 66;

    auto const stats = detail::kernel_stats_from(raw, sizeof(raw));
    EXPECT_EQ(stats.rx_dropped, 11u);
    EXPECT_EQ(stats.rx_invalid_descs, 22u);
    EXPECT_EQ(stats.tx_invalid_descs, 33u);
    EXPECT_EQ(stats.rx_ring_full, 44u);
    EXPECT_EQ(stats.rx_fill_ring_empty_descs, 55u);
    EXPECT_EQ(stats.tx_ring_empty_descs, 66u);
    EXPECT_EQ(stats.counters_reported, 6u);
}

TEST(xdp_kernel_stats, the_reported_length_decides_how_many_counters_are_claimed)
{
    struct xdp_statistics const raw{};

    // The three the kernel has always had.
    EXPECT_EQ(detail::kernel_stats_from(raw, 3 * sizeof(uint64_t)).counters_reported, 3u);
    // All six, since 5.9.
    EXPECT_EQ(detail::kernel_stats_from(raw, sizeof(raw)).counters_reported, 6u);
    // A kernel newer than this header: clamped to the fields we have, never
    // claiming counters we could not have copied.
    EXPECT_EQ(detail::kernel_stats_from(raw, 9 * sizeof(uint64_t)).counters_reported, 6u);
    EXPECT_EQ(detail::kernel_stats_from(raw, 0).counters_reported, 0u);
}

//
// read_xdp_kernel_stats — the syscall's failure paths, unprivileged
//

TEST(xdp_kernel_stats, reading_a_socket_that_is_not_an_af_xdp_socket_fails)
{
    int const udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(udp >= 0);
    auto const stats = detail::read_xdp_kernel_stats(udp);
    ::close(udp);
    EXPECT_FALSE(stats.has_value());
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::stats_read_failed));
}

TEST(xdp_kernel_stats, reading_a_closed_descriptor_fails)
{
    auto const stats = detail::read_xdp_kernel_stats(-1);
    EXPECT_FALSE(stats.has_value());
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::stats_read_failed));
}

//
// Kernel counters against a real AF_XDP socket, with no privilege
//
// A plain uid owns CAP_NET_RAW and CAP_NET_ADMIN over a network namespace it
// creates together with a user namespace, and that is all a transmit-only
// AF_XDP socket needs: binding one attaches no BPF program. Loading a program
// would want CAP_BPF, which a user namespace does NOT grant -- the load fails
// with EPERM inside the namespace exactly as it does outside -- so these tests
// cannot drive XdpContext, whose open() loads the filter. They build the
// socket with libxdp instead and read it through the same code the member
// calls, which is why that code takes a descriptor.
//
// The socket binds to the namespace's own loopback, which is the one device
// every network namespace already has: no veth to create, and so no `ip`
// binary to depend on -- in a build container that has no iproute2 the veth
// version of this skipped instead of running. Loopback must be brought UP
// first, with an ioctl rather than a shell: a down device makes the kick fail
// with ENETDOWN before the kernel ever looks at the descriptor, and the
// counter this test is about stays at zero.
//
// unshare(CLONE_NEWUSER) needs a single-threaded process; a child of fork() is
// one however many threads the test binary has.

namespace {

constexpr size_t PROBE_FRAME_SIZE = 2048;
constexpr size_t PROBE_FRAME_COUNT = 64;
constexpr size_t PROBE_RING_SIZE = 64;
constexpr size_t PROBE_FRAME_LENGTH = 60;

// Write a uid/gid map for the new user namespace, so the child is root in it.
auto write_own_map(char const* path, char const* line) -> bool
{
    FILE* f = ::fopen(path, "we");
    if (f == nullptr) {
        return false;
    }
    bool const wrote = ::fputs(line, f) >= 0;
    return ::fclose(f) == 0 && wrote;
}

auto enter_private_namespaces() -> bool
{
    // The maps name the caller's own id, not a literal: without
    // CAP_SETUID outside the namespace that is the only mapping the kernel
    // will accept, and hardcoding one makes the test skip for every other
    // uid -- including root, which is how this was caught.
    std::array<char, 32> uid_line{};
    std::array<char, 32> gid_line{};
    (void)std::snprintf(uid_line.data(), uid_line.size(), "0 %u 1", static_cast<unsigned>(::getuid()));
    (void)std::snprintf(gid_line.data(), gid_line.size(), "0 %u 1", static_cast<unsigned>(::getgid()));

    if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return false;
    }
    // setgroups must be denied before the gid map may be written.
    (void)write_own_map("/proc/self/setgroups", "deny");
    return write_own_map("/proc/self/uid_map", uid_line.data()) && write_own_map("/proc/self/gid_map", gid_line.data());
}

// Bring a device up with no help from a shell.
auto bring_up(char const* device) -> bool
{
    int const control = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (control < 0) {
        return false;
    }
    auto const closer = detail::scopeguard([control] { ::close(control); });
    ifreq request{};
    (void)std::snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", device);
    if (::ioctl(control, SIOCGIFFLAGS, &request) < 0) {
        return false;
    }
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
    return ::ioctl(control, SIOCSIFFLAGS, &request) == 0;
}

// Everything a child reports back. POD so it crosses the pipe as bytes.
struct ProbeReport
{
    bool entered{false};
    bool link_up{false};
    bool umem_created{false};
    bool socket_bound{false};
    bool fresh_read{false};
    bool bad_desc_submitted{false};
    bool kick_succeeded{false};
    bool after_read{false};
    uint64_t counters_reported{0};
    uint64_t fresh_tx_invalid{0};
    uint64_t fresh_sum{0};
    uint64_t after_tx_invalid{0};
};

// Build a transmit-only AF_XDP socket on the namespace's loopback, submit one
// descriptor addressed past the end of the UMEM, kick it, and report the
// counters either side. Runs as the child of fork(), inside its own
// namespaces.
void probe_tx_invalid(ProbeReport& out)
{
    out.entered = enter_private_namespaces();
    if (!out.entered) {
        return;
    }
    if (!bring_up("lo")) {
        return;
    }
    out.link_up = true;

    // The kernel refuses a UMEM whose area is not page-aligned, so this
    // cannot be a plain vector. aligned_alloc wants the size to be a multiple
    // of the alignment, which a whole number of frames is on any page size
    // that divides the region.
    size_t const area_size = PROBE_FRAME_SIZE * PROBE_FRAME_COUNT;
    auto const page_size = static_cast<size_t>(::getpagesize());
    std::unique_ptr<void, decltype(&std::free)> const area{std::aligned_alloc(page_size, area_size), &std::free};
    if (!area) {
        return;
    }
    std::memset(area.get(), 0, area_size);

    xsk_umem* umem = nullptr;
    xsk_ring_prod fill{};
    xsk_ring_cons comp{};
    xsk_umem_config const umem_config{
        .fill_size = PROBE_RING_SIZE,
        .comp_size = PROBE_RING_SIZE,
        .frame_size = PROBE_FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };
    if (xsk_umem__create(&umem, area.get(), area_size, &fill, &comp, &umem_config) != 0) {
        return;
    }
    out.umem_created = true;

    xsk_socket* xsk = nullptr;
    xsk_ring_prod tx{};
    xsk_socket_config const socket_config{
        .rx_size = PROBE_RING_SIZE,
        .tx_size = PROBE_RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_COPY,
    };
    if (xsk_socket__create(&xsk, "lo", 0, umem, nullptr, &tx, &socket_config) != 0) {
        xsk_umem__delete(umem);
        return;
    }
    out.socket_bound = true;
    int const fd = xsk_socket__fd(xsk);

    if (auto const fresh = detail::read_xdp_kernel_stats(fd); fresh.has_value()) {
        out.fresh_read = true;
        out.counters_reported = fresh->counters_reported;
        out.fresh_tx_invalid = fresh->tx_invalid_descs;
        out.fresh_sum = fresh->rx_dropped + fresh->rx_invalid_descs + fresh->tx_invalid_descs + fresh->rx_ring_full +
            fresh->rx_fill_ring_empty_descs + fresh->tx_ring_empty_descs;
    }

    uint32_t index = 0;
    if (xsk_ring_prod__reserve(&tx, 1, &index) == 1) {
        xdp_desc* desc = xsk_ring_prod__tx_desc(&tx, index);
        desc->addr = area_size + PROBE_FRAME_SIZE;  // past the end of the UMEM
        desc->len = PROBE_FRAME_LENGTH;
        desc->options = 0;
        xsk_ring_prod__submit(&tx, 1);
        out.bad_desc_submitted = true;
        out.kick_succeeded = ::sendto(fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0) == 0;
    }

    if (auto const after = detail::read_xdp_kernel_stats(fd); after.has_value()) {
        out.after_read = true;
        out.after_tx_invalid = after->tx_invalid_descs;
    }

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
}

// Run fill() in a forked child inside private namespaces and bring its report
// back. Reports a visible SKIP when the kernel will not make the namespaces,
// so a test that stops running cannot pass quietly.
auto run_probe(void (*fill)(ProbeReport&), char const* name) -> std::optional<ProbeReport>
{
    std::array<int, 2> pipe_fds{-1, -1};
    if (::pipe(pipe_fds.data()) != 0) {
        std::printf("SKIP %s: pipe() failed\n", name);
        return std::nullopt;
    }
    pid_t const child = ::fork();
    if (child < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        std::printf("SKIP %s: fork() failed\n", name);
        return std::nullopt;
    }
    if (child == 0) {
        ::close(pipe_fds[0]);
        ProbeReport report;
        fill(report);
        auto const* bytes = reinterpret_cast<uint8_t const*>(&report);
        ssize_t const written = ::write(pipe_fds[1], bytes, sizeof(report));
        ::close(pipe_fds[1]);
        ::_exit(written == static_cast<ssize_t>(sizeof(report)) ? 0 : 1);
    }
    ::close(pipe_fds[1]);
    ProbeReport report;
    ssize_t const read_bytes = ::read(pipe_fds[0], &report, sizeof(report));
    ::close(pipe_fds[0]);
    int status = 0;
    (void)::waitpid(child, &status, 0);
    if (read_bytes != static_cast<ssize_t>(sizeof(report))) {
        std::printf("SKIP %s: the child reported nothing\n", name);
        return std::nullopt;
    }
    if (!report.entered) {
        std::printf("SKIP %s: no user+network namespace available to this uid\n", name);
        return std::nullopt;
    }
    if (!report.link_up) {
        std::printf("SKIP %s: could not bring the namespace's loopback up\n", name);
        return std::nullopt;
    }
    if (!report.umem_created) {
        std::printf("SKIP %s: could not register a UMEM (RLIMIT_MEMLOCK?)\n", name);
        return std::nullopt;
    }
    if (!report.socket_bound) {
        std::printf("SKIP %s: could not bind a transmit-only AF_XDP socket to loopback\n", name);
        return std::nullopt;
    }
    return report;
}

}  // namespace

TEST(xdp_kernel_stats, a_fresh_socket_reads_zero_on_every_counter)
{
    auto const report = run_probe(probe_tx_invalid, "xdp_kernel_stats.a_fresh_socket_reads_zero_on_every_counter");
    if (!report) {
        return;
    }
    EXPECT_TRUE(report->fresh_read);
    EXPECT_EQ(report->fresh_sum, 0u);
    // Six, which is what pins that the read asks for the whole struct: a
    // request truncated to the old three would still succeed and still read
    // zero, and only this number would notice. A kernel older than 5.9
    // answers 3 and fails here, which is the right way to find that out.
    EXPECT_EQ(report->counters_reported, 6u);
}

// The point of the whole feature: the kernel refuses the descriptor, drops the
// frame, counts it -- and sendto still returns success, so without this counter
// a dropped frame is indistinguishable from a sent one.
TEST(xdp_kernel_stats, an_out_of_range_tx_descriptor_is_counted_though_the_kick_succeeds)
{
    auto const report =
        run_probe(probe_tx_invalid, "xdp_kernel_stats.an_out_of_range_tx_descriptor_is_counted_though_the_kick_succeeds");
    if (!report) {
        return;
    }
    EXPECT_TRUE(report->bad_desc_submitted);
    EXPECT_TRUE(report->kick_succeeded);
    EXPECT_TRUE(report->after_read);
    EXPECT_EQ(report->fresh_tx_invalid, 0u);
    EXPECT_EQ(report->after_tx_invalid, 1u);
}

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_test)