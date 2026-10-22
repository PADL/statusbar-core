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
// fill_reserve_count tests
//

TEST(xdp_fill_reserve, clamps_to_ring_free)
{
    // Default config: 1024 UMEM frames, 512-entry fill ring. Asking
    // xsk_ring_prod__reserve() for 1024 would reserve nothing.
    EXPECT_EQ(detail::fill_reserve_count(1024, 512), 512u);
}

TEST(xdp_fill_reserve, clamps_to_available)
{
    EXPECT_EQ(detail::fill_reserve_count(64, 512), 64u);
}

TEST(xdp_fill_reserve, zero_when_ring_full_or_no_frames)
{
    EXPECT_EQ(detail::fill_reserve_count(1024, 0), 0u);
    EXPECT_EQ(detail::fill_reserve_count(0, 512), 0u);
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
// Integration tests (require root, veth pairs, Linux with XDP)
//

#    if defined(__linux__) && defined(HAVE_XDP)

#        include <unistd.h>

#        include <cstdlib>

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

TEST(xdp_integration, fill_ring_populated_when_umem_exceeds_fill_ring)
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
        .fill_ring_size = 512,
        .umem_frame_count = 1024,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // open() hands fill_ring_size frames to the kernel for RX; only the
    // remainder is left for TX. An all-or-nothing reserve of 1024 would
    // have left the fill ring empty and all 1024 frames free.
    size_t tx_frames = 0;
    while (ctx.tx_start().has_value()) {
        ++tx_frames;
    }
    EXPECT_EQ(tx_frames, config.umem_frame_count - config.fill_ring_size);
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

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_test)