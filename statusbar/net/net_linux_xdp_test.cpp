// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for statusbar.net:linux_xdp module

#include "statusbar/test/test.hpp"

#ifdef __linux__

#    include "statusbar/ieee/ieee.hpp"
#    include "statusbar/net/net.hpp"
#    include "statusbar/net/net_tcam_classifier.hpp"
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
    check(XdpError::leave_multicast_failed);
    check(XdpError::bpf_query_failed);
    check(XdpError::bpf_pin_failed);
    check(XdpError::bpf_detach_failed);
    check(XdpError::zero_copy_needs_native_attach);
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
    EXPECT_EQ(config.bind_mode, XdpBindMode::auto_);
    EXPECT_TRUE(config.attach_mode == XdpAttachMode::native);
    EXPECT_TRUE(config.pin_path.empty());
    EXPECT_TRUE(config.adopt);
    EXPECT_FALSE(config.detach_on_close.has_value());
    EXPECT_TRUE(config.need_wakeup);
}

TEST(xdp_config, bind_flags_follow_the_attach_mode)
{
    using enum XdpAttachMode;
    // auto_ under a native program: the kernel chooses (zero-copy when the
    // driver offers it); under a generic one: copy, never a zero-copy socket.
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::auto_, native, false), 0u);
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::auto_, generic, false), static_cast<uint16_t>(XDP_COPY));
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::copy, native, false), static_cast<uint16_t>(XDP_COPY));
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::copy, generic, false), static_cast<uint16_t>(XDP_COPY));
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::zero_copy, native, false), static_cast<uint16_t>(XDP_ZEROCOPY));
    auto const refused = detail::xdp_bind_flags(XdpBindMode::zero_copy, generic, false);
    EXPECT_FALSE(refused.has_value());
    EXPECT_TRUE(refused.error() == XdpError::zero_copy_needs_native_attach);
    // need_wakeup adds XDP_USE_NEED_WAKEUP to any of them.
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::auto_, native, true), static_cast<uint16_t>(XDP_USE_NEED_WAKEUP));
    EXPECT_EQ(*detail::xdp_bind_flags(XdpBindMode::auto_, generic, true), static_cast<uint16_t>(XDP_COPY | XDP_USE_NEED_WAKEUP));
    EXPECT_EQ(
        *detail::xdp_bind_flags(XdpBindMode::zero_copy, native, true), static_cast<uint16_t>(XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP));
}

TEST(xdp_config, transient_kick_errors)
{
    for (int const e : {EAGAIN, EWOULDBLOCK, EBUSY, ENOBUFS, ENETDOWN}) {
        EXPECT_TRUE(detail::is_transient_kick_error(e));
    }
    // igb's TX wakeup with no native program, an unbound socket.
    EXPECT_FALSE(detail::is_transient_kick_error(EINVAL));
    EXPECT_FALSE(detail::is_transient_kick_error(ENXIO));
}

TEST(xdp_config, attach_flags)
{
    EXPECT_EQ(detail::xdp_attach_flags(XdpAttachMode::native), static_cast<uint32_t>(XDP_FLAGS_DRV_MODE));
    EXPECT_EQ(detail::xdp_attach_flags(XdpAttachMode::generic), static_cast<uint32_t>(XDP_FLAGS_SKB_MODE));
}

TEST(xdp_config, attach_plan)
{
    using enum XdpAttachMode;
    // Zero-copy: native or nothing.
    auto const zc = detail::attach_plan(native, XdpBindMode::zero_copy);
    EXPECT_TRUE(zc.has_value());
    EXPECT_TRUE(zc->first == native);
    EXPECT_FALSE(zc->fallback.has_value());
    auto const zc_generic = detail::attach_plan(generic, XdpBindMode::zero_copy);
    EXPECT_FALSE(zc_generic.has_value());
    EXPECT_TRUE(zc_generic.error() == XdpError::zero_copy_needs_native_attach);
    // auto_ and copy: native falls back to generic (auto_ then binds copy).
    for (auto const bind : {XdpBindMode::auto_, XdpBindMode::copy}) {
        auto const plan = detail::attach_plan(native, bind);
        EXPECT_TRUE(plan->first == native);
        EXPECT_TRUE(plan->fallback == generic);
        auto const gen = detail::attach_plan(generic, bind);
        EXPECT_TRUE(gen->first == generic);
        EXPECT_FALSE(gen->fallback.has_value());
    }
}

TEST(xdp_config, an_attached_native_program_stays_native)
{
    using enum XdpAttachMode;
    EXPECT_TRUE(detail::effective_attach_mode(native, native) == native);
    EXPECT_TRUE(detail::effective_attach_mode(native, generic) == native);  // detaching it would reset the NIC
    EXPECT_TRUE(detail::effective_attach_mode(generic, native) == native);  // replaced
    EXPECT_TRUE(detail::effective_attach_mode(generic, generic) == generic);
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
    EXPECT_FALSE(ctx.zero_copy());
    EXPECT_EQ(ctx.bind_mode(), XdpBindMode::auto_);
    EXPECT_FALSE(ctx.adopted());
}

TEST(xdp_stub, stats_zero_by_default)
{
    XdpContext ctx;
    auto const& s = ctx.stats();
    EXPECT_EQ(s.rx_count, 0u);
    EXPECT_EQ(s.tx_count, 0u);
    EXPECT_EQ(s.tx_ring_full_count, 0u);
    EXPECT_EQ(s.tx_flush_count, 0u);
    EXPECT_EQ(s.tx_flush_failed, 0u);
    EXPECT_EQ(s.rx_wakeup_count, 0u);
}

//
// AVTP stream rules
//

namespace {

/// An AVTP frame of `subtype`, untagged or with one 802.1Q tag.
auto avtp_frame(uint8_t subtype, bool tagged) -> std::vector<uint8_t>
{
    std::vector<uint8_t> f(64, 0);
    for (size_t i = 0; i < 6; ++i) {
        f[i] = 0x91;  // a MAAP-range multicast destination, for looks
        f[6 + i] = 0x02;
    }
    size_t at = 12;
    if (tagged) {
        f[at++] = 0x81;
        f[at++] = 0x00;
        f[at++] = 0x60;  // PCP 3, VID 2
        f[at++] = 0x02;
    }
    f[at++] = 0x22;
    f[at++] = 0xF0;
    f[at] = subtype;
    return f;
}

}  // namespace

TEST(xdp_avtp_rules, six_rules_for_the_stream_subtypes)
{
    auto const rules = avtp_stream_rules();
    EXPECT_EQ(rules.size(), size_t{6});
    TcamClassifier<32> classifier;
    classifier.set_rules(std::span<CompiledRule<32> const>{rules.data(), rules.size()});
    for (bool const tagged : {false, true}) {
        for (uint8_t const subtype : AVTP_STREAM_SUBTYPES) {
            auto const frame = avtp_frame(subtype, tagged);
            EXPECT_TRUE((classifier.classify_first(frame) & flag::process) != 0);
        }
        // ATDECC (ADP 0xFA, AECP 0xFB, ACMP 0xFC), MAAP (0xFE), CVF (0x03): the kernel's.
        for (uint8_t const subtype : {uint8_t{0xFA}, uint8_t{0xFB}, uint8_t{0xFC}, uint8_t{0xFE}, uint8_t{0x03}}) {
            auto const frame = avtp_frame(subtype, tagged);
            EXPECT_EQ(classifier.classify_first(frame), 0u);
        }
    }
    // Not AVTP at all: gPTP, MSRP.
    auto gptp = avtp_frame(0x02, false);
    gptp[12] = 0x88;
    gptp[13] = 0xF7;
    EXPECT_EQ(classifier.classify_first(gptp), 0u);
    auto msrp = avtp_frame(0x02, false);
    msrp[13] = 0xEA;
    EXPECT_EQ(classifier.classify_first(msrp), 0u);
}

TEST(xdp_avtp_rules, untagged_only_and_overflow)
{
    std::array<uint8_t, 2> const two = {0x02, 0x04};
    auto const untagged = avtp_subtype_rules(two, false, flag::drop);
    EXPECT_EQ(untagged->size(), size_t{2});
    EXPECT_EQ((*untagged)[0].result_flags, flag::drop);
    TcamClassifier<32> classifier;
    classifier.set_rules(std::span<CompiledRule<32> const>{untagged->data(), untagged->size()});
    EXPECT_TRUE(classifier.classify_first(avtp_frame(0x04, false)) != 0);
    EXPECT_EQ(classifier.classify_first(avtp_frame(0x04, true)), 0u);
    std::array<uint8_t, 9> const nine{};
    EXPECT_FALSE(avtp_subtype_rules(nine, true).has_value());  // 18 > 16
    EXPECT_TRUE(avtp_subtype_rules(nine, false).has_value());
}

TEST(xdp_avtp_rules, payload_offset)
{
    EXPECT_EQ(avtp_payload_offset(avtp_frame(0x02, false)), std::optional<size_t>{14});
    EXPECT_EQ(avtp_payload_offset(avtp_frame(0x02, true)), std::optional<size_t>{18});
    auto ipv4 = avtp_frame(0x02, false);
    ipv4[12] = 0x08;
    ipv4[13] = 0x00;
    EXPECT_FALSE(avtp_payload_offset(ipv4).has_value());
    auto tagged_ipv4 = avtp_frame(0x02, true);
    tagged_ipv4[16] = 0x08;
    tagged_ipv4[17] = 0x00;
    EXPECT_FALSE(avtp_payload_offset(tagged_ipv4).has_value());
    auto const frame = avtp_frame(0x02, true);
    EXPECT_FALSE(avtp_payload_offset(std::span{frame}.first(29)).has_value());  // less than the 12-byte AVTP header
    EXPECT_TRUE(avtp_payload_offset(std::span{frame}.first(30)).has_value());
    EXPECT_FALSE(avtp_payload_offset(std::span{frame}.first(10)).has_value());
}

//
// Integration tests (require root, veth pairs, Linux with XDP)
//

#    if defined(__linux__) && defined(HAVE_XDP)

#        include <unistd.h>

#        include <algorithm>
#        include <cstdlib>
#        include <string_view>

#        include <bpf/libbpf.h>
#        include <net/if.h>
#        include <sys/stat.h>
#        include <sys/vfs.h>

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

namespace {

/// Root that can load BPF (a user namespace's root cannot): the veth tests
/// below skip otherwise.
auto xdp_privileged() -> bool
{
    if (getuid() != 0 || xdp_filter_bpf_o_len == 0) {
        return false;
    }
    bpf_object* obj = bpf_object__open_mem(xdp_filter_bpf_o, xdp_filter_bpf_o_len, nullptr);
    if (obj == nullptr) {
        return false;
    }
    bool const loaded = bpf_object__load(obj) == 0;
    bpf_object__close(obj);
    return loaded;
}

/// The veth pair xdptest0/xdptest1 for one test.
struct Veth
{
    Veth()
    {
        destroy_veth_pair("xdptest0");
        ok = create_veth_pair("xdptest0", "xdptest1");
    }
    ~Veth() { destroy_veth_pair("xdptest0"); }
    Veth(Veth const&) = delete;
    auto operator=(Veth const&) -> Veth& = delete;
    [[nodiscard]] static auto index() -> unsigned int { return if_nametoindex("xdptest0"); }
    bool ok{false};
};

auto attached_program() -> std::optional<XdpAttachedProgram>
{
    auto const attached = XdpProgram::query(Veth::index());
    EXPECT_TRUE(attached.has_value());
    return attached ? *attached : std::nullopt;
}

constexpr std::string_view TEST_PIN_ROOT = "/sys/fs/bpf/statusbar-test";
constexpr std::string_view TEST_PIN = "/sys/fs/bpf/statusbar-test/xdptest0";

auto bpffs_mounted() -> bool
{
    struct statfs fs{};
    return ::statfs("/sys/fs/bpf", &fs) == 0 && fs.f_type == static_cast<decltype(fs.f_type)>(0xcafe4a11);  // BPF_FS_MAGIC
}

auto pinned(std::string_view name) -> bool
{
    std::string path{TEST_PIN};
    path += '/';
    path += name;
    return ::access(path.c_str(), F_OK) == 0;
}

}  // namespace

TEST(xdp_integration, native_attach_by_default_kept_at_close)
{
    if (!xdp_privileged()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    XdpContext ctx;
    EXPECT_TRUE(ctx.open({.interface_name = "xdptest0", .umem_frame_count = 64}).has_value());
    EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);  // veth has native XDP
    EXPECT_FALSE(ctx.adopted());
    EXPECT_FALSE(ctx.program().pinned());
    EXPECT_FALSE(ctx.program().will_detach_on_close());  // a native detach resets igb
    EXPECT_FALSE(ctx.zero_copy());                       // veth has no zero-copy: copy under native
    auto const attached = attached_program();
    EXPECT_TRUE(attached.has_value());
    EXPECT_TRUE(attached && attached->mode == XdpAttachMode::native);
    EXPECT_TRUE(attached && attached->prog_id == ctx.program().prog_id());
    ctx.close();
    EXPECT_TRUE(attached_program().has_value());
    EXPECT_TRUE(XdpProgram::detach(Veth::index(), {}).has_value());
    EXPECT_FALSE(attached_program().has_value());
}

TEST(xdp_integration, generic_attach_binds_copy_and_refuses_zero_copy)
{
    if (!xdp_privileged()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    XdpContext ctx;
    EXPECT_TRUE(
        ctx.open({.interface_name = "xdptest0", .umem_frame_count = 64, .attach_mode = XdpAttachMode::generic}).has_value());
    EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::generic);
    EXPECT_FALSE(ctx.zero_copy());
    auto const attached = attached_program();
    EXPECT_TRUE(attached && attached->mode == XdpAttachMode::generic);
    ctx.close();
    EXPECT_FALSE(attached_program().has_value());

    // Zero-copy under a generic program is refused before anything is attached.
    auto const refused = ctx.open(
        {.interface_name = "xdptest0",
         .umem_frame_count = 64,
         .bind_mode = XdpBindMode::zero_copy,
         .attach_mode = XdpAttachMode::generic});
    EXPECT_FALSE(refused.has_value());
    EXPECT_TRUE(!refused && refused.error() == XdpError::zero_copy_needs_native_attach);
    EXPECT_FALSE(attached_program().has_value());
}

TEST(xdp_integration, zero_copy_refused_by_the_driver_leaves_nothing_attached)
{
    if (!xdp_privileged()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    XdpContext ctx;
    auto const status = ctx.open(
        {.interface_name = "xdptest0", .umem_frame_count = 64, .bind_mode = XdpBindMode::zero_copy, .detach_on_close = true});
    EXPECT_FALSE(status.has_value());  // veth: native XDP, but no zero-copy
    EXPECT_FALSE(ctx.valid());
    EXPECT_FALSE(attached_program().has_value());
}

TEST(xdp_integration, a_pinned_native_program_is_kept_adopted_and_replaced)
{
    if (!xdp_privileged() || !bpffs_mounted()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    (void)XdpProgram::detach(Veth::index(), TEST_PIN);
    auto cleanup = detail::scopeguard([] {
        (void)XdpProgram::detach(Veth::index(), TEST_PIN);
        (void)::rmdir(std::string{TEST_PIN_ROOT}.c_str());
    });
    auto const rules = avtp_stream_rules();
    XdpConfig const config{
        .interface_name = "xdptest0",
        .filter_rules = std::span<CompiledRule<32> const>{rules.data(), rules.size()},
        .umem_frame_count = 64,
        .pin_path = TEST_PIN,
    };

    // First open: attached natively and pinned, kept at close.
    uint32_t first_id = 0;
    {
        XdpContext ctx;
        EXPECT_TRUE(ctx.open(config).has_value());
        EXPECT_FALSE(ctx.adopted());
        EXPECT_TRUE(ctx.program().pinned());
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
        EXPECT_FALSE(ctx.program().will_detach_on_close());
        first_id = ctx.program().prog_id();
        EXPECT_TRUE(
            pinned(XdpProgram::PIN_PROG) && pinned(XdpProgram::PIN_RULES_MAP) && pinned(XdpProgram::PIN_XSK_MAP) &&
            pinned(XdpProgram::PIN_DEVMAP));
    }
    auto attached = attached_program();
    EXPECT_TRUE(attached && attached->prog_id == first_id && attached->mode == XdpAttachMode::native);

    // Second open: adopted (the same program), still kept.
    {
        XdpContext ctx;
        EXPECT_TRUE(ctx.open(config).has_value());
        EXPECT_TRUE(ctx.adopted());
        EXPECT_EQ(ctx.program().prog_id(), first_id);
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
        EXPECT_FALSE(ctx.program().will_detach_on_close());
        EXPECT_TRUE(ctx.set_rules({}).has_value());  // the adopted maps are usable
        // A generic request adopts the native program all the same.
        ctx.close();
        XdpConfig generic = config;
        generic.attach_mode = XdpAttachMode::generic;
        EXPECT_TRUE(ctx.open(generic).has_value());
        EXPECT_TRUE(ctx.adopted());
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
    }
    attached = attached_program();
    EXPECT_TRUE(attached && attached->prog_id == first_id);

    // adopt = false: replaced in place (native to native, no detach) and re-pinned.
    uint32_t replaced_id = 0;
    {
        XdpConfig fresh = config;
        fresh.adopt = false;
        XdpContext ctx;
        EXPECT_TRUE(ctx.open(fresh).has_value());
        EXPECT_FALSE(ctx.adopted());
        replaced_id = ctx.program().prog_id();
        EXPECT_NE(replaced_id, first_id);
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
        EXPECT_TRUE(ctx.program().pinned());
    }
    attached = attached_program();
    EXPECT_TRUE(attached && attached->prog_id == replaced_id);

    // The explicit detach (mediabridged --xdp-detach) removes program and pins.
    EXPECT_TRUE(XdpProgram::detach(Veth::index(), TEST_PIN).has_value());
    EXPECT_FALSE(attached_program().has_value());
    EXPECT_FALSE(pinned(XdpProgram::PIN_PROG));
}

TEST(xdp_integration, replacement_keeps_native_and_close_detaches_only_its_own)
{
    if (!xdp_privileged()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    // A generic program gives way to a native request.
    XdpContext generic;
    EXPECT_TRUE(generic
                    .open(
                        {.interface_name = "xdptest0",
                         .umem_frame_count = 64,
                         .attach_mode = XdpAttachMode::generic,
                         .detach_on_close = false})
                    .has_value());
    generic.close();
    auto attached = attached_program();
    EXPECT_TRUE(attached && attached->mode == XdpAttachMode::generic);

    XdpContext first;
    EXPECT_TRUE(first.open({.interface_name = "xdptest0", .umem_frame_count = 64, .detach_on_close = true}).has_value());
    EXPECT_TRUE(first.attach_mode() == XdpAttachMode::native);
    attached = attached_program();
    EXPECT_TRUE(attached && attached->mode == XdpAttachMode::native && attached->prog_id == first.program().prog_id());

    // A generic request while a native program is attached replaces it natively.
    XdpProgram second;
    EXPECT_TRUE(second.open(Veth::index(), {.attach_mode = XdpAttachMode::generic, .detach_on_close = true}).has_value());
    EXPECT_TRUE(second.attach_mode() == XdpAttachMode::native);
    attached = attached_program();
    EXPECT_TRUE(attached && attached->prog_id == second.prog_id() && attached->mode == XdpAttachMode::native);

    // Closing the first leaves the second's program alone.
    first.close();
    attached = attached_program();
    EXPECT_TRUE(attached && attached->prog_id == second.prog_id());
    second.close();
    EXPECT_FALSE(attached_program().has_value());
}

TEST(xdp_integration, tx_flush_kicks_only_when_there_is_something_to_send)
{
    if (!xdp_privileged()) {
        return;
    }
    Veth veth;
    if (!veth.ok) {
        return;
    }
    XdpContext ctx;
    EXPECT_TRUE(
        ctx.open({.interface_name = "xdptest0", .umem_frame_count = 64, .rx_clock_id = -1, .attach_mode = XdpAttachMode::generic})
            .has_value());
    EXPECT_TRUE(ctx.tx_flush().has_value());
    EXPECT_EQ(ctx.stats().tx_flush_skipped, uint64_t{1});
    EXPECT_EQ(ctx.stats().tx_flush_count, uint64_t{0});

    auto slot = ctx.tx_start();
    EXPECT_TRUE(slot.has_value());
    std::fill_n(slot->buffer.begin(), 64, uint8_t{0xFF});
    slot->buffer[12] = 0x90;
    slot->buffer[13] = 0x00;
    EXPECT_TRUE(ctx.tx_commit(slot->handle, 64).has_value());
    EXPECT_TRUE(ctx.tx_flush().has_value());  // copy mode: the kernel always wants the kick
    EXPECT_EQ(ctx.stats().tx_flush_count, uint64_t{1});
    EXPECT_EQ(ctx.stats().tx_flush_failed, uint64_t{0});
    // Sent: nothing outstanding, the next kick is skipped.
    EXPECT_TRUE(ctx.tx_flush().has_value());
    EXPECT_EQ(ctx.stats().tx_flush_count, uint64_t{1});
    EXPECT_EQ(ctx.stats().tx_flush_skipped, uint64_t{2});

    // Multicast filter entries come and go.
    ieee::Eui48 const group{0x91, 0xE0, 0xF0, 0x00, 0x12, 0x34};
    EXPECT_TRUE(ctx.join_multicast(group).has_value());
    EXPECT_TRUE(ctx.leave_multicast(group).has_value());
}

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_test)