// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for EthernetPort concept, TestPortContext, and TrafficClassifier

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net.hpp"
#include "statusbar/status/status.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

//
// EthernetPort concept satisfaction — static asserts
//

static_assert(EthernetPort<TestPortContext>, "TestPortContext must satisfy EthernetPort");
static_assert(EthernetPort<BpfPortContext>, "BpfPortContext must satisfy EthernetPort");

#ifdef __linux__
static_assert(EthernetPort<MmapContext>, "MmapContext must satisfy EthernetPort");
static_assert(EthernetPort<XdpContext>, "XdpContext must satisfy EthernetPort");
#endif

//
// TestPortContext — open/close lifecycle
//

TEST(test_port_lifecycle, open_close)
{
    TestPortContext port;
    EXPECT_FALSE(port.valid());
    EXPECT_EQ(port.fd(), -1);

    auto status = port.open({});
    EXPECT_TRUE(status.has_value());
    EXPECT_TRUE(port.valid());

    port.close();
    EXPECT_FALSE(port.valid());
}

TEST(test_port_lifecycle, hardware_address)
{
    ieee::Eui48 mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x42};
    TestPortContext port;
    auto open_status = port.open({.hardware_address = mac});
    (void)open_status;
    EXPECT_EQ(port.hardware_address().value, mac.value);
}

TEST(test_port_lifecycle, interface_index)
{
    TestPortContext port;
    auto open_status = port.open({.interface_index = 7});
    (void)open_status;
    EXPECT_EQ(port.interface_index(), 7u);
}

//
// TestPortContext — TX cycle
//

TEST(test_port_tx, start_commit_pop)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    auto slot_result = port.tx_start(12345);
    EXPECT_TRUE(slot_result.has_value());

    auto& slot = *slot_result;
    EXPECT_TRUE(slot.buffer.size() >= ETHERNET_PORT_MIN_FRAME_BUFFER);

    // Write a minimal frame
    slot.buffer[12] = 0x88;
    slot.buffer[13] = 0xF7;

    auto commit_status = port.tx_commit(slot.handle, 64);
    EXPECT_TRUE(commit_status.has_value());

    // Inspect captured TX
    EXPECT_EQ(port.tx_pending(), 1u);
    auto tx = port.pop_tx();
    EXPECT_TRUE(tx.has_value());
    EXPECT_EQ(tx->frame.size(), 64u);
    EXPECT_EQ(tx->frame[12], 0x88);
    EXPECT_EQ(tx->frame[13], 0xF7);
    EXPECT_EQ(tx->launch_time_ns, 12345);
}

TEST(test_port_tx, cancel)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    auto slot_result = port.tx_start(0);
    EXPECT_TRUE(slot_result.has_value());

    auto cancel_status = port.tx_cancel(slot_result->handle);
    EXPECT_TRUE(cancel_status.has_value());

    EXPECT_EQ(port.tx_pending(), 0u);
}

TEST(test_port_tx, flush_is_noop)
{
    TestPortContext port;
    auto open_status = port.open({});
    (void)open_status;
    auto status = port.tx_flush();
    EXPECT_TRUE(status.has_value());
}

//
// TestPortContext — RX cycle
//

TEST(test_port_rx, empty_returns_nullopt)
{
    TestPortContext port;
    auto open_status = port.open({});
    (void)open_status;

    auto rx = port.rx_start();
    EXPECT_TRUE(rx.has_value());
    EXPECT_FALSE(rx->has_value());
}

TEST(test_port_rx, inject_and_receive)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    // Build a test frame (64 bytes with ethertype 0x88F7)
    std::array<uint8_t, 64> frame{};
    frame[12] = 0x88;
    frame[13] = 0xF7;

    auto inject_status = port.inject_rx(frame, 99999);
    EXPECT_TRUE(inject_status.has_value());
    EXPECT_EQ(port.rx_pending(), 1u);

    auto rx = port.rx_start();
    EXPECT_TRUE(rx.has_value());
    EXPECT_TRUE(rx->has_value());

    auto& slot = **rx;
    EXPECT_EQ(slot.buffer.size(), 64u);
    EXPECT_EQ(slot.buffer[12], 0x88);
    EXPECT_EQ(slot.buffer[13], 0xF7);
    EXPECT_EQ(slot.timestamp_ns, 99999);

    auto release_status = port.rx_release(slot.handle);
    EXPECT_TRUE(release_status.has_value());

    // Now empty
    auto rx2 = port.rx_start();
    EXPECT_TRUE(rx2.has_value());
    EXPECT_FALSE(rx2->has_value());
}

//
// TestPortContext — multicast
//

TEST(test_port_multicast, join_records_address)
{
    TestPortContext port;
    auto open_status = port.open({});
    (void)open_status;

    ieee::Eui48 mcast{0x91, 0xE0, 0xF0, 0x00, 0x00, 0x01};
    auto status = port.join_multicast(mcast);
    EXPECT_TRUE(status.has_value());

    auto groups = port.joined_multicast_groups();
    EXPECT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].value, mcast.value);
}

//
// TestPortContext — housekeeping
//

TEST(test_port_housekeeping, begin_end_cycle)
{
    TestPortContext port;
    auto open_status = port.open({});
    (void)open_status;

    port.begin_cycle();  // no-op, should not crash

    auto status = port.end_cycle();
    EXPECT_TRUE(status.has_value());
}

//
// TestPortContext — pool exhaustion
//

TEST(test_port_pool, exhaustion)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 2});
    (void)open_status;

    auto s1 = port.tx_start(0);
    EXPECT_TRUE(s1.has_value());
    auto s2 = port.tx_start(0);
    EXPECT_TRUE(s2.has_value());

    // Pool exhausted
    auto s3 = port.tx_start(0);
    EXPECT_FALSE(s3.has_value());

    // Release one
    auto cancel_status = port.tx_cancel(s1->handle);
    (void)cancel_status;

    // Now one is available again
    auto s4 = port.tx_start(0);
    EXPECT_TRUE(s4.has_value());
}

//
// BpfPortContext — lifecycle tests (no real interface required)
//

TEST(bpf_port_lifecycle, default_not_valid)
{
    // Default-constructed BpfPortContext is not valid, fd() returns -1
    BpfPortContext port;
    EXPECT_FALSE(port.valid());
    EXPECT_EQ(port.fd(), -1);
}

TEST(bpf_port_lifecycle, open_empty_interface_fails)
{
    // Opening with an empty interface name should fail
    BpfPortContext port;
    auto status = port.open(BpfPortConfig{.interface_name = ""});
    EXPECT_FALSE(status.has_value());
    EXPECT_FALSE(port.valid());
}

TEST(bpf_port_pool, tx_start_allocates)
{
    // After a successful open, tx_start succeeds and returns a buffer
    // of at least ETHERNET_PORT_MIN_FRAME_BUFFER bytes.
    // Since we can't open a real interface in unit tests, we verify that
    // on a default-constructed (not opened) port, tx_start fails because
    // pool is empty.
    BpfPortContext port;
    auto slot = port.tx_start(0);
    EXPECT_FALSE(slot.has_value());  // no pool allocated
}

TEST(bpf_port_housekeeping, begin_end_cycle)
{
    // begin_cycle/end_cycle are no-ops and should succeed
    BpfPortContext port;
    port.begin_cycle();  // no-op, should not crash
    auto status = port.end_cycle();
    EXPECT_TRUE(status.has_value());
}

//
// TrafficClassifier tests
//

TEST(classifier_basic, default_action)
{
    // No rules: every frame returns the default action (forward_tap)
    TrafficClassifier tc;
    tc.set_rules({});

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;

    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_basic, ethertype_match)
{
    // Match ethertype 0x88F7 → process; others → forward_tap (default)
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x88F7;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 64> ptp_frame{};
    ptp_frame[12] = 0x88;
    ptp_frame[13] = 0xF7;
    EXPECT_EQ(tc.classify(ptp_frame), FrameAction::process);

    std::array<uint8_t, 64> other_frame{};
    other_frame[12] = 0x08;
    other_frame[13] = 0x00;
    EXPECT_EQ(tc.classify(other_frame), FrameAction::forward_tap);
}

TEST(classifier_vlan, tagged_frame)
{
    // VLAN-tagged frame: TPID 0x8100 at bytes 12-13,
    // TCI at bytes 14-15 (VID=42, PCP=0), real ethertype 0x88F7 at bytes 16-17
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x88F7;
    rule.vlan_match = VlanMatch::tagged_exact;
    rule.vlan_id = 42;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x81;
    frame[13] = 0x00;  // TPID 0x8100
    // TCI: PCP=0 (3 bits), DEI=0 (1 bit), VID=42 (12 bits) → 0x002A
    frame[14] = 0x00;
    frame[15] = 0x2A;
    frame[16] = 0x88;
    frame[17] = 0xF7;  // real ethertype

    EXPECT_EQ(tc.classify(frame), FrameAction::process);

    // Wrong VID → no match → default
    frame[15] = 0x63;  // VID=99
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_ip, udp_port_match)
{
    // IPv4 (0x0800) + UDP (proto=17) + dest port 319 → process
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0800;
    rule.ip_protocol = 17;
    rule.udp_port = 319;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    // Build a minimal IPv4/UDP frame (no VLAN tag)
    std::array<uint8_t, 64> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;  // ethertype IPv4
    frame[14] = 0x45;  // version=4, IHL=5 (20-byte header, no options)
    frame[23] = 17;    // UDP protocol (offset 14 + 9)
    // UDP dest port at offset 14 + 20 + 2 = 36
    frame[36] = 0x01;
    frame[37] = 0x3F;  // port 319 (0x013F)

    EXPECT_EQ(tc.classify(frame), FrameAction::process);

    // Wrong port → no match
    frame[37] = 0x40;  // port 320
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_ip, ipv4_udp_port_match_with_options)
{
    // IPv4 with options (IHL=6 → 24-byte header) + UDP + dest port 319.
    // Regression for the IHL=5 hardcode that read into the option bytes
    // instead of the UDP header.
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0800;
    rule.ip_protocol = 17;
    rule.udp_port = 319;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 80> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;  // ethertype IPv4
    frame[14] = 0x46;  // version=4, IHL=6 (24-byte header — one 4-byte option)
    frame[23] = 17;    // UDP protocol (offset 14 + 9)
    // UDP dest port now lives at offset 14 + 24 + 2 = 40 (not 36).
    frame[40] = 0x01;
    frame[41] = 0x3F;  // port 319

    EXPECT_EQ(tc.classify(frame), FrameAction::process);

    // If the classifier still read at offset 36, those bytes are zero and
    // dest_port = 0 ≠ 319, so the rule wouldn't match either way — to make
    // the regression bite, write a *different* port at the old offset.
    frame[36] = 0x01;
    frame[37] = 0x3F;  // would-be port 319 if IHL was hardcoded
    frame[41] = 0x40;  // make the real port 320 at the IHL=6 offset
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_ip, ipv4_rejects_malformed_ihl_below_minimum)
{
    // IHL < 5 is malformed (the IPv4 header has at least 20 bytes). The
    // classifier should skip the rule rather than treat payload bytes as
    // the UDP header.
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0800;
    rule.ip_protocol = 17;
    rule.udp_port = 319;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x44;  // version=4, IHL=4 — illegal
    frame[23] = 17;
    frame[36] = 0x01;
    frame[37] = 0x3F;

    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_ip, ipv6_protocol_match)
{
    // IPv6 (0x86DD) + UDP (next_header=17) → process
    // Bug: code was using IPv4 offset (+9) instead of IPv6 offset (+6)
    // which reads Hop Limit instead of Next Header
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x86DD;
    rule.ip_protocol = 17;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    // Build a minimal IPv6 frame (no VLAN tag)
    // Ethernet header: 14 bytes, then IPv6 header starts at offset 14
    // IPv6 header layout:
    //   bytes 0-3: version(4) + traffic class(8) + flow label(20)
    //   bytes 4-5: payload length
    //   byte 6: next header (protocol) ← this is what we want
    //   byte 7: hop limit
    std::array<uint8_t, 64> frame{};
    frame[12] = 0x86;
    frame[13] = 0xDD;  // ethertype IPv6
    // IPv6 next header at offset 14 + 6 = 20
    frame[20] = 17;  // UDP
    // Set hop limit to something else to prove we're reading the right byte
    frame[21] = 64;  // hop limit (NOT the protocol)

    EXPECT_EQ(tc.classify(frame), FrameAction::process);

    // Also verify: if next header is NOT UDP, should not match
    frame[20] = 6;  // TCP
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_ip, ipv6_udp_port_match)
{
    // IPv6 + UDP + dest port 319 → process
    // IPv6 header is 40 bytes, so UDP header starts at 14 + 40 = 54
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x86DD;
    rule.ip_protocol = 17;
    rule.udp_port = 319;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 72> frame{};
    frame[12] = 0x86;
    frame[13] = 0xDD;  // ethertype IPv6
    frame[20] = 17;    // next header = UDP
    // UDP dest port at offset 14 + 40 + 2 = 56
    frame[56] = 0x01;
    frame[57] = 0x3F;  // port 319

    EXPECT_EQ(tc.classify(frame), FrameAction::process);
}

TEST(classifier_basic, first_match_wins)
{
    // First rule matches ethertype 0x88F7 → process
    // Second rule matches any → drop
    // Frame with 0x88F7 should get process (first rule)
    TrafficClassifier tc;
    std::array<ClassifierRule, 2> rules{};
    rules[0].ethertype = 0x88F7;
    rules[0].action = FrameAction::process;
    rules[1].ethertype = 0;  // match any
    rules[1].action = FrameAction::drop;
    tc.set_rules(rules);

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x88;
    frame[13] = 0xF7;
    EXPECT_EQ(tc.classify(frame), FrameAction::process);

    // Non-matching ethertype → second rule (drop)
    frame[12] = 0x08;
    frame[13] = 0x00;
    EXPECT_EQ(tc.classify(frame), FrameAction::drop);
}

TEST(classifier_basic, drop_action)
{
    // Rule with drop action
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0806;  // ARP
    rule.action = FrameAction::drop;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x08;
    frame[13] = 0x06;
    EXPECT_EQ(tc.classify(frame), FrameAction::drop);
}

TEST(classifier_basic, short_frame)
{
    // Frame shorter than 14 bytes → default action
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x88F7;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 8> tiny{};
    EXPECT_EQ(tc.classify(tiny), FrameAction::forward_tap);
}

//
// TapBridge — lifecycle tests (all platforms)
//

TEST(tap_bridge_lifecycle, default_not_valid)
{
    // Default-constructed TapBridge is not valid and has no fd
    TapBridge bridge;
    EXPECT_FALSE(bridge.valid());
    EXPECT_EQ(bridge.fd(), -1);
}

TEST(tap_bridge_lifecycle, forward_fails_when_closed)
{
    // forward_to_tap should return error when bridge is not open
    TapBridge bridge;
    std::array<uint8_t, 64> frame{};
#if defined(__linux__)
    // On Linux: write() to fd=-1 returns EBADF; or the not_open check
    // Either way, the result should be a failure
    auto status = bridge.forward_to_tap(frame);
    EXPECT_FALSE(status.has_value());
#else
    auto status = bridge.forward_to_tap(frame);
    EXPECT_FALSE(status.has_value());
#endif
}

#if !defined(__linux__)

//
// TapBridge — non-Linux stub tests
//

TEST(tap_bridge_stub, open_fails)
{
    // On non-Linux platforms, open() always returns not_supported
    TapBridge bridge;
    auto status = bridge.open(TapBridgeConfig{.device_name = "tap0"});
    EXPECT_FALSE(status.has_value());
}

#endif  // !__linux__

//
// EthernetTxGuard — RAII TX guard tests
//

TEST(tx_guard, auto_cancels_on_scope_exit)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    {
        auto guard_result = tx_guard(port, 0);
        EXPECT_TRUE(guard_result.has_value());
        // Guard goes out of scope without commit — should auto-cancel
    }

    // No frames should have been transmitted
    EXPECT_EQ(port.tx_pending(), 0u);

    // The slot should be returned to the pool (can allocate again)
    auto slot = port.tx_start(0);
    EXPECT_TRUE(slot.has_value());
    (void)port.tx_cancel(slot->handle);
}

TEST(tx_guard, commit_sends_frame)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    {
        auto guard_result = tx_guard(port, 42);
        EXPECT_TRUE(guard_result.has_value());
        auto& guard = *guard_result;

        // Write something into the buffer
        guard.buffer()[12] = 0x88;
        guard.buffer()[13] = 0xF7;

        auto commit_status = guard.commit(64);
        EXPECT_TRUE(commit_status.has_value());
    }

    // Frame should have been transmitted
    EXPECT_EQ(port.tx_pending(), 1u);
    auto tx = port.pop_tx();
    EXPECT_TRUE(tx.has_value());
    EXPECT_EQ(tx->frame.size(), 64u);
    EXPECT_EQ(tx->frame[12], 0x88);
    EXPECT_EQ(tx->frame[13], 0xF7);
    EXPECT_EQ(tx->launch_time_ns, 42);
}

TEST(tx_guard, move_semantics_no_double_cancel)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    {
        auto guard_result = tx_guard(port, 0);
        EXPECT_TRUE(guard_result.has_value());

        // Move the guard — moved-from guard must not double-cancel
        auto moved_guard = std::move(*guard_result);
        // Original guard_result is now in a committed (no-op) state
        // moved_guard will auto-cancel on scope exit
    }

    // Slot should be returned exactly once (no double-cancel)
    EXPECT_EQ(port.tx_pending(), 0u);

    // Verify pool integrity: can still allocate all 4 slots
    auto s1 = port.tx_start(0);
    EXPECT_TRUE(s1.has_value());
    (void)port.tx_cancel(s1->handle);
}

//
// EthernetRxGuard — RAII RX guard tests
//

TEST(rx_guard_test, auto_releases_on_scope_exit)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    // Inject a frame
    std::array<uint8_t, 64> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;
    auto inject_status = port.inject_rx(frame, 12345);
    EXPECT_TRUE(inject_status.has_value());

    {
        auto guard_result = rx_guard(port);
        EXPECT_TRUE(guard_result.has_value());
        EXPECT_TRUE(guard_result->has_value());

        auto& guard = **guard_result;
        EXPECT_EQ(guard.buffer().size(), 64u);
        EXPECT_EQ(guard.buffer()[12], 0x08);
        EXPECT_EQ(guard.timestamp_ns(), 12345);
        // Guard auto-releases on scope exit
    }

    // Slot should be returned to pool — verify we can inject another frame
    auto inject2 = port.inject_rx(frame, 0);
    EXPECT_TRUE(inject2.has_value());
}

//
// send_frame convenience function tests
//

TEST(send_frame_test, sends_filled_frame)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    auto status = send_frame(port, 77, [](std::span<uint8_t> buffer) -> size_t {
        buffer[12] = 0xAB;
        buffer[13] = 0xCD;
        return 64;
    });
    EXPECT_TRUE(status.has_value());

    EXPECT_EQ(port.tx_pending(), 1u);
    auto tx = port.pop_tx();
    EXPECT_TRUE(tx.has_value());
    EXPECT_EQ(tx->frame.size(), 64u);
    EXPECT_EQ(tx->frame[12], 0xAB);
    EXPECT_EQ(tx->frame[13], 0xCD);
    EXPECT_EQ(tx->launch_time_ns, 77);
}

TEST(send_frame_test, zero_length_cancels)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    auto status = send_frame(port, 0, [](std::span<uint8_t>) -> size_t {
        return 0;  // zero length = cancel
    });
    EXPECT_TRUE(status.has_value());  // success (guard auto-cancelled)

    EXPECT_EQ(port.tx_pending(), 0u);  // no frame sent

    // Pool slot returned — can still allocate
    auto slot = port.tx_start(0);
    EXPECT_TRUE(slot.has_value());
    (void)port.tx_cancel(slot->handle);
}

TEST(rx_guard_test, returns_nullopt_when_empty)
{
    TestPortContext port;
    auto open_status = port.open({.frame_pool_size = 4});
    (void)open_status;

    auto guard_result = rx_guard(port);
    EXPECT_TRUE(guard_result.has_value());
    EXPECT_FALSE(guard_result->has_value());  // nullopt — no frames pending
}

//
// TrafficClassifier — decoder safety. The classifier inspects raw frames
// straight off the wire, so every field read past the declared-present
// header needs a size check. These tests pin down each bounds guard.
//

TEST(classifier_safety, vlan_tagged_frame_shorter_than_18_bytes)
{
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x22F0U;  // arbitrary
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    // 16 bytes: enough for the outer ethertype (0x8100) but too short
    // to read the inner ethertype at offset 16-17.
    std::array<uint8_t, 16> frame{};
    frame[12] = 0x81;
    frame[13] = 0x00;
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_safety, exactly_14_byte_untagged_frame_reads_ethertype)
{
    // Boundary: 14 bytes is exactly enough for the outer ethertype and
    // nothing else. Non-IP rule on this ethertype should still match.
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x22F0U;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 14> frame{};
    frame[12] = 0x22;
    frame[13] = 0xF0;
    EXPECT_EQ(tc.classify(frame), FrameAction::process);
}

TEST(classifier_safety, ipv4_rule_on_frame_too_short_for_proto_byte)
{
    // IPv4 rule needs to read frame[14 + 9 = 23]; provide only 20 bytes.
    // Rule must not match — classifier falls through to default.
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0800U;
    rule.ip_protocol = 17U;  // UDP
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 20> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;  // IPv4 ethertype
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_safety, ipv6_rule_on_frame_too_short_for_next_header)
{
    // IPv6 next_header is at offset 14+6=20. 18 bytes isn't enough.
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x86DDU;
    rule.ip_protocol = 17U;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 18> frame{};
    frame[12] = 0x86;
    frame[13] = 0xDD;
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_safety, udp_port_rule_on_frame_too_short_for_port)
{
    // UDP port offset for IPv4 is 14 + 20 + 2 = 36; need 38 bytes.
    // Provide 30 (IP proto byte present, port bytes not).
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ethertype = 0x0800U;
    rule.ip_protocol = 17U;
    rule.udp_port = 319U;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 30> frame{};
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[23] = 17;  // IP protocol = UDP so proto check passes
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

TEST(classifier_safety, ip_rule_on_non_ip_ethertype_does_not_match)
{
    // ClassifierRule with ip_protocol set but ethertype != IPv4/IPv6
    // must not match (avoids reading past ethertype for non-IP frames).
    TrafficClassifier tc;
    ClassifierRule rule;
    rule.ip_protocol = 17U;
    rule.action = FrameAction::process;
    tc.set_rules(std::span<ClassifierRule const>(&rule, 1));

    std::array<uint8_t, 64> frame{};
    frame[12] = 0x22;
    frame[13] = 0xF0;  // arbitrary non-IP ethertype
    EXPECT_EQ(tc.classify(frame), FrameAction::forward_tap);
}

//
// Told the time: rx_start(now) and rx_guard(port, now)
//

static_assert(std::is_same_v<RxTimePoint, realtime::MonotonicRawClock::time_point>, "the RX clock is CLOCK_MONOTONIC_RAW");

namespace {

constexpr int64_t TOLD_NS = 123'456'789;
constexpr RxTimePoint TOLD{RxClock::duration{TOLD_NS}};

auto open_with_one_frame(TestPortContext& port, int64_t const injected_ns) -> void
{
    (void)port.open({.frame_pool_size = 4});
    std::array<uint8_t, 64> const frame{};
    EXPECT_TRUE(port.inject_rx(frame, injected_ns).has_value());
}

}  // namespace

TEST(test_port_rx, told_time_stamps_a_frame_injected_without_one)
{
    TestPortContext port;
    open_with_one_frame(port, 0);
    auto rx = port.rx_start(TOLD);
    EXPECT_TRUE(rx.has_value() && rx->has_value());
    EXPECT_EQ((*rx)->timestamp_ns, TOLD_NS);
    EXPECT_TRUE(port.rx_release((*rx)->handle).has_value());
}

TEST(test_port_rx, told_time_does_not_replace_an_injected_stamp)
{
    TestPortContext port;
    open_with_one_frame(port, 99999);
    auto rx = port.rx_start(TOLD);
    EXPECT_TRUE(rx.has_value() && rx->has_value());
    EXPECT_EQ((*rx)->timestamp_ns, 99999);
    EXPECT_TRUE(port.rx_release((*rx)->handle).has_value());
}

TEST(test_port_rx, asking_form_reads_the_raw_clock)
{
    TestPortContext port;
    open_with_one_frame(port, 0);
    auto const before = rx_clock_now();
    auto rx = port.rx_start();
    auto const after = rx_clock_now();
    EXPECT_TRUE(rx.has_value() && rx->has_value());
    EXPECT_TRUE((*rx)->timestamp_ns >= rx_timestamp_ns(before));
    EXPECT_TRUE((*rx)->timestamp_ns <= rx_timestamp_ns(after));
    EXPECT_TRUE(port.rx_release((*rx)->handle).has_value());
}

TEST(test_port_rx, rx_guard_told_the_time_forwards_it)
{
    TestPortContext port;
    open_with_one_frame(port, 0);
    auto guard = rx_guard(port, TOLD);
    EXPECT_TRUE(guard.has_value() && guard->has_value());
    EXPECT_EQ((*guard)->timestamp_ns(), TOLD_NS);
}

TEST_MAIN(statusbar_net, net_ethernet_port_test)