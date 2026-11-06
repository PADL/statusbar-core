// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AnyEthernetPort and RawnetPort.
//
// The loopback tests need CAP_NET_RAW (AF_PACKET on Linux, /dev/bpf on
// macOS). Unprivileged they SKIP(), which the runner counts apart from the
// passes: a silent skip would read as one.

#include "statusbar/net/net_any_ethernet_port.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <thread>

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr uint16_t AVTP = 0x22F0;

#if defined(__APPLE__)
constexpr char const* LOOPBACK = "lo0";
#else
constexpr char const* LOOPBACK = "lo";
#endif

}  // namespace

TEST(any_ethernet_port, backend_names_round_trip)
{
    for (size_t i = 0; i < ETHERNET_BACKEND_NAMES.size(); ++i) {
        auto const parsed = parse_ethernet_backend(ETHERNET_BACKEND_NAMES[i]);
        EXPECT_TRUE(parsed.has_value());
        EXPECT_EQ(static_cast<size_t>(*parsed), i);
        EXPECT_EQ(ethernet_backend_name(*parsed), ETHERNET_BACKEND_NAMES[i]);
    }
    EXPECT_EQ(ethernet_backend_name(EthernetBackend::rawnet), std::string_view{"rawnet"});
    EXPECT_EQ(ethernet_backend_name(EthernetBackend::xdp), std::string_view{"xdp"});
}

TEST(any_ethernet_port, a_name_that_is_not_a_backend_is_refused)
{
    EXPECT_FALSE(parse_ethernet_backend("").has_value());
    EXPECT_FALSE(parse_ethernet_backend("XDP").has_value());
    EXPECT_FALSE(parse_ethernet_backend("packet").has_value());
    EXPECT_FALSE(parse_ethernet_backend("rawnet ").has_value());
}

// The RX clock is CLOCK_MONOTONIC_RAW and not a choice; the transitional
// field compiles an old config and refuses a value that would have chosen.
TEST(any_ethernet_port, an_rx_clock_other_than_monotonic_raw_is_refused_before_any_socket)
{
    AnyEthernetPort port;
    auto const status =
        port.open(EthernetBackend::rawnet, {.interface_name = "lo", .ethertype = 0x22F0, .rx_clock_id = CLOCK_MONOTONIC});
    EXPECT_FALSE(status.has_value());
    EXPECT_EQ(status.error(), make_error_code(NetError::invalid_argument));
    EXPECT_FALSE(port.valid());
    EXPECT_TRUE(software_rx_timestamp_ns(CLOCK_MONOTONIC_RAW) > 0);
}

TEST(any_ethernet_port, a_closed_port_is_closed_in_every_answer)
{
    AnyEthernetPort port;
    EXPECT_FALSE(port.valid());
    EXPECT_EQ(port.fd(), -1);
    EXPECT_FALSE(port.backend().has_value());
    EXPECT_FALSE(port.tx_rx_independent());
    EXPECT_EQ(port.describe(), std::string{"closed"});
    EXPECT_EQ(port.interface_index(), 0U);
    EXPECT_FALSE(port.hardware_address().is_set());

    auto const tx = port.tx_start();
    EXPECT_FALSE(tx.has_value());
    EXPECT_EQ(tx.error(), make_error_code(NetError::not_connected));
    auto const rx = port.rx_start();
    EXPECT_FALSE(rx.has_value());
    auto const rx_told_a_count = port.rx_start(int64_t{5});  // the transitional bare-count form
    EXPECT_FALSE(rx_told_a_count.has_value());
    EXPECT_EQ(rx_told_a_count.error(), make_error_code(NetError::not_connected));
    EXPECT_FALSE(port.tx_flush().has_value());
    EXPECT_FALSE(port.end_cycle().has_value());
    port.begin_cycle();  // nothing to do, and nothing to crash on
    EXPECT_FALSE(port.join_multicast(ieee::Eui48{}).has_value());
    EXPECT_FALSE(port.leave_multicast(ieee::Eui48{}).has_value());
}

TEST(any_ethernet_port, rawnet_refuses_an_empty_interface_and_ethertype_zero_without_opening_anything)
{
    AnyEthernetPort port;
    auto const no_interface = port.open(EthernetBackend::rawnet, {.interface_name = "", .ethertype = AVTP});
    EXPECT_FALSE(no_interface.has_value());
    EXPECT_EQ(no_interface.error(), make_error_code(NetError::invalid_argument));
    EXPECT_FALSE(port.backend().has_value());

    auto const no_ethertype = port.open(EthernetBackend::rawnet, {.interface_name = LOOPBACK, .ethertype = 0});
    EXPECT_FALSE(no_ethertype.has_value());
    EXPECT_EQ(no_ethertype.error(), make_error_code(NetError::invalid_argument));
    EXPECT_FALSE(port.valid());
}

TEST(rawnet_port, a_handle_that_was_never_handed_out_is_refused)
{
    RawnetPort port;
    EXPECT_FALSE(port.valid());
    EXPECT_EQ(port.tx_cancel(0).error(), make_error_code(NetError::invalid_handle));
    EXPECT_EQ(port.rx_release(RawnetPort::RX_SLOTS).error(), make_error_code(NetError::invalid_handle));
    EXPECT_EQ(port.tx_start().error(), make_error_code(NetError::not_connected));
    EXPECT_EQ(port.rx_start().error(), make_error_code(NetError::not_connected));
    EXPECT_EQ(port.tx_commit(0, 64).error(), make_error_code(NetError::not_connected));
}

#if defined(__linux__)

namespace {

[[nodiscard]] auto open_rawnet(AnyEthernetPort& port) -> bool
{
    return port.open(EthernetBackend::rawnet, {.interface_name = LOOPBACK, .ethertype = AVTP}).has_value();
}

}  // namespace

// Linux only, like the rawnet loopback tests: macOS's lo0 is DLT_NULL, not
// Ethernet, so a BPF on it does not carry the frames this port builds.
TEST(any_ethernet_port, rawnet_round_trips_a_frame_on_loopback)
{
    AnyEthernetPort port;
    if (!open_rawnet(port)) {
        SKIP("needs CAP_NET_RAW (raw socket open refused)");
    }
    EXPECT_TRUE(port.valid());
    EXPECT_TRUE(port.backend().has_value());
    EXPECT_TRUE(*port.backend() == EthernetBackend::rawnet);
    EXPECT_TRUE(port.tx_rx_independent());
    EXPECT_TRUE(port.fd() >= 0);
    EXPECT_EQ(port.describe(), std::string{"rawnet (AF_PACKET, two sockets)"});

    ieee::Eui48 const group{0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80};
    EXPECT_TRUE(port.join_multicast(group).has_value());

    // One frame: untagged header, then a payload that identifies it.
    std::array<uint8_t, 48> payload{};
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(0xA0 + i);
    }
    auto slot = port.tx_start();
    EXPECT_TRUE(slot.has_value());
    ieee::EthernetFrame header{};
    header.dest_mac = group;
    header.src_mac = port.hardware_address();
    header.ethertype = AVTP;
    auto const header_length = ieee::store_unchecked(slot->buffer, header);
    EXPECT_EQ(header_length, size_t{14});
    span_copy(slot->buffer.subspan(header_length, payload.size()), make_const_span(payload));
    EXPECT_TRUE(port.tx_commit(slot->handle, header_length + payload.size()).has_value());
    EXPECT_TRUE(port.tx_flush().has_value());

    // Loopback may deliver more than one copy; find ours.
    bool found = false;
    for (int attempt = 0; attempt < 200 && !found; ++attempt) {
        auto rx = port.rx_start();
        EXPECT_TRUE(rx.has_value());
        if (!rx.has_value()) {
            break;
        }
        if (!rx->has_value()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        auto const& frame = (*rx)->buffer;
        if (frame.size() == 14 + payload.size() && frame[12] == 0x22 && frame[13] == 0xF0 &&
            std::equal(payload.begin(), payload.end(), frame.begin() + 14)) {
            ieee::EthernetFrame seen{};
            (void)ieee::load_unchecked(frame, &seen);
            EXPECT_TRUE(seen.dest_mac == group);
            EXPECT_FALSE(seen.vlan_tag.is_set());
            found = true;
        }
        EXPECT_TRUE(port.rx_release((*rx)->handle).has_value());
    }
    EXPECT_TRUE(found);
    EXPECT_TRUE(port.leave_multicast(group).has_value());

    // Every TX slot came back: the pool can hand out all of them again.
    for (size_t i = 0; i < RawnetPort::TX_SLOTS; ++i) {
        auto s = port.tx_start();
        EXPECT_TRUE(s.has_value());
        if (s.has_value()) {
            EXPECT_TRUE(port.tx_cancel(s->handle).has_value());
        }
    }
    port.close();
    EXPECT_FALSE(port.valid());
    EXPECT_FALSE(port.backend().has_value());
}

TEST(any_ethernet_port, an_mmap_slot_given_back_is_the_next_one_handed_out)
{
    // The kernel sends an AF_PACKET TX ring in order and stops at the first
    // slot that is not a send request. A cancelled slot left behind the
    // index is therefore a hole that holds every frame committed after it
    // until the index has gone round the ring: a talker that cancels a slot
    // whenever it has nothing to send would stall its TX for a whole ring.
    MmapContext port;
    auto const status = port.open({.interface_name = LOOPBACK, .ethertype = AVTP, .tx_queue_size = 4});
    if (!status.has_value()) {
        SKIP("needs CAP_NET_RAW (AF_PACKET open refused)");
    }
    auto const first = port.tx_start();
    EXPECT_TRUE(first.has_value());
    if (!first.has_value()) {
        return;
    }
    EXPECT_TRUE(port.tx_cancel(first->handle).has_value());

    // The slot given back is the one handed out next: no hole.
    auto const again = port.tx_start();
    EXPECT_TRUE(again.has_value());
    if (again.has_value()) {
        EXPECT_EQ(again->handle, first->handle);
        EXPECT_TRUE(port.tx_cancel(again->handle).has_value());
        // Only the slot last handed out, and only once.
        EXPECT_FALSE(port.tx_cancel(again->handle).has_value());
    }
    port.close();
}

#endif  // __linux__

// A test port carries frames in process: TX is captured with its launch time,
// injected RX comes back, groups are joined and left, and no backend is named.
TEST(any_ethernet_port, a_test_port_captures_tx_and_returns_injected_rx)
{
    AnyEthernetPort port;
    EXPECT_TRUE(port.open_test({.hardware_address = ieee::Eui48{0x02, 0, 0, 0, 0, 1}}).has_value());
    EXPECT_TRUE(port.valid() && !port.backend().has_value() && !port.tx_rx_independent());
    auto slot = port.tx_start(1234);
    EXPECT_TRUE(slot.has_value() && port.tx_commit(slot->handle, 60).has_value() && port.tx_flush().has_value());
    auto* const test = port.as<TestPortContext>();
    auto const sent = test->pop_tx();
    EXPECT_TRUE(sent.has_value() && sent->frame.size() == 60 && sent->launch_time_ns == 1234);
    EXPECT_EQ(test->tx_flushes(), size_t{1});
    std::array<uint8_t, 64> const frame{0xAA};
    EXPECT_TRUE(test->inject_rx(frame).has_value());
    auto received = port.rx_start();
    EXPECT_TRUE(received.has_value() && received->has_value() && (*received)->buffer[0] == 0xAA);
    EXPECT_TRUE(port.rx_release((*received)->handle).has_value());
    ieee::Eui48 const group{0x91, 0xE0, 0xF0, 0, 0, 1};
    EXPECT_TRUE(port.join_multicast(group).has_value() && test->joined_multicast_groups().size() == 1);
    EXPECT_TRUE(port.leave_multicast(group).has_value() && test->joined_multicast_groups().empty());
}

// The test port sends a frame from several buffers as one, as a multi-buffer AF_XDP socket does: its own
// slot's header, then each buffer where it lies; past its tx_segments() a gather is refused, the slot freed.
TEST(any_ethernet_port, a_test_port_captures_a_gathered_frame_whole)
{
    AnyEthernetPort port;
    EXPECT_TRUE(port.open_test({.frame_pool_size = 2, .tx_segments = 3}).has_value());
    EXPECT_EQ(port.tx_segments(), size_t{3});
    std::array<uint8_t, 4> const first{1, 2, 3, 4};
    std::array<uint8_t, 3> const second{5, 6, 7};
    std::array<std::span<uint8_t const>, 2> const rest{first, second};
    auto slot = port.tx_start();
    EXPECT_TRUE(slot.has_value());
    slot->buffer[0] = 0xAA;
    slot->buffer[1] = 0xBB;
    EXPECT_TRUE(port.tx_commit_gather(slot->handle, 2, rest, 42).has_value());
    auto* const test = port.as<TestPortContext>();
    auto const sent = test->pop_tx();
    std::array<uint8_t, 9> const whole{0xAA, 0xBB, 1, 2, 3, 4, 5, 6, 7};
    EXPECT_TRUE(sent && sent->frame.size() == whole.size() && std::equal(whole.begin(), whole.end(), sent->frame.data()));
    EXPECT_TRUE(sent && sent->launch_time_ns == 42);
    EXPECT_TRUE(test->last_gather().size() == 2 && test->last_gather()[0].data() == first.data());
    std::array<std::span<uint8_t const>, 3> const too_many{first, second, first};
    auto again = port.tx_start();
    EXPECT_FALSE(port.tx_commit_gather(again->handle, 2, too_many).has_value());
    EXPECT_TRUE(port.tx_start().has_value() && port.tx_start().has_value());  // both slots free again
    EXPECT_TRUE(port.tx_commit_gather(std::nullopt, 0, rest).has_value());    // no header of its own
    EXPECT_EQ(test->tx_gathers(), size_t{2});
}

// The pin path reaches the xdp backend: one outside bpffs is refused as
// such, before the interface is looked up or anything is attached.
TEST(any_ethernet_port, the_xdp_backend_takes_the_pin_path)
{
    AnyEthernetPort port;
    auto const opened = port.open(
        EthernetBackend::xdp,
        AnyEthernetPortConfig{.interface_name = "lo", .ethertype = 0x22F0, .xdp_pin_path = "/tmp/statusbar-not-bpffs/lo"});
    EXPECT_FALSE(opened.has_value());
#if defined(__linux__) && defined(HAVE_XDP)
    if (!opened) {
        EXPECT_TRUE(opened.error() == XdpError::invalid_pin_path);
    }
#endif
    EXPECT_FALSE(port.valid());
}

// Frames a receiver holds come on top of the default UMEM, so neither the fill ring nor the
// transmit reserve gives them up.
TEST(any_ethernet_port, the_xdp_umem_grows_by_the_frames_a_receiver_holds)
{
    auto const plain = xdp_config_for({.interface_name = "lo", .ring_size = 128});
    auto const held = xdp_config_for({.interface_name = "lo", .ring_size = 128, .xdp_rx_hold_frames = 512});
    EXPECT_EQ(plain.umem_frame_count, XdpConfig{}.umem_frame_count);
    EXPECT_EQ(held.umem_frame_count, XdpConfig{}.umem_frame_count + 512);
    EXPECT_EQ(held.fill_ring_size, size_t{256});
    EXPECT_EQ(held.tx_frame_reserve, XdpConfig{}.tx_frame_reserve);
}

// A port on a UMEM shared with another device's takes its share, and multi-buffer transmit, as given.
TEST(any_ethernet_port, the_xdp_backend_takes_a_shared_umem_and_its_share)
{
    auto const plain = xdp_config_for({.interface_name = "lo"});
    EXPECT_TRUE(plain.shared_umem == nullptr && !plain.tx_scatter_gather);
    auto* const umem = reinterpret_cast<XdpSharedUmem*>(uintptr_t{0x1000});  // NOLINT(performance-no-int-to-ptr): only compared
    auto const shared =
        xdp_config_for({.interface_name = "lo", .xdp_shared_umem = umem, .xdp_umem_share = 1, .xdp_scatter_gather = true});
    EXPECT_TRUE(shared.shared_umem == umem && shared.umem_share == 1 && shared.tx_scatter_gather);
}

TEST(any_ethernet_port, a_ring_backend_shares_state_between_tx_and_rx_or_is_not_available)
{
    AnyEthernetPort port;
    for (auto const backend : {EthernetBackend::mmap, EthernetBackend::xdp}) {
        auto const status = port.open(backend, {.interface_name = LOOPBACK, .ethertype = AVTP});
        if (status.has_value()) {
            // A privileged Linux run: the backend opened. It is one socket.
            EXPECT_TRUE(port.valid());
            EXPECT_TRUE(port.backend().has_value() && *port.backend() == backend);
            EXPECT_FALSE(port.tx_rx_independent());
            EXPECT_TRUE(port.describe().starts_with(ethernet_backend_name(backend)));
        } else {
            // Not this platform, not this build, or not this privilege: the
            // port is closed, not half-open.
            EXPECT_FALSE(port.valid());
            EXPECT_FALSE(port.backend().has_value());
            EXPECT_FALSE(port.tx_rx_independent());
            std::printf(
                "  note: %s did not open on %s: %s\n",
                std::string{ethernet_backend_name(backend)}.c_str(),
                LOOPBACK,
                status.error().message().c_str());
        }
        port.close();
    }
}

TEST_MAIN(statusbar_net, net_any_ethernet_port_test)
