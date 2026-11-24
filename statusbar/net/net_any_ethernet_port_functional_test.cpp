// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AnyEthernetPort and RawnetPort.
//
// The loopback tests need CAP_NET_RAW (AF_PACKET on Linux, /dev/bpf on
// macOS). Unprivileged they SKIP(), which the runner counts apart from the
// passes: a silent skip would read as one.

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_any_ethernet_port.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/test/test.hpp"

#include <poll.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

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
            // Nothing yet: block until the socket has a frame, however long
            // the host takes to loop it back. The timeout only ends the
            // test for a frame that never comes.
            struct pollfd waiting{.fd = port.fd(), .events = POLLIN, .revents = 0};
            if (::poll(&waiting, 1, 10'000) <= 0) {
                break;
            }
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

TEST_MAIN(statusbar_net, net_any_ethernet_port_functional_test)
