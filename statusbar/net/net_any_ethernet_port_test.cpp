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

TEST_MAIN(statusbar_net, net_any_ethernet_port_test)
