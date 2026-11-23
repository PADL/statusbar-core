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
    auto const rx_told = port.rx_start(RxTimePoint{RxClock::duration{5}});
    EXPECT_FALSE(rx_told.has_value());
    EXPECT_EQ(rx_told.error(), make_error_code(NetError::not_connected));
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

#endif  // __linux__

// The one port config stands for a config per backend, and a caller that
// opens a backend itself gets the same translation the port applies.
TEST(any_ethernet_port, the_backend_configs_follow_the_one_port_config)
{
    AnyEthernetPortConfig const config{
        .interface_name = "eth7",
        .ethertype = AVTP,
        .priority = 3,
        .ring_size = 512,
        .xdp_queue_id = 2,
        .xdp_attach_mode = XdpAttachMode::generic,
        .xdp_bind_mode = XdpBindMode::copy,
        .xdp_tx_launch_time = true,
    };

    auto const rawnet = rawnet_config_from(config);
    EXPECT_EQ(rawnet.interface_name, std::string_view{"eth7"});
    EXPECT_EQ(rawnet.ethertype, AVTP);
    EXPECT_EQ(rawnet.priority, 3);

    auto const mmap = mmap_config_from(config);
    EXPECT_EQ(mmap.interface_name, std::string_view{"eth7"});
    EXPECT_EQ(mmap.ethertype, AVTP);
    EXPECT_EQ(mmap.priority, 3U);
    EXPECT_EQ(mmap.rx_queue_size, size_t{512});
    EXPECT_EQ(mmap.tx_queue_size, size_t{512});

    auto const xdp = xdp_config_from(config);
    EXPECT_EQ(xdp.interface_name, std::string_view{"eth7"});
    EXPECT_EQ(xdp.queue_id, 2U);
    EXPECT_EQ(xdp.rx_ring_size, size_t{512});
    EXPECT_EQ(xdp.tx_ring_size, size_t{512});
    EXPECT_EQ(xdp.fill_ring_size, size_t{1024});  // twice the ring: the NIC's side of it
    EXPECT_EQ(xdp.completion_ring_size, size_t{1024});
    EXPECT_TRUE(xdp.tx_launch_time);
    EXPECT_TRUE(xdp.attach_mode == XdpAttachMode::generic);
    EXPECT_TRUE(xdp.bind_mode == XdpBindMode::copy);
    EXPECT_TRUE(xdp.filter_rules.empty());  // none given: none handed on

    // A negative priority is "leave the socket's default", which mmap spells as 0.
    auto negative = config;
    negative.priority = -1;
    EXPECT_EQ(mmap_config_from(negative).priority, 0U);
    EXPECT_EQ(rawnet_config_from(negative).priority, -1);
}

TEST_MAIN(statusbar_net, net_any_ethernet_port_test)
