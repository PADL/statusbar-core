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

// A test port carries frames in process: TX is captured with its launch time,
// injected RX comes back, groups are joined and left, and no backend is named.
TEST(any_ethernet_port, a_test_port_captures_tx_and_returns_injected_rx)
{
    AnyEthernetPort port;
    EXPECT_TRUE(port.open_test({.hardware_address = ieee::Eui48{0x02, 0, 0, 0, 0, 1}}).has_value());
    EXPECT_TRUE(port.valid());
    EXPECT_FALSE(port.backend().has_value());
    EXPECT_FALSE(port.tx_rx_independent());
    EXPECT_TRUE(port.describe().starts_with("test"));
    auto const slot = port.tx_start(1234);
    EXPECT_TRUE(slot.has_value());
    EXPECT_TRUE(slot.has_value() && port.tx_commit(slot->handle, 60).has_value());
    auto* const test = port.as<TestPortContext>();
    auto const sent = test->pop_tx();
    EXPECT_EQ(sent.has_value() ? sent->frame.size() : 0, size_t{60});
    EXPECT_EQ(sent.has_value() ? sent->launch_time_ns : 0, int64_t{1234});

    std::array<uint8_t, 64> const frame{0xAA};
    EXPECT_TRUE(test->inject_rx(frame).has_value());
    auto const received = port.rx_start(RxTimePoint{RxClock::duration{5}});
    auto const rx = received.value_or(std::nullopt);
    EXPECT_EQ(rx.has_value() ? rx->buffer[0] : 0, uint8_t{0xAA});
    EXPECT_EQ(rx.has_value() ? rx->timestamp_ns : 0, int64_t{5});
    EXPECT_TRUE(rx.has_value() && port.rx_release(rx->handle).has_value());

    ieee::Eui48 const group{0x91, 0xE0, 0xF0, 0, 0, 1};
    EXPECT_TRUE(port.join_multicast(group).has_value());
    EXPECT_EQ(test->joined_multicast_groups().size(), size_t{1});
    EXPECT_TRUE(port.leave_multicast(group).has_value());
    EXPECT_TRUE(test->joined_multicast_groups().empty());
}

// A test port counts its flushes and cycles, and a refused commit sends
// nothing and gives its slot back.
TEST(any_ethernet_port, a_test_port_counts_flushes_and_cycles_and_can_refuse_commits)
{
    AnyEthernetPort port;
    EXPECT_TRUE(port.open_test({.hardware_address = ieee::Eui48{0x02, 0, 0, 0, 0, 1}, .frame_pool_size = 1}).has_value());
    auto* const test = port.as<TestPortContext>();
    port.begin_cycle();
    EXPECT_TRUE(port.tx_flush().has_value());
    EXPECT_TRUE(port.end_cycle().has_value());
    EXPECT_EQ(test->tx_flushes(), size_t{1});
    EXPECT_EQ(test->cycles_begun(), size_t{1});
    EXPECT_EQ(test->cycles_ended(), size_t{1});

    test->refuse_commits(true);
    auto const refused = port.tx_start(0);
    EXPECT_TRUE(refused.has_value());
    EXPECT_FALSE(refused.has_value() && port.tx_commit(refused->handle, 60).has_value());
    EXPECT_EQ(test->tx_pending(), size_t{0});
    test->refuse_commits(false);
    auto const accepted = port.tx_start(0);  // the one slot, given back by the refusal
    EXPECT_TRUE(accepted.has_value() && port.tx_commit(accepted->handle, 60).has_value());
    EXPECT_EQ(test->tx_pending(), size_t{1});
// The pin path reaches the xdp backend: one outside bpffs is refused as
// such, before the interface is looked up or anything is attached.
TEST(any_ethernet_port, the_xdp_backend_accepts_the_pin_path)
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
