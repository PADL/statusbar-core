// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// parse_link_carrier against RTM_NEWLINK messages framed as rtnl_fill_ifinfo writes them (linux/rtnetlink.h,
// linux/if_link.h: IFLA_IFNAME 3, IFLA_CARRIER 33, IFLA_CARRIER_DOWN_COUNT 48). The bytes are little-endian.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_carrier_watch.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <span>

#    include <linux/netlink.h>
#    include <sys/socket.h>

namespace {

using namespace statusbar::net;

constexpr bool LITTLE = std::endian::native == std::endian::little;

// clang-format off
/// RTM_NEWLINK for ifindex 3, up and running with LOWER_UP: carrier 1, carrier_down_count 7, ifname "eth0".
constexpr std::array<uint8_t, 60> NEWLINK{
    0x3c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x30, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x03, 0x00, 'e', 't', 'h', '0', 0x00, 0x00, 0x00, 0x00,
};
// clang-format on

/// NEWLINK with the octet at `at` replaced by `value`.
auto patched(size_t const at, uint8_t const value) -> std::array<uint8_t, 60>
{
    auto message = NEWLINK;
    message[at] = value;
    return message;
}

}  // namespace

TEST(net_carrier_watch, a_newlink_reports_the_carrier_and_its_down_count)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const link = parse_link_carrier(NEWLINK, 3);
    EXPECT_TRUE(link.has_value() && link->has_value());
    EXPECT_TRUE(link && *link && **link == (LinkCarrier{.carrier = true, .down_count = 7}));
    auto const down = parse_link_carrier(patched(36, 0), 3);
    EXPECT_TRUE(down && *down && !(*down)->carrier && (*down)->down_count == 7);
}

TEST(net_carrier_watch, without_ifla_carrier_lower_up_says)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const flags = parse_link_carrier(patched(34, 0x22), 3);  // IFLA_CARRIER retyped away
    EXPECT_TRUE(flags && *flags && (*flags)->carrier);
    auto lower_down = patched(34, 0x22);
    lower_down[26] = 0x00;
    auto const no_lower_up = parse_link_carrier(lower_down, 3);
    EXPECT_TRUE(no_lower_up && *no_lower_up && !(*no_lower_up)->carrier);
}

TEST(net_carrier_watch, other_links_and_messages_are_none)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const other = parse_link_carrier(NEWLINK, 4);
    EXPECT_TRUE(other && !*other);
    auto const dellink = parse_link_carrier(patched(4, 0x11), 3);
    EXPECT_TRUE(dellink && !*dellink);
    auto const short_other = parse_link_carrier(std::span{NEWLINK}.first(4), 3);
    EXPECT_TRUE(short_other && !*short_other);
    auto const bridge = parse_link_carrier(patched(16, AF_BRIDGE), 3);  // another family's view of the port
    EXPECT_TRUE(bridge && !*bridge);
}

TEST(net_carrier_watch, a_dellink_removes_the_link_in_af_unspec_alone)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    EXPECT_TRUE(is_link_removed(patched(4, 0x11), 3));
    EXPECT_FALSE(is_link_removed(patched(4, 0x11), 4));
    EXPECT_FALSE(is_link_removed(NEWLINK, 3));
    auto bridge = patched(4, 0x11);
    bridge[16] = AF_BRIDGE;  // the port leaving its bridge: the link stays
    EXPECT_FALSE(is_link_removed(bridge, 3));
    EXPECT_FALSE(is_link_removed(std::span{bridge}.first(20), 3));
}

TEST(net_carrier_watch, a_malformed_newlink_is_refused)
{
    EXPECT_FALSE(parse_link_carrier(patched(32, 0x06), 3).has_value());             // carrier of 2 octets
    EXPECT_FALSE(parse_link_carrier(patched(40, 0x06), 3).has_value());             // down count of 2 octets
    EXPECT_FALSE(parse_link_carrier(patched(48, 0x20), 3).has_value());             // overruns
    EXPECT_FALSE(parse_link_carrier(std::span{NEWLINK}.first(40), 3).has_value());  // truncated
    EXPECT_FALSE(parse_link_carrier(patched(0, 0x14), 3).has_value());              // shorter than ifinfomsg
}

TEST(net_carrier_watch, a_get_link_names_the_index_alone)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // clang-format off
    constexpr std::array<uint8_t, 32> EXPECTED{
        0x20, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    std::array<uint8_t, 32> out{};
    auto const length = build_get_link(out, 3, 5);
    EXPECT_TRUE(length && *length == out.size());
    EXPECT_TRUE(out == EXPECTED);
    EXPECT_FALSE(build_get_link(out, 0, 5).has_value());
    EXPECT_FALSE(build_get_link(std::span{out}.first(16), 3, 5).has_value());
}

TEST(net_carrier_watch, the_watch_reports_the_state_at_open_then_waits)
{
    // Host-dependent: skipped where NETLINK_ROUTE is unavailable. Loopback (ifindex 1) always has a carrier.
    int reports = 0;
    bool carrier = false;
    CarrierWatch watch{1, [&](LinkCarrier const& link) {
                           ++reports;
                           carrier = link.carrier;
                       }};
    if (!watch.open().has_value()) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    EXPECT_TRUE(watch.fd() >= 0);
    watch.on_ready(0);
    EXPECT_FALSE(watch.finished());
    EXPECT_EQ(reports, 1);
    EXPECT_TRUE(carrier);
    watch.on_ready(0);
    EXPECT_EQ(reports, 1);
}

TEST(net_carrier_watch, after_an_overrun_the_link_is_asked_for_again)
{
    // Host-dependent: skipped where NETLINK_ROUTE is unavailable. Unanswered requests overrun a small queue.
    int reports = 0;
    CarrierWatch watch{1, [&reports](LinkCarrier const&) { ++reports; }};
    if (!watch.open().has_value()) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    int const small = 1;
    (void)::setsockopt(watch.fd(), SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    std::array<uint8_t, 32> request{};
    sockaddr_nl const kernel{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
    for (uint32_t seq = 2; seq < 66; ++seq) {
        auto const length = build_get_link(request, 1, seq);
        (void)::sendto(
            watch.fd(), request.data(), length.value_or(0), 0, reinterpret_cast<sockaddr const*>(&kernel), sizeof(kernel));
    }
    watch.on_ready(0);  // the replies that fitted, then the overrun's request
    EXPECT_FALSE(watch.finished());
    int const drained = reports;
    EXPECT_TRUE(drained < 65);
    watch.on_ready(0);
    EXPECT_EQ(reports, drained + 1);
    EXPECT_FALSE(watch.finished());
}

TEST(net_carrier_watch, a_link_the_kernel_does_not_know_finishes_the_watch)
{
    int reports = 0;
    CarrierWatch watch{0x7FFFFFF0, [&reports](LinkCarrier const&) { ++reports; }};
    if (!watch.open().has_value()) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    watch.on_ready(0);
    EXPECT_TRUE(watch.finished());
    EXPECT_EQ(reports, 0);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_carrier_watch_test)
