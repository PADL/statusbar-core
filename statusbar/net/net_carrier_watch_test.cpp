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

namespace {

using namespace statusbar::net;

constexpr bool LITTLE = std::endian::native == std::endian::little;

// clang-format off
/// RTM_NEWLINK for ifindex 3, up and running with LOWER_UP: carrier 1, carrier_down_count 7, ifname "ens4".
constexpr std::array<uint8_t, 60> NEWLINK{
    0x3c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x30, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x03, 0x00, 'e', 'n', 's', '4', 0x00, 0x00, 0x00, 0x00,
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
        return;
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
        return;
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
        return;
    }
    auto const other = parse_link_carrier(NEWLINK, 4);
    EXPECT_TRUE(other && !*other);
    auto const dellink = parse_link_carrier(patched(4, 0x11), 3);
    EXPECT_TRUE(dellink && !*dellink);
    auto const short_other = parse_link_carrier(std::span{NEWLINK}.first(4), 3);
    EXPECT_TRUE(short_other && !*short_other);
}

TEST(net_carrier_watch, a_malformed_newlink_is_refused)
{
    EXPECT_FALSE(parse_link_carrier(patched(32, 0x06), 3).has_value());             // carrier of 2 octets
    EXPECT_FALSE(parse_link_carrier(patched(40, 0x06), 3).has_value());             // down count of 2 octets
    EXPECT_FALSE(parse_link_carrier(patched(48, 0x20), 3).has_value());             // overruns
    EXPECT_FALSE(parse_link_carrier(std::span{NEWLINK}.first(40), 3).has_value());  // truncated
    EXPECT_FALSE(parse_link_carrier(patched(0, 0x14), 3).has_value());              // shorter than ifinfomsg
}

TEST(net_carrier_watch, the_watch_opens_unprivileged_and_waits)
{
    // Host-dependent: skipped where NETLINK_ROUTE is unavailable.
    int reports = 0;
    CarrierWatch watch{3, [&reports](LinkCarrier const&) { ++reports; }};
    if (!watch.open().has_value()) {
        return;
    }
    EXPECT_TRUE(watch.fd() >= 0);
    watch.on_ready(0);
    EXPECT_FALSE(watch.finished());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_carrier_watch_test)
