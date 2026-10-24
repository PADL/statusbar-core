// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The RSS table construction; the ioctls need a NIC with RSS (and
// CAP_NET_ADMIN to write), so on lo they only have to fail cleanly.

#include "statusbar/net/net_rss.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <print>
#include <system_error>

using namespace statusbar::net;

TEST(net_rss, every_bucket_goes_to_the_one_queue)
{
    auto const table = rss_indirection_all(128, 0);  // an i210's table
    EXPECT_EQ(table.size(), size_t{128});
    EXPECT_TRUE(rss_steered_to(table, 0));
    EXPECT_FALSE(rss_steered_to(table, 1));
    auto const other = rss_indirection_all(512, 3);
    EXPECT_EQ(other.size(), size_t{512});
    EXPECT_EQ(other.front(), uint32_t{3});
    EXPECT_EQ(other.back(), uint32_t{3});
    EXPECT_TRUE(rss_indirection_all(0, 0).empty());
}

TEST(net_rss, a_spread_table_is_not_steered)
{
    std::array<uint32_t, 8> const spread{0, 1, 2, 3, 0, 1, 2, 3};  // the default over 4 queues
    EXPECT_FALSE(rss_steered_to(spread, 0));
    std::array<uint32_t, 4> const one_left{0, 0, 0, 1};
    EXPECT_FALSE(rss_steered_to(one_left, 0));
    EXPECT_FALSE(rss_steered_to({}, 0));  // no table, nothing steered
}

#if defined(__linux__)

TEST(net_rss, an_interface_without_rss_fails_cleanly)
{
    EXPECT_FALSE(rss_indirection("no-such-if0").has_value());
    EXPECT_FALSE(rss_indirection("").has_value());
    auto const lo = rss_indirection("lo");
    if (lo) {
        std::println("  skipped: lo reports an RSS table of {}", lo->size());
        return;
    }
    EXPECT_TRUE(lo.error() == std::errc::operation_not_supported || lo.error() == std::errc::no_such_device);
    EXPECT_FALSE(set_rss_indirection_all("lo", 0).has_value());
}

#endif

TEST_MAIN(statusbar_net, net_rss_test)
