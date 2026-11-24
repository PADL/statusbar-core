// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for the RSS indirection table module.
//
// The decision - what to write, when to leave the NIC alone, what to refuse -
// is in detail::plan_rss_steer and is tested here without any hardware. So is
// the restore protocol: RssSteering is driven through an RssRecorder, which is
// what lets "the table comes back byte for byte" and "a resized table is
// refused" be asserted at all.
//
// What cannot be tested anywhere here is a real steer. It needs a NIC with an
// indirection table and CAP_NET_ADMIN, and no interface on any host this was
// written on has one: `lo` and the wifi both answer operation_not_supported,
// the Raspberry Pi's macb answers the same, and neither kernel has netdevsim.
// The real read and write paths are exercised only by their failure cases.

#include "statusbar/net/net_rss.hpp"
#include "statusbar/net/net_rss_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

// Pure helpers

// The decision

// Against the kernel

TEST(net_rss, loopback_has_no_indirection_table)
{
    auto const steered = set_rss_indirection_all("lo", 0);
    EXPECT_FALSE(steered.has_value());
    if (!steered) {
        EXPECT_TRUE(steered.error() == std::errc::operation_not_supported);
    }
}

TEST(net_rss, writing_to_loopback_fails_rather_than_pretending)
{
    std::array<uint32_t, 4> const all_zero{0, 0, 0, 0};
    auto const written = set_rss_indirection("lo", all_zero);
    EXPECT_FALSE(written.has_value());
}

// The guard: who puts the table back

// The read, as its own entry point: this is what a startup check uses to ask
// whether a single-queue table is the previous run's leftover.
TEST(net_rss, reading_loopbacks_table_reports_no_rss)
{
    auto const table = rss_indirection("lo");
    EXPECT_FALSE(table.has_value());
    if (!table) {
        EXPECT_TRUE(table.error() == std::errc::operation_not_supported);
    }
}

TEST_MAIN(statusbar_net, net_rss_functional_test)
