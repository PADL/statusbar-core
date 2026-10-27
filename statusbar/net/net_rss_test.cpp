// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for the RSS indirection table module.
//
// The decision - what to write, when to leave the NIC alone, what to refuse -
// is in detail::plan_rss_steer and is tested here without any hardware. What
// cannot be tested here is a real steer: it needs a multi-queue NIC and
// CAP_NET_ADMIN, and `lo` has no indirection table at all. That path is
// exercised only by the operation_not_supported case below.

#include "statusbar/net/net_rss.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>

using namespace statusbar;
using namespace statusbar::net;

// Pure helpers

TEST(net_rss, make_steered_table)
{
    auto const table = detail::make_steered_table(8, 3);
    EXPECT_EQ(table.size(), 8U);
    for (auto const queue : table) {
        EXPECT_EQ(queue, 3U);
    }

    EXPECT_TRUE(detail::make_steered_table(0, 0).empty());
    EXPECT_EQ(detail::make_steered_table(1, 0).size(), 1U);
}

TEST(net_rss, is_steered_to)
{
    std::array<uint32_t, 4> const all_two{2, 2, 2, 2};
    EXPECT_TRUE(detail::is_steered_to(all_two, 2));
    EXPECT_FALSE(detail::is_steered_to(all_two, 0));

    std::array<uint32_t, 4> const spread{0, 1, 2, 3};
    EXPECT_FALSE(detail::is_steered_to(spread, 0));
    EXPECT_FALSE(detail::is_steered_to(spread, 3));

    // One stray bucket is still a table we have to write.
    std::array<uint32_t, 4> const nearly{2, 2, 2, 1};
    EXPECT_FALSE(detail::is_steered_to(nearly, 2));

    // An empty table is steered nowhere, not everywhere.
    EXPECT_FALSE(detail::is_steered_to(std::span<uint32_t const>{}, 0));
}

// The decision

TEST(net_rss, plan_steers_a_spread_table)
{
    std::array<uint32_t, 8> const spread{0, 1, 2, 3, 0, 1, 2, 3};
    auto const plan = detail::plan_rss_steer(spread, 4, 2);
    EXPECT_TRUE(plan.has_value());
    if (plan) {
        // The previous table comes back exactly as it was, for restoring.
        EXPECT_EQ(plan->previous.size(), spread.size());
        EXPECT_TRUE(std::ranges::equal(plan->previous, spread));

        EXPECT_TRUE(plan->wanted.has_value());
        if (plan->wanted) {
            EXPECT_EQ(plan->wanted->size(), spread.size());
            EXPECT_TRUE(detail::is_steered_to(*plan->wanted, 2));
        }
    }
}

TEST(net_rss, plan_writes_nothing_when_already_steered)
{
    std::array<uint32_t, 4> const all_one{1, 1, 1, 1};
    auto const plan = detail::plan_rss_steer(all_one, 4, 1);
    EXPECT_TRUE(plan.has_value());
    if (plan) {
        // Skipping the write avoids a privileged syscall and, on some
        // drivers, a link reset.
        EXPECT_FALSE(plan->wanted.has_value());
        EXPECT_TRUE(std::ranges::equal(plan->previous, all_one));
    }
}

TEST(net_rss, plan_reports_a_nic_with_no_table)
{
    auto const plan = detail::plan_rss_steer(std::span<uint32_t const>{}, 4, 0);
    EXPECT_FALSE(plan.has_value());
    if (!plan) {
        // Distinguishable on purpose: for a caller this is "nothing to
        // steer", not a fault.
        EXPECT_TRUE(plan.error() == std::errc::operation_not_supported);
    }
}

TEST(net_rss, plan_refuses_a_queue_the_nic_does_not_have)
{
    std::array<uint32_t, 4> const spread{0, 1, 2, 3};
    auto const beyond = detail::plan_rss_steer(spread, 4, 4);
    EXPECT_FALSE(beyond.has_value());
    if (!beyond) {
        EXPECT_TRUE(beyond.error() == std::errc::invalid_argument);
    }

    auto const far_beyond = detail::plan_rss_steer(spread, 4, 0xFFFFFFFFU);
    EXPECT_FALSE(far_beyond.has_value());

    // The last real queue is in range.
    EXPECT_TRUE(detail::plan_rss_steer(spread, 4, 3).has_value());
}

TEST(net_rss, plan_defers_to_the_driver_when_the_queue_count_is_unknown)
{
    std::array<uint32_t, 4> const spread{0, 1, 2, 3};
    // 0 means the NIC would not say. Refusing everything here would make the
    // module useless on such a driver, so the write goes ahead and the
    // driver's own check is what rejects a bad queue.
    auto const plan = detail::plan_rss_steer(spread, 0, 9);
    EXPECT_TRUE(plan.has_value());
    if (plan) {
        EXPECT_TRUE(plan->wanted.has_value());
    }
}

TEST(net_rss, plan_keeps_a_table_whose_size_is_not_a_power_of_two)
{
    std::array<uint32_t, 3> const odd{1, 0, 1};
    auto const plan = detail::plan_rss_steer(odd, 2, 0);
    EXPECT_TRUE(plan.has_value());
    if (plan && plan->wanted) {
        EXPECT_EQ(plan->wanted->size(), 3U);
    }
}

// Against the kernel

TEST(net_rss, loopback_has_no_indirection_table)
{
    auto const steered = set_rss_indirection_all("lo", 0);
    EXPECT_FALSE(steered.has_value());
    if (!steered) {
        EXPECT_TRUE(steered.error() == std::errc::operation_not_supported);
    }
}

TEST(net_rss, an_unknown_interface_is_not_operation_not_supported)
{
    // A name no host has must be told apart from a NIC without RSS, or a
    // typo looks like "nothing to steer".
    auto const steered = set_rss_indirection_all("statusbar-no-such-if", 0);
    EXPECT_FALSE(steered.has_value());
    if (!steered) {
        EXPECT_FALSE(steered.error() == std::errc::operation_not_supported);
    }
}

TEST(net_rss, an_oversize_interface_name_is_refused)
{
    std::string const too_long(64, 'e');
    auto const steered = set_rss_indirection_all(too_long, 0);
    EXPECT_FALSE(steered.has_value());
    if (!steered) {
        EXPECT_TRUE(steered.error() == std::errc::no_such_device);
    }

    auto const empty = set_rss_indirection_all("", 0);
    EXPECT_FALSE(empty.has_value());
}

TEST(net_rss, writing_to_loopback_fails_rather_than_pretending)
{
    std::array<uint32_t, 4> const all_zero{0, 0, 0, 0};
    auto const written = set_rss_indirection("lo", all_zero);
    EXPECT_FALSE(written.has_value());
}

TEST_MAIN(statusbar_net, net_rss_test)
