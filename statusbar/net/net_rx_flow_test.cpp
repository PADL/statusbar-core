// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for RX flow rules: the ethtool spec encoding, the RSS spread that excludes
// queues, and RxFlowSteering driven through RxFlowRecorder and RssRecorder.

#include "statusbar/net/net_rx_flow.hpp"

#include "statusbar/net/net_rss_recorder.hpp"
#include "statusbar/net/net_rx_flow_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <system_error>
#include <utility>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr RxFlowRange RANGE{.first = 12, .count = 4};

auto avtp_rule() -> RxFlowRule
{
    return RxFlowRule{.location = 12, .queue = 0, .ethertype = 0x22f0};
}

auto pcp_rule() -> RxFlowRule
{
    return RxFlowRule{.location = 13, .queue = 0, .vlan_pcp = 3};
}

auto ptp_rule() -> RxFlowRule
{
    return RxFlowRule{.location = 14, .queue = 3, .ethertype = 0x88f7};
}

auto plan() -> RxFlowPlan
{
    return RxFlowPlan{.locations = RANGE, .rules = {avtp_rule(), pcp_rule(), ptp_rule()}, .rss_excluded = {0, 3}};
}

auto spread_table() -> RssIndirection
{
    return RssIndirection{0, 1, 2, 3, 0, 1, 2, 3};
}

}  // namespace

// The ethtool spec

#if defined(__linux__)

TEST(net_rx_flow, an_ethertype_rule_survives_the_spec)
{
    auto const spec = detail::flow_spec_of(avtp_rule());
    EXPECT_EQ(spec.flow_type, uint32_t{ETHER_FLOW});
    EXPECT_EQ(spec.m_u.ether_spec.h_proto, uint16_t{0xffff});
    EXPECT_EQ(detail::rule_of(spec), avtp_rule());
}

TEST(net_rx_flow, a_pcp_rule_matches_the_priority_bits_alone)
{
    auto const spec = detail::flow_spec_of(pcp_rule());
    EXPECT_EQ(spec.flow_type, uint32_t{ETHER_FLOW | FLOW_EXT});
    EXPECT_EQ(spec.m_u.ether_spec.h_proto, uint16_t{0});
    EXPECT_EQ(detail::rule_of(spec), pcp_rule());
}

TEST(net_rx_flow, a_rule_on_other_fields_is_marked)
{
    auto spec = detail::flow_spec_of(avtp_rule());
    spec.m_u.ether_spec.h_dest[0] = 0xff;
    EXPECT_TRUE(detail::rule_of(spec).other_fields);

    auto partial = detail::flow_spec_of(avtp_rule());
    partial.m_u.ether_spec.h_proto = 0x00ff;
    EXPECT_TRUE(detail::rule_of(partial).other_fields);

    auto udp = detail::flow_spec_of(avtp_rule());
    udp.flow_type = UDP_V4_FLOW;
    EXPECT_TRUE(detail::rule_of(udp).other_fields);
}

TEST(net_rx_flow, a_drop_rule_is_marked)
{
    auto spec = detail::flow_spec_of(avtp_rule());
    spec.ring_cookie = RX_CLS_FLOW_DISC;
    EXPECT_TRUE(detail::rule_of(spec).other_fields);
}

#endif

// The RSS spread

TEST(net_rx_flow, the_spread_skips_the_excluded_queues)
{
    std::array<uint32_t, 2> const excluded{0, 3};
    EXPECT_EQ(rss_indirection_excluding(6, 4, excluded), (RssIndirection{1, 2, 1, 2, 1, 2}));
}

TEST(net_rx_flow, nothing_left_to_spread_is_an_empty_table)
{
    std::array<uint32_t, 2> const excluded{0, 1};
    EXPECT_TRUE(rss_indirection_excluding(8, 2, excluded).empty());
    EXPECT_TRUE(rss_indirection_excluding(8, 0, {}).empty());
}

TEST(net_rx_flow, a_plan_outside_its_range_or_queues_is_refused)
{
    auto stray = plan();
    stray.rules.push_back(RxFlowRule{.location = 20, .queue = 0, .ethertype = 0x22ea});
    EXPECT_EQ(detail::check_rx_flow_plan(stray, 4).error(), std::make_error_code(std::errc::invalid_argument));
    EXPECT_FALSE(detail::check_rx_flow_plan(plan(), 3).has_value());
    EXPECT_TRUE(detail::check_rx_flow_plan(plan(), 4).has_value());
}

TEST(net_rx_flow, a_rule_matching_nothing_is_refused)
{
    auto wildcard = plan();
    wildcard.rules.push_back(RxFlowRule{.location = 15, .queue = 1});
    EXPECT_FALSE(detail::check_rx_flow_plan(wildcard, 4).has_value());
}

// RxFlowSteering

TEST(net_rx_flow_steering, steering_installs_the_rules_ntuple_and_the_spread)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_TRUE(steered.has_value());
    EXPECT_EQ(flows.rules().size(), size_t{3});
    EXPECT_TRUE(flows.ntuple_flag());
    EXPECT_EQ(rss.table(), (RssIndirection{1, 2, 1, 2, 1, 2, 1, 2}));
    EXPECT_TRUE(steered->enabled_ntuple());
    EXPECT_TRUE(steered->wrote_rss());
}

TEST(net_rx_flow_steering, a_restore_leaves_the_nic_as_it_was)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    {
        auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
        EXPECT_TRUE(steered.has_value());
        EXPECT_TRUE(steered->restore().has_value());
        EXPECT_FALSE(steered->holds());
    }
    EXPECT_TRUE(flows.rules().empty());
    EXPECT_TRUE(flows.ntuple_flag());
    EXPECT_EQ(flows.ntuple_writes(), size_t{1});
    EXPECT_EQ(rss.table(), spread_table());
    EXPECT_EQ(rss.writes().size(), size_t{2});
}

TEST(net_rx_flow_steering, a_plan_without_ntuple_leaves_the_flag_alone)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    auto unflagged = plan();
    unflagged.ntuple = false;
    {
        auto steered = RxFlowSteering::steer(flows, rss, "eth0", unflagged);
        EXPECT_EQ(flows.rules().size(), size_t{3});
    }
    EXPECT_FALSE(flows.ntuple_flag());
    EXPECT_EQ(flows.ntuple_writes(), size_t{0});
}

TEST(net_rx_flow_steering, ntuple_already_on_is_left_on)
{
    RxFlowRecorder flows;
    flows.set_ntuple_flag(true);
    RssRecorder rss;
    rss.set_table(spread_table());
    {
        auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
        EXPECT_FALSE(steered->enabled_ntuple());
    }
    EXPECT_TRUE(flows.ntuple_flag());
    EXPECT_EQ(flows.ntuple_writes(), size_t{0});
    EXPECT_TRUE(flows.rules().empty());
}

TEST(net_rx_flow_steering, leftovers_are_removed_and_their_table_reset_at_restore)
{
    RxFlowRecorder flows;
    flows.place(RxFlowRule{.location = 15, .queue = 1, .ethertype = 0x22ea});
    flows.place(RxFlowRule{.location = 2, .queue = 1, .ethertype = 0x88cc});
    RssRecorder rss;
    rss.set_table(RssIndirection{1, 2, 1, 2});
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_EQ(steered->leftovers(), size_t{1});
    EXPECT_TRUE(rss.writes().empty());
    EXPECT_EQ(flows.rules().size(), size_t{4});
    EXPECT_TRUE(steered->restore().has_value());
    EXPECT_TRUE(rss.writes().back().table.empty());
}

TEST(net_rx_flow_steering, an_administrators_table_survives_leftovers_and_a_refusal)
{
    RxFlowRecorder flows;
    flows.place(RxFlowRule{.location = 15, .queue = 1, .ethertype = 0x22ea});
    flows.fail_insert_after(1, std::make_error_code(std::errc::invalid_argument));
    RssRecorder rss;
    rss.set_table(RssIndirection{3, 3, 2, 2});
    EXPECT_FALSE(RxFlowSteering::steer(flows, rss, "eth0", plan()).has_value());
    EXPECT_TRUE(rss.writes().empty());
    EXPECT_EQ(rss.table(), (RssIndirection{3, 3, 2, 2}));
}

TEST(net_rx_flow_steering, an_administrators_table_comes_back_after_leftovers)
{
    RxFlowRecorder flows;
    flows.place(RxFlowRule{.location = 15, .queue = 1, .ethertype = 0x22ea});
    RssRecorder rss;
    rss.set_table(RssIndirection{3, 3, 2, 2});
    {
        auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
        EXPECT_EQ(rss.table(), (RssIndirection{1, 2, 1, 2}));
    }
    EXPECT_EQ(rss.table(), (RssIndirection{3, 3, 2, 2}));
}

TEST(net_rx_flow_steering, a_resized_table_is_refused_at_restore_and_the_rules_still_go)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    rss.set_table(RssIndirection{1, 2, 1, 2});
    EXPECT_EQ(steered->restore().error(), std::make_error_code(std::errc::state_not_recoverable));
    EXPECT_TRUE(flows.rules().empty());
    EXPECT_EQ(rss.table(), (RssIndirection{1, 2, 1, 2}));
}

TEST(net_rx_flow_steering, a_guard_assigned_over_one_for_the_same_range_keeps_its_rules)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    auto first = RxFlowSteering::steer(flows, rss, "eth0", plan());
    auto second = RxFlowSteering::steer(flows, rss, "eth0", plan());
    *first = std::move(*second);
    EXPECT_EQ(flows.rules().size(), size_t{3});
    EXPECT_TRUE(first->restore().has_value());
    EXPECT_TRUE(flows.rules().empty());
    EXPECT_EQ(rss.table(), spread_table());
}

TEST(net_rx_flow_steering, a_refused_rule_undoes_the_ones_before_it)
{
    RxFlowRecorder flows;
    flows.fail_insert_after(1, std::make_error_code(std::errc::invalid_argument));
    RssRecorder rss;
    rss.set_table(spread_table());
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_EQ(steered.error(), std::make_error_code(std::errc::invalid_argument));
    EXPECT_TRUE(flows.rules().empty());
    EXPECT_TRUE(flows.ntuple_flag());
    EXPECT_EQ(rss.table(), spread_table());
}

TEST(net_rx_flow_steering, a_nic_without_rss_keeps_the_rules_alone)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_TRUE(steered.has_value());
    EXPECT_FALSE(steered->wrote_rss());
    EXPECT_EQ(flows.rules().size(), size_t{3});
}

TEST(net_rx_flow_steering, a_table_already_spread_so_is_not_written)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(RssIndirection{1, 2, 1, 2});
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_FALSE(steered->wrote_rss());
    EXPECT_TRUE(rss.writes().empty());
}

TEST(net_rx_flow_steering, a_nic_without_flow_rules_is_left_untouched)
{
    RxFlowRecorder flows;
    flows.set_unsupported();
    RssRecorder rss;
    rss.set_table(spread_table());
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    EXPECT_EQ(steered.error(), std::make_error_code(std::errc::operation_not_supported));
    EXPECT_TRUE(rss.writes().empty());
    EXPECT_EQ(flows.ntuple_writes(), size_t{0});
}

TEST(net_rx_flow_steering, a_moved_from_guard_owes_nothing)
{
    RxFlowRecorder flows;
    RssRecorder rss;
    rss.set_table(spread_table());
    auto steered = RxFlowSteering::steer(flows, rss, "eth0", plan());
    RxFlowSteering moved{std::move(*steered)};
    EXPECT_FALSE(steered->holds());
    EXPECT_TRUE(moved.holds());
    EXPECT_EQ(flows.rules().size(), size_t{3});
}

TEST(net_rx_flow_steering, clearing_counts_the_rules_in_the_range_alone)
{
    RxFlowRecorder flows;
    flows.place(avtp_rule());
    flows.place(RxFlowRule{.location = 3, .queue = 1, .ethertype = 0x88cc});
    auto const removed = clear_rx_flow_rules(flows, "eth0", RANGE);
    EXPECT_EQ(*removed, size_t{1});
    EXPECT_EQ(flows.rules().size(), size_t{1});
}

// The real calls, by their failures

#if defined(__linux__)

TEST(net_rx_flow, loopback_has_no_flow_rules)
{
    EXPECT_TRUE(rx_flow_rule("lo", 0).error() == std::errc::operation_not_supported);
}

TEST(net_rx_flow, an_unknown_interface_is_no_such_device)
{
    EXPECT_TRUE(ntuple_enabled("nonexistent0").error() == std::errc::no_such_device);
    EXPECT_FALSE(insert_rx_flow_rule("nonexistent0", avtp_rule()).has_value());
}

#endif

TEST_MAIN(statusbar_net, net_rx_flow_test)
