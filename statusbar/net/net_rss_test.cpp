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

TEST(net_rss, rss_indirection_all_builds_a_single_queue_table)
{
    auto const table = rss_indirection_all(8, 3);
    EXPECT_EQ(table.size(), 8U);
    for (auto const queue : table) {
        EXPECT_EQ(queue, 3U);
    }

    EXPECT_TRUE(rss_indirection_all(0, 0).empty());
    EXPECT_EQ(rss_indirection_all(1, 0).size(), 1U);
}

TEST(net_rss, rss_steered_to_answers_for_a_whole_table)
{
    std::array<uint32_t, 4> const all_two{2, 2, 2, 2};
    EXPECT_TRUE(rss_steered_to(all_two, 2));
    EXPECT_FALSE(rss_steered_to(all_two, 0));

    std::array<uint32_t, 4> const spread{0, 1, 2, 3};
    EXPECT_FALSE(rss_steered_to(spread, 0));
    EXPECT_FALSE(rss_steered_to(spread, 3));

    // One stray bucket is still a table we have to write.
    std::array<uint32_t, 4> const nearly{2, 2, 2, 1};
    EXPECT_FALSE(rss_steered_to(nearly, 2));

    // An empty table is steered nowhere, not everywhere.
    EXPECT_FALSE(rss_steered_to(std::span<uint32_t const>{}, 0));
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
            EXPECT_TRUE(rss_steered_to(*plan->wanted, 2));
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
#if !defined(__linux__)
    SKIP("RSS steering is Linux-only; the stub answers operation_not_supported for every name");
#endif
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
#if !defined(__linux__)
    SKIP("RSS steering is Linux-only; the stub answers operation_not_supported for every name");
#endif
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

// The guard: who puts the table back

namespace {

// A table spread across four queues, the normal state of a NIC.
auto spread_table() -> RssIndirection
{
    return RssIndirection{0, 1, 2, 3, 0, 1, 2, 3};
}

// RssControl is not movable, so a configured recorder is filled in place
// rather than returned.
auto with_spread(RssRecorder& recorder) -> void
{
    recorder.set_table(spread_table());
    recorder.set_rx_queues(4);
}

}  // namespace

TEST(net_rss_steering, steering_writes_the_single_queue_table)
{
    RssRecorder recorder;
    with_spread(recorder);
    auto const guard = RssSteering::steer(recorder, "eth9", 2);
    EXPECT_TRUE(guard.has_value());
    EXPECT_EQ(recorder.writes().size(), 1u);
    EXPECT_TRUE(recorder.table() == rss_indirection_all(8, 2));
    EXPECT_TRUE(std::ranges::equal(guard->previous(), spread_table()));
}

// The criterion the whole issue exists for: the table that was there comes
// back, byte for byte, without the caller remembering to ask.
TEST(net_rss_steering, the_previous_table_is_back_after_destruction)
{
    RssRecorder recorder;
    with_spread(recorder);
    {
        auto guard = RssSteering::steer(recorder, "eth9", 2);
        EXPECT_TRUE(guard.has_value());
        EXPECT_FALSE(recorder.table() == spread_table());
    }
    EXPECT_TRUE(recorder.table() == spread_table());
    EXPECT_EQ(recorder.writes().size(), 2u);
}

TEST(net_rss_steering, an_exception_out_of_a_constructor_still_restores)
{
    // A transport that steers in its constructor and then fails: the guard is
    // a member, so unwinding destroys it, and the NIC is left as it was.
    struct Transport
    {
        explicit Transport(RssControl& control)
            : steering_{RssSteering::steer(control, "eth9", 2).value()}
        {
            throw std::runtime_error("the rest of the constructor failed");
        }
        RssSteering steering_;
    };

    RssRecorder recorder;
    with_spread(recorder);
    bool threw = false;
    try {
        Transport const transport{recorder};
    } catch (std::runtime_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
    EXPECT_TRUE(recorder.table() == spread_table());
}

TEST(net_rss_steering, restore_is_explicit_and_idempotent)
{
    RssRecorder recorder;
    with_spread(recorder);
    auto guard = RssSteering::steer(recorder, "eth9", 2).value();

    EXPECT_TRUE(guard.restore().has_value());
    EXPECT_TRUE(recorder.table() == spread_table());
    EXPECT_EQ(recorder.writes().size(), 2u);
    EXPECT_FALSE(guard.holds_table());

    // Again, and on the way out of scope: neither writes a second time.
    EXPECT_TRUE(guard.restore().has_value());
    EXPECT_EQ(recorder.writes().size(), 2u);
}

TEST(net_rss_steering, release_keeps_the_steering_on_purpose)
{
    RssRecorder recorder;
    with_spread(recorder);
    {
        auto guard = RssSteering::steer(recorder, "eth9", 2).value();
        guard.release();
        EXPECT_FALSE(guard.holds_table());
    }
    EXPECT_TRUE(recorder.table() == rss_indirection_all(8, 2));
    EXPECT_EQ(recorder.writes().size(), 1u);
}

// A NIC already pointing everywhere at that queue was not changed, so there is
// nothing to put back -- and the guard must not write one anyway, because a
// write can cost a link reset.
TEST(net_rss_steering, a_nic_already_steered_there_is_left_entirely_alone)
{
    RssRecorder recorder;
    recorder.set_table(rss_indirection_all(8, 2));
    recorder.set_rx_queues(4);
    {
        auto const guard = RssSteering::steer(recorder, "eth9", 2);
        EXPECT_TRUE(guard.has_value());
        EXPECT_FALSE(guard->holds_table());
    }
    EXPECT_EQ(recorder.writes().size(), 0u);
}

TEST(net_rss_steering, a_resized_table_is_refused_rather_than_written)
{
    RssRecorder recorder;
    with_spread(recorder);
    auto guard = RssSteering::steer(recorder, "eth9", 2).value();
    EXPECT_EQ(recorder.writes().size(), 1u);

    // The NIC's channel count changed underneath us: the table we hold no
    // longer describes it, and writing it would be a guess.
    recorder.set_table(rss_indirection_all(16, 0));

    auto const restored = guard.restore();
    EXPECT_FALSE(restored.has_value());
    EXPECT_TRUE(restored.error() == std::errc::state_not_recoverable);
    EXPECT_EQ(recorder.writes().size(), 1u);
    // Still owed, so a caller that can fix the NIC may try again.
    EXPECT_TRUE(guard.holds_table());
}

TEST(net_rss_steering, a_moved_from_guard_restores_nothing)
{
    RssRecorder recorder;
    with_spread(recorder);
    {
        auto first = RssSteering::steer(recorder, "eth9", 2).value();
        auto second = std::move(first);
        EXPECT_FALSE(first.holds_table());
        EXPECT_TRUE(second.holds_table());
    }
    // One restore, not two: the moved-from guard owes nothing.
    EXPECT_EQ(recorder.writes().size(), 2u);
    EXPECT_TRUE(recorder.table() == spread_table());
}

TEST(net_rss_steering, a_nic_with_no_table_yields_no_guard)
{
    RssRecorder recorder;  // no table at all
    auto const guard = RssSteering::steer(recorder, "eth9", 0);
    EXPECT_FALSE(guard.has_value());
    EXPECT_TRUE(guard.error() == std::errc::operation_not_supported);
    EXPECT_EQ(recorder.writes().size(), 0u);
}

TEST(net_rss_steering, a_failed_restore_is_reported_and_still_owed)
{
    RssRecorder recorder;
    with_spread(recorder);
    auto guard = RssSteering::steer(recorder, "eth9", 2).value();

    recorder.fail_next_write(std::make_error_code(std::errc::operation_not_permitted));
    auto const restored = guard.restore();
    EXPECT_FALSE(restored.has_value());
    EXPECT_TRUE(restored.error() == std::errc::operation_not_permitted);
    EXPECT_TRUE(guard.holds_table());

    // The destructor tries once more, and this time it works.
    guard = RssSteering{};
    EXPECT_TRUE(recorder.table() == spread_table());
}

// A NIC that cannot be read cannot be checked, so the restore is still owed
// rather than quietly dropped -- the caller may be unplugging the interface,
// or may be able to put it back.
TEST(net_rss_steering, a_restore_that_cannot_read_the_nic_is_still_owed)
{
    RssRecorder recorder;
    with_spread(recorder);
    auto guard = RssSteering::steer(recorder, "eth9", 2).value();

    recorder.fail_next_read(std::make_error_code(std::errc::no_such_device));
    auto const restored = guard.restore();
    EXPECT_FALSE(restored.has_value());
    EXPECT_TRUE(restored.error() == std::errc::no_such_device);
    EXPECT_EQ(recorder.writes().size(), 1u);
    EXPECT_TRUE(guard.holds_table());

    guard.release();  // the interface is gone; there is nothing to put back
}

TEST(net_rss_steering, a_default_guard_owes_nothing)
{
    RssSteering const guard;
    EXPECT_FALSE(guard.holds_table());
    EXPECT_TRUE(guard.previous().empty());
    EXPECT_TRUE(guard.interface_name().empty());
}

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

TEST(net_rss, reading_an_unknown_interface_is_told_apart_from_no_rss)
{
#if !defined(__linux__)
    SKIP("RSS steering is Linux-only; the stub answers operation_not_supported for every name");
#endif
    auto const table = rss_indirection("statusbar-no-such-if");
    EXPECT_FALSE(table.has_value());
    if (!table) {
        EXPECT_FALSE(table.error() == std::errc::operation_not_supported);
    }
}

TEST_MAIN(statusbar_net, net_rss_test)
