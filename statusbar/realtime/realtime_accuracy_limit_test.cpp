// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AccuracyLimit: one user's tolerance against a clock's reported quality.
// Every time here is made up, so each case is exact and none waits.

#include "statusbar/realtime/realtime_accuracy_limit.hpp"

#include "statusbar/test/test.hpp"

#include <chrono>
#include <cstdint>

using namespace statusbar::realtime;
using namespace std::chrono_literals;

namespace {

constexpr auto raw(Nanoseconds const since_start) -> MonotonicRawClock::time_point
{
    return MonotonicRawClock::time_point{since_start};
}

/// A clock synchronized at @p synced with one microsecond of error, wandering
/// at 10 ppm afterwards: ten microseconds more for each second without sync.
constexpr auto synced_at(Nanoseconds const synced, uint64_t const epoch = 0) -> ClockQuality
{
    return {
        .synced_at = raw(synced), .bound_at_sync = 1us, .epoch = epoch, .drift_bound_ppb = 10'000, .time_source = TimeSource::ptp};
}

}  // namespace

TEST(accuracy_limit, a_clock_that_never_synchronized_is_not_usable)
{
    AccuracyLimit limit{100us};
    auto const verdict = limit.judge(ClockQuality{}, raw(5s));
    EXPECT_FALSE(verdict.usable);
    EXPECT_FALSE(verdict.timeline_changed);
    EXPECT_TRUE(verdict.accuracy == UNBOUNDED_ACCURACY);
    EXPECT_FALSE(limit.usable());
    EXPECT_EQ(limit.record().excursions, 0U);
    EXPECT_TRUE(limit.record().outside == 0ns);
}

TEST(accuracy_limit, a_clock_coasts_inside_the_limit_and_leaves_it_at_the_exact_instant)
{
    AccuracyLimit limit{100us};
    auto const quality = synced_at(10s);

    EXPECT_TRUE(limit.judge(quality, raw(10s)).usable);
    // 1 us at sync plus 10 us a second: 99 us after 9.8 s, 100 us after 9.9 s.
    auto const inside = limit.judge(quality, raw(10s + 9'900ms));
    EXPECT_TRUE(inside.usable);
    EXPECT_TRUE(inside.accuracy == 100us);
    auto const outside = limit.judge(quality, raw(10s + 9'900ms + 1ms));
    EXPECT_FALSE(outside.usable);
    EXPECT_TRUE(outside.accuracy > 100us);
    EXPECT_EQ(limit.record().excursions, 1U);
    EXPECT_TRUE(limit.record().worst_usable == 100us);
}

TEST(accuracy_limit, the_record_counts_each_excursion_and_the_time_spent_outside)
{
    AccuracyLimit limit{100us};
    (void)limit.judge(synced_at(0s), raw(0s));
    (void)limit.judge(synced_at(0s), raw(20s));  // 201 us: outside
    (void)limit.judge(synced_at(0s), raw(23s));  // still outside
    EXPECT_EQ(limit.record().excursions, 1U);
    EXPECT_TRUE(limit.record().outside == 3s);

    // Sync returns: inside again, and the time outside ends at this verdict.
    EXPECT_TRUE(limit.judge(synced_at(25s), raw(25s)).usable);
    EXPECT_TRUE(limit.record().outside == 5s);
    (void)limit.judge(synced_at(25s), raw(50s));  // a second excursion
    EXPECT_EQ(limit.record().excursions, 2U);
    EXPECT_TRUE(limit.record().outside == 5s);
}

TEST(accuracy_limit, time_before_the_first_usable_verdict_is_not_time_outside)
{
    AccuracyLimit limit{100us};
    (void)limit.judge(ClockQuality{}, raw(0s));
    (void)limit.judge(ClockQuality{}, raw(30s));
    EXPECT_TRUE(limit.judge(synced_at(31s), raw(31s)).usable);
    EXPECT_TRUE(limit.record().outside == 0ns);
    EXPECT_EQ(limit.record().excursions, 0U);
}

TEST(accuracy_limit, a_change_of_timeline_is_told_once)
{
    AccuracyLimit limit{100us};
    EXPECT_FALSE(limit.judge(synced_at(0s, 7), raw(0s)).timeline_changed);  // the first is not a change
    EXPECT_FALSE(limit.judge(synced_at(1s, 7), raw(1s)).timeline_changed);
    EXPECT_TRUE(limit.judge(synced_at(2s, 8), raw(2s)).timeline_changed);
    EXPECT_FALSE(limit.judge(synced_at(3s, 8), raw(3s)).timeline_changed);
    EXPECT_EQ(limit.record().timeline_changes, 1U);
}

TEST(accuracy_limit, the_default_limit_takes_any_bounded_clock)
{
    AccuracyLimit limit{};
    EXPECT_TRUE(limit.limit() == AccuracyLimit::ANY_BOUNDED);
    EXPECT_FALSE(limit.judge(ClockQuality{}, raw(1s)).usable);
    EXPECT_TRUE(limit.judge(synced_at(1s), raw(1s) + std::chrono::hours{24 * 365}).usable);
}

TEST(accuracy_limit, a_verdict_is_a_constant_expression)
{
    constexpr auto verdict = [] {
        AccuracyLimit limit{50us};
        return limit.judge(synced_at(0s), raw(1s));
    }();
    static_assert(verdict.usable);
    static_assert(verdict.accuracy == 11us);
    EXPECT_TRUE(verdict.usable);
}

TEST_MAIN(statusbar_realtime, realtime_accuracy_limit_test)
