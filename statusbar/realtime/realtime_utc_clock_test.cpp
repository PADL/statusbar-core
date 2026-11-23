// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// UtcClockQualityTracker: the system clock's worst-case accuracy, taken from
// what the operating system reports and coasted on the deployment's own
// drift figure. Every test but the last is told its readings: the times are
// made up, so each case is exact and none waits.

#include "statusbar/realtime/realtime_utc_clock.hpp"

#include "statusbar/test/test.hpp"

#include <chrono>
#include <cstdint>

using namespace statusbar::realtime;

namespace {

constexpr int64_t BILLION = 1'000'000'000;
/// A system clock far from the RAW counter, as a real one is.
constexpr int64_t UTC_AT_RAW_ZERO_NS = 1'795'000'000 * BILLION;

/// Readings of the two clocks at @p raw_ns of uptime, with the system clock
/// @p utc_shift_ns away from where it started.
struct At
{
    MonotonicRawClock::time_point raw;
    UtcClock::time_point utc;
};

constexpr auto at(int64_t raw_ns, int64_t utc_shift_ns = 0) -> At
{
    return {.raw = MonotonicRawClock::from_ns(raw_ns), .utc = UtcClock::from_ns(UTC_AT_RAW_ZERO_NS + raw_ns + utc_shift_ns)};
}

constexpr auto reported(bool synchronized, int64_t max_error_us) -> SystemClockError
{
    return {
        .synchronized = synchronized,
        .max_error = std::chrono::microseconds{max_error_us},
        .estimated_error = std::chrono::microseconds{10}};
}

auto observe(UtcClockQualityTracker& tracker, At const& when, SystemClockError const& what) -> void
{
    tracker.observe(when.raw, when.utc, what);
}

}  // namespace

TEST(utc_clock_quality, a_clock_the_system_never_called_synchronized_bounds_nothing)
{
    UtcClockQualityTracker tracker;
    EXPECT_FALSE(tracker.quality().is_bounded());

    observe(tracker, at(1 * BILLION), reported(false, 16'000'000));
    observe(tracker, at(2 * BILLION), reported(false, 16'000'000));
    EXPECT_FALSE(tracker.quality().is_bounded());
    EXPECT_TRUE(tracker.quality().uncertainty(at(3 * BILLION).raw) == UNBOUNDED_ACCURACY);
}

TEST(utc_clock_quality, the_first_synchronized_report_is_the_bound)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));  // a local GPS receiver over NTP

    auto const quality = tracker.quality();
    EXPECT_TRUE(quality.is_bounded());
    EXPECT_TRUE(quality.synced_at == at(10 * BILLION).raw);
    EXPECT_EQ(quality.bound_at_sync.count(), int64_t{1'470'000});
    EXPECT_EQ(quality.drift_bound_ppb, DEFAULT_HOLDOVER_DRIFT_PPB);
    EXPECT_TRUE(quality.time_source == TimeSource::ntp);
    EXPECT_EQ(quality.epoch, uint64_t{0});
}

TEST(utc_clock_quality, the_systems_own_growth_is_not_an_update)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    // Sampled four times a second: no whole second of the system clock
    // crossed, the figure stands; one crossed, it grew by exactly 500 us.
    observe(tracker, at((10 * BILLION) + 250'000'000), reported(true, 1'470));
    observe(tracker, at((10 * BILLION) + 500'000'000), reported(true, 1'470));
    observe(tracker, at(11 * BILLION), reported(true, 1'970));
    observe(tracker, at(14 * BILLION), reported(true, 3'470));

    // Still anchored at the daemon's update, growing at the configured
    // 15 ppm and not at the system's 500 ppm: 4 s is 60 us, not 2 ms.
    auto const quality = tracker.quality();
    EXPECT_TRUE(quality.synced_at == at(10 * BILLION).raw);
    EXPECT_EQ(quality.uncertainty(at(14 * BILLION).raw).count(), int64_t{1'470'000 + 60'000});
}

TEST(utc_clock_quality, a_value_the_daemon_wrote_moves_the_anchor)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    observe(tracker, at(11 * BILLION), reported(true, 1'970));
    // The daemon updated: a lower figure than growth alone would give.
    observe(tracker, at(26 * BILLION), reported(true, 1'465));
    EXPECT_TRUE(tracker.quality().synced_at == at(26 * BILLION).raw);
    EXPECT_EQ(tracker.quality().bound_at_sync.count(), int64_t{1'465'000});

    // And a worse one is believed just the same: the source got worse.
    observe(tracker, at(42 * BILLION), reported(true, 9'560));
    EXPECT_TRUE(tracker.quality().synced_at == at(42 * BILLION).raw);
    EXPECT_EQ(tracker.quality().bound_at_sync.count(), int64_t{9'560'000});
}

TEST(utc_clock_quality, the_clock_coasts_when_the_time_server_is_lost)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    // No more updates. The system grows its figure for 30 s, then gives up.
    for (int64_t s = 11; s <= 40; ++s) {
        observe(tracker, at(s * BILLION), reported(true, 1'470 + ((s - 10) * 500)));
    }
    observe(tracker, at(41 * BILLION), reported(false, 16'000'000));
    observe(tracker, at(70 * BILLION), reported(false, 16'000'000));

    // A minute after the last update the system says 16 s and
    // "unsynchronized". The clock has drifted at most 900 us more.
    auto const quality = tracker.quality();
    EXPECT_TRUE(quality.is_bounded());
    EXPECT_TRUE(quality.synced_at == at(10 * BILLION).raw);
    EXPECT_EQ(quality.uncertainty(at(70 * BILLION).raw).count(), int64_t{1'470'000 + 900'000});
    EXPECT_TRUE(quality.within(std::chrono::milliseconds{3}, at(70 * BILLION).raw));
    EXPECT_EQ(quality.epoch, uint64_t{0});
}

TEST(utc_clock_quality, a_slew_is_the_same_timeline)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    // The daemon slews 263 ms out over four seconds: fast, but a slew.
    observe(tracker, at(11 * BILLION, 66'000'000), reported(true, 1'970));
    observe(tracker, at(14 * BILLION, 263'000'000), reported(true, 3'470));
    EXPECT_EQ(tracker.quality().epoch, uint64_t{0});
    EXPECT_TRUE(tracker.quality().is_bounded());
}

TEST(utc_clock_quality, a_step_is_a_new_timeline)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    // Two seconds of system time appear between readings 250 ms apart.
    observe(tracker, at((10 * BILLION) + 250'000'000, 2 * BILLION), reported(true, 800));

    auto const quality = tracker.quality();
    EXPECT_EQ(quality.epoch, uint64_t{1});
    // Synchronized after the step: bounded again, from the step on.
    EXPECT_TRUE(quality.synced_at == at((10 * BILLION) + 250'000'000).raw);
    EXPECT_EQ(quality.bound_at_sync.count(), int64_t{800'000});
}

TEST(utc_clock_quality, a_step_with_nothing_to_vouch_for_it_bounds_nothing)
{
    UtcClockQualityTracker tracker;
    observe(tracker, at(10 * BILLION), reported(true, 1'470));
    // Somebody set the clock by hand while the daemon had no source.
    observe(tracker, at(11 * BILLION, -3'600 * BILLION), reported(false, 16'000'000));
    EXPECT_EQ(tracker.quality().epoch, uint64_t{1});
    EXPECT_FALSE(tracker.quality().is_bounded());

    // Until the system is synchronized again.
    observe(tracker, at(12 * BILLION, -3'600 * BILLION), reported(true, 2'000));
    EXPECT_TRUE(tracker.quality().is_bounded());
    EXPECT_EQ(tracker.quality().epoch, uint64_t{1});
}

TEST(utc_clock_quality, the_deployment_says_how_it_drifts_and_what_disciplines_it)
{
    UtcClockQualityTracker tracker{{.drift_bound_ppb = 2'000, .time_source = TimeSource::gnss}};
    observe(tracker, at(10 * BILLION), reported(true, 1'470));

    auto const quality = tracker.quality();
    EXPECT_TRUE(quality.time_source == TimeSource::gnss);
    EXPECT_EQ(quality.drift_bound_ppb, uint32_t{2'000});
    // An hour without the receiver: 7.2 ms more at 2 ppm.
    EXPECT_EQ(quality.uncertainty(at(3'610 * BILLION).raw).count(), int64_t{1'470'000 + 7'200'000});
}

// The one test on the real clocks. Whether this machine is synchronized, and
// what its clock does between two reads, are not this test's business: it
// only checks that what the tracker says agrees with itself.
TEST(utc_clock_quality, sampling_the_real_clocks_gives_a_reading_that_agrees_with_itself)
{
    UtcClockQualityTracker tracker;
    tracker.sample();
    auto const quality = tracker.quality();
    auto const now = tracker.read_bounded();

    EXPECT_EQ(now.is_bounded(), quality.is_bounded());
    if (quality.is_bounded()) {
        EXPECT_TRUE(now.accuracy >= quality.bound_at_sync);
    }
    EXPECT_EQ(quality.epoch, uint64_t{0});
}

TEST_MAIN(statusbar_realtime, realtime_utc_clock_test)
