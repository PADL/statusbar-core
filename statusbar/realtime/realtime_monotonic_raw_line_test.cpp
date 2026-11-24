// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// MonotonicRawLine and MonotonicRawTracker: the RAW->MONOTONIC line a
// sleeper converts its deadline through. The tracker tests are told their
// samples, so they pin the fit exactly and no clock is read here. The
// asking form (sample()) is tried on the real clocks in
// realtime_functional_test.cpp.

#include "statusbar/realtime/realtime_monotonic_raw_line.hpp"

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/test/test.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <type_traits>

using namespace statusbar;
using namespace statusbar::realtime;

namespace {

/// Nanoseconds of uptime past where a double stops carrying nanoseconds:
/// the conversions have to stay exact out here.
constexpr int64_t LONG_UPTIME_NS = 400LL * 24 * 3600 * 1'000'000'000LL;

[[nodiscard]] auto within(int64_t a, int64_t b, int64_t tolerance) -> bool
{
    return std::llabs(a - b) <= tolerance;
}

/// Whether the tracker accepts a pair of readings of these types.
template <typename Raw, typename Mono>
concept TrackerTakes = requires(MonotonicRawTracker& tracker, Raw raw, Mono mono) { tracker.push(raw, mono); };

/// A told sample: the same instant as a count on each clock.
[[nodiscard]] auto push(MonotonicRawTracker& tracker, int64_t raw_ns, int64_t mono_ns) -> bool
{
    return tracker.push(MonotonicRawClock::from_ns(raw_ns), MonotonicClock::from_ns(mono_ns));
}

}  // namespace

TEST(monotonic_raw_line, a_fresh_line_is_the_identity)
{
    MonotonicRawLine line;
    EXPECT_EQ(line.to_monotonic_ns(0), int64_t{0});
    EXPECT_EQ(line.to_monotonic_ns(LONG_UPTIME_NS), LONG_UPTIME_NS);
    EXPECT_EQ(line.from_monotonic_ns(LONG_UPTIME_NS), LONG_UPTIME_NS);
    auto const published = line.consume();
    EXPECT_EQ(published.rate, 1.0);
    EXPECT_EQ(published.offset_ns, int64_t{0});
}

TEST(monotonic_raw_line, a_published_line_converts_both_ways_exactly_at_long_uptime)
{
    MonotonicRawLine line;
    // phc2sys railed at +10%, and MONOTONIC half an hour ahead of RAW.
    line.publish({.rate = 1.1, .offset_ns = 1'800'000'000'000LL});

    int64_t const raw = LONG_UPTIME_NS + 123'456'789;
    int64_t const mono = line.to_monotonic_ns(raw);
    // 1.1 * raw + offset, checked in integers.
    EXPECT_EQ(mono, raw + (raw / 10) + 1'800'000'000'000LL);
    // The inverse lands on the same nanosecond (one ns of truncation allowed).
    EXPECT_TRUE(within(line.from_monotonic_ns(mono), raw, 1));
}

TEST(monotonic_raw_line, the_published_line_is_integers)
{
    MonotonicRawLine line;
    auto const identity = line.consume_fixed();
    EXPECT_EQ(identity.slope_numerator, MonotonicRawLine::SLOPE_DENOMINATOR);
    EXPECT_EQ(identity.offset_ns, int64_t{0});
    EXPECT_EQ(line.rate_deviation_ppb(), int64_t{0});

    // A rate is rounded to the integer slope once, by the writer.
    line.publish({.rate = 1.000'013'6, .offset_ns = 42});
    auto const fixed = line.consume_fixed();
    EXPECT_EQ(fixed.slope_numerator, int64_t{1'000'013'600});
    EXPECT_EQ(fixed.offset_ns, int64_t{42});
    EXPECT_EQ(line.rate_deviation_ppb(), int64_t{13'600});

    // A slow clock deviates by the same measure.
    line.publish_fixed({.slope_numerator = 999'996'700, .offset_ns = 0});
    EXPECT_EQ(line.rate_deviation_ppb(), int64_t{3'300});
    EXPECT_EQ(line.to_monotonic_ns(1'000'000'000), int64_t{999'996'700});
    // The line read back as a ratio is the integer slope, for reports.
    EXPECT_EQ(line.consume().rate, 0.9999967);
}

TEST(monotonic_raw_line, typed_conversions_change_the_clock_tag)
{
    MonotonicRawLine line;
    line.publish({.rate = 1.0, .offset_ns = 5});
    auto const mono = line.to_monotonic(MonotonicRawClock::from_ns(100));
    static_assert(std::is_same_v<decltype(mono), MonotonicClock::time_point const>);
    EXPECT_EQ(MonotonicClock::to_ns(mono), int64_t{105});
    auto const raw = line.from_monotonic(mono);
    static_assert(std::is_same_v<decltype(raw), MonotonicRawClock::time_point const>);
    EXPECT_EQ(MonotonicRawClock::to_ns(raw), int64_t{100});
}

TEST(monotonic_raw_tracker, a_sample_names_the_clock_of_each_reading)
{
    // The two readings cannot be passed the wrong way round.
    static_assert(TrackerTakes<MonotonicRawClock::time_point, MonotonicClock::time_point>);
    static_assert(!TrackerTakes<MonotonicClock::time_point, MonotonicRawClock::time_point>);
    static_assert(!TrackerTakes<int64_t, int64_t>);
}

TEST(monotonic_raw_tracker, one_sample_publishes_the_offset_at_rate_one)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    EXPECT_TRUE(push(tracker, 1'000, 1'000'000));
    auto const published = line.consume();
    EXPECT_EQ(published.rate, 1.0);
    EXPECT_EQ(published.offset_ns, int64_t{999'000});
    EXPECT_EQ(tracker.size(), size_t{1});
}

TEST(monotonic_raw_tracker, told_samples_on_a_line_recover_its_rate_and_offset)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    // mono = 1.0005 * raw + 7 s, sampled every 100 ms from a long uptime.
    constexpr int64_t OFFSET_NS = 7'000'000'000LL;
    for (int i = 0; i < 16; ++i) {
        int64_t const raw = LONG_UPTIME_NS + (i * 100'000'000LL);
        int64_t const mono = raw + (raw / 2000) + OFFSET_NS;
        EXPECT_TRUE(push(tracker, raw, mono));
    }
    auto const published = line.consume();
    EXPECT_TRUE(published.rate > 1.00049 && published.rate < 1.00051);
    // The line reproduces the samples it was fitted to, and extrapolates a
    // second ahead to within the slope's resolution.
    int64_t const raw = LONG_UPTIME_NS + 1'500'000'000LL;
    int64_t const mono = raw + (raw / 2000) + OFFSET_NS;
    EXPECT_TRUE(within(line.to_monotonic_ns(LONG_UPTIME_NS), LONG_UPTIME_NS + (LONG_UPTIME_NS / 2000) + OFFSET_NS, 2));
    EXPECT_TRUE(within(line.to_monotonic_ns(raw), mono, 100));
}

TEST(monotonic_raw_tracker, a_rate_outside_the_window_is_rejected_and_the_old_line_kept)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    EXPECT_TRUE(push(tracker, 0, 100));
    EXPECT_TRUE(push(tracker, 1'000'000, 1'000'100));
    // A pair that says MONOTONIC runs at twice RAW: not a clock, a glitch.
    EXPECT_FALSE(push(tracker, 2'000'000, 3'000'100));
    auto const published = line.consume();
    EXPECT_EQ(published.rate, 1.0);
    EXPECT_EQ(published.offset_ns, int64_t{100});
}

TEST(monotonic_raw_tracker, the_window_forgets_old_samples)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line, 4};
    for (int i = 0; i < 10; ++i) {
        (void)push(tracker, i * 1'000'000LL, (i * 1'000'000LL) + 50);
    }
    EXPECT_EQ(tracker.size(), size_t{4});
}

TEST(monotonic_raw_line, a_line_nobody_has_fitted_claims_no_accuracy)
{
    MonotonicRawLine line;
    EXPECT_FALSE(line.quality().is_bounded());
    // Publishing a line by hand says nothing of how good it is either.
    line.publish({.rate = 1.0, .offset_ns = 5});
    EXPECT_FALSE(line.quality().is_bounded());
}

TEST(monotonic_raw_line, a_sleeper_allows_for_the_misfit_of_the_line_and_for_the_time_since_it_was_sampled)
{
    MonotonicRawLine line;
    auto const now = MonotonicRawClock::from_ns(LONG_UPTIME_NS);
    constexpr Nanoseconds AHEAD{5'000'000};

    // Never sampled: nothing to count from but now. 100 ppm of 5 ms.
    EXPECT_EQ(line.sleep_margin(now + AHEAD, now).count(), int64_t{500});

    // Sampled 80 ms ago and good to 300 ns then: the margin runs from the
    // sample to the target, 85 ms at 100 ppm, on top of the misfit.
    line.publish_quality(
        {.synced_at = now - Nanoseconds{80'000'000},
         .bound_at_sync = Nanoseconds{300},
         .epoch = 0,
         .drift_bound_ppb = MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB,
         .time_source = TimeSource::internal_oscillator});
    EXPECT_EQ(line.sleep_margin(now + AHEAD, now).count(), int64_t{300 + 8'500});

    // A line 50 ppm off rate one could be slewed back by as much: 150 ppm.
    line.publish_fixed({.slope_numerator = 1'000'050'000, .offset_ns = 0});
    EXPECT_EQ(line.sleep_margin(now + AHEAD, now).count(), int64_t{300 + 12'750});

    // Left unsampled for ten seconds the margin has grown past a
    // millisecond: a sleeper then spins rather than trust the line.
    auto const later = now + std::chrono::seconds{10};
    EXPECT_EQ(line.sleep_margin(later + AHEAD, later).count(), int64_t{300 + 1'512'750});

    // A target the sample is already past still owes the misfit.
    EXPECT_EQ(line.sleep_margin(now - std::chrono::seconds{1}, now).count(), int64_t{300});
}

TEST(monotonic_raw_tracker, an_exact_fit_is_bounded_by_half_the_read_bracket)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    // mono = raw + 7 s exactly, every 100 ms, each pair read in 400 ns.
    constexpr int64_t OFFSET_NS = 7'000'000'000LL;
    for (int i = 0; i < 8; ++i) {
        int64_t const raw = LONG_UPTIME_NS + (i * 100'000'000LL);
        EXPECT_TRUE(tracker.push(MonotonicRawClock::from_ns(raw), MonotonicClock::from_ns(raw + OFFSET_NS), Nanoseconds{400}));
    }
    auto const last = MonotonicRawClock::from_ns(LONG_UPTIME_NS + 700'000'000LL);
    auto const quality = line.quality();
    EXPECT_TRUE(quality.is_bounded());
    EXPECT_TRUE(quality.synced_at == last);
    EXPECT_EQ(quality.bound_at_sync.count(), int64_t{200});
    EXPECT_EQ(quality.drift_bound_ppb, MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB);
    // Unsampled for a second, CLOCK_MONOTONIC may have been slewed 500 us away.
    EXPECT_EQ(quality.uncertainty(last + std::chrono::seconds{1}).count(), int64_t{200 + 500'000});
}

TEST(monotonic_raw_tracker, samples_that_miss_the_line_widen_its_bound)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    // The same line, with every other reading 3 us late.
    for (int i = 0; i < 16; ++i) {
        int64_t const raw = LONG_UPTIME_NS + (i * 100'000'000LL);
        int64_t const mono = raw + 7'000'000'000LL + ((i % 2) * 3'000);
        EXPECT_TRUE(push(tracker, raw, mono));
    }
    auto const quality = line.quality();
    EXPECT_TRUE(quality.is_bounded());
    // The fit runs between the two populations: each is about 1.5 us off it.
    EXPECT_TRUE(quality.bound_at_sync >= Nanoseconds{1'400});
    EXPECT_TRUE(quality.bound_at_sync <= Nanoseconds{3'000});
}

TEST(monotonic_raw_tracker, a_rate_that_moved_within_the_window_raises_the_drift_bound)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line, 16};
    // Eight samples at rate 1, then eight while the clock is slewed 2000 ppm.
    int64_t mono = LONG_UPTIME_NS;
    for (int i = 0; i < 16; ++i) {
        int64_t const raw = LONG_UPTIME_NS + (i * 100'000'000LL);
        EXPECT_TRUE(push(tracker, raw, mono));
        mono += 100'000'000LL + (i >= 7 ? 200'000 : 0);
    }
    // The halves differ by 2000 ppm and the fit itself sits between them,
    // off rate one: both come on top of the frequency correction's range.
    EXPECT_TRUE(line.quality().drift_bound_ppb >= MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB + uint32_t{1'900'000});
    EXPECT_TRUE(line.quality().drift_bound_ppb <= MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB + uint32_t{4'200'000});
}

TEST(monotonic_raw_tracker, a_line_far_from_rate_one_may_move_by_as_much_as_it_is_off)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    // CLOCK_MONOTONIC railed 5% fast and steady: beyond any frequency
    // correction, so a tick adjustment that could be taken away again.
    for (int i = 0; i < 16; ++i) {
        int64_t const raw = LONG_UPTIME_NS + (i * 100'000'000LL);
        EXPECT_TRUE(push(tracker, raw, LONG_UPTIME_NS + (i * 105'000'000LL)));
    }
    // On top of the 500 ppm the frequency correction could add either way.
    EXPECT_TRUE(line.quality().drift_bound_ppb >= uint32_t{50'400'000});
    EXPECT_TRUE(line.quality().drift_bound_ppb <= uint32_t{50'600'000});
}

TEST(monotonic_raw_tracker, a_negative_bracket_takes_nothing_off_the_bound)
{
    // A bracket is how long the pair took to read. One below zero is a
    // caller's mistake; it must not make the line look better known.
    MonotonicRawLine told_wrong;
    MonotonicRawTracker wrong{told_wrong};
    MonotonicRawLine told_none;
    MonotonicRawTracker none{told_none};
    for (int i = 0; i < 16; ++i) {
        auto const raw = MonotonicRawClock::from_ns(1'000'000'000LL + (i * 100'000'000LL));
        auto const mono = MonotonicClock::from_ns(5'000'000'000LL + (i * 100'000'000LL) + ((i % 2) * 40));
        (void)wrong.push(raw, mono, Nanoseconds{-1000});
        (void)none.push(raw, mono, Nanoseconds::zero());
    }
    EXPECT_TRUE(told_wrong.quality().is_bounded());
    EXPECT_TRUE(told_wrong.quality().bound_at_sync >= Nanoseconds::zero());
    EXPECT_TRUE(told_wrong.quality().bound_at_sync == told_none.quality().bound_at_sync);
}

TEST(monotonic_raw_line, the_figures_a_line_goes_by_are_given_when_it_is_made)
{
    MonotonicRawLine defaults;
    EXPECT_EQ(defaults.config().drift_bound_ppb, MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB);
    EXPECT_EQ(int64_t{defaults.config().sleep_rate_margin_ppb}, MonotonicRawLine::SLEEP_RATE_MARGIN_PPB);
    EXPECT_TRUE(defaults.config().max_rate_ppm == MonotonicRawTracker::MAX_RATE_PPM);

    // A system that corrects its clock by no more than 50 ppm, and a
    // sleeper that allows 20 ppm for the line's own rate error.
    MonotonicRawLine line{{.drift_bound_ppb = 50'000, .sleep_rate_margin_ppb = 20'000}};
    auto const now = MonotonicRawClock::from_ns(LONG_UPTIME_NS);

    // Never sampled: 20 ppm of 5 ms.
    EXPECT_EQ(line.sleep_margin(now + Nanoseconds{5'000'000}, now).count(), int64_t{100});

    // The tracker publishes the line's own figure as the drift bound.
    MonotonicRawTracker tracker{line};
    EXPECT_TRUE(tracker.push(now, MonotonicClock::from_ns(LONG_UPTIME_NS + 7)));
    EXPECT_EQ(line.quality().drift_bound_ppb, uint32_t{50'000});
}

TEST(monotonic_raw_tracker, the_rate_window_is_the_lines_figure)
{
    // A line that accepts no more than 100 ppm keeps what it had when a
    // fit comes out 1000 ppm fast.
    MonotonicRawLine line{{.max_rate_ppm = 100.0}};
    MonotonicRawTracker tracker{line};
    EXPECT_TRUE(tracker.push(MonotonicRawClock::from_ns(LONG_UPTIME_NS), MonotonicClock::from_ns(LONG_UPTIME_NS)));
    EXPECT_FALSE(tracker.push(
        MonotonicRawClock::from_ns(LONG_UPTIME_NS + 1'000'000'000), MonotonicClock::from_ns(LONG_UPTIME_NS + 1'001'000'000)));

    // By the default window the same pair is a line to follow.
    MonotonicRawLine wide;
    MonotonicRawTracker follower{wide};
    EXPECT_TRUE(follower.push(MonotonicRawClock::from_ns(LONG_UPTIME_NS), MonotonicClock::from_ns(LONG_UPTIME_NS)));
    EXPECT_TRUE(follower.push(
        MonotonicRawClock::from_ns(LONG_UPTIME_NS + 1'000'000'000), MonotonicClock::from_ns(LONG_UPTIME_NS + 1'001'000'000)));
}

TEST_MAIN(statusbar_realtime, realtime_monotonic_raw_line_test)
