// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// MonotonicRawLine and MonotonicRawTracker: the RAW->MONOTONIC line a
// sleeper converts its deadline through. The tracker tests are told their
// samples, so they pin the fit exactly; only the last test reads clocks.

#include "statusbar/realtime/realtime_monotonic_raw_line.hpp"

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/test/test.hpp"

#include <cstdint>
#include <cstdlib>

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

TEST(monotonic_raw_tracker, one_sample_publishes_the_offset_at_rate_one)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    EXPECT_TRUE(tracker.push(1'000, 1'000'000));
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
        EXPECT_TRUE(tracker.push(raw, mono));
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
    EXPECT_TRUE(tracker.push(0, 100));
    EXPECT_TRUE(tracker.push(1'000'000, 1'000'100));
    // A pair that says MONOTONIC runs at twice RAW: not a clock, a glitch.
    EXPECT_FALSE(tracker.push(2'000'000, 3'000'100));
    auto const published = line.consume();
    EXPECT_EQ(published.rate, 1.0);
    EXPECT_EQ(published.offset_ns, int64_t{100});
}

TEST(monotonic_raw_tracker, the_window_forgets_old_samples)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line, 4};
    for (int i = 0; i < 10; ++i) {
        (void)tracker.push(i * 1'000'000LL, (i * 1'000'000LL) + 50);
    }
    EXPECT_EQ(tracker.size(), size_t{4});
}

TEST(monotonic_raw_tracker, sampling_the_clocks_gives_a_line_near_the_live_offset)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    int64_t const bracket = tracker.sample();
    EXPECT_TRUE(bracket >= 0);
    // Right after one sample the line maps now to now, give or take the
    // bracket and the time these reads took.
    int64_t const raw_now = read_monotonic_raw_ns();
    int64_t const mono_now = read_monotonic_ns();
    EXPECT_TRUE(within(line.to_monotonic_ns(raw_now), mono_now, bracket + 1'000'000));
}

TEST_MAIN(statusbar_realtime, realtime_monotonic_raw_line_test)
