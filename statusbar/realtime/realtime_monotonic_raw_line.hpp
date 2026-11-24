#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The CLOCK_MONOTONIC_RAW <-> CLOCK_MONOTONIC line.
///
/// CLOCK_MONOTONIC_RAW is the timing reference clock: the raw hardware
/// counter, immune to the frequency slew that NTP or phc2sys applies to
/// CLOCK_MONOTONIC. Deadlines, stamps and measurements live on RAW. The
/// kernel can only sleep on CLOCK_MONOTONIC, so a sleep to a RAW deadline
/// goes through this line:
///
///     monotonic = rate * raw + offset_ns
///
/// published by whoever samples the two clocks (one writer) and read by
/// whoever sleeps (any thread). A sleeper converts its RAW deadline to a
/// coarse MONOTONIC one, wakes early by a guard that covers the slew it
/// could accrue over the sleep, then spins on RAW to the exact deadline.
/// The line only has to be good enough that "early" is early; the spin
/// does the rest.

#include "statusbar/itc/itc_seqlock_value.hpp"
#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timing_sample_window.hpp"

#include <cstddef>
#include <cstdint>

namespace statusbar::realtime {

/// One published line: `monotonic = rate * raw + offset_ns`.
struct MonotonicRawRateOffset
{
    double rate{1.0};
    int64_t offset_ns{0};
};

/// The same line as the conversions use it: the slope as an integer number
/// of parts per MonotonicRawLine::SLOPE_DENOMINATOR, so a conversion is
/// integer arithmetic only.
struct MonotonicRawFixedLine
{
    int64_t slope_numerator{1'000'000'000};
    int64_t offset_ns{0};
};

/// The figures the line between the two local clocks is built on. They
/// describe how the operating system treats CLOCK_MONOTONIC, and their
/// defaults are Linux's; a deployment on another system, or one that
/// knows its own better, sets them when it makes the line.
struct MonotonicRawLineConfig
{
    /// How fast CLOCK_MONOTONIC may move against RAW while the line is not
    /// being sampled, in parts per billion: 500 ppm, the range of Linux's
    /// frequency correction of the system clock.
    uint32_t drift_bound_ppb{500'000};

    /// The line's rate error after a 1 ms priming baseline, in parts per
    /// billion: added to its distance from rate one in sleep_margin, so
    /// that an early wake stays early.
    uint32_t sleep_rate_margin_ppb{100'000};

    /// A fit whose rate is further than this from 1.0, in parts per
    /// million, is rejected and the previous line kept. Wide on purpose:
    /// phc2sys may rail CLOCK_MONOTONIC at +/-10%, and the line must follow
    /// it or the early wake is late.
    double max_rate_ppm{200'000.0};
};

/// The shared line. Reads take no lock and are consistent (a seqlock: a
/// reader retries while the writer is mid-update); the
/// conversions are exact to the nanosecond for any uptime, so a deadline
/// hours away converts the same way a deadline microseconds away does.
class MonotonicRawLine
{
  public:
    using RateOffset = MonotonicRawRateOffset;
    using FixedLine = MonotonicRawFixedLine;

    /// Fixed-point slope resolution: rate is published as an integer number
    /// of parts per 1e9, which carries the sub-ppm steps adjtimex makes.
    static constexpr int64_t SLOPE_DENOMINATOR = 1'000'000'000;

    using Config = MonotonicRawLineConfig;

    MonotonicRawLine() noexcept = default;

    /// A line on figures other than the defaults. They are fixed for the
    /// line's life, so any thread may read them.
    /// @param config The figures the line and its tracker go by
    explicit MonotonicRawLine(Config const& config) noexcept
        : config_{config}
    {}

    /// The figures this line was made with.
    [[nodiscard]] auto config() const noexcept -> Config const& { return config_; }

    /// Writer side (one thread at a time). A default line is the identity.
    /// The rate is rounded to the integer slope once, here, so that no
    /// reader does floating point.
    void publish(RateOffset line) noexcept
    {
        publish_fixed({.slope_numerator = slope_numerator(line.rate), .offset_ns = line.offset_ns});
    }

    /// Writer side, for a writer that already holds the integer slope.
    void publish_fixed(FixedLine line) noexcept { line_.store(line); }

    /// Reader side (any thread): the line with its rate as a ratio, for
    /// reports and tests. The conversions do not go through this.
    [[nodiscard]] auto consume() const noexcept -> RateOffset
    {
        auto const line = line_.load();
        return {
            .rate = static_cast<double>(line.slope_numerator) / static_cast<double>(SLOPE_DENOMINATOR),
            .offset_ns = line.offset_ns};
    }

    /// Reader side (any thread): the line as the conversions use it.
    [[nodiscard]] auto consume_fixed() const noexcept -> FixedLine { return line_.load(); }

    /// How far the line's rate is from 1, in parts per billion (never
    /// negative): the slew a sleeper has to allow for.
    [[nodiscard]] auto rate_deviation_ppb() const noexcept -> int64_t
    {
        int64_t const deviation = line_.load().slope_numerator - SLOPE_DENOMINATOR;
        return deviation < 0 ? -deviation : deviation;
    }

    /// The default of Config::sleep_rate_margin_ppb.
    static constexpr int64_t SLEEP_RATE_MARGIN_PPB = Config{}.sleep_rate_margin_ppb;

    /// How much earlier than to_monotonic(@p target_raw) a sleeper has to
    /// aim to be sure of waking before the target: the line's misfit when
    /// it was last sampled (its fit residual and half the read bracket),
    /// plus the slew it could have accrued from that sample to the target,
    /// at the line's distance from rate one and its sleep_rate_margin_ppb. The
    /// longer the line goes unsampled the larger this is, and the more of
    /// a wait is spent spinning. A line never sampled (the identity) has no
    /// sample to count from: the slew is counted from @p raw_now.
    /// @param target_raw The CLOCK_MONOTONIC_RAW instant to be awake before
    /// @param raw_now The CLOCK_MONOTONIC_RAW instant it is now
    [[nodiscard]] auto sleep_margin(MonotonicRawClock::time_point target_raw, MonotonicRawClock::time_point raw_now) const noexcept
        -> Nanoseconds;

    /// Writer side: how well the line just published is known.
    void publish_quality(ClockQuality const& quality) noexcept { quality_.store(quality); }

    /// Reader side (any thread): how well CLOCK_MONOTONIC is known through
    /// this line. Unbounded until a tracker has published one; while no
    /// new sample arrives it grows from the last one, so a sleeper can
    /// tell how far the line may have gone stale.
    [[nodiscard]] auto quality() const noexcept -> ClockQuality { return quality_.load(); }

    /// CLOCK_MONOTONIC instant for a CLOCK_MONOTONIC_RAW one.
    [[nodiscard]] auto to_monotonic_ns(int64_t raw_ns) const noexcept -> int64_t;

    /// CLOCK_MONOTONIC_RAW instant for a CLOCK_MONOTONIC one.
    [[nodiscard]] auto from_monotonic_ns(int64_t mono_ns) const noexcept -> int64_t;

    [[nodiscard]] auto to_monotonic(MonotonicRawClock::time_point raw) const noexcept -> MonotonicClock::time_point
    {
        return MonotonicClock::from_ns(to_monotonic_ns(MonotonicRawClock::to_ns(raw)));
    }

    [[nodiscard]] auto from_monotonic(MonotonicClock::time_point mono) const noexcept -> MonotonicRawClock::time_point
    {
        return MonotonicRawClock::from_ns(from_monotonic_ns(MonotonicClock::to_ns(mono)));
    }

    /// The rate as the integer slope the conversions use.
    [[nodiscard]] static auto slope_numerator(double rate) noexcept -> int64_t;

  private:
    Config config_{};
    itc::SeqlockValue<FixedLine> line_{FixedLine{}};
    itc::SeqlockValue<ClockQuality> quality_{ClockQuality{}};
};

/// The writer side of a line: takes paired readings of the two clocks,
/// fits them and publishes the result. Single-threaded, no allocation,
/// so a timer thread can own one and feed it between wakes.
class MonotonicRawTracker
{
  public:
    /// One paired reading: the same instant on each clock.
    struct Sample
    {
        MonotonicRawClock::time_point raw{};
        MonotonicClock::time_point mono{};
    };

    static constexpr size_t DEFAULT_WINDOW = 64;

    /// The default of MonotonicRawLineConfig::max_rate_ppm. The tracker
    /// goes by the figure of the line it writes.
    static constexpr double MAX_RATE_PPM = MonotonicRawLineConfig{}.max_rate_ppm;

    /// The default of MonotonicRawLineConfig::drift_bound_ppb. A line seen
    /// away from rate one may move back by as much as it is off, and a rate
    /// seen moving within the window may move as much again. The three can
    /// happen together, so the drift bound the tracker publishes is the
    /// line's configured figure plus those two.
    static constexpr uint32_t DEFAULT_DRIFT_BOUND_PPB = MonotonicRawLineConfig{}.drift_bound_ppb;

    explicit MonotonicRawTracker(MonotonicRawLine& line, size_t window = DEFAULT_WINDOW) noexcept
        : line_{&line}
        , window_{window}
    {}

    /// Told form: one paired reading, taken by the caller. Refits the window
    /// and publishes. One sample publishes an offset-only line.
    /// @param raw The CLOCK_MONOTONIC_RAW reading
    /// @param mono The CLOCK_MONOTONIC reading of the same instant
    /// @param bracket How long the paired read took: half of it is the
    ///        uncertainty of the pairing. Zero when the caller cannot say.
    /// @return false when the fit was rejected (rate out of range); the
    ///         previous line stands.
    auto push(
        MonotonicRawClock::time_point raw, MonotonicClock::time_point mono, Nanoseconds bracket = Nanoseconds::zero()) noexcept
        -> bool;

    /// Asking form, for the tick owner: reads RAW, MONOTONIC, RAW and pushes
    /// the pair at the RAW midpoint of the bracket.
    /// @return the bracket width (how uncertain the pairing is).
    auto sample() noexcept -> Nanoseconds;

    [[nodiscard]] auto size() const noexcept -> size_t { return window_.size(); }
    void clear() noexcept { window_.clear(); }

  private:
    MonotonicRawLine* line_;
    TimingSampleWindow<Sample> window_;
};

}  // namespace statusbar::realtime
