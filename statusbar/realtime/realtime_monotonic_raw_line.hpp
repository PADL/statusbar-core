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

/// The shared line. Reads are wait-free and consistent (seqlock); the
/// conversions are exact to the nanosecond for any uptime, so a deadline
/// hours away converts the same way a deadline microseconds away does.
class MonotonicRawLine
{
  public:
    using RateOffset = MonotonicRawRateOffset;

    /// Fixed-point slope resolution: rate is published as an integer number
    /// of parts per 1e9, which carries the sub-ppm steps adjtimex makes.
    static constexpr int64_t SLOPE_DENOMINATOR = 1'000'000'000;

    MonotonicRawLine() noexcept = default;

    /// Writer side (one thread at a time). A default line is the identity.
    void publish(RateOffset line) noexcept { line_.store(line); }

    /// Reader side (any thread).
    [[nodiscard]] auto consume() const noexcept -> RateOffset { return line_.load(); }

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
    itc::SeqlockValue<RateOffset> line_{RateOffset{}};
};

/// The writer side of a line: takes paired readings of the two clocks,
/// fits them and publishes the result. Single-threaded, no allocation,
/// so a timer thread can own one and feed it between wakes.
class MonotonicRawTracker
{
  public:
    struct Sample
    {
        int64_t raw_ns{0};
        int64_t mono_ns{0};
    };

    static constexpr size_t DEFAULT_WINDOW = 64;

    /// A fit whose rate is further than this from 1.0 is rejected and the
    /// previous line kept. Wide on purpose: phc2sys may rail CLOCK_MONOTONIC
    /// at +/-10%, and the line must follow it or the early wake is late.
    static constexpr double MAX_RATE_PPM = 200'000.0;

    explicit MonotonicRawTracker(MonotonicRawLine& line, size_t window = DEFAULT_WINDOW) noexcept
        : line_{&line}
        , window_{window}
    {}

    /// Told form: one paired reading, taken by the caller. Refits the window
    /// and publishes. One sample publishes an offset-only line.
    /// @return false when the fit was rejected (rate out of range); the
    ///         previous line stands.
    auto push(int64_t raw_ns, int64_t mono_ns) noexcept -> bool;

    /// Asking form, for the tick owner: reads RAW, MONOTONIC, RAW and pushes
    /// the pair at the RAW midpoint of the bracket.
    /// @return the bracket width in ns (how uncertain the pairing is).
    auto sample() noexcept -> int64_t;

    [[nodiscard]] auto size() const noexcept -> size_t { return window_.size(); }
    void clear() noexcept { window_.clear(); }

  private:
    MonotonicRawLine* line_;
    TimingSampleWindow<Sample> window_;
};

}  // namespace statusbar::realtime
