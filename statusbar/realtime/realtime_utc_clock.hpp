#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// How well the system clock knows UTC, as a ClockQuality that coasts.
///
/// The operating system already keeps a worst-case error for its clock: the
/// time daemon sets it from its source at each update and the system grows
/// it in between. That figure is right whatever disciplines the clock (a
/// local GPS receiver, a distant NTP server), so it is what a user of
/// UtcClock should judge the time by. Its growth is not: the system assumes
/// the largest frequency error it can be told to correct, 500 ppm, which is
/// far looser than a real oscillator and turns a short loss of the time
/// server into an unusable bound within seconds.
///
/// UtcClockQualityTracker takes the system's figure at each update as the
/// bound at that instant and grows it itself, at the drift the deployment
/// configures. While the daemon keeps updating, the two agree. When updates
/// stop, the clock coasts on the configured figure.

#include "statusbar/realtime/realtime_clock.hpp"

#include <cstdint>

namespace statusbar::realtime {

/// Tracks the system clock's ClockQuality from what the operating system
/// reports. Single-threaded: one owner observes, and publishes quality()
/// to whoever else needs it. No allocation, integers only.
class UtcClockQualityTracker
{
  public:
    struct Config
    {
        /// How fast the error may grow while the time daemon is not
        /// updating: the deployment's oscillator and temperature figure.
        uint32_t drift_bound_ppb{DEFAULT_HOLDOVER_DRIFT_PPB};

        /// What disciplines the system clock, when the deployment knows.
        /// The tracker cannot tell a GPS receiver from any other server.
        TimeSource time_source{TimeSource::ntp};
    };

    /// The system grows its worst-case error by this much at each whole
    /// second of its clock between updates (its 500 ppm tolerance).
    static constexpr Nanoseconds SYSTEM_GROWTH_PER_SECOND{500'000};

    /// A change of the system clock against CLOCK_MONOTONIC_RAW faster than
    /// this, in parts per billion, is a step and not a slew: a slewing
    /// daemon stays far below a tenth of real time.
    static constexpr uint32_t STEP_RATE_PPB = 100'000'000;

    /// Allowed on top of the rate before a change counts as a step: the
    /// uncertainty of pairing the two clock reads.
    static constexpr Nanoseconds STEP_MARGIN{1'000'000};

    UtcClockQualityTracker() noexcept = default;

    explicit UtcClockQualityTracker(Config config) noexcept
        : config_{config}
    {}

    /// Told form: one paired reading of the two clocks and the system's
    /// report, all taken by the caller at the same instant.
    /// @param raw The CLOCK_MONOTONIC_RAW reading
    /// @param utc The system clock reading of the same instant
    /// @param reported What the operating system said about its clock then
    auto observe(MonotonicRawClock::time_point raw, UtcClock::time_point utc, SystemClockError const& reported) noexcept -> void
    {
        bool const stepped = observed_ && is_step(raw, utc);
        if (stepped) {
            // A different timeline: what was known about the old one says
            // nothing about this one.
            ++quality_.epoch;
            quality_.bound_at_sync = UNBOUNDED_ACCURACY;
        }
        if (reported.synchronized && (stepped || !quality_.is_bounded() || is_update(utc, reported.max_error))) {
            quality_.synced_at = raw;
            quality_.bound_at_sync = reported.max_error;
        }
        remember(raw, utc, reported.max_error);
    }

    /// Asking form, for the owner of a tick: reads CLOCK_MONOTONIC_RAW, the
    /// system clock and the system's report, and observes them.
    auto sample() noexcept -> void { observe(read_monotonic_raw(), read_utc(), read_system_clock_error()); }

    /// How well the system clock knows UTC. Unbounded until the system has
    /// once reported itself synchronized; from then on it coasts through
    /// any loss of the time daemon's source.
    [[nodiscard]] auto quality() const noexcept -> ClockQuality { return quality_; }

    /// The system clock now with its worst-case accuracy. Reads both
    /// clocks, so it is for a tick owner, not a fast path.
    [[nodiscard]] auto read_bounded() const noexcept -> BoundedTime<UtcClock>
    {
        auto const raw = read_monotonic_raw();
        return {.time = read_utc(), .accuracy = quality_.uncertainty(raw)};
    }

  private:
    /// Whether the system clock moved against RAW further than a slew could
    /// take it since the last observation.
    [[nodiscard]] auto is_step(MonotonicRawClock::time_point raw, UtcClock::time_point utc) const noexcept -> bool
    {
        Nanoseconds const raw_elapsed = raw - last_raw_;
        Nanoseconds const utc_elapsed = utc - last_utc_;
        Nanoseconds const moved = utc_elapsed > raw_elapsed ? utc_elapsed - raw_elapsed : raw_elapsed - utc_elapsed;
        return moved > accumulated_drift(raw_elapsed, STEP_RATE_PPB) + STEP_MARGIN;
    }

    /// Whether the time daemon has set the system's worst-case error since
    /// the last observation. Left alone, the system adds exactly
    /// SYSTEM_GROWTH_PER_SECOND at each whole second of its clock; any
    /// other value was written by the daemon. A reading that races the
    /// system's own increment looks like an update too: it anchors on a
    /// figure the system has grown, which is the looser one.
    [[nodiscard]] auto is_update(UtcClock::time_point utc, Nanoseconds max_error) const noexcept -> bool
    {
        constexpr int64_t BILLION = 1'000'000'000;
        int64_t const seconds_crossed = (UtcClock::to_ns(utc) / BILLION) - (UtcClock::to_ns(last_utc_) / BILLION);
        return max_error != last_max_error_ + (SYSTEM_GROWTH_PER_SECOND * seconds_crossed);
    }

    auto remember(MonotonicRawClock::time_point raw, UtcClock::time_point utc, Nanoseconds max_error) noexcept -> void
    {
        last_raw_ = raw;
        last_utc_ = utc;
        last_max_error_ = max_error;
        observed_ = true;
    }

    Config config_{};
    ClockQuality quality_{.drift_bound_ppb = config_.drift_bound_ppb, .time_source = config_.time_source};
    MonotonicRawClock::time_point last_raw_{};
    UtcClock::time_point last_utc_{};
    Nanoseconds last_max_error_{0};
    bool observed_{false};
};

}  // namespace statusbar::realtime
