#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/sg14/inplace_function.h"
#include "statusbar/stats/stats.hpp"

#include <cstdint>
#include <print>

namespace statusbar::realtime {

/// Event data passed to timer callback on each wake.
/// Templated on clock type for type-safe time_point values.
///
/// @tparam ClockT The clock the schedule is in (e.g., MonotonicRawClock, GptpClock<0>)
template <ClockType ClockT = MonotonicRawClock>
struct TimerEvent
{
    using clock_type = ClockT;
    using time_point = ClockT::time_point;
    using duration = ClockT::duration;

    time_point scheduled_time;  ///< The scheduled wake time (uncompensated)
    duration error;             ///< Wake error (positive = late, negative = early)
    int64_t wake_count;         ///< The cycle number of this wake: the adapter's time over the period, not a count from 1
    int64_t skipped_counts;     ///< Number of missed wakes (0 = no misses)

    /// The CLOCK_MONOTONIC_RAW instant the timer entered the callback: the
    /// start the callback's own duration is measured from, told rather than
    /// re-read, and in the timing domain whatever clock the schedule is in.
    /// Zero for an event built by hand (tests), which readers treat as
    /// "not told".
    MonotonicRawClock::time_point wake_raw{};

    /// The worst-case accuracy of this wake's schedule: how far the
    /// schedule's clock, as the timer's adapter maps it, may be from true at
    /// the scheduled instant. It grows while the adapter's source coasts
    /// without its master, so a callback can decide whether the time it is
    /// told is still good enough. UNBOUNDED_ACCURACY when the adapter
    /// reports no quality, and for an event built by hand.
    Nanoseconds accuracy{UNBOUNDED_ACCURACY};

    /// The timeline of the adapter's clock the schedule is laid on: its
    /// ClockQuality::epoch, 0 for an adapter that reports no quality and
    /// for an event built by hand. When it differs from the wake before,
    /// the clock moved to another timeline (a new grandmaster, a step) and
    /// the grid was laid again: scheduled_time and wake_count are not
    /// comparable with the earlier ones.
    uint64_t timeline{0};

    /// Get scheduled time as raw nanoseconds (for backward compatibility)
    [[nodiscard]] constexpr auto scheduled_time_ns() const noexcept -> int64_t { return scheduled_time.time_since_epoch().count(); }

    /// Get error as raw nanoseconds (for backward compatibility)
    [[nodiscard]] constexpr auto error_ns() const noexcept -> int64_t { return error.count(); }

    /// The RAW callback-entry instant in nanoseconds, 0 when not told
    [[nodiscard]] constexpr auto wake_raw_ns() const noexcept -> int64_t { return wake_raw.time_since_epoch().count(); }

    /// Print this event to stdout
    /// @param stats Snapshot of cumulative statistics
    auto print(this auto const& self, stats::AtomicWakeStats::Snapshot const& stats) -> void
    {
        std::print(
            "Wake: scheduled={} ns  error={} ns  count={}  skipped={} total_skipped={}\n",
            self.scheduled_time_ns(),
            self.error_ns(),
            self.wake_count,
            self.skipped_counts,
            stats.skipped_counts);
    }
};

/// Callback signature for timer wakes
/// @param event The timer event with timing data for this wake
/// @param stats Snapshot of the statistics up to the wake before this one (this wake is added after the callback)
template <ClockType ClockT = MonotonicRawClock>
using TimerCallback =
    statusbar::sg14::inplace_function<void(TimerEvent<ClockT> const&, stats::AtomicWakeStats::Snapshot const&), 64>;

}  // namespace statusbar::realtime
