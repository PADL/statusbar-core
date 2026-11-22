#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/sg14/inplace_function.h"
#include "statusbar/stats/stats.hpp"

#include <cstdint>
#include <optional>
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

    time_point scheduled_time;  ///< The scheduled wake time (uncompensated), on the schedule's clock
    duration error;             ///< Wake error (positive = late, negative = early), measured on CLOCK_MONOTONIC_RAW
    int64_t wake_count;         ///< The wake number (starting from 1)
    int64_t skipped_counts;     ///< Number of missed wakes (0 = no misses)

    /// The CLOCK_MONOTONIC_RAW instant the timer entered the callback: the
    /// start the callback's own duration is measured from, told rather than
    /// re-read, and in the timing domain whatever clock the schedule is in.
    /// Empty for an event built by hand (tests): it was not told.
    std::optional<MonotonicRawClock::time_point> wake_raw{};

    /// Print this event to stdout
    /// @param stats Snapshot of cumulative statistics
    auto print(this auto const& self, stats::AtomicWakeStats::Snapshot const& stats) -> void
    {
        std::print(
            "Wake: scheduled={} ns  error={} ns  count={}  skipped={} total_skipped={}\n",
            ClockT::to_ns(self.scheduled_time),
            self.error.count(),
            self.wake_count,
            self.skipped_counts,
            stats.skipped_counts);
    }
};

/// Callback signature for timer wakes
/// @param event The timer event with timing data for this wake
/// @param stats Snapshot of cumulative statistics (includes this wake's data)
template <ClockType ClockT = MonotonicRawClock>
using TimerCallback =
    statusbar::sg14::inplace_function<void(TimerEvent<ClockT> const&, stats::AtomicWakeStats::Snapshot const&), 64>;

}  // namespace statusbar::realtime
