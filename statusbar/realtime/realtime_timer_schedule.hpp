#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The schedule a Timer keeps, apart from the thread that waits on it.
///
/// A TimerSchedule is told everything: the time it starts at, and how each
/// wait ended. It reads no clock and never blocks. The whole of a timer's
/// arithmetic lives here (the grid of period boundaries, each deadline on
/// two clocks, the periodic resync, whether the clock is ready, the
/// accuracy told with each wake), so all of it can be run on made-up time.
/// Timer is this schedule plus a thread that waits for its deadlines.

#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timer_event.hpp"

#include <chrono>
#include <cstdint>
#include <utility>

namespace statusbar::realtime {

/// Return the cycle number that contains @p time_ns for a timer of period
/// @p period_ns (floor division). A "cycle number" here is the integer index
/// of the period-sized slot the time falls within, counted from the clock's
/// zero epoch.
///
/// Precondition: period_ns > 0.
[[nodiscard]] constexpr auto cycle_number_from_ns(int64_t time_ns, int64_t period_ns) noexcept -> int64_t
{
    return time_ns / period_ns;
}

/// Return the ns time at the start of cycle @p cycle for a timer of period
/// @p period_ns. Inverse of cycle_number_from_ns (exact: round-trip restores
/// the cycle number, not necessarily the original ns value).
///
/// Also usable as "convert N cycles to a ns delta" since the math is symmetric.
[[nodiscard]] constexpr auto cycle_number_to_ns(int64_t cycle, int64_t period_ns) noexcept -> int64_t
{
    return cycle * period_ns;
}

/// The cycle number that contains @p time, on whichever clock @p time is.
///
/// Precondition: period > 0.
template <typename Tag>
[[nodiscard]] constexpr auto cycle_number(std::chrono::time_point<Clock<Tag>, Nanoseconds> time, Nanoseconds period) noexcept
    -> int64_t
{
    return cycle_number_from_ns(Clock<Tag>::to_ns(time), period.count());
}

/// The instant on @p ClockT at which cycle @p cycle starts.
template <ClockType ClockT>
[[nodiscard]] constexpr auto cycle_start(int64_t cycle, Nanoseconds period) noexcept -> ClockT::time_point
{
    return ClockT::from_ns(cycle_number_to_ns(cycle, period.count()));
}

/// How a wait for a deadline ended: the wake error (positive = late) and the
/// number of full periods the wake is past the deadline (0 when on time).
struct WaitResult
{
    Nanoseconds error;
    int64_t skipped_counts;
};

/// The outcome of a wake @p error past its deadline on a grid of @p period.
[[nodiscard]] constexpr auto wait_result(Nanoseconds error, Nanoseconds period) noexcept -> WaitResult
{
    // A period of zero can be asked for on a command line: never divide by it.
    int64_t const skipped_counts = (period > Nanoseconds::zero() && error > period) ? (error / period) : 0;
    return {.error = error, .skipped_counts = skipped_counts};
}

/// A timer's schedule on its adapter's clock, told the time.
/// @tparam ClockAdapterT The clock adapter the schedule is laid on
template <ClockAdapterType ClockAdapterT>
class TimerSchedule
{
  public:
    using adapter_type = ClockAdapterT;
    using clock_type = ClockAdapterT::clock_type;
    using time_point = clock_type::time_point;
    using event_type = TimerEvent<clock_type>;

    struct Config
    {
        Nanoseconds period{};
        /// Cycles ahead of the starting time to schedule the first wake.
        int64_t start_offset_cycles{2};
        /// Wakes between fresh conversions of the deadline (0 = never).
        int64_t resync_interval_cycles{1000};
    };

    /// The two instants that drive each tick, one per clock: @p scheduled
    /// is the canonical target in the adapter's clock domain (used for
    /// event data and stats); @p raw_deadline is the same instant on
    /// CLOCK_MONOTONIC_RAW, the clock the wait is made on.
    struct Deadline
    {
        time_point scheduled{};
        MonotonicRawClock::time_point raw_deadline{};
    };

    TimerSchedule(ClockAdapterT adapter, Config const& config)
        : adapter_{std::move(adapter)}
        , config_{config}
    {}

    [[nodiscard]] auto adapter() const noexcept -> ClockAdapterT const& { return adapter_; }

    /// Whether the adapter's clock has synchronized, so that a schedule can
    /// be laid on it. An adapter that reports quality is ready once it
    /// claims a bound, and stays ready while it coasts; any other adapter
    /// is ready while it says it is healthy.
    [[nodiscard]] auto is_ready() const -> bool
    {
        if constexpr (QualifiedClockAdapter<ClockAdapterT>) {
            return adapter_.quality().is_bounded();
        } else {
            return adapter_.is_healthy();
        }
    }

    /// Lay the grid, told the adapter's time now: the first wake is
    /// start_offset_cycles past the cycle that contains @p now, far enough
    /// ahead that thread setup cannot leave it in the past.
    auto begin(time_point now) -> void
    {
        wake_count_ = cycle_number(now, config_.period) + config_.start_offset_cycles;
        deadline_ = fresh_deadline();
    }

    /// The deadline to wait for next.
    [[nodiscard]] auto deadline() const noexcept -> Deadline const& { return deadline_; }

    /// The cycle number of that deadline.
    [[nodiscard]] auto wake_count() const noexcept -> int64_t { return wake_count_; }

    /// The worst-case accuracy of the schedule at the deadline. No clock is
    /// read: the deadline is the instant, and the adapter's quality grows
    /// from its last sync to it.
    [[nodiscard]] auto accuracy() const -> Nanoseconds
    {
        if constexpr (QualifiedClockAdapter<ClockAdapterT>) {
            return adapter_.quality().uncertainty(deadline_.raw_deadline);
        } else {
            return UNBOUNDED_ACCURACY;
        }
    }

    /// What the callback is told about the wake for the current deadline,
    /// given how the wait for it ended. The instant the callback is
    /// entered is not the schedule's to know: the thread stamps wake_raw.
    [[nodiscard]] auto event(WaitResult const& wait) const -> event_type
    {
        return {
            .scheduled_time = deadline_.scheduled,
            .error = wait.error,
            .wake_count = wake_count_,
            .skipped_counts = wait.skipped_counts,
            .accuracy = accuracy(),
        };
    }

    /// Move on by one period, and by one more for each period the wait
    /// skipped. Both instants move by the same duration although their
    /// clocks tick at slightly different rates: that avoids the adapter's
    /// conversion on every tick, and every resync_interval_cycles wakes a
    /// fresh conversion cancels what has accumulated. At the default 1000
    /// cycles and 11 ppm of skew that caps the error near 1.4 us.
    auto advance(WaitResult const& wait) -> void
    {
        int64_t const periods = wait.skipped_counts + 1;
        Nanoseconds const step = config_.period * periods;
        wake_count_ += periods;
        deadline_.scheduled += step;
        deadline_.raw_deadline += step;
        if (config_.resync_interval_cycles > 0 && (wake_count_ % config_.resync_interval_cycles) == 0) {
            deadline_ = fresh_deadline();
        }
    }

  private:
    /// Both instants of the current cycle, converted afresh.
    [[nodiscard]] auto fresh_deadline() const -> Deadline
    {
        time_point const scheduled = cycle_start<clock_type>(wake_count_, config_.period);
        return {.scheduled = scheduled, .raw_deadline = adapter_.to_raw(scheduled)};
    }

    ClockAdapterT adapter_;
    Config config_;
    int64_t wake_count_{0};
    Deadline deadline_{};
};

}  // namespace statusbar::realtime
