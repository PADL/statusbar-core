#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timer_base.hpp"
#include "statusbar/realtime/realtime_timer_config.hpp"
#include "statusbar/realtime/realtime_timer_event.hpp"
#include "statusbar/realtime/realtime_tripwire.hpp"
#include "statusbar/stats/stats.hpp"

#include <chrono>
#include <cstdint>
#include <iterator>
#include <print>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

namespace statusbar::realtime {

/// High-precision periodic timer with realtime scheduling.
/// Templated on clock adapter type for type-safe time_point values and clock domain conversion.
///
/// This timer runs in a dedicated thread with SCHED_FIFO priority and optional CPU affinity.
/// It calls a user-provided callback on each wake, providing timing statistics.
///
/// The schedule is a grid of period boundaries in the adapter's clock domain (a gPTP
/// domain, say). Each boundary is converted to a CLOCK_MONOTONIC_RAW deadline through the
/// adapter, and the timer waits for that: it sleeps early on CLOCK_MONOTONIC and spins on
/// RAW to the exact instant (TimerBase::wait_until_raw_deadline).
///
/// @tparam ClockAdapterT The clock adapter type (e.g., MonotonicRawClockAdapter, ClockAdapter<GptpClock<0>, PtpTimeBridge>)
template <ClockAdapterType ClockAdapterT = MonotonicRawClockAdapter>
class Timer : public TimerBase
{
  public:
    using adapter_type = ClockAdapterT;
    using clock_type = ClockAdapterT::clock_type;
    using time_point = clock_type::time_point;
    using duration = clock_type::duration;
    using event_type = TimerEvent<clock_type>;
    using callback_type = TimerCallback<clock_type>;

    /// Construct a realtime timer.
    /// The caller is responsible for validating @p config (see validate_timer_config)
    /// before construction; passing an invalid config produces undefined behavior.
    /// @param config Timer configuration (period, compensation, CPU, busy-wait mode, histograms)
    /// @param callback Function to call on each wake
    /// @param adapter Clock adapter for time reading and conversion (timer takes ownership);
    ///                defaults to a value-initialized adapter — valid only when that default
    ///                represents a usable runtime state (e.g. MonotonicRawClockAdapter).
    Timer(TimerConfig const& config, callback_type callback, ClockAdapterT adapter = ClockAdapterT{})
        : TimerBase{config}
        , adapter_{std::move(adapter)}
        , callback_{std::move(callback)}
    {}

    ~Timer() noexcept override { stop(); }

    Timer(Timer const&) = delete;
    auto operator=(Timer const&) -> Timer& = delete;
    Timer(Timer&&) = delete;
    auto operator=(Timer&&) -> Timer& = delete;

  protected:
    /// The two instants that drive each tick, one per clock: @p scheduled
    /// is the canonical target in the adapter's clock domain (used for
    /// event data and stats); @p raw_deadline is the same instant on
    /// CLOCK_MONOTONIC_RAW, the clock the wait is made on.
    struct Deadline
    {
        time_point scheduled;
        MonotonicRawClock::time_point raw_deadline;
    };

    /// Whether the adapter's clock has synchronized, so that a schedule can
    /// be laid on it. An adapter that reports quality is ready once it
    /// claims a bound, and stays ready while it coasts; any other adapter
    /// is ready while it says it is healthy.
    [[nodiscard]] auto adapter_is_ready() const -> bool
    {
        if constexpr (QualifiedClockAdapter<ClockAdapterT>) {
            return adapter_.quality().is_bounded();
        } else {
            return adapter_.is_healthy();
        }
    }

    /// The worst-case accuracy of the schedule at a CLOCK_MONOTONIC_RAW
    /// deadline, for the event. No clock is read: the deadline is the
    /// instant, and the adapter's quality grows from its last sync to it.
    [[nodiscard]] auto schedule_accuracy(MonotonicRawClock::time_point raw_deadline) const -> Nanoseconds
    {
        if constexpr (QualifiedClockAdapter<ClockAdapterT>) {
            return adapter_.quality().uncertainty(raw_deadline);
        } else {
            return UNBOUNDED_ACCURACY;
        }
    }

    /// Block until the adapter's clock is ready (for clocks like gPTP that
    /// need to synchronise before producing valid timestamps). The timer
    /// only waits here, once: after it has started it keeps its schedule
    /// through a loss of sync and reports the accuracy in every event.
    /// Returns false if shutdown was requested before the adapter became ready.
    [[nodiscard]] auto wait_until_ready() -> bool override
    {
        while (should_run() && !adapter_is_ready()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return should_run();
    }

    /// Compute both instants from @p next_wake_count as a fresh pair. Used
    /// for the initial deadline setup in run_loop and (via
    /// maybe_resync_deadline) for the periodic drift correction.
    [[nodiscard]] auto resync_deadline(int64_t next_wake_count) const -> Deadline
    {
        time_point const scheduled = cycle_start<clock_type>(next_wake_count, period());
        return {.scheduled = scheduled, .raw_deadline = adapter_.to_raw(scheduled)};
    }

    /// Periodic drift correction: every resync_interval_cycles wakes, return
    /// a freshly-computed Deadline to cancel the slope error accumulated by
    /// advancing the RAW deadline directly in advance_schedule. On
    /// non-resync ticks this returns @p current unchanged. At the default
    /// 1000-cycle cadence and ~11 ppm clock skew the resync caps residual
    /// error at ~1.4µs; a resync_interval_cycles of 0 disables it.
    [[nodiscard]] auto maybe_resync_deadline(int64_t next_wake_count, Deadline current) const -> Deadline
    {
        int64_t const interval = config_.resync_interval_cycles;
        if (interval > 0 && (next_wake_count % interval) == 0) {
            return resync_deadline(next_wake_count);
        }
        return current;
    }

    /// Advance the loop-carried wake state by (skipped_counts + 1) periods.
    /// Both instants move by the same duration, although their clocks tick
    /// at slightly different rates — this is the key optimisation that
    /// avoids re-running the adapter's slope conversion every tick (the tiny
    /// accumulated drift is fixed up by the periodic resync in run_loop).
    auto advance_schedule(WaitResult const& wait, int64_t& next_wake_count, Deadline& deadline) const noexcept -> void
    {
        int64_t const periods_to_advance = wait.skipped_counts + 1;
        Nanoseconds const advance = period() * periods_to_advance;
        next_wake_count += periods_to_advance;
        deadline.scheduled += advance;
        deadline.raw_deadline += advance;
    }

    /// Construct the per-wake event, invoke the user callback, measure its
    /// wall-clock duration, and feed the error / duration / skipped counts
    /// into the wake stats. A TripwireFiredException thrown by the callback
    /// (via ScopedTripwireObserver) is allowed to propagate — it aborts the
    /// stats update for this tick and is caught in TimerBase::start()'s
    /// thread lambda, which lets the thread exit while the tripwire machinery
    /// drives shutdown from the monitor/main threads.
    auto invoke_callback(Deadline const& deadline, int64_t wake_count, WaitResult const& wait) -> void
    {
        Nanoseconds callback_duration{0};
        if (callback_) {
            Nanoseconds const accuracy = schedule_accuracy(deadline.raw_deadline);
            auto const callback_start = read_monotonic_raw();
            event_type const event{
                .scheduled_time = deadline.scheduled,
                .error = wait.error,
                .wake_count = wake_count,
                .skipped_counts = wait.skipped_counts,
                .wake_raw = callback_start,
                .accuracy = accuracy,
            };

            callback_(event, stats_.snapshot());
            callback_duration = read_monotonic_raw() - callback_start;
        }
        stats_.update_with_duration(wait.error.count(), callback_duration.count(), wait.skipped_counts);
    }

    auto run_loop() -> void override
    {
        prime_raw_line();
        // Calculate starting wake count based on current time in the adapter's clock domain.
        // start_offset_cycles (default 2) schedules the first wake far enough in the future
        // that thread setup latency can't leave us past the deadline before we even sleep.
        int64_t next_wake_count = cycle_number(adapter_.now(), period()) + config_.start_offset_cycles;

        // Seed both instants from next_wake_count. After this we advance
        // the RAW deadline directly in advance_schedule — the slope
        // error is cancelled periodically by maybe_resync_deadline.
        Deadline deadline = resync_deadline(next_wake_count);

        while (should_run()) {
            WaitResult const wait = wait_until_raw_deadline(deadline.raw_deadline);
            invoke_callback(deadline, next_wake_count, wait);

            advance_schedule(wait, next_wake_count, deadline);
            deadline = maybe_resync_deadline(next_wake_count, deadline);
        }
    }

  private:
    ClockAdapterT adapter_;
    callback_type callback_;
};

/// Print timer statistics report to stdout
/// @param timer The timer to print statistics for
inline auto print_timer_stats(TimerBase const& timer) -> void
{
    std::string report;
    timer.stats().format_report_to(std::back_inserter(report), timer.compensation_ns());
    std::print("{}", report);
}

}  // namespace statusbar::realtime
