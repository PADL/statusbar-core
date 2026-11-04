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
/// The timer uses absolute deadline scheduling for maximum accuracy. When using a non-monotonic
/// clock adapter (e.g., for gPTP), the timer calculates scheduled times in the adapter's clock
/// domain but sleeps using the monotonic clock (via the adapter's conversion functions).
///
/// @tparam ClockAdapterT The clock adapter type (e.g., MonotonicClockAdapter, ClockAdapter<GptpClock<0>, PtpTimeBridge>)
template <ClockAdapterType ClockAdapterT = MonotonicClockAdapter>
class Timer : public TimerBase
{
  public:
    using adapter_type = ClockAdapterT;
    using clock_type = ClockAdapterT::clock_type;
    using time_point = ClockAdapterT::time_point;
    using duration = ClockAdapterT::duration;
    using event_type = TimerEvent<clock_type>;
    using callback_type = TimerCallback<clock_type>;

    /// Whether the adapter's reference clock is CLOCK_MONOTONIC_RAW. Then
    /// deadlines are RAW instants and each wait sleeps early on
    /// CLOCK_MONOTONIC and spins on RAW (TimerBase::wait_until_raw_deadline);
    /// otherwise they are CLOCK_MONOTONIC instants slept to directly.
    static constexpr bool raw_reference = reference_is_raw_v<ClockAdapterT>;

    /// Construct a realtime timer.
    /// The caller is responsible for validating @p config (see validate_timer_config)
    /// before construction; passing an invalid config produces undefined behavior.
    /// @param config Timer configuration (period, compensation, CPU, busy-wait mode, histograms)
    /// @param callback Function to call on each wake
    /// @param adapter Clock adapter for time reading and conversion (timer takes ownership);
    ///                defaults to a value-initialized adapter — valid only when that default
    ///                represents a usable runtime state (e.g. MonotonicClockAdapter).
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

    /// Get configured period as duration
    [[nodiscard]] auto period() const noexcept -> duration { return duration{config_.period_ns}; }

    /// Get configured compensation as duration
    [[nodiscard]] auto compensation() const noexcept -> duration { return duration{config_.compensation_ns}; }

  protected:
    /// The two deadlines that drive each tick: @p scheduled_time_ns is the
    /// canonical target in the adapter's clock domain (used for event data
    /// and stats); @p reference_deadline_ns is the same instant on the
    /// reference clock we actually wait on: CLOCK_MONOTONIC_RAW when
    /// raw_reference, CLOCK_MONOTONIC otherwise.
    struct Deadline
    {
        int64_t scheduled_time_ns;
        int64_t reference_deadline_ns;
    };

    /// The adapter-domain instant on the reference clock.
    [[nodiscard]] auto to_reference_ns(int64_t scheduled_time_ns) const -> int64_t
    {
        if constexpr (raw_reference) {
            return adapter_.to_raw_ns(scheduled_time_ns);
        } else {
            return adapter_.to_monotonic_ns(scheduled_time_ns);
        }
    }

    /// Wait for a reference-clock deadline the way that clock needs.
    [[nodiscard]] auto wait_until_reference_deadline(int64_t reference_deadline_ns) noexcept -> WaitResult
    {
        if constexpr (raw_reference) {
            return wait_until_raw_deadline(reference_deadline_ns);
        } else {
            return wait_until_deadline(reference_deadline_ns);
        }
    }

    /// Block until the clock adapter reports healthy (for non-monotonic clocks
    /// like gPTP that need to synchronise before producing valid timestamps).
    /// Returns false if shutdown was requested before the adapter became ready.
    [[nodiscard]] auto wait_until_ready() -> bool override
    {
        while (should_run() && !adapter_.is_healthy()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return should_run();
    }

    /// Compute both deadlines from @p next_wake_count as a fresh pair. Used
    /// for the initial deadline setup in run_loop and (via
    /// maybe_resync_mono_deadline) for the periodic drift correction.
    [[nodiscard]] auto resync_mono_deadline(int64_t next_wake_count) const -> Deadline
    {
        int64_t const scheduled_time_ns = cycle_number_to_ns(next_wake_count, config_.period_ns);
        return {.scheduled_time_ns = scheduled_time_ns, .reference_deadline_ns = to_reference_ns(scheduled_time_ns)};
    }

    /// Periodic drift correction: every resync_interval_cycles wakes, return
    /// a freshly-computed Deadline to cancel the slope error accumulated by
    /// incrementing the monotonic deadline directly in advance_schedule. On
    /// non-resync ticks this returns @p current unchanged. At the default
    /// 1000-cycle cadence and ~11 ppm clock skew the resync caps residual
    /// error at ~1.4µs; a resync_interval_cycles of 0 disables it.
    [[nodiscard]] auto maybe_resync_mono_deadline(int64_t next_wake_count, Deadline current) const -> Deadline
    {
        int64_t const interval = config_.resync_interval_cycles;
        if (interval > 0 && (next_wake_count % interval) == 0) {
            return resync_mono_deadline(next_wake_count);
        }
        return current;
    }

    /// Advance the loop-carried wake state by (skipped_counts + 1) periods.
    /// Increments both the adapter-domain scheduled_time and the reference
    /// deadline by the same ns delta — this is the key optimisation that
    /// avoids re-running the adapter's slope conversion every tick (the tiny
    /// accumulated drift is fixed up by the periodic resync in run_loop).
    auto advance_schedule(
        WaitResult const& wait, int64_t& next_wake_count, int64_t& scheduled_time_ns, int64_t& reference_deadline_ns) const noexcept
        -> void
    {
        int64_t const periods_to_advance = wait.skipped_counts + 1;
        int64_t const advance_ns = cycle_number_to_ns(periods_to_advance, config_.period_ns);
        next_wake_count += periods_to_advance;
        scheduled_time_ns += advance_ns;
        reference_deadline_ns += advance_ns;
    }

    /// Construct the per-wake event, invoke the user callback, measure its
    /// wall-clock duration, and feed the error / duration / skipped counts
    /// into the wake stats. A TripwireFiredException thrown by the callback
    /// (via ScopedTripwireObserver) is allowed to propagate — it aborts the
    /// stats update for this tick and is caught in TimerBase::start()'s
    /// thread lambda, which lets the thread exit while the tripwire machinery
    /// drives shutdown from the monitor/main threads.
    auto invoke_callback(int64_t scheduled_time_ns, int64_t wake_count, WaitResult const& wait) -> void
    {
        int64_t duration_ns_raw = 0;
        if (callback_) {
            event_type const event{
                .scheduled_time = time_point{duration{scheduled_time_ns}},
                .error = duration{wait.error_ns},
                .wake_count = wake_count,
                .skipped_counts = wait.skipped_counts,
            };

            int64_t const callback_start_ns = read_monotonic_raw_ns();
            callback_(event, stats_.snapshot());
            int64_t const callback_end_ns = read_monotonic_raw_ns();
            duration_ns_raw = callback_end_ns - callback_start_ns;
        }
        stats_.update_with_duration(wait.error_ns, duration_ns_raw, wait.skipped_counts);
    }

    auto run_loop() -> void override
    {
        if constexpr (raw_reference) {
            prime_raw_line();
        }
        // Calculate starting wake count based on current time in the adapter's clock domain.
        // start_offset_cycles (default 2) schedules the first wake far enough in the future
        // that thread setup latency can't leave us past the deadline before we even sleep.
        int64_t next_wake_count = cycle_number_from_ns(adapter_.now_ns(), config_.period_ns) + config_.start_offset_cycles;

        // Seed both deadlines from next_wake_count. After this we increment
        // the monotonic deadline directly in advance_schedule — the slope
        // error is cancelled periodically by maybe_resync_mono_deadline.
        Deadline deadline = resync_mono_deadline(next_wake_count);

        while (should_run()) {
            WaitResult const wait = wait_until_reference_deadline(deadline.reference_deadline_ns);
            invoke_callback(deadline.scheduled_time_ns, next_wake_count, wait);

            advance_schedule(wait, next_wake_count, deadline.scheduled_time_ns, deadline.reference_deadline_ns);
            deadline = maybe_resync_mono_deadline(next_wake_count, deadline);
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
