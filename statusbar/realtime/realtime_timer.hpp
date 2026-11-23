#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timer_base.hpp"
#include "statusbar/realtime/realtime_timer_config.hpp"
#include "statusbar/realtime/realtime_timer_event.hpp"
#include "statusbar/realtime/realtime_timer_schedule.hpp"
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
/// The arithmetic of that (the grid, the two instants of each deadline, the resync, the
/// accuracy told with each wake) is TimerSchedule, which is told the time and reads no
/// clock; this class is the thread around it.
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
        , schedule_{
              std::move(adapter),
              {.period = period(),
               .start_offset_cycles = config.start_offset_cycles,
               .resync_interval_cycles = config.resync_interval_cycles}}
        , callback_{std::move(callback)}
    {}

    ~Timer() noexcept override { stop(); }

    Timer(Timer const&) = delete;
    auto operator=(Timer const&) -> Timer& = delete;
    Timer(Timer&&) = delete;
    auto operator=(Timer&&) -> Timer& = delete;

    /// The schedule this timer's thread is working through. The thread
    /// writes it; read it from another thread only while the timer is stopped.
    [[nodiscard]] auto schedule() const noexcept -> TimerSchedule<ClockAdapterT> const& { return schedule_; }

  protected:
    /// Block until the adapter's clock is ready (for clocks like gPTP that
    /// need to synchronise before producing valid timestamps). The timer
    /// only waits here, once: after it has started it keeps its schedule
    /// through a loss of sync and reports the accuracy in every event.
    /// Returns false if shutdown was requested before the adapter became ready.
    [[nodiscard]] auto wait_until_ready() -> bool override
    {
        while (should_run() && !schedule_.is_ready()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return should_run();
    }

    /// Build the event for the wake the schedule is at, stamp the RAW
    /// instant of entry, invoke the user callback, measure its duration,
    /// and feed the error / duration / skipped counts into the wake stats.
    /// A TripwireFiredException thrown by the callback (via
    /// ScopedTripwireObserver) is allowed to propagate — it aborts the
    /// stats update for this tick and is caught in TimerBase::start()'s
    /// thread lambda, which lets the thread exit while the tripwire machinery
    /// drives shutdown from the monitor/main threads.
    auto invoke_callback(WaitResult const& wait) -> void
    {
        Nanoseconds callback_duration{0};
        if (callback_) {
            event_type event = schedule_.event(wait);
            event.wake_raw = read_monotonic_raw();
            callback_(event, stats_.snapshot());
            callback_duration = read_monotonic_raw() - event.wake_raw;
        }
        stats_.update_with_duration(wait.error.count(), callback_duration.count(), wait.skipped_counts);
    }

    auto run_loop() -> void override
    {
        prime_raw_line();
        schedule_.begin(schedule_.adapter().now());
        while (should_run()) {
            WaitResult const wait = wait_until_raw_deadline(schedule_.deadline().raw_deadline);
            invoke_callback(wait);
            schedule_.advance(wait);
        }
    }

  private:
    TimerSchedule<ClockAdapterT> schedule_;
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
