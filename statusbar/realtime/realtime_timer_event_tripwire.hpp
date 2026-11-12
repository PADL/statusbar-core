#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Bridge between TimerEvent and the tripwire / latency-monitor framework.
// These helpers couple TripwireMonitor (from realtime_tripwire.hpp) with
// TimerEvent<ClockT> (from realtime_timer_event.hpp); neither of those
// headers otherwise depends on the other, so the bridge lives here.

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timer_event.hpp"
#include "statusbar/realtime/realtime_tripwire.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <cstdint>

namespace statusbar::realtime {

/// Observe wake latency on a tripwire monitor and handle firing if threshold exceeded.
/// Call this at the START of your callback, BEFORE doing work.
/// Uses the shutdown_token passed to TripwireMonitor::start().
/// @param monitor The TripwireMonitor to observe on
/// @param event The timer event with timing data
/// @return The CLOCK_MONOTONIC_RAW start of the callback, for the duration
///         measurement, or 0 if the tripwire fired. This is the instant the
///         timer told in event.wake_raw, so the wake costs no clock read; an
///         event built by hand (wake_raw zero) is stamped with one RAW read
///         here. It is never a value in the event's own clock: the schedule
///         may run on a gPTP domain, and a duration is a RAW difference.
template <ClockType ClockT>
inline auto observe_wake_and_handle_tripwire(TripwireMonitor& monitor, TimerEvent<ClockT> const& event) -> int64_t
{
    int64_t const actual_time_ns = event.scheduled_time_ns() + event.error_ns();
    monitor.tripwire().observe(event.wake_count, event.scheduled_time_ns(), actual_time_ns);
    if (monitor.check_and_handle_fired(event.wake_count, event.error_ns())) {
        return 0;  // Tripwire fired, caller should abort
    }
    return event.wake_raw_ns() != 0 ? event.wake_raw_ns() : read_monotonic_raw_ns();
}

/// Observe callback duration on a tripwire monitor and handle firing if threshold exceeded.
/// Call this at the END of your callback, AFTER doing work.
/// @param monitor The TripwireMonitor to observe on
/// @param event The timer event with timing data
/// @param start_time_ns The RAW start returned by observe_wake_and_handle_tripwire()
/// @return true if tripwire fired and shutdown was requested
template <ClockType ClockT>
inline auto observe_duration_and_handle_tripwire(TripwireMonitor& monitor, TimerEvent<ClockT> const& event, int64_t start_time_ns)
    -> bool
{
    // One RAW read: the end of the work, in the same domain as the start.
    int64_t const now_ns = read_monotonic_raw_ns();
    int64_t const duration_ns = now_ns - start_time_ns;
    monitor.tripwire().observe_duration(static_cast<uint64_t>(event.wake_count), duration_ns);
    return monitor.check_and_handle_fired(event.wake_count, event.error_ns(), duration_ns);
}

/// Observe a timer event on a tripwire monitor and handle firing if threshold exceeded.
/// This is a convenience function for simple cases where you only care about wake latency.
/// Uses the shutdown_token passed to TripwireMonitor::start().
/// @param monitor The TripwireMonitor to observe on
/// @param event The timer event with timing data
/// @return true if tripwire fired and shutdown was requested
template <ClockType ClockT>
inline auto observe_and_handle_tripwire(TripwireMonitor& monitor, TimerEvent<ClockT> const& event) -> bool
{
    int64_t const actual_time_ns = event.scheduled_time_ns() + event.error_ns();
    monitor.tripwire().observe(event.wake_count, event.scheduled_time_ns(), actual_time_ns);
    return monitor.check_and_handle_fired(event.wake_count, event.error_ns());
}

/// RAII helper for tripwire observation.
/// Constructor checks wake latency and throws TripwireFiredException if threshold exceeded.
/// Destructor checks callback duration.
/// Usage:
///   try {
///       ScopedTripwireObserver observer(monitor, event);
///       // ... do work ...
///   } catch (TripwireFiredException const&) {
///       return;  // Wake latency exceeded, abort
///   }
template <ClockType ClockT = MonotonicClock>
class ScopedTripwireObserver
{
  public:
    ScopedTripwireObserver(TripwireMonitor& monitor, TimerEvent<ClockT> const& event)
        : monitor_{monitor}
        , event_{event}
    {
        start_time_ns_ = observe_wake_and_handle_tripwire(monitor_, event_);
        if (start_time_ns_ == 0) {
#if __cpp_exceptions
            throw TripwireFiredException{};
#else
            // A fired tripwire is a latency-budget violation; without exceptions
            // it cannot be observed via catch, so treat it as fatal.
            throw_or_abort(std::errc::timed_out, "tripwire fired");
#endif
        }
    }

    ~ScopedTripwireObserver() noexcept
    {
        if (start_time_ns_ != 0) {
            (void)observe_duration_and_handle_tripwire(monitor_, event_, start_time_ns_);
        }
    }

    // Non-copyable and non-movable
    ScopedTripwireObserver(ScopedTripwireObserver const&) = delete;
    auto operator=(ScopedTripwireObserver const&) -> ScopedTripwireObserver& = delete;
    ScopedTripwireObserver(ScopedTripwireObserver&&) = delete;
    auto operator=(ScopedTripwireObserver&&) -> ScopedTripwireObserver& = delete;

  private:
    TripwireMonitor& monitor_;
    TimerEvent<ClockT> const& event_;
    int64_t start_time_ns_{0};
};

}  // namespace statusbar::realtime
