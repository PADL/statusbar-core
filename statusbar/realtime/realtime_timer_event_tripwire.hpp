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
#include <optional>

namespace statusbar::realtime {

/// Observe wake latency on a tripwire monitor and handle firing if threshold exceeded.
/// Call this at the START of your callback, BEFORE doing work.
/// Uses the shutdown_token passed to TripwireMonitor::start().
/// @param monitor The TripwireMonitor to observe on
/// @param event The timer event with timing data
/// @return The CLOCK_MONOTONIC_RAW start of the callback, for the duration
///         measurement, or nothing if the tripwire fired. This is the
///         instant the timer told in event.wake_raw, so the wake costs no
///         clock read; an event built by hand (no wake_raw) is stamped with
///         one RAW read here. It is never a value in the event's own clock:
///         the schedule may run on a gPTP domain, and a duration is a RAW
///         difference.
template <ClockType ClockT>
inline auto observe_wake_and_handle_tripwire(TripwireMonitor& monitor, TimerEvent<ClockT> const& event)
    -> std::optional<MonotonicRawClock::time_point>
{
    // The tripwire record keeps bare counts on the schedule's clock: it
    // serves timers of any domain and only ever compares the two.
    int64_t const scheduled_ns = ClockT::to_ns(event.scheduled_time);
    monitor.tripwire().observe(event.wake_count, scheduled_ns, scheduled_ns + event.error.count());
    if (monitor.check_and_handle_fired(event.wake_count, event.error.count())) {
        return std::nullopt;  // Tripwire fired, caller should abort
    }
    return event.wake_raw ? *event.wake_raw : read_monotonic_raw();
}

/// Observe callback duration on a tripwire monitor and handle firing if threshold exceeded.
/// Call this at the END of your callback, AFTER doing work.
/// @param monitor The TripwireMonitor to observe on
/// @param event The timer event with timing data
/// @param start The RAW start returned by observe_wake_and_handle_tripwire()
/// @return true if tripwire fired and shutdown was requested
template <ClockType ClockT>
inline auto observe_duration_and_handle_tripwire(
    TripwireMonitor& monitor, TimerEvent<ClockT> const& event, MonotonicRawClock::time_point start) -> bool
{
    // One RAW read: the end of the work, in the same domain as the start.
    int64_t const duration_ns = (read_monotonic_raw() - start).count();
    monitor.tripwire().observe_duration(static_cast<uint64_t>(event.wake_count), duration_ns);
    return monitor.check_and_handle_fired(event.wake_count, event.error.count(), duration_ns);
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
    int64_t const scheduled_ns = ClockT::to_ns(event.scheduled_time);
    monitor.tripwire().observe(event.wake_count, scheduled_ns, scheduled_ns + event.error.count());
    return monitor.check_and_handle_fired(event.wake_count, event.error.count());
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
template <ClockType ClockT = MonotonicRawClock>
class ScopedTripwireObserver
{
  public:
    ScopedTripwireObserver(TripwireMonitor& monitor, TimerEvent<ClockT> const& event)
        : monitor_{monitor}
        , event_{event}
        , start_{observe_wake_and_handle_tripwire(monitor_, event_)}
    {
        if (!start_) {
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
        if (start_) {
            (void)observe_duration_and_handle_tripwire(monitor_, event_, *start_);
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
    std::optional<MonotonicRawClock::time_point> start_;
};

}  // namespace statusbar::realtime
