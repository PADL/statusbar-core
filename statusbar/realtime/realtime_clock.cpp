// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The platform side of realtime_clock.hpp: how the two local clocks are
/// read and how a thread sleeps to a deadline. Everything that names an
/// operating system lives in this file, so the header stays portable and a
/// new platform is ported here and nowhere else.

#include "statusbar/realtime/realtime_clock.hpp"

#include <cstdint>
#include <ctime>

#include <sys/timex.h>

#if defined(__APPLE__)
#    include <mach/mach_time.h>
#endif

namespace statusbar::realtime {

namespace {

constexpr int64_t NS_PER_SECOND = 1'000'000'000;

[[nodiscard]] auto read_clock_ns(clockid_t const clock) noexcept -> int64_t
{
    timespec ts{};
    ::clock_gettime(clock, &ts);
    return (static_cast<int64_t>(ts.tv_sec) * NS_PER_SECOND) + ts.tv_nsec;
}

#if defined(__APPLE__)
/// Nanoseconds to mach_absolute_time ticks, for the relative wait in
/// sleep_until_monotonic_ns(). Mach's own counter stops while the machine
/// sleeps (it is CLOCK_UPTIME_RAW), so it never carries an absolute deadline.
[[nodiscard]] auto ns_to_mach(uint64_t const ns) noexcept -> uint64_t
{
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return ns * tb.denom / tb.numer;
}
#endif

}  // namespace

auto read_monotonic_ns() noexcept -> int64_t
{
    return read_clock_ns(CLOCK_MONOTONIC);
}

auto read_monotonic_raw_ns() noexcept -> int64_t
{
#if defined(CLOCK_MONOTONIC_RAW)
    return read_clock_ns(CLOCK_MONOTONIC_RAW);
#else
    return read_clock_ns(CLOCK_MONOTONIC);
#endif
}

auto sleep_until_monotonic_ns(int64_t const deadline_ns) noexcept -> int
{
    int64_t const remaining_ns = deadline_ns - read_monotonic_ns();
    if (remaining_ns <= 0) {
        return 0;
    }
#if defined(__linux__)
    timespec const deadline{
        .tv_sec = static_cast<time_t>(deadline_ns / NS_PER_SECOND), .tv_nsec = static_cast<long>(deadline_ns % NS_PER_SECOND)};
    return ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, nullptr);
#elif defined(__APPLE__)
    (void)::mach_wait_until(::mach_absolute_time() + ns_to_mach(static_cast<uint64_t>(remaining_ns)));
    return 0;
#else
#    error "Unsupported platform: port the clock reads and the sleep in this file"
#endif
}

auto read_utc_ns() noexcept -> int64_t
{
    return read_clock_ns(CLOCK_REALTIME);
}

auto read_system_clock_error() noexcept -> SystemClockError
{
    constexpr int64_t NS_PER_MICROSECOND = 1'000;
#if defined(__linux__)
    // modes == 0 reads the kernel's NTP state and changes nothing; it needs
    // no privilege.
    struct timex state{};
    int const result = ::adjtimex(&state);
    bool const synchronized = result != -1 && result != TIME_ERROR && (state.status & STA_UNSYNC) == 0;
    return {
        .synchronized = synchronized,
        .max_error = Nanoseconds{static_cast<int64_t>(state.maxerror) * NS_PER_MICROSECOND},
        .estimated_error = Nanoseconds{static_cast<int64_t>(state.esterror) * NS_PER_MICROSECOND}};
#elif defined(__APPLE__)
    struct ntptimeval state{};
    int const result = ::ntp_gettime(&state);
    return {
        .synchronized = result != -1 && result != TIME_ERROR,
        .max_error = Nanoseconds{static_cast<int64_t>(state.maxerror) * NS_PER_MICROSECOND},
        .estimated_error = Nanoseconds{static_cast<int64_t>(state.esterror) * NS_PER_MICROSECOND}};
#else
#    error "Unsupported platform: port the system clock's synchronization state in this file"
#endif
}

}  // namespace statusbar::realtime
