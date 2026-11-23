#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Realtime Clock Types Module
///
/// One type per time domain, so a time on one clock cannot be passed where
/// a time on another is expected:
/// - MonotonicRawClock: CLOCK_MONOTONIC_RAW, the reference clock (raw
///   hardware counter, immune to NTP/phc2sys frequency slew). Stamps,
///   deadlines and measurements live here, and every other domain is
///   mapped to and from it.
/// - MonotonicClock: CLOCK_MONOTONIC, the clock the kernel sleeps on; its
///   rate is slewed, so it is for sleeping, not for timing.
/// - GptpClock<N>: gPTP clock domains (rate may differ from the local
///   oscillator, and the time steps when the grandmaster changes).
/// - UtcClock: UTC as the system clock keeps it, whatever disciplines it.
/// - TaiClock: International Atomic Time, a constant offset from UTC.
///
/// Integers enter and leave a domain only through Clock::from_ns() and
/// Clock::to_ns(). A ClockAdapter binds a clock type to a ClockSource and
/// is the one place a source's bare nanoseconds are given their domain.
///
/// This header includes no operating-system header. The clock reads and
/// the sleep it declares are implemented in realtime_clock.cpp, which is
/// the one place the platform is named.

#include <chrono>
#include <concepts>
#include <cstdint>
#include <ratio>

namespace statusbar::realtime {

/// The duration every clock here counts in. It is one type for all
/// domains on purpose: a period added to a gPTP schedule and to a RAW
/// deadline is the same value, even though the two clocks tick at rates a
/// few ppm apart.
using Nanoseconds = std::chrono::duration<int64_t, std::nano>;

//
// Clock Type Tags
//

/// Tag type for the raw monotonic clock (CLOCK_MONOTONIC_RAW), the
/// reference clock: stamps, deadlines and measurements live here.
struct MonotonicRawClockTag
{};

/// Tag type for the monotonic clock (CLOCK_MONOTONIC), the clock the
/// kernel sleeps on.
struct MonotonicClockTag
{};

/// Tag type for gPTP clock domains (parameterized by domain ID)
template <int DomainId>
struct GptpClockTag
{
    static constexpr int domain_id = DomainId;
};

/// Tag type for UTC as the system clock keeps it
struct UtcClockTag
{};

/// Tag type for TAI clock
struct TaiClockTag
{};

//
// Clock Template
//

/// A time domain: std::chrono-compatible aliases whose time_point is
/// distinct for each Tag. There is no now(): most of these clocks need
/// runtime state (a bridge) to be read, and the two that do not are read
/// with read_monotonic_raw() and read_monotonic() so that every clock
/// read in the code has a name that can be searched for.
///
/// @tparam Tag A unique tag type that distinguishes this clock from others
template <typename Tag>
struct Clock
{
    using tag_type = Tag;
    using rep = int64_t;
    using period = std::nano;
    using duration = Nanoseconds;
    using time_point = std::chrono::time_point<Clock<Tag>, duration>;

    /// Give a bare nanosecond count this clock's domain
    /// @param ns Time value in nanoseconds
    [[nodiscard]] static constexpr auto from_ns(int64_t ns) noexcept -> time_point { return time_point{duration{ns}}; }

    /// Take a time_point out of its domain, as a bare nanosecond count
    /// @param tp The time_point to convert
    [[nodiscard]] static constexpr auto to_ns(time_point tp) noexcept -> int64_t { return tp.time_since_epoch().count(); }
};

//
// Concrete Clock Types
//

/// Raw monotonic clock - CLOCK_MONOTONIC_RAW, read with read_monotonic_raw().
/// The raw hardware counter: NTP and phc2sys slew CLOCK_MONOTONIC's rate but
/// never this one, so timing, stamps and deadlines use it. The kernel cannot
/// sleep on it; a deadline here is reached by sleeping early on
/// CLOCK_MONOTONIC through a MonotonicRawLine and spinning the last stretch.
using MonotonicRawClock = Clock<MonotonicRawClockTag>;

/// Monotonic clock - CLOCK_MONOTONIC, read with read_monotonic(). The only
/// clock the kernel sleeps on, and that is all it is used for.
using MonotonicClock = Clock<MonotonicClockTag>;

/// gPTP clock for a specific domain.
/// gPTP clocks are epochless (start at 0 when the grandmaster boots) and
/// may run at a different rate than the local oscillator (up to ±50 ppm).
/// Converting to or from MonotonicRawClock takes a ClockAdapter on a bridge.
///
/// @tparam DomainId The gPTP domain number (typically 0, but complex AVB
///         systems may have multiple domains on different network ports)
template <int DomainId = 0>
using GptpClock = Clock<GptpClockTag<DomainId>>;

/// Default gPTP clock (domain 0)
using GptpClock0 = GptpClock<0>;

/// UTC clock - the system clock (CLOCK_REALTIME on POSIX), counted from
/// 1970-01-01 UTC. The type names the timescale only: the clock may be
/// disciplined by a local GPS receiver, by a distant NTP server, or by
/// nothing at all, and how well it is known is a ClockQuality, not a type.
using UtcClock = Clock<UtcClockTag>;

/// TAI clock - International Atomic Time. A constant offset from UTC: no
/// further leap seconds are to be applied to UTC, so the offset is fixed.
using TaiClock = Clock<TaiClockTag>;

/// TAI - UTC, in force since 2017-01-01 and fixed from here on.
inline constexpr Nanoseconds TAI_MINUS_UTC{37'000'000'000LL};

/// The TAI instant of a UTC one (exact: a constant offset)
[[nodiscard]] constexpr auto to_tai(UtcClock::time_point utc) noexcept -> TaiClock::time_point
{
    return TaiClock::from_ns(UtcClock::to_ns(utc)) + TAI_MINUS_UTC;
}

/// The UTC instant of a TAI one (exact: a constant offset)
[[nodiscard]] constexpr auto to_utc(TaiClock::time_point tai) noexcept -> UtcClock::time_point
{
    return UtcClock::from_ns(TaiClock::to_ns(tai)) - TAI_MINUS_UTC;
}

//
// Concept for Clock Types
//

namespace detail {

template <typename T>
inline constexpr bool is_clock = false;

template <typename Tag>
inline constexpr bool is_clock<Clock<Tag>> = true;

}  // namespace detail

/// Any clock type in this system (an instantiation of Clock)
template <typename T>
concept ClockType = detail::is_clock<T>;

//
// Reading the Two Clocks That Need No Bridge
//
// Declared here, implemented per platform in realtime_clock.cpp.
//

/// CLOCK_MONOTONIC_RAW in nanoseconds: the reference clock, immune to
/// frequency slew. Not sleepable; a deadline on it is reached by sleeping
/// early on CLOCK_MONOTONIC through a MonotonicRawLine and spinning here.
auto read_monotonic_raw_ns() noexcept -> int64_t;

/// CLOCK_MONOTONIC in nanoseconds (it keeps counting through a system
/// sleep, and NTP slews its rate). This is the clock the kernel sleeps on:
/// use it for sleeping, not for timing. Timing, stamps and deadlines take
/// read_monotonic_raw_ns().
auto read_monotonic_ns() noexcept -> int64_t;

/// Sleep until an absolute CLOCK_MONOTONIC deadline, the one kernel sleep
/// primitive every sleeper goes through. Returns 0 when the deadline has
/// passed (a missed or non-positive deadline returns at once rather than
/// failing), EINTR when a signal cut the sleep short, or the errno of a
/// failed sleep. Where the platform has no absolute sleep the wait is
/// relative, over the remaining time as read on entry.
/// @param deadline_ns The CLOCK_MONOTONIC instant to sleep to, in nanoseconds
auto sleep_until_monotonic_ns(int64_t deadline_ns) noexcept -> int;

/// CLOCK_MONOTONIC_RAW now: the reference clock, read once and passed on.
[[nodiscard]] inline auto read_monotonic_raw() noexcept -> MonotonicRawClock::time_point
{
    return MonotonicRawClock::from_ns(read_monotonic_raw_ns());
}

/// CLOCK_MONOTONIC now: for sleeping, not for timing.
[[nodiscard]] inline auto read_monotonic() noexcept -> MonotonicClock::time_point
{
    return MonotonicClock::from_ns(read_monotonic_ns());
}

/// Sleep until an absolute CLOCK_MONOTONIC deadline; see
/// sleep_until_monotonic_ns() for what it returns.
/// @param deadline The CLOCK_MONOTONIC instant to sleep to
inline auto sleep_until_monotonic(MonotonicClock::time_point const deadline) noexcept -> int
{
    return sleep_until_monotonic_ns(MonotonicClock::to_ns(deadline));
}

//
// Drift Over a Span
//

namespace detail {

/// `seconds * ppb + part` in nanoseconds, or the largest count when that
/// would not fit. All three are non-negative and @p ppb is not zero.
[[nodiscard]] constexpr auto saturating_drift_ns(int64_t const seconds, int64_t const ppb, int64_t const part) noexcept -> int64_t
{
    constexpr int64_t LIMIT = Nanoseconds::max().count();
    return seconds > (LIMIT - part) / ppb ? LIMIT : (seconds * ppb) + part;
}

}  // namespace detail

/// How far a clock running @p ppb parts per billion off can move in
/// @p elapsed: `elapsed * ppb / 1e9`, rounded up, in integers only. A
/// result that would not fit saturates to Nanoseconds::max(). A span that
/// is not positive drifts nothing.
/// @param elapsed The span the drift accumulates over
/// @param ppb The rate error, in nanoseconds per second
[[nodiscard]] constexpr auto accumulated_drift(Nanoseconds const elapsed, uint32_t const ppb) noexcept -> Nanoseconds
{
    constexpr int64_t BILLION = 1'000'000'000;
    if (elapsed <= Nanoseconds::zero() || ppb == 0) {
        return Nanoseconds::zero();
    }
    int64_t const seconds = elapsed.count() / BILLION;
    int64_t const remainder_ns = elapsed.count() % BILLION;
    // remainder_ns is below 1e9 and ppb below 2^32: the product is under
    // 4.3e18 and fits, with room for the rounding term.
    int64_t const part = ((remainder_ns * int64_t{ppb}) + (BILLION - 1)) / BILLION;
    return Nanoseconds{detail::saturating_drift_ns(seconds, int64_t{ppb}, part)};
}

//
// Clock Source Concept
//

/// A time domain mapped onto CLOCK_MONOTONIC_RAW, in bare nanoseconds. A
/// source (a PTP bridge, a gPTP slave) does not know which Clock type its
/// domain is; a ClockAdapter says so.
///
/// A ClockSource must provide:
/// - now_ns(): Current time in the source's domain
/// - to_raw_ns(): Convert the source's domain to CLOCK_MONOTONIC_RAW
/// - from_raw_ns(): Convert CLOCK_MONOTONIC_RAW to the source's domain
/// - is_healthy(): Whether the mapping is currently valid
template <typename T>
concept ClockSource = requires(T const& t, int64_t ns) {
    { t.now_ns() } -> std::convertible_to<int64_t>;
    { t.to_raw_ns(ns) } -> std::convertible_to<int64_t>;
    { t.from_raw_ns(ns) } -> std::convertible_to<int64_t>;
    { t.is_healthy() } -> std::convertible_to<bool>;
};

//
// Clock Adapter
//

/// Binds a ClockSource to a Clock type: the source's bare nanoseconds go
/// in and come out as that clock's time_point, and conversions name the
/// clock on both sides. Holds a pointer to the source, which must outlive
/// the adapter and every copy of it.
///
/// @tparam ClockT The clock type (e.g., GptpClock<0>)
/// @tparam Source The clock source type (e.g., PtpTimeBridge)
template <ClockType ClockT, ClockSource Source>
class ClockAdapter
{
  public:
    using clock_type = ClockT;
    using time_point = ClockT::time_point;
    using duration = ClockT::duration;

    /// @param source The clock source this adapter reads and converts through
    explicit ClockAdapter(Source const& source) noexcept
        : source_{&source}
    {}

    /// A temporary source would be gone before the adapter is used.
    explicit ClockAdapter(Source const&&) = delete;

    /// Current time in this clock's domain
    [[nodiscard]] auto now() const noexcept -> time_point { return ClockT::from_ns(source_->now_ns()); }

    /// The CLOCK_MONOTONIC_RAW instant of a time in this clock's domain
    /// @param tp Time point in this clock's domain
    [[nodiscard]] auto to_raw(time_point tp) const noexcept -> MonotonicRawClock::time_point
    {
        return MonotonicRawClock::from_ns(source_->to_raw_ns(ClockT::to_ns(tp)));
    }

    /// The time in this clock's domain of a CLOCK_MONOTONIC_RAW instant
    /// @param raw Time point on CLOCK_MONOTONIC_RAW
    [[nodiscard]] auto from_raw(MonotonicRawClock::time_point raw) const noexcept -> time_point
    {
        return ClockT::from_ns(source_->from_raw_ns(MonotonicRawClock::to_ns(raw)));
    }

    /// Whether the source's mapping is currently valid
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return source_->is_healthy(); }

  private:
    Source const* source_;
};

//
// Raw Monotonic Clock Adapter (the reference clock, no source needed)
//

/// Adapter for MonotonicRawClock: reads CLOCK_MONOTONIC_RAW directly and is
/// always healthy. The adapter a Timer uses unless it is given another: it
/// schedules and measures on the slew-immune clock.
struct MonotonicRawClockAdapter
{
    using clock_type = MonotonicRawClock;
    using time_point = MonotonicRawClock::time_point;
    using duration = MonotonicRawClock::duration;

    /// Current CLOCK_MONOTONIC_RAW time (direct read)
    [[nodiscard]] static auto now() noexcept -> time_point { return read_monotonic_raw(); }

    /// Already on CLOCK_MONOTONIC_RAW (identity)
    [[nodiscard]] static constexpr auto to_raw(time_point tp) noexcept -> time_point { return tp; }

    /// Already on CLOCK_MONOTONIC_RAW (identity)
    [[nodiscard]] static constexpr auto from_raw(time_point raw) noexcept -> time_point { return raw; }

    [[nodiscard]] static constexpr auto is_healthy() noexcept -> bool { return true; }
};

//
// Concept for Clock Adapters
//

/// What a Timer needs of its clock: the domain it schedules in, the time
/// there now, the CLOCK_MONOTONIC_RAW instant to wait for, and whether the
/// mapping can be trusted yet.
template <typename T>
concept ClockAdapterType = ClockType<typename T::clock_type> && requires(T const& t, typename T::clock_type::time_point tp) {
    { t.now() } -> std::same_as<typename T::clock_type::time_point>;
    { t.to_raw(tp) } -> std::same_as<MonotonicRawClock::time_point>;
    { t.is_healthy() } -> std::convertible_to<bool>;
};

}  // namespace statusbar::realtime
