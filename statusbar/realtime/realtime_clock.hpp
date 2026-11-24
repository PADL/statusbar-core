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
/// How well a domain is known is a ClockQuality: a worst-case accuracy
/// that grows from the last synchronization, so that a follower which has
/// lost its master can keep its rate and offset and coast, and whoever
/// uses the time decides whether it is still good enough. A time carried
/// with that accuracy is a BoundedTime. All of it is integer arithmetic.
///
/// This header includes no operating-system header (the standard library
/// and the header-only overflow checks are all it needs). The clock reads and
/// the sleep it declares are implemented in realtime_clock.cpp, which is
/// the one place the platform is named.

#include "statusbar/safe_arith/safe_arith.hpp"

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

/// TAI clock - International Atomic Time. This code takes its offset from
/// UTC as a constant (TAI_MINUS_UTC).
using TaiClock = Clock<TaiClockTag>;

/// TAI - UTC, in force since 2017-01-01, and taken as fixed. No further
/// leap second is expected: the General Conference on Weights and Measures
/// resolved in 2022 to stop inserting them, from 2035 at the latest. Should
/// one still be applied before then, this constant changes and everything
/// is built again.
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

/// CLOCK_MONOTONIC in nanoseconds (NTP slews its rate; through a system
/// sleep it keeps counting on macOS and stops on Linux, as RAW does on each). This is the clock the kernel sleeps on:
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
/// would not fit. The overflow is detected on the product itself, so there
/// is no division here.
[[nodiscard]] constexpr auto saturating_drift_ns(uint64_t const seconds, uint64_t const ppb, uint64_t const part) noexcept
    -> int64_t
{
    constexpr auto LIMIT = static_cast<uint64_t>(Nanoseconds::max().count());
    if (!can_multiply(seconds, ppb)) {
        return static_cast<int64_t>(LIMIT);
    }
    uint64_t const whole = seconds * ppb;
    return static_cast<int64_t>(whole > LIMIT - part ? LIMIT : whole + part);
}

}  // namespace detail

/// How far a clock running @p ppb parts per billion off can move in
/// @p elapsed: `elapsed * ppb / 1e9`, rounded up, in integers only: two
/// divisions by a constant and two multiplies. A result that would not fit
/// saturates to Nanoseconds::max(). A span that is not positive drifts
/// nothing.
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
    return Nanoseconds{detail::saturating_drift_ns(static_cast<uint64_t>(seconds), uint64_t{ppb}, static_cast<uint64_t>(part))};
}

//
// Clock Quality
//

/// Where a clock's time ultimately comes from: the IEEE 1588 timeSource
/// enumeration, so a gPTP source can fill it from the Announce it received.
enum class TimeSource : uint8_t
{
    atomic_clock = 0x10,
    gnss = 0x20,  ///< GPS or another satellite system
    terrestrial_radio = 0x30,
    serial_time_code = 0x39,
    ptp = 0x40,
    ntp = 0x50,
    hand_set = 0x60,
    other = 0x90,
    internal_oscillator = 0xA0,  ///< free running
};

/// An accuracy that claims nothing: never synchronized, or not reported.
inline constexpr Nanoseconds UNBOUNDED_ACCURACY = Nanoseconds::max();

/// The drift a source assumes while it coasts when its deployment has told
/// it nothing better: 15 ppm, the frequency tolerance NTP assumes of any
/// clock when it grows its own dispersion. A deployment that knows its
/// oscillator and its temperature range configures its own figure.
inline constexpr uint32_t DEFAULT_HOLDOVER_DRIFT_PPB = 15'000;

namespace detail {

/// The sum of two accuracies, or UNBOUNDED_ACCURACY when either is
/// unbounded, either is negative (not an accuracy at all), or the sum
/// would not fit.
[[nodiscard]] constexpr auto add_accuracy(Nanoseconds const a, Nanoseconds const b) noexcept -> Nanoseconds
{
    if (a < Nanoseconds::zero() || b < Nanoseconds::zero()) {
        return UNBOUNDED_ACCURACY;
    }
    return a > UNBOUNDED_ACCURACY - b ? UNBOUNDED_ACCURACY : a + b;
}

}  // namespace detail

/// How well a clock domain is known, as a worst-case bound that grows from
/// the last synchronization.
///
/// A source that is following its master refreshes this on every sync. A
/// source that has lost its master changes nothing: it keeps converting
/// with the rate and offset it had, and uncertainty() grows with the time
/// since synced_at. Nothing here says "unhealthy"; the user of the time
/// compares uncertainty() with what its own application can tolerate.
///
/// A default ClockQuality has never been synchronized and bounds nothing.
/// Trivially copyable, integers only, usable in a constant expression.
struct ClockQuality
{
    /// The CLOCK_MONOTONIC_RAW instant of the last synchronization event.
    MonotonicRawClock::time_point synced_at{};

    /// The worst-case error at that instant. Negative, or
    /// UNBOUNDED_ACCURACY, means no bound is claimed.
    Nanoseconds bound_at_sync{UNBOUNDED_ACCURACY};

    /// Changes when the timeline itself changes (a new grandmaster, a
    /// step): time before and after is not the same clock, however small
    /// the uncertainty.
    uint64_t epoch{0};

    /// The worst-case rate at which the error grows after synced_at, in
    /// parts per billion (nanoseconds per second): how far the held rate
    /// may wander, not how far the oscillator is from nominal.
    uint32_t drift_bound_ppb{0};

    /// Where the time comes from. Only a user that makes a claim about the
    /// source needs it; most compare the accuracy and nothing else.
    TimeSource time_source{TimeSource::internal_oscillator};

    /// A clock that is exact by definition: the reference read as itself.
    [[nodiscard]] static constexpr auto exact() noexcept -> ClockQuality
    {
        return {
            .synced_at = {},
            .bound_at_sync = Nanoseconds::zero(),
            .epoch = 0,
            .drift_bound_ppb = 0,
            .time_source = TimeSource::internal_oscillator};
    }

    /// Whether any bound is claimed at all (the clock has synchronized).
    [[nodiscard]] constexpr auto is_bounded() const noexcept -> bool
    {
        return bound_at_sync >= Nanoseconds::zero() && bound_at_sync != UNBOUNDED_ACCURACY;
    }

    /// The time since the last synchronization event, never negative:
    /// an instant before synced_at has age zero.
    /// @param now The CLOCK_MONOTONIC_RAW instant to measure to
    [[nodiscard]] constexpr auto age(MonotonicRawClock::time_point const now) const noexcept -> Nanoseconds
    {
        return now > synced_at ? now - synced_at : Nanoseconds::zero();
    }

    /// The worst-case error at @p now: the bound at the last sync plus the
    /// drift accumulated since, rounded up. UNBOUNDED_ACCURACY when no
    /// bound is claimed or the sum does not fit. Told the time, so it reads
    /// no clock, and it is integer arithmetic only.
    /// @param now The CLOCK_MONOTONIC_RAW instant the error is wanted at
    [[nodiscard]] constexpr auto uncertainty(MonotonicRawClock::time_point const now) const noexcept -> Nanoseconds
    {
        if (!is_bounded()) {
            return UNBOUNDED_ACCURACY;
        }
        return detail::add_accuracy(bound_at_sync, accumulated_drift(age(now), drift_bound_ppb));
    }

    /// Whether the worst-case error at @p now is within @p limit.
    /// @param limit The largest error the caller can tolerate
    /// @param now The CLOCK_MONOTONIC_RAW instant the error is wanted at
    [[nodiscard]] constexpr auto within(Nanoseconds const limit, MonotonicRawClock::time_point const now) const noexcept -> bool
    {
        // An uncertainty that has grown to the ceiling is no bound, whatever the limit.
        Nanoseconds const grown = uncertainty(now);
        return is_bounded() && grown != UNBOUNDED_ACCURACY && grown <= limit;
    }

    /// This quality with @p extra added to its bound: what a further step
    /// with an error of its own (a read bracket, a fit residual) leaves.
    /// An @p extra that is negative adds nothing.
    /// @param extra The worst-case error of the further step
    [[nodiscard]] constexpr auto widened_by(Nanoseconds const extra) const noexcept -> ClockQuality
    {
        ClockQuality wider = *this;
        if (is_bounded() && extra > Nanoseconds::zero()) {
            wider.bound_at_sync = detail::add_accuracy(bound_at_sync, extra);
        }
        return wider;
    }

    auto operator==(ClockQuality const&) const noexcept -> bool = default;
};

/// A time together with its worst-case accuracy: the true time is within
/// `time` plus or minus `accuracy`. What the bounded forms of the clock
/// functions return, and what they take to carry a bound through a
/// conversion.
///
/// @tparam ClockT The clock the time is on
template <ClockType ClockT>
struct BoundedTime
{
    using clock_type = ClockT;

    typename ClockT::time_point time{};
    Nanoseconds accuracy{UNBOUNDED_ACCURACY};

    /// Whether any accuracy is claimed at all
    [[nodiscard]] constexpr auto is_bounded() const noexcept -> bool
    {
        return accuracy >= Nanoseconds::zero() && accuracy != UNBOUNDED_ACCURACY;
    }

    /// Whether the worst-case error is within @p limit.
    /// @param limit The largest error the caller can tolerate
    [[nodiscard]] constexpr auto within(Nanoseconds const limit) const noexcept -> bool
    {
        return is_bounded() && accuracy <= limit;
    }

    auto operator==(BoundedTime const&) const noexcept -> bool = default;
};

//
// The System Clock (UTC)
//
// Declared here, implemented per platform in realtime_clock.cpp.
//

/// The system clock (CLOCK_REALTIME on POSIX) in nanoseconds since
/// 1970-01-01 UTC. It is stepped and slewed by whatever disciplines it, so
/// it is never a timing reference: it is how absolute time is learned.
auto read_utc_ns() noexcept -> int64_t;

/// The system clock now, as a UtcClock time.
[[nodiscard]] inline auto read_utc() noexcept -> UtcClock::time_point
{
    return UtcClock::from_ns(read_utc_ns());
}

/// What the operating system says about how well its clock is
/// synchronized: the figures its time daemon (NTP, chrony) maintains.
struct SystemClockError
{
    /// False while the system reports its clock unsynchronized, and where
    /// the platform cannot say.
    bool synchronized{false};

    /// The system's own worst-case error, which the daemon sets from its
    /// source at each update and the system grows between updates.
    Nanoseconds max_error{UNBOUNDED_ACCURACY};

    /// The system's estimate of the typical error.
    Nanoseconds estimated_error{UNBOUNDED_ACCURACY};

    auto operator==(SystemClockError const&) const noexcept -> bool = default;
};

/// Ask the operating system for its clock's synchronization state. One
/// system call: for a tick owner to make at its sampling rate, not on a
/// fast path.
[[nodiscard]] auto read_system_clock_error() noexcept -> SystemClockError;

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

/// A ClockSource that also reports how well its domain is known. A source
/// without quality() is still a source: it claims no accuracy, and what is
/// built on it behaves as it did before accuracy existed.
template <typename T>
concept QualifiedClockSource = ClockSource<T> && requires(T const& t) {
    { t.quality() } -> std::convertible_to<ClockQuality>;
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

    // With the worst-case accuracy (see ClockQuality)

    /// How well the source's domain is known. Only when the source reports it.
    [[nodiscard]] auto quality() const -> ClockQuality
        requires QualifiedClockSource<Source>
    {
        return source_->quality();
    }

    /// The worst-case error of this adapter's mapping at a
    /// CLOCK_MONOTONIC_RAW instant: UNBOUNDED_ACCURACY when the source
    /// reports no quality. The instant is told, so no clock is read.
    /// @param raw The instant the mapping is used at
    [[nodiscard]] auto accuracy_at(MonotonicRawClock::time_point raw) const -> Nanoseconds
    {
        if constexpr (QualifiedClockSource<Source>) {
            return source_->quality().uncertainty(raw);
        } else {
            return UNBOUNDED_ACCURACY;
        }
    }

    /// Current time in this clock's domain, with its worst-case accuracy
    [[nodiscard]] auto now_bounded() const -> BoundedTime<ClockT>
    {
        time_point const time = now();
        return {.time = time, .accuracy = accuracy_at(to_raw(time))};
    }

    /// The CLOCK_MONOTONIC_RAW instant of a bounded time in this clock's
    /// domain. The result's accuracy is the input's plus this mapping's
    /// at the converted instant.
    /// @param bounded Time point in this clock's domain, with its accuracy
    [[nodiscard]] auto to_raw(BoundedTime<ClockT> bounded) const -> BoundedTime<MonotonicRawClock>
    {
        auto const raw = to_raw(bounded.time);
        return {.time = raw, .accuracy = detail::add_accuracy(bounded.accuracy, accuracy_at(raw))};
    }

    /// The time in this clock's domain of a bounded CLOCK_MONOTONIC_RAW
    /// instant. The result's accuracy is the input's plus this mapping's
    /// at that instant.
    /// @param bounded Time point on CLOCK_MONOTONIC_RAW, with its accuracy
    [[nodiscard]] auto from_raw(BoundedTime<MonotonicRawClock> bounded) const -> BoundedTime<ClockT>
    {
        return {.time = from_raw(bounded.time), .accuracy = detail::add_accuracy(bounded.accuracy, accuracy_at(bounded.time))};
    }

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

    /// The reference clock read as itself is exact.
    [[nodiscard]] static constexpr auto quality() noexcept -> ClockQuality { return ClockQuality::exact(); }

    /// The identity adds no error.
    [[nodiscard]] static constexpr auto accuracy_at(time_point) noexcept -> Nanoseconds { return Nanoseconds::zero(); }

    /// Current CLOCK_MONOTONIC_RAW time, exact
    [[nodiscard]] static auto now_bounded() noexcept -> BoundedTime<MonotonicRawClock>
    {
        return {.time = read_monotonic_raw(), .accuracy = Nanoseconds::zero()};
    }

    /// Already on CLOCK_MONOTONIC_RAW (identity, the accuracy is unchanged)
    [[nodiscard]] static constexpr auto to_raw(BoundedTime<MonotonicRawClock> bounded) noexcept -> BoundedTime<MonotonicRawClock>
    {
        return bounded;
    }

    /// Already on CLOCK_MONOTONIC_RAW (identity, the accuracy is unchanged)
    [[nodiscard]] static constexpr auto from_raw(BoundedTime<MonotonicRawClock> bounded) noexcept -> BoundedTime<MonotonicRawClock>
    {
        return bounded;
    }
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

/// An adapter that also reports how well its clock is known. A Timer on one
/// tells every wake the accuracy of its schedule; on any other adapter the
/// wake claims none.
template <typename T>
concept QualifiedClockAdapter = ClockAdapterType<T> && requires(T const& t) {
    { t.quality() } -> std::convertible_to<ClockQuality>;
};

}  // namespace statusbar::realtime
