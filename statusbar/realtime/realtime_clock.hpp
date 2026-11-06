#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Realtime Clock Types Module
/// Provides type-safe clock definitions for different time domains:
/// - MonotonicRawClock: CLOCK_MONOTONIC_RAW, the timing reference clock
///   (raw hardware counter, immune to NTP/phc2sys frequency slew)
/// - MonotonicClock: Native system monotonic clock (CLOCK_MONOTONIC), the
///   clock the kernel sleeps on; its rate is slewed, so it is for sleeping,
///   not for timing
/// - GptpClock<N>: gPTP clock domains (epochless, rate may differ from monotonic)
/// - GpsClock: GPS time domain
/// - TaiClock: TAI time domain
///
/// Each clock type produces distinct time_point types that cannot be accidentally
/// mixed at compile time. Conversion between clock domains requires explicit
/// use of a ClockAdapter with the appropriate time mapping.

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/status/throw_or_abort.hpp"
#include "statusbar/tsn/tsn.hpp"

#include <chrono>
#include <concepts>
#include <cstdint>
#include <optional>
#include <ratio>
#include <stdexcept>
#include <type_traits>

namespace statusbar::realtime {

//
// Clock Type Tags
//

/// Tag type for monotonic clock (the reference clock for all conversions)
struct MonotonicClockTag
{};

/// Tag type for the raw monotonic clock (CLOCK_MONOTONIC_RAW), the timing
/// reference: stamps, deadlines and measurements live here.
struct MonotonicRawClockTag
{};

/// Tag type for gPTP clock domains (parameterized by domain ID)
template <int DomainId>
struct GptpClockTag
{
    static constexpr int domain_id = DomainId;
};

/// Tag type for GPS clock
struct GpsClockTag
{};

/// Tag type for TAI clock
struct TaiClockTag
{};

//
// Base Clock Template
//

/// Base clock type that provides std::chrono-compatible type aliases.
/// This is not a TrivialClock (no static now()) because these clocks
/// require runtime state (mapping parameters) to read time.
///
/// @tparam Tag A unique tag type that distinguishes this clock from others
template <typename Tag>
struct Clock
{
    using tag_type = Tag;
    using rep = int64_t;
    using period = std::ratio<1, 1'000'000'000>;  // nanoseconds
    using duration = std::chrono::duration<rep, period>;
    using time_point = std::chrono::time_point<Clock<Tag>, duration>;

    /// This clock is not steady - the rate relative to real time may change
    /// (e.g., due to oscillator drift or temperature changes)
    static constexpr bool is_steady = false;

    /// Create a time_point from a raw nanosecond value
    /// @param ns Time value in nanoseconds
    [[nodiscard]] static constexpr auto from_ns(int64_t ns) noexcept -> time_point { return time_point{duration{ns}}; }

    /// Extract raw nanosecond value from a time_point
    /// @param tp The time_point to convert
    [[nodiscard]] static constexpr auto to_ns(time_point tp) noexcept { return tp.time_since_epoch().count(); }
};

//
// Concrete Clock Types
//

/// Monotonic clock - the native reference clock for the timer system.
/// Maps directly to CLOCK_MONOTONIC on Linux and on macOS (clock_gettime).
/// This is the only clock that can be read without a time bridge.
using MonotonicClock = Clock<MonotonicClockTag>;

/// Raw monotonic clock - CLOCK_MONOTONIC_RAW, read with read_monotonic_raw_ns().
/// The raw hardware counter: NTP and phc2sys slew CLOCK_MONOTONIC's rate but
/// never this one, so timing, stamps and deadlines use it. The kernel cannot
/// sleep on it; a deadline here is reached by sleeping early on
/// CLOCK_MONOTONIC through a MonotonicRawLine and spinning the last stretch.
using MonotonicRawClock = Clock<MonotonicRawClockTag>;

/// gPTP clock for a specific domain.
/// gPTP clocks are epochless (start at 0 when the grandmaster boots) and
/// may run at a different rate than the local oscillator (up to ±50 ppm).
/// Converting to/from MonotonicClock requires a PtpTimeBridge or similar.
///
/// @tparam DomainId The gPTP domain number (typically 0, but complex AVB
///         systems may have multiple domains on different network ports)
template <int DomainId = 0>
using GptpClock = Clock<GptpClockTag<DomainId>>;

/// GPS clock - time from GPS receivers.
/// GPS time has a fixed epoch (January 6, 1980) and does not include leap seconds.
/// Converting to/from MonotonicClock requires a GPS time bridge.
using GpsClock = Clock<GpsClockTag>;

/// TAI clock - International Atomic Time.
/// TAI has a fixed epoch and a known offset from UTC (currently 37 seconds).
/// Converting to/from MonotonicClock requires a TAI time bridge.
using TaiClock = Clock<TaiClockTag>;

//
// Common Type Aliases for Convenience
//

/// Default gPTP clock (domain 0)
using GptpClock0 = GptpClock<0>;

/// gPTP clock domain 1 (for multi-port AVB systems)
using GptpClock1 = GptpClock<1>;

//
// Clock Traits
//

/// Check if a type is a Clock instantiation
template <typename T>
struct is_clock : std::false_type
{};

template <typename Tag>
struct is_clock<Clock<Tag>> : std::true_type
{};

template <typename T>
inline constexpr bool is_clock_v = is_clock<T>::value;

/// Check if a type is a gPTP clock
template <typename T>
struct is_gptp_clock : std::false_type
{};

template <int DomainId>
struct is_gptp_clock<Clock<GptpClockTag<DomainId>>> : std::true_type
{};

template <typename T>
inline constexpr bool is_gptp_clock_v = is_gptp_clock<T>::value;

/// Check if a type is the monotonic clock
template <typename T>
struct is_monotonic_clock : std::false_type
{};

template <>
struct is_monotonic_clock<MonotonicClock> : std::true_type
{};

template <typename T>
inline constexpr bool is_monotonic_clock_v = is_monotonic_clock<T>::value;

/// Check if a type is the raw monotonic clock
template <typename T>
struct is_monotonic_raw_clock : std::false_type
{};

template <>
struct is_monotonic_raw_clock<MonotonicRawClock> : std::true_type
{};

template <typename T>
inline constexpr bool is_monotonic_raw_clock_v = is_monotonic_raw_clock<T>::value;

/// Whether a clock source or adapter says its reference clock is
/// CLOCK_MONOTONIC_RAW (a `static constexpr bool reference_is_raw`). A type
/// that says nothing maps to CLOCK_MONOTONIC, as the originals did.
template <typename T>
struct reference_is_raw : std::false_type
{};

template <typename T>
    requires requires {
        { T::reference_is_raw } -> std::convertible_to<bool>;
    }
struct reference_is_raw<T> : std::bool_constant<T::reference_is_raw>
{};

template <typename T>
inline constexpr bool reference_is_raw_v = reference_is_raw<T>::value;

/// Get the domain ID from a gPTP clock type (compile-time)
template <typename T>
struct gptp_domain_id;

template <int DomainId>
struct gptp_domain_id<Clock<GptpClockTag<DomainId>>>
{
    static constexpr int value = DomainId;
};

template <typename T>
    requires is_gptp_clock_v<T>
inline constexpr int gptp_domain_id_v = gptp_domain_id<T>::value;

//
// Concepts for Clock Types
//

/// Concept for any clock type in this system
template <typename T>
concept ClockType = is_clock_v<T>;

/// Concept for gPTP clock types
template <typename T>
concept GptpClockType = is_gptp_clock_v<T>;

/// Concept for the monotonic clock
template <typename T>
concept MonotonicClockType = is_monotonic_clock_v<T>;

/// Concept for the raw monotonic clock
template <typename T>
concept MonotonicRawClockType = is_monotonic_raw_clock_v<T>;

//
// Time Point Conversion Result
//

/// Result of a time conversion operation.
/// Includes the converted time and metadata about the conversion's validity.
///
/// @tparam Clock The target clock type for the converted time_point
template <ClockType Clock>
struct TimeConversion
{
    using time_point = Clock::time_point;

    time_point time{};    ///< The converted time
    uint64_t epoch{0};    ///< Epoch counter at time of conversion
    bool healthy{false};  ///< Whether the time bridge was healthy

    /// Check if conversion is valid (bridge was healthy)
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return healthy; }

    /// Get the time value, throwing if unhealthy
    [[nodiscard]] constexpr auto value() const -> time_point
    {
        if (!healthy) {
            throw_or_abort(std::errc::state_not_recoverable, "TimeConversion: bridge not healthy");
        }
        return time;
    }

    /// Get the time value or a default if unhealthy
    /// @param default_value Value to return if the conversion is unhealthy
    [[nodiscard]] constexpr auto value_or(time_point default_value) const noexcept -> time_point
    {
        return healthy ? time : default_value;
    }
};

//
// Clock Source Concept
//

/// Concept for a clock source that provides time mapping between a foreign
/// clock domain and the monotonic clock.
///
/// A ClockSource must provide:
/// - now_ns(): Current time in the foreign clock domain (nanoseconds)
/// - to_monotonic_ns(): Convert foreign clock ns to monotonic ns
/// - from_monotonic_ns(): Convert monotonic ns to foreign clock ns
/// - is_healthy(): Whether the time mapping is currently valid
/// - epoch(): Counter that increments on time discontinuities
template <typename T>
concept ClockSource = requires(T const& t, int64_t ns) {
    { t.now_ns() } -> std::convertible_to<int64_t>;
    { t.to_monotonic_ns(ns) } -> std::convertible_to<int64_t>;
    { t.from_monotonic_ns(ns) } -> std::convertible_to<int64_t>;
    { t.is_healthy() } -> std::convertible_to<bool>;
    { t.epoch() } -> std::convertible_to<uint64_t>;
};

/// A ClockSource whose reference clock is CLOCK_MONOTONIC_RAW: it declares
/// `reference_is_raw` and maps its domain to and from RAW nanoseconds. A
/// Timer driven by such a source sleeps early on CLOCK_MONOTONIC and spins
/// on RAW to the exact deadline (see MonotonicRawLine) instead of trusting
/// the slewed clock.
template <typename T>
concept RawReferenceClockSource = ClockSource<T> && reference_is_raw_v<T> && requires(T const& t, int64_t ns) {
    { t.to_raw_ns(ns) } -> std::convertible_to<int64_t>;
    { t.from_raw_ns(ns) } -> std::convertible_to<int64_t>;
};

//
// gPTP Domain Information
//

/// Runtime information about a gPTP clock domain.
/// This includes the current grandmaster identity and clock quality parameters.
/// The grandmaster can change during operation due to BMCA (Best Master Clock Algorithm).
struct GptpDomainInfo
{
    /// Current grandmaster clock identity (EUI-64)
    tsn::ClockIdentity grandmaster_id{};

    /// GM priority1 (lower = better, per IEEE 802.1AS)
    uint8_t priority1{255};

    /// GM priority2 (lower = better, tie-breaker)
    uint8_t priority2{255};

    /// GM clock class (per IEEE 802.1AS Table 6-4)
    /// 6 = GPS/atomic primary reference, 7 = GPS/atomic primary reference holdover
    /// 248 = default, 255 = slave-only
    uint8_t clock_class{255};

    /// GM clock accuracy (per IEEE 802.1AS Table 6-5)
    /// 0x20 = 25ns, 0x21 = 100ns, 0x22 = 250ns, etc.
    /// 0xFE = unknown, 0xFF = reserved
    uint8_t clock_accuracy{0xFE};

    /// GM offset scaled log variance (per IEEE 802.1AS)
    /// Represents the stability of the clock oscillator
    uint16_t offset_scaled_log_variance{0xFFFF};

    /// Number of communication paths (hops) from the grandmaster
    /// 0 = we are the grandmaster
    uint16_t steps_removed{0};

    /// True if this device is the current grandmaster
    bool is_grandmaster{false};

    /// Monotonic timestamp of the last successful sync from grandmaster
    /// Used to detect stale time mappings
    int64_t last_sync_mono_ns{0};

    /// Check if we have a valid grandmaster (non-zero ID)
    [[nodiscard]] constexpr auto has_grandmaster() const noexcept -> bool { return grandmaster_id.is_set(); }

    /// Check if the sync is stale (older than threshold)
    /// @param current_mono_ns Current monotonic time in nanoseconds
    /// @param threshold_ns Staleness threshold in nanoseconds
    [[nodiscard]] constexpr auto is_stale(int64_t current_mono_ns, int64_t threshold_ns) const noexcept -> bool
    {
        if (last_sync_mono_ns == 0) {
            return true;  // Never synced
        }
        return (current_mono_ns - last_sync_mono_ns) > threshold_ns;
    }

    /// Default comparison (for detecting changes)
    auto operator==(GptpDomainInfo const&) const noexcept -> bool = default;
};

/// Default staleness threshold: 1 second without sync = stale
inline constexpr int64_t default_staleness_threshold_ns = 1'000'000'000LL;

/// Extended concept for gPTP clock sources that provide domain information.
/// A GptpClockSource extends ClockSource with:
/// - domain_info(): Returns optional<GptpDomainInfo> - nullopt until first sync
/// - staleness_threshold_ns(): Returns the configured staleness threshold
template <typename T>
concept GptpClockSource = ClockSource<T> && requires(T const& t) {
    { t.domain_info() } -> std::convertible_to<std::optional<GptpDomainInfo>>;
    { t.staleness_threshold_ns() } -> std::convertible_to<int64_t>;
};

//
// Clock Adapter
//

/// Adapter that binds a ClockSource to a specific Clock type, providing
/// type-safe time_point conversions.
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
    using monotonic_time_point = MonotonicClock::time_point;

    /// Construct adapter with reference to a clock source
    /// @param source The clock source providing time mapping between clock domains
    explicit ClockAdapter(Source& source) noexcept
        : source_{&source}
    {}

    ~ClockAdapter() = default;

    // Non-copyable but movable
    ClockAdapter(ClockAdapter const&) = delete;
    auto operator=(ClockAdapter const&) -> ClockAdapter& = delete;
    ClockAdapter(ClockAdapter&&) noexcept = default;
    auto operator=(ClockAdapter&&) noexcept -> ClockAdapter& = default;

    /// Get current time in this clock's domain
    [[nodiscard]] auto now() const -> TimeConversion<ClockT>
    {
        return TimeConversion<ClockT>{
            .time = time_point{duration{source_->now_ns()}}, .epoch = source_->epoch(), .healthy = source_->is_healthy()};
    }

    /// Convert a time_point from this clock to monotonic clock
    /// @param tp Time point in this clock's domain to convert
    [[nodiscard]] auto to_monotonic(time_point tp) const -> TimeConversion<MonotonicClock>
    {
        auto mono_ns = source_->to_monotonic_ns(tp.time_since_epoch().count());
        return TimeConversion<MonotonicClock>{
            .time = monotonic_time_point{MonotonicClock::duration{mono_ns}},
            .epoch = source_->epoch(),
            .healthy = source_->is_healthy()};
    }

    /// Convert a time_point from monotonic clock to this clock
    /// @param tp Monotonic time point to convert to this clock's domain
    [[nodiscard]] auto from_monotonic(monotonic_time_point tp) const -> TimeConversion<ClockT>
    {
        auto clock_ns = source_->from_monotonic_ns(tp.time_since_epoch().count());
        return TimeConversion<ClockT>{
            .time = time_point{duration{clock_ns}}, .epoch = source_->epoch(), .healthy = source_->is_healthy()};
    }

    /// Check if the clock source is healthy
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return source_->is_healthy(); }

    /// Get the current epoch (increments on time discontinuities)
    [[nodiscard]] auto epoch() const noexcept -> uint64_t { return source_->epoch(); }

    /// Get raw nanoseconds for timer integration
    [[nodiscard]] auto now_ns() const noexcept { return source_->now_ns(); }

    /// Convert to monotonic nanoseconds for timer integration
    /// @param clock_ns Time in this clock's domain in nanoseconds
    [[nodiscard]] auto to_monotonic_ns(int64_t clock_ns) const noexcept { return source_->to_monotonic_ns(clock_ns); }

    /// Convert from monotonic nanoseconds for timer integration
    /// @param mono_ns Monotonic time in nanoseconds
    [[nodiscard]] auto from_monotonic_ns(int64_t mono_ns) const noexcept { return source_->from_monotonic_ns(mono_ns); }

    // Raw reference (only when Source is a RawReferenceClockSource)

    /// Whether the source maps to CLOCK_MONOTONIC_RAW; a Timer on this
    /// adapter then takes the RAW-authoritative wait.
    static constexpr bool reference_is_raw = RawReferenceClockSource<Source>;

    /// Convert this clock's nanoseconds to CLOCK_MONOTONIC_RAW nanoseconds
    /// @param clock_ns Time in this clock's domain in nanoseconds
    [[nodiscard]] auto to_raw_ns(int64_t clock_ns) const noexcept -> int64_t
        requires RawReferenceClockSource<Source>
    {
        return source_->to_raw_ns(clock_ns);
    }

    /// Convert CLOCK_MONOTONIC_RAW nanoseconds to this clock's nanoseconds
    /// @param raw_ns Raw monotonic time in nanoseconds
    [[nodiscard]] auto from_raw_ns(int64_t raw_ns) const noexcept -> int64_t
        requires RawReferenceClockSource<Source>
    {
        return source_->from_raw_ns(raw_ns);
    }

    // gPTP Domain Information (only available when Source is GptpClockSource)

    /// Get gPTP domain information (grandmaster ID, quality, etc.)
    /// Returns nullopt if the clock has not yet synchronized with a grandmaster.
    /// Only available when the underlying source provides domain info.
    [[nodiscard]] auto domain_info() const -> std::optional<GptpDomainInfo>
        requires GptpClockSource<Source>
    {
        return source_->domain_info();
    }

    /// Get the current grandmaster clock identity.
    /// Returns nullopt if not yet synchronized.
    /// Only available when the underlying source provides domain info.
    [[nodiscard]] auto grandmaster_id() const -> std::optional<tsn::ClockIdentity>
        requires GptpClockSource<Source>
    {
        auto const info = source_->domain_info();
        if (!info) {
            return std::nullopt;
        }
        return info->grandmaster_id;
    }

    /// Check if synchronized with a grandmaster.
    /// Returns true only if domain_info() has a value.
    /// Only available when the underlying source provides domain info.
    [[nodiscard]] auto is_synchronized() const -> bool
        requires GptpClockSource<Source>
    {
        return source_->domain_info().has_value();
    }

    /// Check if the sync data is stale (no recent sync from grandmaster).
    /// Returns true if not synchronized OR if last sync is older than threshold.
    /// Only available when the underlying source provides domain info.
    [[nodiscard]] auto is_stale() const -> bool
        requires GptpClockSource<Source>
    {
        auto const info = source_->domain_info();
        if (!info) {
            return true;  // Not synchronized = stale
        }
        auto const threshold = source_->staleness_threshold_ns();
        return info->is_stale(read_monotonic_ns(), threshold);
    }

    /// Get the staleness threshold in nanoseconds.
    /// Only available when the underlying source provides domain info.
    [[nodiscard]] auto staleness_threshold_ns() const -> int64_t
        requires GptpClockSource<Source>
    {
        return source_->staleness_threshold_ns();
    }

  private:
    Source* source_;
};

//
// Monotonic Clock Adapter (Special Case - No Conversion Needed)
//

/// Specialized adapter for MonotonicClock that requires no time bridge.
/// This is the native clock - reading time is direct with no conversion.
class MonotonicClockAdapter
{
  public:
    using clock_type = MonotonicClock;
    using time_point = MonotonicClock::time_point;
    using duration = MonotonicClock::duration;

    MonotonicClockAdapter() noexcept = default;

    /// Get current monotonic time (direct read, always healthy)
    [[nodiscard]] auto now() const -> TimeConversion<MonotonicClock>;

    /// Convert to monotonic (identity operation)
    /// @param tp Monotonic time point (returned as-is)
    [[nodiscard]] auto to_monotonic(time_point tp) const noexcept -> TimeConversion<MonotonicClock>
    {
        return TimeConversion<MonotonicClock>{.time = tp, .epoch = 0, .healthy = true};
    }

    /// Convert from monotonic (identity operation)
    /// @param tp Monotonic time point (returned as-is)
    [[nodiscard]] auto from_monotonic(time_point tp) const noexcept -> TimeConversion<MonotonicClock>
    {
        return TimeConversion<MonotonicClock>{.time = tp, .epoch = 0, .healthy = true};
    }

    /// Monotonic clock is always healthy
    [[nodiscard]] static constexpr auto is_healthy() noexcept -> bool { return true; }

    /// Monotonic clock epoch is always 0 (no discontinuities)
    [[nodiscard]] static constexpr auto epoch() noexcept -> uint64_t { return 0; }

    /// Get raw nanoseconds for timer integration
    [[nodiscard]] auto now_ns() const noexcept -> int64_t;

    /// Convert to monotonic nanoseconds (identity)
    /// @param ns Time in nanoseconds (returned as-is)
    [[nodiscard]] static constexpr auto to_monotonic_ns(int64_t ns) noexcept { return ns; }

    /// Convert from monotonic nanoseconds (identity)
    /// @param ns Time in nanoseconds (returned as-is)
    [[nodiscard]] static constexpr auto from_monotonic_ns(int64_t ns) noexcept { return ns; }
};

//
// Raw Monotonic Clock Adapter (the timing reference, no bridge needed)
//

class MonotonicRawLine;

/// Adapter for MonotonicRawClock: reads CLOCK_MONOTONIC_RAW directly, always
/// healthy. The adapter new timers should default to: a Timer on it schedules
/// and measures on the slew-immune clock, sleeping early on CLOCK_MONOTONIC
/// and spinning on RAW to each deadline.
///
/// to_monotonic_ns()/from_monotonic_ns() convert through the MonotonicRawLine
/// given at construction. Without one they apply the offset between the two
/// clocks at the moment of the call, which ignores any slew over the span
/// converted: good enough for a one-off conversion, not for a schedule. The
/// Timer never uses them on this adapter; its TimerBase keeps its own line.
class MonotonicRawClockAdapter
{
  public:
    using clock_type = MonotonicRawClock;
    using time_point = MonotonicRawClock::time_point;
    using duration = MonotonicRawClock::duration;

    static constexpr bool reference_is_raw = true;

    explicit MonotonicRawClockAdapter(MonotonicRawLine const* line = nullptr) noexcept
        : line_{line}
    {}

    /// Get current raw monotonic time (direct read, always healthy)
    [[nodiscard]] auto now() const noexcept -> TimeConversion<MonotonicRawClock>;

    /// Convert to monotonic through the line (see class note)
    /// @param tp Raw monotonic time point
    [[nodiscard]] auto to_monotonic(time_point tp) const noexcept -> TimeConversion<MonotonicClock>
    {
        return TimeConversion<MonotonicClock>{
            .time = MonotonicClock::from_ns(to_monotonic_ns(MonotonicRawClock::to_ns(tp))), .epoch = 0, .healthy = true};
    }

    /// Convert from monotonic through the line (see class note)
    /// @param tp Monotonic time point
    [[nodiscard]] auto from_monotonic(MonotonicClock::time_point tp) const noexcept -> TimeConversion<MonotonicRawClock>
    {
        return TimeConversion<MonotonicRawClock>{
            .time = MonotonicRawClock::from_ns(from_monotonic_ns(MonotonicClock::to_ns(tp))), .epoch = 0, .healthy = true};
    }

    [[nodiscard]] static constexpr auto is_healthy() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto epoch() noexcept -> uint64_t { return 0; }

    /// Get raw nanoseconds for timer integration (CLOCK_MONOTONIC_RAW)
    [[nodiscard]] auto now_ns() const noexcept -> int64_t;

    /// Convert to CLOCK_MONOTONIC nanoseconds (see class note)
    [[nodiscard]] auto to_monotonic_ns(int64_t raw_ns) const noexcept -> int64_t;

    /// Convert from CLOCK_MONOTONIC nanoseconds (see class note)
    [[nodiscard]] auto from_monotonic_ns(int64_t mono_ns) const noexcept -> int64_t;

    /// Convert to CLOCK_MONOTONIC_RAW nanoseconds (identity)
    [[nodiscard]] static constexpr auto to_raw_ns(int64_t ns) noexcept { return ns; }

    /// Convert from CLOCK_MONOTONIC_RAW nanoseconds (identity)
    [[nodiscard]] static constexpr auto from_raw_ns(int64_t ns) noexcept { return ns; }

  private:
    MonotonicRawLine const* line_;
};

//
// Concept for Clock Adapters
//

/// Concept for any clock adapter (type-safe or monotonic)
template <typename T>
concept ClockAdapterType = requires(T const& t, int64_t ns) {
    typename T::clock_type;
    typename T::time_point;
    typename T::duration;
    { t.now() } -> std::same_as<TimeConversion<typename T::clock_type>>;
    { t.is_healthy() } -> std::convertible_to<bool>;
    { t.epoch() } -> std::convertible_to<uint64_t>;
    { t.now_ns() } -> std::convertible_to<int64_t>;
    { t.to_monotonic_ns(ns) } -> std::convertible_to<int64_t>;
    { t.from_monotonic_ns(ns) } -> std::convertible_to<int64_t>;
};

//
// MonotonicClockAdapter Implementation
//

inline auto MonotonicClockAdapter::now() const -> TimeConversion<MonotonicClock>
{
    return TimeConversion<MonotonicClock>{.time = time_point{duration{read_monotonic_ns()}}, .epoch = 0, .healthy = true};
}

inline auto MonotonicClockAdapter::now_ns() const noexcept -> int64_t
{
    return read_monotonic_ns();
}

//
// MonotonicRawClockAdapter Implementation
//

inline auto MonotonicRawClockAdapter::now() const noexcept -> TimeConversion<MonotonicRawClock>
{
    return TimeConversion<MonotonicRawClock>{
        .time = MonotonicRawClock::from_ns(read_monotonic_raw_ns()), .epoch = 0, .healthy = true};
}

inline auto MonotonicRawClockAdapter::now_ns() const noexcept -> int64_t
{
    return read_monotonic_raw_ns();
}

// to_monotonic_ns()/from_monotonic_ns() need the full MonotonicRawLine and
// live in realtime_monotonic_raw_line.cpp.

}  // namespace statusbar::realtime
