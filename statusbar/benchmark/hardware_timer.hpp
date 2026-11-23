#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

//
// Hardware performance counter timer for benchmarking
//
// Reads CPU performance counters directly to minimize per-sample overhead:
//   - x86_64: rdtscp (invariant TSC required — post-Nehalem/Bulldozer)
//   - aarch64: cntvct_el0 (virtual counter)
//
// Tick→ns conversion is deferred to presentation time. The sampling path
// only reads the counter and stores the raw tick value, so the measured
// code is perturbed as little as possible.

#include <chrono>
#include <cstdint>
#include <thread>

namespace statusbar::benchmark {

namespace hw_detail {

inline auto read_counter() noexcept -> uint64_t
{
#if defined(__x86_64__) || defined(_M_X64)
    // rdtscp reads TSC and TSC_AUX; acts as a partial serializing read
    // (waits for prior instructions to retire before sampling TSC).
    uint32_t lo{};
    uint32_t hi{};
    uint32_t aux{};
    asm volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    return (static_cast<uint64_t>(hi) << 32) | static_cast<uint64_t>(lo);
#elif defined(__aarch64__)
    // isb prevents the counter read from being hoisted above prior
    // instructions — matters for tight benchmark loops.
    uint64_t count{};  // NOLINT(misc-const-correctness) — asm output operand; const is not valid here
    asm volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(count));
    return count;
#else
    // Fallback: no hardware counter. Use steady_clock ticks.
    return static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

/// Calibrate the counter frequency in ticks per second.
/// - aarch64: read cntfrq_el0 directly (no calibration needed).
/// - x86_64: measure rdtsc against steady_clock over a short interval.
/// - fallback: steady_clock's period gives ticks per second.
inline auto calibrate_ticks_per_second() noexcept -> uint64_t
{
#if defined(__aarch64__)
    uint64_t freq{};  // NOLINT(misc-const-correctness) — asm output operand; const is not valid here
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
#elif defined(__x86_64__) || defined(_M_X64)
    // Measure TSC against steady_clock over ~10ms.
    using clock = std::chrono::steady_clock;
    auto const wall_start = clock::now();
    auto const tsc_start = read_counter();
    auto const deadline = wall_start + std::chrono::milliseconds(10);
    while (clock::now() < deadline) {
        // busy-wait so the kernel doesn't migrate us; keeps the calibration tight
    }
    auto const tsc_end = read_counter();
    auto const wall_end = clock::now();
    auto const elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall_end - wall_start).count();
    if (elapsed_ns <= 0) {
        return 0;
    }
    auto const ticks = tsc_end - tsc_start;
    return static_cast<uint64_t>((static_cast<double>(ticks) * 1'000'000'000.0) / static_cast<double>(elapsed_ns));
#else
    using period = std::chrono::steady_clock::period;
    return static_cast<uint64_t>(period::den / period::num);
#endif
}

inline auto ticks_per_second() noexcept -> uint64_t
{
    // Lazy init: pay calibration once, on first use, not at static init time.
    static uint64_t const freq = calibrate_ticks_per_second();
    return freq;
}

/// Convert a raw tick count to nanoseconds using integer math.
/// Splits into whole-seconds + remainder to avoid overflow when
/// `ticks * 1e9` would exceed uint64_t on multi-GHz counters.
inline auto ticks_to_ns(uint64_t ticks) noexcept -> int64_t
{
    uint64_t const freq = ticks_per_second();
    if (freq == 0) {
        return 0;
    }
    uint64_t const whole_seconds = ticks / freq;
    uint64_t const remainder = ticks % freq;
    return static_cast<int64_t>((whole_seconds * 1'000'000'000ULL) + ((remainder * 1'000'000'000ULL) / freq));
}

}  // namespace hw_detail

/// High-resolution timer backed by CPU performance counters.
///
/// Same interface shape as `Timer`, but reads `rdtscp` (x86_64) or
/// `cntvct_el0` (aarch64) instead of going through steady_clock.
/// The tick→ns conversion happens only when the caller asks for a
/// time value — the sampling path stores raw ticks.
class HardwareTimer
{
  public:
    using Tick = uint64_t;

    /// Start timing
    static auto start() noexcept -> HardwareTimer { return HardwareTimer{hw_detail::read_counter()}; }

    /// Raw tick count since start — the cheapest possible query.
    [[nodiscard]] auto elapsed_ticks() const noexcept -> Tick { return elapsed_ticks_at(hw_detail::read_counter()); }

    /// Told form: the ticks elapsed when the counter reads @p now.
    [[nodiscard]] auto elapsed_ticks_at(Tick now) const noexcept -> Tick { return now - start_; }

    /// Told form: the nanoseconds elapsed when the counter reads @p now.
    [[nodiscard]] auto elapsed_ns_at(Tick now) const noexcept -> int64_t { return hw_detail::ticks_to_ns(elapsed_ticks_at(now)); }

    /// Elapsed time in nanoseconds (converted at call time).
    [[nodiscard]] auto elapsed_ns() const noexcept -> int64_t { return hw_detail::ticks_to_ns(elapsed_ticks()); }

    /// Elapsed time in microseconds.
    [[nodiscard]] auto elapsed_us() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000.0; }

    /// Elapsed time in milliseconds.
    [[nodiscard]] auto elapsed_ms() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000'000.0; }

    /// Elapsed time in seconds.
    [[nodiscard]] auto elapsed_s() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000'000'000.0; }

    /// Reset timer to current counter value.
    auto reset() noexcept { start_ = hw_detail::read_counter(); }

    /// Starting tick — useful for callers doing their own batch conversion.
    [[nodiscard]] auto start_tick() const noexcept -> Tick { return start_; }

    /// Counter frequency (ticks per second) for external conversion.
    static auto ticks_per_second() noexcept -> uint64_t { return hw_detail::ticks_per_second(); }

    /// Convert a tick delta to nanoseconds — lets callers batch-convert
    /// raw samples (e.g., a vector of `elapsed_ticks()` values) at the
    /// end of a measurement loop rather than inside the hot path.
    static auto ticks_to_ns(Tick ticks) noexcept -> int64_t { return hw_detail::ticks_to_ns(ticks); }

  private:
    explicit HardwareTimer(Tick start) noexcept
        : start_{start}
    {}

    Tick start_;
};

}  // namespace statusbar::benchmark
