#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

//
// Benchmark utilities module
// Provides tools for writing performance benchmarks that prevent compiler optimizations

#include "statusbar/benchmark/hardware_timer.hpp"
#include "statusbar/stats/stats.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <print>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace statusbar::benchmark {

//
// Optimization Barriers - Prevent Dead Code Elimination
//
/// Prevent compiler from optimizing away computed values
/// Based on Google Benchmark's DoNotOptimize implementation
///
/// Uses inline assembly with memory clobber to force the compiler to:
/// 1. Materialize all computed values
/// 2. Assume memory can be accessed through the pointer
/// 3. Prevent reordering optimizations
///
/// This is essential for benchmarks to ensure the code being measured
/// actually executes and produces results, rather than being eliminated
/// by the compiler's dead code elimination pass.
///
/// Example usage:
/// ```cpp
/// auto result = expensive_computation();
/// do_not_optimize(result);  // Compiler must compute result
/// ```
///
/// \param value The value to prevent optimization of (const reference)
template <class T>
inline auto do_not_optimize(T const& value)
{
#if defined(__clang__) || defined(__GNUC__)
    // Tell compiler: this value is used (even though we do nothing with it)
    // "r,m" = value can be in register or memory
    // "memory" = assume all memory is clobbered (prevents reordering)
    asm volatile("" : : "r,m"(value) : "memory");
#else
    // Fallback for other compilers - use volatile to prevent optimization
    auto volatile tmp = &value;
    (void)tmp;
#endif
}

/// Overload for non-const references (values that might be modified)
///
/// This variant tells the compiler that the value is both read AND written,
/// which prevents even more aggressive optimizations.
///
/// \param value The value to prevent optimization of (mutable reference)
template <class T>
inline auto do_not_optimize(T& value)
{
#if defined(__clang__)
    // "+r,m" = value is both read and written
    asm volatile("" : "+r,m"(value) : : "memory");
#elif defined(__GNUC__)
    // GCC gets the single "m" alternative, not clang's "+r,m" multi-alternative
    // form. Two distinct GCC behaviours force this:
    //
    //   "+r,m"  rejected outright at compile time ("impossible constraint in
    //           'asm'") for any T that cannot live in a register.
    //   "+m,r"  compiles, but is silently miscompiled on GCC 16.2 aarch64:
    //           although "+" marks the operand read-write, GCC treats it as
    //           write-only and eliminates the store that initialises it, so
    //           the asm reads uninitialised stack. `int v = 42;
    //           do_not_optimize(v);` leaves v holding garbage, and a counter
    //           incremented in a benchmark loop reads back as 0 -- benchmark
    //           results would be wrong, not just the tests.
    //
    // "+m" is always satisfiable, needs no alternative selection, and is the
    // stronger barrier anyway: it forces the value to memory and marks it
    // read-written, which is exactly the guarantee this function exists to
    // provide. The input-only const overload above keeps "r,m" -- only
    // read-write operands are affected.
    //
    // Full analysis, constraint matrix and a 9-line reproducer:
    // docs/GCC_INLINE_ASM_MULTI_ALTERNATIVE_BUG.md
    asm volatile("" : "+m"(value) : : "memory");
#else
    // Fallback for other compilers
    auto volatile tmp = &value;
    (void)tmp;
#endif
}

//
// High-Resolution Timing Utilities
//
/// High-resolution timer for benchmarking
/// Uses steady_clock which is monotonic and best for measuring intervals
class Timer
{
  public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = std::chrono::nanoseconds;

    /// Start timing
    static auto start() noexcept -> Timer { return Timer{Clock::now()}; }

    /// Get elapsed time since timer started
    [[nodiscard]] auto elapsed() const noexcept -> Duration { return std::chrono::duration_cast<Duration>(Clock::now() - start_); }

    /// Get elapsed time in nanoseconds
    [[nodiscard]] auto elapsed_ns() const noexcept -> int64_t { return elapsed().count(); }

    /// Get elapsed time in microseconds
    [[nodiscard]] auto elapsed_us() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000.0; }

    /// Get elapsed time in milliseconds
    [[nodiscard]] auto elapsed_ms() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000'000.0; }

    /// Get elapsed time in seconds
    [[nodiscard]] auto elapsed_s() const noexcept -> double { return static_cast<double>(elapsed_ns()) / 1'000'000'000.0; }

    /// Reset timer to current time
    auto reset() noexcept { start_ = Clock::now(); }

  private:
    explicit Timer(TimePoint start) noexcept
        : start_{start}
    {}

    TimePoint start_;
};

//
// Statistical Analysis (delegated to statusbar::stats)
//
using BenchmarkStats = stats::DescriptiveStats;

inline auto analyze(std::vector<double> measurements) -> BenchmarkStats
{
    return stats::analyze(std::move(measurements));
}

//
// Result Formatting and Reporting (delegated to statusbar::stats)
//
using stats::format_duration;
using stats::report;

//
// Warmup and Iteration Control
//
/// Configuration for benchmark execution
struct BenchmarkConfig
{
    size_t warmup_iterations{100};        ///< Number of warmup iterations (not measured)
    size_t measurement_iterations{1000};  ///< Number of iterations to measure
    size_t batch_size{1};                 ///< Number of function calls per measurement (for sub-microsecond operations)
    bool verbose{false};                  ///< Print detailed progress
};

/// Run a benchmark function with warmup and statistical analysis
/// @tparam Func Callable type (lambda, function pointer, etc.)
/// @param name Benchmark name for reporting
/// @param func Function to benchmark (should return void)
/// @param config Benchmark configuration
/// @return Statistical analysis of the measurements
template <typename Func>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward) - func is called multiple times in loops
[[nodiscard]] auto run(std::string_view name, Func&& func, BenchmarkConfig const& config = BenchmarkConfig{}) -> BenchmarkStats
{
    if (config.verbose) {
        std::println("Running benchmark: {}", name);
        std::println("  Warmup iterations: {}", config.warmup_iterations);
        std::println("  Measurement iterations: {}", config.measurement_iterations);
        std::println("  Batch size: {}", config.batch_size);
    }

    // If func returns a value, capture it and feed through do_not_optimize so
    // the compiler can't eliminate the call as dead code. Void-returning
    // funcs are responsible for applying barriers to their own internal
    // state (as run_hw's docstring describes).
    constexpr bool func_returns_void = std::is_void_v<std::invoke_result_t<Func&>>;

    // Warmup phase (not measured)
    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        for (size_t j = 0; j < config.batch_size; ++j) {
            if constexpr (func_returns_void) {
                func();
            } else {
                auto result = func();
                do_not_optimize(result);
            }
        }
    }

    // Measurement phase
    std::vector<double> measurements;
    measurements.reserve(config.measurement_iterations);

    for (size_t i = 0; i < config.measurement_iterations; ++i) {
        auto timer = Timer::start();
        for (size_t j = 0; j < config.batch_size; ++j) {
            if constexpr (func_returns_void) {
                func();
            } else {
                auto result = func();
                do_not_optimize(result);
            }
        }
        // Divide by batch_size to get per-call time (preserves sub-nanosecond precision)
        double const per_call_ns = static_cast<double>(timer.elapsed_ns()) / static_cast<double>(config.batch_size);
        measurements.push_back(per_call_ns);
    }

    // Analyze results
    auto stats = analyze(std::move(measurements));

    if (config.verbose) {
        std::println("  Completed {} measurements", stats.sample_count);
    }

    return stats;
}

/// Run a benchmark using the hardware performance counter.
///
/// Unlike `run()`, the measurement loop stores only raw tick deltas —
/// no division, no floating-point, no std::chrono conversion in the hot
/// path. Ticks are batch-converted to per-call nanoseconds after the
/// measurement loop finishes, so the sampled code is perturbed as
/// little as possible.
///
/// Prefer this over `run()` for sub-microsecond benchmarks where
/// `steady_clock::now()` overhead (~20ns on Linux vDSO) dominates the
/// measurement.
///
/// The lambda receives the inner-iteration count `n` and is expected to
/// run the benchmarked operation that many times itself. This gives the
/// caller a single memory barrier per timer sample (one `do_not_optimize`
/// placed after the inner loop) instead of one per call — allowing the
/// compiler to keep state in registers across the batch.
///
///     auto stats = run_hw("aes_block", [&](size_t n) {
///         for (size_t k = 0; k < n; ++k) {
///             aes_encrypt_block(rk, block);
///         }
///         do_not_optimize(block);
///     }, cfg);
///
/// @tparam Func Callable taking `size_t` (inner iteration count)
/// @param name Benchmark name for reporting
/// @param func Function to benchmark, signature `void(size_t n)`
/// @param config Benchmark configuration; `batch_size` is the `n` passed to `func`
/// @return Statistical analysis of the measurements, in per-call nanoseconds
template <typename Func>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward) - func is called multiple times in loops
[[nodiscard]] auto run_hw(std::string_view name, Func&& func, BenchmarkConfig const& config = BenchmarkConfig{}) -> BenchmarkStats
{
    if (config.verbose) {
        std::println("Running hw benchmark: {}", name);
        std::println("  Warmup iterations: {}", config.warmup_iterations);
        std::println("  Measurement iterations: {}", config.measurement_iterations);
        std::println("  Batch size: {}", config.batch_size);
        std::println("  Counter frequency: {} Hz", HardwareTimer::ticks_per_second());
    }

    // Warmup phase (not measured)
    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        func(config.batch_size);
    }

    // Measurement phase — store raw tick deltas only.
    std::vector<uint64_t> tick_samples;
    tick_samples.reserve(config.measurement_iterations);

    for (size_t i = 0; i < config.measurement_iterations; ++i) {
        auto timer = HardwareTimer::start();
        func(config.batch_size);
        tick_samples.push_back(timer.elapsed_ticks());
    }

    // Presentation-time conversion: ticks → per-call nanoseconds.
    // Using FP multiply-by-reciprocal is faster than integer division
    // and precision is more than enough for benchmark timing.
    std::vector<double> measurements;
    measurements.reserve(tick_samples.size());
    auto const freq = HardwareTimer::ticks_per_second();
    double const ns_per_tick = (freq == 0) ? 0.0 : (1'000'000'000.0 / static_cast<double>(freq));
    double const batch_divisor = static_cast<double>(config.batch_size);
    for (uint64_t const ticks : tick_samples) {
        double const per_call_ns = (static_cast<double>(ticks) * ns_per_tick) / batch_divisor;
        measurements.push_back(per_call_ns);
    }

    auto stats = analyze(std::move(measurements));

    if (config.verbose) {
        std::println("  Completed {} measurements", stats.sample_count);
    }

    return stats;
}

}  // namespace statusbar::benchmark
