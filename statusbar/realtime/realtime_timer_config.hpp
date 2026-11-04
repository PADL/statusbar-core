#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/args/args.hpp"
#include "statusbar/stats/stats.hpp"

#include <cstddef>
#include <cstdint>
#include <print>
#include <string_view>

namespace statusbar::realtime {

/// Configuration for the realtime Timer
struct TimerConfig
{
    std::string_view name{};                          ///< Timer name for logging/debugging
    int64_t period_ns{500'000'000};                   ///< Wake period in nanoseconds
    int64_t compensation_ns{0};                       ///< Compensation offset in nanoseconds
    int64_t busy_wait_threshold_ns{200'000};          ///< Busy-wait threshold in ns (sleep if remaining > this)
    int cpu{3};                                       ///< CPU number for affinity (-1 to disable)
    int priority{49};                                 ///< SCHED_FIFO priority (1-99, default 49)
    bool busy_wait{false};                            ///< Use busy-wait mode for ultra-low latency
    bool strict_affinity{false};                      ///< Fail if CPU affinity cannot be set
    size_t stack_prefault_bytes{size_t{128} * 1024};  ///< Stack bytes to prefault before RT loop (0 = skip)
    int64_t start_offset_cycles{2};        ///< Cycles ahead of now to schedule the first wake (>=2 avoids a startup race)
    int64_t resync_interval_cycles{1000};  ///< Wakes between mono-deadline resyncs that correct accumulated slope drift (0 = never)
    /// Raw-reference timers only (see MonotonicRawClockAdapter): how early,
    /// in ns, to wake on CLOCK_MONOTONIC before spinning on CLOCK_MONOTONIC_RAW
    /// to the deadline. busy_wait timers use busy_wait_threshold_ns instead.
    int64_t raw_spin_guard_ns{50'000};
    /// Raw-reference timers only: how often, in ns of RAW time, the timer
    /// thread re-samples its RAW->MONOTONIC line (0 = only once, at the start).
    int64_t raw_line_sample_interval_ns{100'000'000};

    /// Histogram configuration for wake error distribution
    stats::AtomicHistogramConfig error_histogram{
        .low_ns = -10'000,     // -10 us
        .high_ns = 200'000,    // 200 us
        .bin_width_ns = 5'000  // 5 us bins
    };

    /// Histogram configuration for callback duration distribution
    stats::AtomicHistogramConfig duration_histogram{
        .low_ns = 0,           // 0 ns (durations are always positive)
        .high_ns = 200'000,    // 200 us
        .bin_width_ns = 5'000  // 5 us bins
    };
};

/// Build argument specs for a stats::AtomicHistogramConfig
/// Returns a standalone ArgumentSpecs that can be merged with a prefix
/// @param config stats::AtomicHistogramConfig to bind argument specs to
auto build_histogram_arg_specs(stats::AtomicHistogramConfig& config) -> args::ArgumentSpecs;

/// Build argument specs for a TimerConfig
/// Returns a standalone ArgumentSpecs that can be merged with a prefix
/// @param config TimerConfig to bind argument specs to
auto build_timer_arg_specs(TimerConfig& config) -> args::ArgumentSpecs;

/// Validate a TimerConfig
/// @param config The configuration to validate
/// @param error_prefix Optional prefix for error messages (e.g., "timer.")
/// @return true if valid, false if invalid (error printed to stderr)
inline auto validate_timer_config(TimerConfig const& config, std::string_view error_prefix = "") -> bool
{
    if (config.period_ns <= 0) {
        std::println(stderr, "Error: --{}period_ns must be positive", error_prefix);
        return false;
    }
    return true;
}

/// Print a TimerConfig summary to stdout
/// @param config The configuration to print
inline auto print_timer_config(TimerConfig const& config) -> void
{
    if (config.name.empty()) {
        std::print(
            "Timer: period={}ns, cpu={}, compensation={}ns, mode={}\n",
            config.period_ns,
            config.cpu,
            config.compensation_ns,
            config.busy_wait ? "BUSY-WAIT" : "sleep-based");
    } else {
        std::print(
            "{}: period={}ns, cpu={}, compensation={}ns, mode={}\n",
            config.name,
            config.period_ns,
            config.cpu,
            config.compensation_ns,
            config.busy_wait ? "BUSY-WAIT" : "sleep-based");
    }
}

}  // namespace statusbar::realtime
