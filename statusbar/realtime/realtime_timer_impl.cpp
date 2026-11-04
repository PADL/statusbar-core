// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Implementation of large non-template functions extracted from realtime_timer.hpp

#include "statusbar/realtime/realtime_timer_config.hpp"

namespace statusbar::realtime {

auto build_histogram_arg_specs(stats::AtomicHistogramConfig& config) -> args::ArgumentSpecs
{
    args::ArgumentSpecs specs;
    specs.add<int64_t>(
        "low_ns", "Low end of histogram range in nanoseconds", config.low_ns, [&](auto v) -> void { config.low_ns = v; });
    specs.add<int64_t>(
        "high_ns", "High end of histogram range in nanoseconds", config.high_ns, [&](auto v) -> void { config.high_ns = v; });
    specs.add<int64_t>("bin_width_ns", "Width of each histogram bin in nanoseconds", config.bin_width_ns, [&](auto v) -> void {
        config.bin_width_ns = v;
    });
    return specs;
}

auto build_timer_arg_specs(TimerConfig& config) -> args::ArgumentSpecs
{  // NOLINT(statusbar-block-statements) one table of specs, one per config field, read top to bottom
    args::ArgumentSpecs specs;
    specs.add<int64_t>("period_ns", "Wake period in nanoseconds", config.period_ns, [&](auto v) -> void { config.period_ns = v; });
    specs.add<int64_t>("compensation_ns", "Compensation in nanoseconds", config.compensation_ns, [&](auto v) -> void {
        config.compensation_ns = v;
    });
    specs.add<int>("cpu", "CPU number to run timer on", config.cpu, [&](auto v) -> void { config.cpu = v; });
    specs.add<int>("priority", "SCHED_FIFO priority (1-99)", config.priority, [&](auto v) -> void { config.priority = v; });
    specs.add<bool>(
        "busy_wait", "Use busy-wait mode for ultra-low latency (100% CPU, <5us jitter)", config.busy_wait, [&](auto v) -> void {
            config.busy_wait = v;
        });
    specs.add<int64_t>(
        "busy_wait_threshold_ns",
        "Busy-wait threshold in ns (sleep if remaining time > this, then busy-wait)",
        config.busy_wait_threshold_ns,
        [&](auto v) -> void { config.busy_wait_threshold_ns = v; });
    specs.add<bool>(
        "strict_affinity",
        "Fail if CPU affinity cannot be set (default: log warning and continue)",
        config.strict_affinity,
        [&](auto v) -> void { config.strict_affinity = v; });
    specs.add<int64_t>(
        "stack_prefault_bytes",
        "Stack bytes to prefault before the RT loop (0 = skip)",
        static_cast<int64_t>(config.stack_prefault_bytes),
        [&](auto v) -> void { config.stack_prefault_bytes = (v > 0) ? static_cast<size_t>(v) : 0; });
    specs.add<int64_t>(
        "start_offset_cycles",
        "Cycles ahead of now to schedule the first wake (>=2 avoids a startup race)",
        config.start_offset_cycles,
        [&](auto v) -> void { config.start_offset_cycles = v; });
    specs.add<int64_t>(
        "resync_interval_cycles",
        "Wakes between mono-deadline resyncs that correct accumulated slope drift (0 = never)",
        config.resync_interval_cycles,
        [&](auto v) -> void { config.resync_interval_cycles = v; });
    specs.add<int64_t>(
        "raw_spin_guard_ns",
        "Raw-reference timers: wake this early on CLOCK_MONOTONIC, then spin on CLOCK_MONOTONIC_RAW to the deadline",
        config.raw_spin_guard_ns,
        [&](auto v) -> void { config.raw_spin_guard_ns = v; });
    specs.add<int64_t>(
        "raw_line_sample_interval_ns",
        "Raw-reference timers: RAW->MONOTONIC line re-sample interval in ns (0 = once at start)",
        config.raw_line_sample_interval_ns,
        [&](auto v) -> void { config.raw_line_sample_interval_ns = v; });

    // Merge histogram specs with prefixes
    specs.merge(build_histogram_arg_specs(config.error_histogram), "error_histogram.");
    specs.merge(build_histogram_arg_specs(config.duration_histogram), "duration_histogram.");

    return specs;
}

}  // namespace statusbar::realtime
