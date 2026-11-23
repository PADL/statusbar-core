#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/realtime/realtime_monotonic_raw_line.hpp"
#include "statusbar/realtime/realtime_timer_config.hpp"
#include "statusbar/realtime/realtime_timer_schedule.hpp"
#include "statusbar/stats/stats.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <thread>

namespace statusbar::realtime {

/// Non-template base class for Timer.
///
/// Holds everything that does not depend on the clock adapter template: config,
/// statistics, running flag, worker thread, and the thread prepare / wait
/// primitives. Every timer waits on CLOCK_MONOTONIC_RAW, whatever domain its
/// schedule is in, so the wait lives here. Derived Timer<ClockAdapterT>
/// supplies the per-tick loop body via the pure virtual run_loop() hook.
class TimerBase
{
  public:
    explicit TimerBase(TimerConfig config) noexcept;
    virtual ~TimerBase() noexcept;

    TimerBase(TimerBase const&) = delete;
    auto operator=(TimerBase const&) -> TimerBase& = delete;
    TimerBase(TimerBase&&) = delete;
    auto operator=(TimerBase&&) -> TimerBase& = delete;

    /// Start the timer thread
    /// @param shutdown_token Optional external stop token to check in addition to internal running state
    auto start(statusbar::itc::StopToken* shutdown_token = nullptr) -> void;

    /// Stop the timer thread (blocks until thread exits)
    auto stop() noexcept -> void;

    [[nodiscard]] auto is_running() const noexcept -> bool { return is_running_atomic(); }
    [[nodiscard]] auto stats() const noexcept -> stats::AtomicWakeStats::Snapshot { return stats_.snapshot(); }
    [[nodiscard]] auto config() const noexcept -> TimerConfig const& { return config_; }
    [[nodiscard]] auto period_ns() const noexcept -> int64_t { return config_.period_ns; }
    [[nodiscard]] auto compensation_ns() const noexcept -> int64_t { return config_.compensation_ns; }
    [[nodiscard]] auto period() const noexcept -> Nanoseconds { return Nanoseconds{config_.period_ns}; }
    [[nodiscard]] auto compensation() const noexcept -> Nanoseconds { return Nanoseconds{config_.compensation_ns}; }
    [[nodiscard]] auto cpu() const noexcept -> int { return config_.cpu; }
    [[nodiscard]] auto is_busy_wait() const noexcept -> bool { return config_.busy_wait; }

    /// The RAW->MONOTONIC line this timer's thread keeps for its own sleeps
    /// (see wait_until_raw_deadline). Identity until the thread primes it at the top of its loop.
    [[nodiscard]] auto raw_line() const noexcept -> MonotonicRawLine const& { return raw_line_; }

  protected:
    /// Derived class supplies the timing loop body.
    virtual auto run_loop() -> void = 0;

    /// Gating hook called after prepare_thread() and before run_loop().
    /// Derived classes override this to wait for prerequisites (e.g. clock
    /// adapter becoming healthy). Must honour should_run() so a shutdown
    /// requested during the wait can exit the thread without entering
    /// the timing loop.
    /// @return true to proceed into run_loop(); false to exit the thread.
    [[nodiscard]] virtual auto wait_until_ready() -> bool { return true; }

    [[nodiscard]] auto is_running_atomic() const noexcept -> bool;
    auto set_running(bool value) noexcept -> void;
    [[nodiscard]] auto try_start() noexcept -> bool;
    [[nodiscard]] auto try_stop() noexcept -> bool;

    /// Return true while the timer should continue running (checks internal
    /// atomic flag and the external shutdown flag, if any).
    [[nodiscard]] auto should_run() const noexcept -> bool;

    /// Prepare thread for realtime operation: stack prefault, CPU affinity,
    /// SCHED_FIFO priority, and memory locking. Virtual so tests can override
    /// without paying the 1MB stack prefault, which overflows the default
    /// std::thread stack on some platforms.
    /// @return true on success; false only if strict_affinity is set and CPU affinity failed.
    [[nodiscard]] virtual auto prepare_thread() -> bool;

    /// The CPU half of prepare_thread(): the isolated-CPU preparation and the
    /// affinity, for config_.cpu >= 0. False only if strict_affinity is set and
    /// the affinity could not be set.
    [[nodiscard]] auto prepare_cpu() -> bool;

    /// Sleep until an absolute CLOCK_MONOTONIC deadline: the coarse sleep
    /// under every RAW wait.
    /// @return wake error (positive = late)
    static auto wait_until_absolute(MonotonicClock::time_point deadline) noexcept -> Nanoseconds;

    /// Result of a deadline wait (see realtime_timer_schedule.hpp).
    using WaitResult = realtime::WaitResult;

    //
    // The arithmetic of a RAW wait, told the time. wait_until_raw_deadline
    // is these three with the clock reads, the sleep and the spin between.
    //

    /// The RAW instant a wait for @p raw_deadline aims at: the deadline
    /// with the configured compensation applied.
    [[nodiscard]] auto wake_target(MonotonicRawClock::time_point raw_deadline) const noexcept -> MonotonicRawClock::time_point
    {
        return raw_deadline + compensation();
    }

    /// Where on CLOCK_MONOTONIC the coarse sleep toward @p target_raw should
    /// end, told that RAW now reads @p raw_now: the target through the
    /// timer's line, less the spin guard and the slew the line says the
    /// sleep could accrue. Empty when that is already here and the whole
    /// wait is a spin.
    [[nodiscard]] auto early_wake(MonotonicRawClock::time_point target_raw, MonotonicRawClock::time_point raw_now) const noexcept
        -> std::optional<MonotonicClock::time_point>;

    /// How a wait for @p raw_deadline ended, told the RAW instant it ended
    /// at. Measured against the uncompensated deadline.
    [[nodiscard]] auto wait_outcome(MonotonicRawClock::time_point raw_deadline, MonotonicRawClock::time_point woke) const noexcept
        -> WaitResult
    {
        return wait_result(woke - raw_deadline, period());
    }

    /// Wait until a CLOCK_MONOTONIC_RAW deadline, the RAW-authoritative way:
    /// convert the (compensated) deadline to CLOCK_MONOTONIC through the
    /// timer's own line, sleep until a guard before it, then spin on RAW to
    /// the exact instant. The guard is config_.raw_spin_guard_ns (or
    /// busy_wait_threshold_ns in busy_wait mode) plus the slew the line says
    /// the sleep could accrue, so the sleep never overshoots. Error and
    /// skipped-cycle counts are measured on RAW against the uncompensated
    /// @p raw_deadline, so statistics remain comparable across compensation
    /// settings. Re-samples the line when it is due.
    auto wait_until_raw_deadline(MonotonicRawClock::time_point raw_deadline) noexcept -> WaitResult;

    /// Give the line a rate before the schedule is seeded: two samples a
    /// millisecond apart. A run loop calls this first, so the millisecond
    /// is spent before the first deadline exists rather than inside the
    /// first wait. wait_until_raw_deadline primes on its own if this was
    /// skipped.
    auto prime_raw_line() noexcept -> void;

    TimerConfig config_;
    stats::AtomicWakeStats stats_;
    statusbar::itc::StopToken* shutdown_token_{nullptr};
    std::thread timer_thread_;

  private:
    /// Prime the line if it never was, else re-sample it once
    /// raw_line_sample_interval_ns has passed.
    auto track_raw_line(MonotonicRawClock::time_point raw_now) noexcept -> void;

    /// The exact part of a RAW wait. @return the RAW time at which it ended.
    [[nodiscard]] static auto spin_until_raw(MonotonicRawClock::time_point target_raw) noexcept -> MonotonicRawClock::time_point;

    std::atomic<bool> running_{false};
    MonotonicRawLine raw_line_;
    MonotonicRawTracker raw_tracker_{raw_line_};
    /// When the line was last sampled; empty until it has been primed.
    std::optional<MonotonicRawClock::time_point> raw_line_sampled_{};
};

}  // namespace statusbar::realtime
