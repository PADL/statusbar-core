// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Implementation of TimerBase
///
/// Everything here is intentionally non-template so each translation unit
/// links against one copy instead of instantiating per clock adapter. The
/// atomic operations live here so they are not inlined across module
/// boundaries.

#include "statusbar/realtime/realtime_timer_base.hpp"

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/realtime/realtime_tripwire.hpp"

#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace statusbar::realtime {

TimerBase::TimerBase(TimerConfig config) noexcept
    : config_{config}
    , stats_{config_.error_histogram, config_.duration_histogram}
{}

TimerBase::~TimerBase() noexcept
{
    // Timer's own destructor has stopped the thread by now; this is the net
    // under a derived class that did not, for the thread that left on its
    // own (see stop()): a joinable std::thread destructs into std::terminate.
    stop();
}

auto TimerBase::is_running_atomic() const noexcept -> bool
{
    return running_.load(std::memory_order_acquire);
}

auto TimerBase::set_running(bool value) noexcept -> void
{
    running_.store(value, std::memory_order_release);
}

auto TimerBase::try_start() noexcept -> bool
{
    bool expected = false;
    return running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
}

auto TimerBase::try_stop() noexcept -> bool
{
    bool expected = true;
    return running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel);
}

auto TimerBase::should_run() const noexcept -> bool
{
    if (!is_running_atomic()) {
        return false;
    }
    if (shutdown_token_ != nullptr && shutdown_token_->stop_requested()) {
        return false;
    }
    return true;
}

auto TimerBase::start(statusbar::itc::StopToken* shutdown_token) -> void
{
    if (!try_start()) {
        return;  // Already running
    }
    shutdown_token_ = shutdown_token;
    timer_thread_ = std::thread([this]() -> void {
        // Named before anything else can fail, so a thread that dies during
        // preparation is still identifiable in a core dump.
        set_current_thread_name("rt-timer");
#if __cpp_exceptions
        try {
#endif
            if (!prepare_thread()) {
                set_running(false);
                return;  // Exit thread if preparation failed in strict mode
            }
            if (!wait_until_ready()) {
                set_running(false);
                return;  // Shutdown requested during readiness wait
            }
            run_loop();
#if __cpp_exceptions
        } catch (TripwireFiredException const&) {  // NOLINT(bugprone-empty-catch)
            // Tripwire framework has already signalled shutdown; let the
            // thread exit and rely on stop() to join. Other threads (monitor
            // thread, main thread) drive the orderly teardown from here.
        } catch (...) {
            std::terminate();
        }
#endif
    });
}

auto TimerBase::stop() noexcept -> void
{
    // Clearing the flag asks a running thread to leave. A thread that left on
    // its own (preparation failed, the readiness wait was cut short, a
    // tripwire fired) cleared it already, and it is joined all the same:
    // the join cannot wait on whether the flag was ours to clear.
    (void)try_stop();
    if (timer_thread_.joinable()) {
        timer_thread_.join();
    }
}

auto TimerBase::prepare_cpu() -> bool
{
    if (config_.cpu < 0) {
        return true;
    }
    // Prepare isolated CPU (sets governor, timer slack, etc.), then pin to it.
    (void)prepare_isolated_cpu(config_.cpu);
    auto affinity_result = set_realtime_affinity_ex(config_.cpu);
    if (!affinity_result) {
        affinity_result.log_if_failed("Timer CPU affinity");
        if (config_.strict_affinity) {
            std::print(stderr, "Error: strict_affinity is set but CPU affinity failed - timer thread exiting\n");
            return false;
        }
    }
    return true;
}

auto TimerBase::prepare_thread() -> bool
{
    stats_.reset();

    // Pre-fault stack to avoid page faults in the RT loop (nothing when 0).
    prefault_stack(config_.stack_prefault_bytes);

    if (!prepare_cpu()) {
        return false;
    }

    // Set realtime priority (SCHED_FIFO)
    (void)set_realtime_priority_logged(config_.priority, "Timer");

    // Lock memory to prevent page faults. mlockall is process-wide and takes
    // in every mapping of the moment, so a process that maps large files and
    // locks ranges of them itself turns this off and locks once at startup.
    if (config_.lock_memory) {
        (void)lock_memory_ex();
    }

    return true;
}

auto TimerBase::wait_until_absolute(int64_t deadline_ns) noexcept -> int64_t
{
    // A signal that cuts the sleep short is not a wake: sleep again to the
    // same deadline. Any other failure returns at once and the caller sees
    // the early wake in the error it is handed.
    int sleep_result = 0;
    do {
        sleep_result = sleep_until_monotonic_ns(deadline_ns);
    } while (sleep_result == EINTR);

    int64_t const actual_ns = read_monotonic_ns();
    return actual_ns - deadline_ns;
}

auto TimerBase::wait_until_deadline(int64_t mono_deadline_ns) noexcept -> WaitResult
{
    int64_t const sleep_deadline_ns = mono_deadline_ns + config_.compensation_ns;
    if (config_.busy_wait) {
        (void)wait_until_busy(sleep_deadline_ns, config_.busy_wait_threshold_ns);
    } else {
        (void)wait_until_absolute(sleep_deadline_ns);
    }

    return wait_result(read_monotonic_ns() - mono_deadline_ns);
}

auto TimerBase::wait_result(int64_t error_ns) const noexcept -> WaitResult
{
    // Guard against period_ns == 0 (CLI-settable via build_timer_arg_specs)
    // so we never divide by zero in the hot path.
    int64_t const skipped_counts = (config_.period_ns > 0 && error_ns > config_.period_ns) ? (error_ns / config_.period_ns) : 0;
    return {.error_ns = error_ns, .skipped_counts = skipped_counts};
}

auto TimerBase::wait_until_raw_deadline(int64_t raw_deadline_ns) noexcept -> WaitResult
{
    int64_t const target_raw_ns = raw_deadline_ns + config_.compensation_ns;
    track_raw_line(read_monotonic_raw_ns());
    sleep_early_for_raw(target_raw_ns);
    return wait_result(spin_until_raw(target_raw_ns) - raw_deadline_ns);
}

auto TimerBase::prime_raw_line() noexcept -> void
{
    // Two samples a millisecond apart give a rate good to ~100 ppm, which
    // the slew margin in sleep_early_for_raw covers; one sample alone would
    // leave the first sleep trusting rate 1.0 against a clock phc2sys may be
    // railing at 10%.
    (void)raw_tracker_.sample();
    (void)wait_until_absolute(read_monotonic_ns() + 1'000'000);
    (void)raw_tracker_.sample();
    raw_line_sampled_ns_ = read_monotonic_raw_ns();
}

auto TimerBase::track_raw_line(int64_t raw_now_ns) noexcept -> void
{
    if (raw_line_sampled_ns_ == 0) {
        prime_raw_line();
        return;
    }
    int64_t const interval_ns = config_.raw_line_sample_interval_ns;
    if (interval_ns <= 0 || raw_now_ns - raw_line_sampled_ns_ < interval_ns) {
        return;
    }
    (void)raw_tracker_.sample();
    raw_line_sampled_ns_ = raw_now_ns;
}

auto TimerBase::sleep_early_for_raw(int64_t target_raw_ns) noexcept -> void
{
    // The line's rate error after the 1 ms priming baseline, as a fraction;
    // added to the measured slew so the early wake stays early.
    constexpr double RATE_MARGIN = 100e-6;
    auto const line = raw_line_.consume();
    int64_t const remaining_ns = target_raw_ns - read_monotonic_raw_ns();
    int64_t const base_guard_ns = config_.busy_wait ? config_.busy_wait_threshold_ns : config_.raw_spin_guard_ns;
    int64_t const slew_guard_ns =
        remaining_ns > 0 ? static_cast<int64_t>((std::fabs(line.rate - 1.0) + RATE_MARGIN) * static_cast<double>(remaining_ns)) : 0;
    if (remaining_ns > base_guard_ns + slew_guard_ns) {
        (void)wait_until_absolute(raw_line_.to_monotonic_ns(target_raw_ns) - base_guard_ns - slew_guard_ns);
    }
}

auto TimerBase::spin_until_raw(int64_t target_raw_ns) noexcept -> int64_t
{
    int64_t now_ns = read_monotonic_raw_ns();
    while (now_ns < target_raw_ns) {
        cpu_relax();
        now_ns = read_monotonic_raw_ns();
    }
    return now_ns;
}

auto TimerBase::wait_until_busy(int64_t deadline_ns, int64_t threshold_ns) noexcept -> int64_t
{
    int64_t now_ns = read_monotonic_ns();
    int64_t const remaining_ns = deadline_ns - now_ns;

    // If we have more than threshold time remaining, sleep first
    if (remaining_ns > threshold_ns) {
        (void)wait_until_absolute(deadline_ns - threshold_ns);
    }

    // Busy-wait for remaining time (or all time if period < threshold)
    while ((now_ns = read_monotonic_ns()) < deadline_ns) {
        cpu_relax();
    }

    return now_ns - deadline_ns;
}

}  // namespace statusbar::realtime
