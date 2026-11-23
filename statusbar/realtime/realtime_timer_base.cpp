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

auto TimerBase::wait_until_absolute(MonotonicClock::time_point const deadline) noexcept -> Nanoseconds
{
    // A signal that cuts the sleep short is not a wake: sleep again to the
    // same deadline. Any other failure returns at once and the caller sees
    // the early wake in the error it is handed.
    int sleep_result = 0;
    do {
        sleep_result = sleep_until_monotonic(deadline);
    } while (sleep_result == EINTR);

    return read_monotonic() - deadline;
}

auto TimerBase::wait_until_raw_deadline(MonotonicRawClock::time_point const raw_deadline) noexcept -> WaitResult
{
    auto const target_raw = wake_target(raw_deadline);
    track_raw_line(read_monotonic_raw());
    if (auto const wake = early_wake(target_raw, read_monotonic_raw())) {
        (void)wait_until_absolute(*wake);
    }
    return wait_outcome(raw_deadline, spin_until_raw(target_raw));
}

auto TimerBase::prime_raw_line() noexcept -> void
{
    // Two samples a millisecond apart give a rate good to ~100 ppm, which
    // the slew margin in early_wake covers; one sample alone would
    // leave the first sleep trusting rate 1.0 against a clock phc2sys may be
    // railing at 10%.
    (void)raw_tracker_.sample();
    (void)wait_until_absolute(read_monotonic() + Nanoseconds{1'000'000});
    (void)raw_tracker_.sample();
    raw_line_sampled_ = read_monotonic_raw();
}

auto TimerBase::track_raw_line(MonotonicRawClock::time_point const raw_now) noexcept -> void
{
    if (!raw_line_sampled_) {
        prime_raw_line();
        return;
    }
    Nanoseconds const interval{config_.raw_line_sample_interval_ns};
    if (interval <= Nanoseconds::zero() || raw_now - *raw_line_sampled_ < interval) {
        return;
    }
    (void)raw_tracker_.sample();
    raw_line_sampled_ = raw_now;
}

auto TimerBase::early_wake(MonotonicRawClock::time_point const target_raw, MonotonicRawClock::time_point const raw_now)
    const noexcept -> std::optional<MonotonicClock::time_point>
{
    // The line's rate error after the 1 ms priming baseline, in parts per
    // billion; added to the measured slew so the early wake stays early.
    constexpr int64_t RATE_MARGIN_PPB = 100'000;
    auto const slew_ppb = static_cast<uint32_t>(raw_line_.rate_deviation_ppb() + RATE_MARGIN_PPB);
    Nanoseconds const remaining = target_raw - raw_now;
    Nanoseconds const guard = Nanoseconds{config_.busy_wait ? config_.busy_wait_threshold_ns : config_.raw_spin_guard_ns} +
        accumulated_drift(remaining, slew_ppb);
    if (remaining <= guard) {
        return std::nullopt;
    }
    return raw_line_.to_monotonic(target_raw) - guard;
}

auto TimerBase::spin_until_raw(MonotonicRawClock::time_point const target_raw) noexcept -> MonotonicRawClock::time_point
{
    auto now = read_monotonic_raw();
    while (now < target_raw) {
        cpu_relax();
        now = read_monotonic_raw();
    }
    return now;
}

}  // namespace statusbar::realtime
