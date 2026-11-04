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

#if defined(__linux__)
#    include <ctime>
#elif defined(__APPLE__)
#    include <mach/mach_time.h>
#endif

namespace statusbar::realtime {

namespace {

#if defined(__linux__)
/// Build a timespec for clock_nanosleep(TIMER_ABSTIME) from a monotonic
/// nanosecond deadline. A non-positive deadline (already missed, or clock
/// skew during shutdown) is clamped to {0, 0}, which makes the call return
/// immediately rather than failing with EINVAL — the original split via
/// `tv_sec = ns/1e9, tv_nsec = ns%1e9` produced a negative tv_nsec for
/// negative ns (C++ truncates toward zero), and EINVAL is not in the
/// EINTR-only retry loop, so the call would silently return failure and the
/// caller would spin.
[[nodiscard]] inline auto ns_to_abs_timespec(int64_t ns) noexcept -> struct timespec
{
    if (ns <= 0) {
        return {.tv_sec = 0, .tv_nsec = 0};
    }
    return {.tv_sec = static_cast<time_t>(ns / 1'000'000'000LL), .tv_nsec = static_cast<long>(ns % 1'000'000'000LL)};
}
#endif

/// Recursively grow the stack in 4096-byte chunks, writing each chunk so the
/// kernel commits a physical page for every stack page the chunks span. This
/// is the classic RT-programming "stack prefault" step that, combined with
/// mlockall(MCL_CURRENT), prevents page faults inside the hot loop.
///
/// The chunk size intentionally does not depend on the platform page size —
/// touching any byte of a page commits the whole page, and consecutive frames
/// are contiguous on the stack, so a 4 KB chunk trivially hits every page on
/// 4 KB, 16 KB (Apple Silicon), and 64 KB page systems alike.
///
/// noinline + the post-recursion volatile read block tail-call optimization,
/// which would otherwise collapse the recursion and leave the stack ungrown.
// clang-format off
// Keep [[gnu::noinline]] on its own line — clang-19 leaves it, clang-22+
// rewraps it. Wrap-off lets both versions produce identical output.
[[gnu::noinline]] auto
prefault_stack_4096(size_t remaining_bytes) noexcept -> void
// clang-format on
{
    if (remaining_bytes == 0) {
        return;
    }
    constexpr size_t chunk = 4096;
    char volatile buf[chunk] = {};
    size_t const next = (remaining_bytes > chunk) ? remaining_bytes - chunk : 0;
    prefault_stack_4096(next);
    asm volatile("" : : "r"(&buf[0]) : "memory");
}

}  // namespace

TimerBase::TimerBase(TimerConfig config) noexcept
    : config_{config}
    , stats_{config_.error_histogram, config_.duration_histogram}
{}

TimerBase::~TimerBase() noexcept = default;

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
    if (!try_stop()) {
        return;  // Not running
    }
    if (timer_thread_.joinable()) {
        timer_thread_.join();
    }
}

auto TimerBase::prepare_thread() -> bool
{
    stats_.reset();

    // Pre-fault stack to avoid page faults in the RT loop (skipped when 0).
    if (config_.stack_prefault_bytes > 0) {
        prefault_stack_4096(config_.stack_prefault_bytes);
    }

    // Prepare isolated CPU (sets governor, timer slack, etc.)
    if (config_.cpu >= 0) {
        (void)prepare_isolated_cpu(config_.cpu);
    }

    // Set CPU affinity
    if (config_.cpu >= 0) {
        auto affinity_result = set_realtime_affinity_ex(config_.cpu);
        if (!affinity_result) {
            affinity_result.log_if_failed("Timer CPU affinity");
            if (config_.strict_affinity) {
                std::print(stderr, "Error: strict_affinity is set but CPU affinity failed - timer thread exiting\n");
                return false;
            }
        }
    }

    // Set realtime priority (SCHED_FIFO)
    (void)set_realtime_priority_logged(config_.priority, "Timer");

    // Lock memory to prevent page faults
    (void)lock_memory_ex();

    return true;
}

auto TimerBase::wait_until_absolute(int64_t deadline_ns) noexcept -> int64_t
{
#if defined(__linux__)
    // Use clock_nanosleep with absolute deadline for maximum precision
    struct timespec const deadline = ns_to_abs_timespec(deadline_ns);

    int sleep_result = 0;
    do {
        sleep_result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, nullptr);
    } while (sleep_result == EINTR);

#elif defined(__APPLE__)
    uint64_t const mach_deadline = static_cast<uint64_t>(ns_to_mach(static_cast<uint64_t>(deadline_ns)));
    mach_wait_until(mach_deadline);
#else
#    error "Unsupported platform"
#endif

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
        int64_t const sleep_until_ns = deadline_ns - threshold_ns;

#if defined(__linux__)
        struct timespec const sleep_deadline = ns_to_abs_timespec(sleep_until_ns);
        int sleep_result = 0;
        do {
            sleep_result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_deadline, nullptr);
        } while (sleep_result == EINTR);

#elif defined(__APPLE__)
        uint64_t const mach_sleep_deadline = static_cast<uint64_t>(ns_to_mach(static_cast<uint64_t>(sleep_until_ns)));
        mach_wait_until(mach_sleep_deadline);
#endif
    }

    // Busy-wait for remaining time (or all time if period < threshold)
    while ((now_ns = read_monotonic_ns()) < deadline_ns) {
        cpu_relax();
    }

    return now_ns - deadline_ns;
}

}  // namespace statusbar::realtime
