#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Realtime Base Utilities
// Memory locking and realtime scheduling functions

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>

#include <sys/mman.h>
#include <sys/stat.h>

#if defined(__APPLE__)
#    include <mach/mach.h>
#    include <mach/mach_time.h>
#    include <mach/thread_policy.h>
#elif defined(__linux__)
#    include <sys/prctl.h>
#endif

#include "statusbar/itc/itc_stop_token.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <csignal>
#include <cstddef>
#include <print>
#include <string>
#include <string_view>

namespace statusbar::realtime {

namespace detail {

inline auto file_exists(char const* path) noexcept -> bool
{
    struct stat st{};
    return ::stat(path, &st) == 0;
}

auto write_all(int fd, std::string_view s) noexcept -> bool;

inline auto write_text(char const* path, std::string_view s) noexcept -> bool
{
    int const fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    bool const ok = write_all(fd, s);
    ::close(fd);
    return ok;
}

auto read_all(char const* path, std::string& out) -> bool;

inline void save_file(char const* src, std::string const& dst)
{
    std::string data;
    if (!read_all(src, data)) {
        return;
    }

    int const fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return;
    }

    (void)write_all(fd, data);
    ::close(fd);
}

/// CLOCK_MONOTONIC_RAW in nanoseconds: the raw hardware counter, immune to
/// the NTP/phc2sys frequency slew on CLOCK_MONOTONIC. The timing reference
/// clock; see read_monotonic_raw_ns() for the public spelling.
inline auto now_monotonic_raw_ns() noexcept -> int64_t
{
    timespec ts{};
#if defined(CLOCK_MONOTONIC_RAW)
    ::clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (static_cast<int64_t>(ts.tv_sec) * 1000000000LL) + ts.tv_nsec;
}

}  // namespace detail

//
// Result Types for Realtime Operations
//

/// Result of a realtime operation with optional error message.
///
/// This intentionally differs from Status/StatusValue (status.hpp) to avoid
/// dynamic allocation and std::error_code construction in realtime and
/// signal-handling contexts. Uses a static error message pointer and raw
/// errno for allocation-free, signal-safe error reporting.
struct RealtimeResult
{
    bool success{false};
    int error_code{0};
    char const* error_message{nullptr};

    explicit operator bool() const noexcept { return success; }

    /// Log failure to stderr if operation failed
    /// @param operation Name of the operation that was attempted
    void log_if_failed(std::string_view operation) const
    {
        if (!success) {
            if (error_message != nullptr) {
                std::print(stderr, "Warning: {} failed: {} (errno={})\n", operation, error_message, error_code);
            } else {
                std::print(stderr, "Warning: {} failed (errno={})\n", operation, error_code);
            }
        }
    }
};

/// Create a success result
[[nodiscard]] inline auto realtime_success() noexcept -> RealtimeResult
{
    return {.success = true, .error_code = 0, .error_message = nullptr};
}

/// Create a failure result from errno
[[nodiscard]] inline auto realtime_failure_errno() noexcept -> RealtimeResult
{
    return {.success = false, .error_code = errno, .error_message = std::strerror(errno)};
}

/// Create a failure result from an error code
/// @param err Error code (typically errno value)
[[nodiscard]] inline auto realtime_failure(int const err) noexcept -> RealtimeResult
{
    return {.success = false, .error_code = err, .error_message = std::strerror(err)};
}

/// Create a failure result with custom message
/// @param err Error code (typically errno value)
/// @param msg Human-readable error message
[[nodiscard]] inline auto realtime_failure(int const err, char const* const msg) noexcept -> RealtimeResult
{
    return {.success = false, .error_code = err, .error_message = msg};
}

//
// Memory Locking
//

/// Lock all currently mapped memory pages to prevent page faults.
/// MCL_FUTURE is intentionally omitted by default: it causes the MMU to
/// lock pages for unrelated allocations (heap, stack growth, shared
/// libraries), adding unpredictable latency. The application must touch
/// all required pages before calling this function.
/// Pass `lock_future = true` on memory-constrained hosts where any
/// unlocked page risks being swapped out under pressure (the
/// allocate-time lock cost is preferable to a multi-ms swap-in stall in
/// the RT loop).
/// Requires root or CAP_IPC_LOCK capability.
/// @return true on success, false if permission denied or error
[[nodiscard]] inline auto lock_memory(bool lock_future = false) noexcept -> bool
{
    int const flags = lock_future ? (MCL_CURRENT | MCL_FUTURE) : MCL_CURRENT;
    return mlockall(flags) == 0;
}

/// Lock memory with detailed result. See `lock_memory(bool)` for the
/// MCL_FUTURE tradeoff.
/// @return RealtimeResult with success status and error details
[[nodiscard]] inline auto lock_memory_ex(bool lock_future = false) noexcept -> RealtimeResult
{
    int const flags = lock_future ? (MCL_CURRENT | MCL_FUTURE) : MCL_CURRENT;
    if (mlockall(flags) == 0) {
        return realtime_success();
    }
    return realtime_failure_errno();
}

/// Unlock all memory pages locked by mlockall
/// @return true on success
[[nodiscard]] inline auto unlock_memory() noexcept -> bool
{
    return munlockall() == 0;
}

//
// Thread Priority - Platform-Specific Implementations
//

#if defined(__APPLE__)

/// macOS: Set thread to time-constraint (realtime) policy using Mach APIs
/// This is the preferred way to get realtime behavior on macOS.
/// Uses time-constraint policy which is designed for audio/video processing.
///
/// @param period_ns Nominal period between wakes in nanoseconds (e.g., 1000000 for 1ms)
/// @param computation_ns Max computation time per period in nanoseconds
/// @param constraint_ns Maximum time from start to finish (usually = period_ns)
/// @param preemptible Whether thread can be preempted during computation
/// @return RealtimeResult with success status and error details
[[nodiscard]] auto set_time_constraint_policy(
    uint32_t period_ns = 1'000'000,
    uint32_t computation_ns = 500'000,
    uint32_t constraint_ns = 1'000'000,
    bool preemptible = false) noexcept -> RealtimeResult;

/// macOS: Set thread to high priority using precedence policy
/// Less strict than time-constraint but easier to obtain.
/// Priority range is typically 0-63, with higher being more important.
///
/// @param importance Priority importance (-127 to 127, higher = more important)
/// @return RealtimeResult with success status and error details
[[nodiscard]] inline auto set_thread_precedence(int const importance = 63) noexcept -> RealtimeResult
{
    thread_precedence_policy_data_t policy;
    policy.importance = importance;

    kern_return_t const kr = thread_policy_set(
        mach_thread_self(),
        THREAD_PRECEDENCE_POLICY,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — Mach API requires thread_policy_t
        reinterpret_cast<thread_policy_t>(&policy),
        THREAD_PRECEDENCE_POLICY_COUNT);

    if (kr != KERN_SUCCESS) {
        return realtime_failure(static_cast<int>(kr), mach_error_string(kr));
    }

    return realtime_success();
}

/// macOS: Set current thread to highest available priority
/// Tries time-constraint policy first (requires specific entitlements for some settings),
/// falls back to high precedence policy.
/// @return RealtimeResult with success status and error details
[[nodiscard]] inline auto set_realtime_priority_ex() noexcept -> RealtimeResult
{
    // Try time-constraint policy first (best for realtime audio)
    // Use conservative defaults that should work without special entitlements
    auto result = set_time_constraint_policy(1'000'000, 500'000, 1'000'000, false);
    if (result) {
        return result;
    }

    // Fall back to high precedence policy
    return set_thread_precedence(63);
}

#else  // Linux

/// Linux: Set current thread to SCHED_FIFO with specified priority
/// Requires root or CAP_SYS_NICE capability.
/// @param priority Priority level (1 to sched_get_priority_max(SCHED_FIFO))
/// @return RealtimeResult with success status and error details
[[nodiscard]] inline auto set_realtime_priority_ex(int const priority) noexcept -> RealtimeResult
{
    sched_param param{};
    param.sched_priority = priority;

    int const err = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    if (err != 0) {
        return realtime_failure(err);
    }

    return realtime_success();
}

/// Linux: Set current thread to SCHED_FIFO with maximum priority
/// @return RealtimeResult with success status and error details
[[nodiscard]] inline auto set_realtime_priority_ex() noexcept -> RealtimeResult
{
    return set_realtime_priority_ex(sched_get_priority_max(SCHED_FIFO));
}

#endif

//
// System Configuration and Diagnostics
//

/// Diagnostic information about realtime capabilities
struct RealtimeCapabilities
{
    bool can_use_realtime{false};   ///< Can set SCHED_FIFO priority
    bool is_root{false};            ///< Running as root
    bool has_preempt_rt{false};     ///< Kernel has PREEMPT_RT
    bool has_isolated_cpus{false};  ///< System has isolated CPUs
    std::string isolated_cpus;      ///< List of isolated CPUs (e.g., "3")
    std::string recommendations;    ///< Recommendations for improving realtime performance
};

/// Check realtime capabilities and return diagnostic information
/// This function can be called by non-root users to diagnose realtime setup.
/// @return Diagnostic information about system capabilities
[[nodiscard]] auto check_realtime_capabilities() -> RealtimeCapabilities;

/// Prepare an isolated CPU for realtime operation
/// This function configures CPU-specific settings for optimal realtime performance.
/// Requires root privileges on Linux.
///
/// @param cpu CPU number to prepare (e.g., 3 for CPU3)
/// @return Result with success status and error details
///
/// Operations performed:
/// - Set CPU governor to "performance" (disable frequency scaling)
/// - Set timer slack to 0 for calling thread
/// - Verify CPU is isolated (if /sys/devices/system/cpu/isolated exists)
[[nodiscard]] auto prepare_isolated_cpu(int cpu) noexcept -> RealtimeResult;

/// Prepare system for realtime operation
/// This function performs system-wide configuration for realtime operation.
/// Should be called once at program startup. Requires root privileges on Linux.
///
/// @param verbose If true, print diagnostic messages to stdout
/// @return Result with success status and error details
///
/// Operations performed:
/// - Lock all memory (current and future) to prevent page faults
/// - Set sched_rt_runtime_us to unlimited (-1) to allow 100% CPU for RT threads
/// - Disable timer migration to reduce latency
[[nodiscard]] auto prepare_realtime_system(bool verbose, bool lock_future = false) -> RealtimeResult;

/// Set current thread to SCHED_FIFO with maximum priority (legacy interface)
/// Requires root or CAP_SYS_NICE capability on Linux.
/// On macOS, uses Mach thread policies for realtime behavior.
/// @return true on success, false if permission denied or error
[[nodiscard]] inline auto set_realtime_priority() noexcept -> bool
{
    return static_cast<bool>(set_realtime_priority_ex());
}

/// Set current thread to SCHED_FIFO with specified priority (legacy interface)
/// @param priority Priority level (1 to sched_get_priority_max(SCHED_FIFO))
/// @return true on success, false if permission denied or error
[[nodiscard]] inline auto set_realtime_priority(int const priority) noexcept -> bool
{
#if defined(__APPLE__)
    // On macOS, ignore the priority parameter and use time-constraint policy
    (void)priority;
    return static_cast<bool>(set_realtime_priority_ex());
#else
    sched_param param{};
    param.sched_priority = priority;
    return pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0;
#endif
}

//
// CPU Affinity
//

/// Set current thread to run on specified CPU.
/// @param cpu CPU number.
/// @return RealtimeResult with success status and error details
/// @note On macOS, CPU affinity is a hint via affinity tags, not a hard constraint.
[[nodiscard]] auto set_realtime_affinity_ex(int cpu) noexcept -> RealtimeResult;

/// Set current thread to run on specified CPU (legacy interface).
/// @param cpu CPU number.
/// @return true on success, false if permission denied or error
[[nodiscard]] inline auto set_realtime_affinity(int const cpu) noexcept -> bool
{
    return static_cast<bool>(set_realtime_affinity_ex(cpu));
}

//
// Additional Scheduling Functions
//

/// Set current thread to SCHED_RR (round-robin) with maximum priority
/// @return true on success, false if permission denied or error
[[nodiscard]] inline auto set_realtime_rr_priority() noexcept -> bool
{
#if defined(__APPLE__)
    // macOS doesn't really support SCHED_RR, use precedence policy instead
    return static_cast<bool>(set_thread_precedence(63));
#else
    sched_param param{};
    param.sched_priority = sched_get_priority_max(SCHED_RR);
    return pthread_setschedparam(pthread_self(), SCHED_RR, &param) == 0;
#endif
}

/// Reset current thread to normal scheduling (SCHED_OTHER)
/// @return true on success
[[nodiscard]] inline auto reset_scheduling() noexcept -> bool
{
#if defined(__APPLE__)
    // Reset to standard policy
    thread_standard_policy_data_t policy;
    kern_return_t const kr = thread_policy_set(
        mach_thread_self(),
        THREAD_STANDARD_POLICY,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — Mach API requires thread_policy_t
        reinterpret_cast<thread_policy_t>(&policy),
        THREAD_STANDARD_POLICY_COUNT);
    return kr == KERN_SUCCESS;
#else
    sched_param param{};
    param.sched_priority = 0;
    return pthread_setschedparam(pthread_self(), SCHED_OTHER, &param) == 0;
#endif
}

/// Get maximum priority for SCHED_FIFO
[[nodiscard]] inline auto get_max_fifo_priority() noexcept -> int
{
    return sched_get_priority_max(SCHED_FIFO);
}

/// Get minimum priority for SCHED_FIFO
[[nodiscard]] inline auto get_min_fifo_priority() noexcept -> int
{
    return sched_get_priority_min(SCHED_FIFO);
}

//
// Spin Hints and Thread Names
//

/// Tell the CPU that this is a spin-wait: `pause` on x86, `yield` on ARM.
/// A spin loop without it burns the pipeline, slows the sibling hyperthread
/// and draws power for nothing.
///
/// It is only a hint, so correctness must never depend on it — an
/// architecture with no such instruction compiles to an empty function
/// rather than failing the build. The per-architecture spelling lives here
/// once because it is exactly the kind of thing that gets copied wrongly.
inline void cpu_relax() noexcept
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield");
#endif
}

/// The longest thread name the kernel keeps, NUL included — Linux's
/// TASK_COMM_LEN. A name at or over this length is refused outright by
/// prctl()/pthread_setname_np(), so we truncate to fit instead.
inline constexpr std::size_t thread_name_max = 16;

/// Name the calling thread, so `top -H`, `perf` and a core dump say
/// `rt-timer` instead of an anonymous LWP id. That is the difference
/// between a bug report we can act on and one we cannot.
///
/// A name longer than 15 bytes is truncated here, before the call. It has
/// to be: `pthread_setname_np()` returns ERANGE for an over-long name and
/// sets nothing, leaving the thread anonymous — the exact outcome this
/// function exists to prevent. (Linux's `prctl(PR_SET_NAME)` would truncate
/// for us instead, but then the behaviour would be the platform's rather
/// than ours, and macOS allows 64 bytes where Linux allows 15. Truncating
/// here means one name, the same everywhere.) Prefer short prefixed names
/// (`rt-timer`, `avtp-tx`) that stay distinguishable once truncated.
///
/// An empty name is a no-op rather than a request to erase the name a
/// thread already has — a caller passing an unset config value should not
/// silently anonymise the thread.
///
/// Never fails and never throws: a thread must not break because naming it
/// did. Takes no thread handle because macOS can only name the current
/// thread, and an API we cannot implement portably is worse than a narrow
/// one.
/// @param name The name to set; truncated to 15 bytes
inline void set_current_thread_name(std::string_view name) noexcept
{
    if (name.empty()) {
        return;
    }
    std::array<char, thread_name_max> buf{};
    std::size_t const n = std::min(name.size(), buf.size() - 1);
    std::copy_n(name.data(), n, buf.data());
    buf[n] = '\0';

#if defined(__linux__)
    (void)::pthread_setname_np(::pthread_self(), buf.data());
#elif defined(__APPLE__)
    (void)::pthread_setname_np(buf.data());  // macOS names only the caller
#else
    (void)buf;  // no thread names on this platform
#endif
}

//
// Convenience Functions with Logging
//

/// Set realtime priority with automatic logging on failure
/// @param operation_name Name to use in log messages (e.g., "PTP timer thread")
/// @return true on success
[[nodiscard]] inline auto set_realtime_priority_logged(std::string_view const operation_name = "Thread") -> bool
{
    auto result = set_realtime_priority_ex();
    result.log_if_failed(std::string(operation_name) + " realtime priority");
    return result.success;
}

/// Set realtime priority with specified priority and automatic logging on failure
/// @param priority SCHED_FIFO priority (1-99 on Linux)
/// @param operation_name Name to use in log messages (e.g., "PTP timer thread")
/// @return true on success
[[nodiscard]] inline auto set_realtime_priority_logged(int const priority, std::string_view const operation_name = "Thread") -> bool
{
#if defined(__APPLE__)
    // On macOS, ignore priority and use time-constraint policy
    (void)priority;
    return set_realtime_priority_logged(operation_name);
#else
    auto result = set_realtime_priority_ex(priority);
    result.log_if_failed(std::string(operation_name) + " realtime priority");
    return result.success;
#endif
}

/// Set CPU affinity with automatic logging on failure
/// @param cpu CPU number
/// @param operation_name Name to use in log messages
/// @return true on success
[[nodiscard]] inline auto set_realtime_affinity_logged(int const cpu, std::string_view const operation_name = "Thread") -> bool
{
    auto result = set_realtime_affinity_ex(cpu);
    result.log_if_failed(std::string(operation_name) + " CPU affinity");
    return result.success;
}

/// Lock memory with automatic logging on failure
/// @return true on success
[[nodiscard]] inline auto lock_memory_logged() -> bool
{
    auto result = lock_memory_ex();
    result.log_if_failed("Memory locking");
    return result.success;
}

[[nodiscard]] constexpr auto timespec_to_ns(int64_t const tv_sec, int64_t const tv_nsec) noexcept
{
    return (tv_sec * 1'000'000'000LL) + tv_nsec;
}

#if defined(__APPLE__)
/// Nanoseconds to mach_absolute_time ticks, for the relative wait in
/// sleep_until_monotonic_ns(). Mach's own counter stops while the machine
/// sleeps (it is CLOCK_UPTIME_RAW), so it never carries an absolute deadline.
inline auto ns_to_mach(uint64_t const ns) -> uint64_t
{
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return ns * tb.denom / tb.numer;
}
#endif

/// CLOCK_MONOTONIC in nanoseconds, read with clock_gettime on every
/// platform (macOS has had it since 10.12, with the same meaning as Linux:
/// it keeps counting through a system sleep and NTP slews its rate). This
/// is the clock the kernel sleeps on: use it for sleeping, not for timing.
/// Timing, stamps and deadlines take read_monotonic_raw_ns().
inline auto read_monotonic_ns() noexcept -> int64_t
{
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return timespec_to_ns(ts.tv_sec, ts.tv_nsec);
}

/// CLOCK_MONOTONIC_RAW in nanoseconds: the timing reference clock, immune
/// to frequency slew. Not sleepable; a deadline on it is reached by sleeping
/// early on CLOCK_MONOTONIC through a MonotonicRawLine and spinning here.
inline auto read_monotonic_raw_ns() noexcept -> int64_t
{
    return detail::now_monotonic_raw_ns();
}

/// Sleep until an absolute CLOCK_MONOTONIC deadline, the one kernel sleep
/// primitive every sleeper goes through. Returns 0 when the deadline has
/// passed (a missed or non-positive deadline returns at once rather than
/// failing with EINVAL), EINTR when a signal cut the sleep short on Linux,
/// or the errno of a failed clock_nanosleep. On macOS there is no
/// clock_nanosleep, so the wait is relative: the remaining nanoseconds are
/// handed to mach_wait_until from mach_absolute_time, which is a different
/// counter (it stops in system sleep) but the same rate over one wait.
inline auto sleep_until_monotonic_ns(int64_t const deadline_ns) noexcept -> int
{
    int64_t const remaining_ns = deadline_ns - read_monotonic_ns();
    if (remaining_ns <= 0) {
        return 0;
    }
#if defined(__linux__)
    timespec const deadline{
        .tv_sec = static_cast<time_t>(deadline_ns / 1'000'000'000LL), .tv_nsec = static_cast<long>(deadline_ns % 1'000'000'000LL)};
    return ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, nullptr);
#elif defined(__APPLE__)
    (void)::mach_wait_until(::mach_absolute_time() + ns_to_mach(static_cast<uint64_t>(remaining_ns)));
    return 0;
#else
#    error "Unsupported platform"
#endif
}

//
// Diagnostic Output and Initialization
//

/// Print realtime capabilities and prepare system for realtime operation.
/// This is a convenience function that:
/// 1. Checks and prints realtime capabilities
/// 2. Prepares the system for realtime operation
/// 3. Prints any recommendations for improving performance
///
/// Typical output:
///   Realtime Capabilities:
///     Running as root: yes
///     Can use SCHED_FIFO: yes
///     PREEMPT_RT kernel: no
///     Has isolated CPUs: no
///
///   Recommendations:
///   Consider using a PREEMPT_RT kernel for better realtime performance.
///
///   System prepared for realtime operation
///
/// @param verbose If true, print capability details and recommendations to stdout
/// @param lock_future If true, mlockall uses MCL_FUTURE in addition to MCL_CURRENT
/// @return RealtimeResult from prepare_realtime_system()
auto print_realtime_diagnostics_and_prepare(bool verbose = true, bool lock_future = false) -> RealtimeResult;

//
// Signal Handling for Clean Shutdown
//
// The process-wide shutdown token is the same instance vended by
// statusbar::itc::install_stop_signal().  All realtime timers and other
// callers share a single coordinated stop signal.
//

/// Return a reference to the process-wide shutdown token.
/// Installs SIGINT/SIGTERM/SIGPIPE handlers on first call (idempotent).
/// This is the canonical accessor; all other helpers below delegate to it.
[[nodiscard]] auto shutdown_token() noexcept -> statusbar::itc::StopToken&;

/// Check if shutdown has been requested (via signal or request_shutdown())
/// @return true if shutdown was requested
[[nodiscard]] inline auto is_shutdown_requested() noexcept -> bool
{
    return shutdown_token().stop_requested();
}

/// Request a shutdown (sets the shutdown flag and notifies waiters)
/// Can be called from any thread. NOT signal-safe — use handle_shutdown_signal
/// from signal handlers.
inline void request_shutdown() noexcept
{
    shutdown_token().request_stop();
}

/// Signal handler that requests shutdown (signal-safe variant).
/// Writes through signal_set() which sets only the atomic flag without
/// calling notify_all (not async-signal-safe).
inline void handle_shutdown_signal(int /* sig */)
{
    shutdown_token().signal_set();
}

/// Set up signal handlers for clean shutdown (SIGINT, SIGTERM, SIGPIPE).
/// Delegates to statusbar::itc::install_stop_signal() — idempotent.
/// - SIGINT and SIGTERM call signal_set() on the shared StopToken.
/// - SIGPIPE is ignored (common for network applications).
inline void setup_shutdown_signal_handlers()
{
    (void)statusbar::itc::install_stop_signal();
}

}  // namespace statusbar::realtime
