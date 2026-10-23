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

#include <array>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <csignal>
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

inline auto now_monotonic_raw_ns() noexcept -> int64_t
{
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return (static_cast<int64_t>(ts.tv_sec) * 1000000000LL) + ts.tv_nsec;
}

}  // namespace detail

/// One iteration of a busy-wait: a CPU spin hint (`pause` on x86, `yield` on
/// ARM) and no syscall. Lowers the power of the spin, frees execution
/// resources for a hyperthread sibling and avoids the memory-order mis-
/// speculation penalty on loop exit. Unlike sched_yield it never enters the
/// kernel, so a spin made of these lands within tens of nanoseconds of its
/// deadline rather than within a syscall round trip.
inline void cpu_relax() noexcept
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield" ::: "memory");
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

/// Name the calling thread, for `top -H`, `ps -L`, perf and gdb. Linux keeps
/// at most 15 characters; a longer name is truncated. Do not call it on a
/// process's main thread: there the name is the process name (`pgrep`,
/// `killall`, systemd's comm). A no-op where threads cannot be named.
inline void set_current_thread_name(std::string_view const name) noexcept
{
#if defined(__linux__) || defined(__APPLE__)
#    if defined(__linux__)
    constexpr std::size_t max_len = 15;
#    else
    constexpr std::size_t max_len = 63;
#    endif
    std::array<char, max_len + 1> buf{};
    std::size_t const n = name.size() < max_len ? name.size() : max_len;
    std::memcpy(buf.data(), name.data(), n);
#    if defined(__linux__)
    (void)::pthread_setname_np(::pthread_self(), buf.data());
#    else
    (void)::pthread_setname_np(buf.data());
#    endif
#else
    (void)name;
#endif
}

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

#if defined(__APPLE__)
inline auto ns_to_mach(uint64_t const ns) -> uint64_t
{
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return ns * tb.denom / tb.numer;
}

inline auto mach_to_ns(uint64_t const mach) -> uint64_t
{
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return mach * tb.numer / tb.denom;
}
#else
[[nodiscard]] constexpr auto timespec_to_ns(int64_t const tv_sec, int64_t const tv_nsec) noexcept
{
    return (tv_sec * 1'000'000'000LL) + tv_nsec;
}
#endif

inline auto read_monotonic_ns() noexcept -> int64_t
{
#if defined(__linux__)
    timespec ts;
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t const time_mono = timespec_to_ns(ts.tv_sec, ts.tv_nsec);
    return time_mono;
#elif defined(__APPLE__)
    uint64_t const mach_now = mach_absolute_time();
    return static_cast<int64_t>(mach_to_ns(mach_now));
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
