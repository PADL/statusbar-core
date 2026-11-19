// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Implementation of large non-template functions extracted from realtime_base.hpp

#include "statusbar/realtime/realtime_base.hpp"

#include <optional>
#include <utility>

namespace statusbar::realtime {

namespace detail {

auto write_all(int fd, std::string_view s) noexcept -> bool
{
    char const* p = s.data();
    size_t n = s.size();
    while (n > 0) {
        ssize_t const w = ::write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        p += static_cast<size_t>(w);
        n -= static_cast<size_t>(w);
    }
    return true;
}

namespace {

/// Append everything `fd` has left to `out`. False on a read error.
auto append_all(int const fd, std::string& out) -> bool
{
    char buf[1 << 16];
    for (;;) {
        ssize_t const r = ::read(fd, buf, sizeof(buf));
        if (r == 0) {
            return true;
        }
        if (r < 0 && errno != EINTR) {
            return false;
        }
        if (r > 0) {
            out.append(buf, static_cast<size_t>(r));
        }
    }
}

}  // namespace

auto read_all(char const* path, std::string& out) -> bool
{
    int const fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    out.clear();
    bool const ok = append_all(fd, out);
    ::close(fd);
    return ok;
}

}  // namespace detail

namespace {

/// Recursively grow the stack in 4096-byte chunks, writing each chunk so the
/// kernel commits a physical page for every stack page the chunks span.
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

/// Whether this thread may take SCHED_FIFO: tried, then undone.
[[nodiscard]] auto can_use_sched_fifo() noexcept -> bool
{
#if defined(__linux__)
    sched_param param{};
    param.sched_priority = 1;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
        return false;
    }
    param.sched_priority = 0;
    (void)pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);
    return true;
#else
    return true;  // macOS doesn't require root for thread priorities
#endif
}

/// Whether the running kernel is a PREEMPT_RT build (Linux; false elsewhere).
[[nodiscard]] auto kernel_is_preempt_rt() -> bool
{
#if defined(__linux__)
    std::string version;
    if (!detail::read_all("/proc/version", version)) {
        return false;
    }
    return version.find("PREEMPT_RT") != std::string::npos || version.find("PREEMPT RT") != std::string::npos;
#else
    return false;
#endif
}

/// The kernel's isolated CPU list ("3", "2-3", "2,3" ...), trailing
/// whitespace removed; nothing when the kernel does not say.
[[nodiscard]] auto isolated_cpu_list() -> std::optional<std::string>
{
#if defined(__linux__)
    std::string isolated;
    if (!detail::read_all("/sys/devices/system/cpu/isolated", isolated)) {
        return std::nullopt;
    }
    while (!isolated.empty() && (std::isspace(isolated.back()) != 0)) {
        isolated.pop_back();
    }
    return isolated;
#else
    return std::nullopt;
#endif
}

/// What the host could do better for real-time work, one line each.
[[nodiscard]] auto recommendations_for(RealtimeCapabilities const& caps) -> std::string
{
#if defined(__linux__)
    std::string text;
    if (!caps.can_use_realtime) {
        text += "Run as root or add CAP_SYS_NICE capability.\n";
    }
    if (!caps.has_preempt_rt) {
        text += "Consider using a PREEMPT_RT kernel for better realtime performance.\n";
    }
    if (!caps.has_isolated_cpus) {
        text += "Consider isolating CPUs with isolcpus= boot parameter (e.g., isolcpus=3 for CPU 3).\n";
    }
    return text;
#else
    (void)caps;
    return "macOS uses Mach thread policies; no special setup required.\n";
#endif
}

/// Print what the host offers for real-time work.
auto print_capabilities(RealtimeCapabilities const& caps) -> void
{
    std::print("Realtime Capabilities:\n  Running as root: {}\n", caps.is_root ? "yes" : "no");
    std::print("  Can use SCHED_FIFO: {}\n", caps.can_use_realtime ? "yes" : "no");
    std::print("  PREEMPT_RT kernel: {}\n", caps.has_preempt_rt ? "yes" : "no");
    std::print("  Has isolated CPUs: {}\n", caps.has_isolated_cpus ? "yes" : "no");
    if (caps.has_isolated_cpus) {
        std::print("  Isolated CPUs: {}\n", caps.isolated_cpus);
    }
    if (!caps.recommendations.empty()) {
        std::print("\nRecommendations:\n{}\n", caps.recommendations);
    }
}

#if defined(__linux__)

/// Ask for the "performance" cpufreq governor on `cpu`: a warning when the
/// host refuses, a note when it has no frequency scaling.
auto set_performance_governor(int const cpu) -> void
{
    std::string const governor_path =
        std::string("/sys/devices/system/cpu/cpu") + std::to_string(cpu) + "/cpufreq/scaling_governor";
    if (!detail::file_exists(governor_path.c_str())) {
        std::print(stderr, "Info: CPU{} frequency scaling not available (file does not exist)\n", cpu);
        return;
    }
    if (!detail::write_text(governor_path.c_str(), "performance\n")) {
        std::print(
            stderr,
            "Warning: Failed to set CPU{} governor to performance (errno={}). This may reduce timer accuracy.\n",
            cpu,
            errno);
    }
}

/// A warning when the kernel's isolated list does not name `cpu`.
auto warn_if_not_isolated(int const cpu) -> void
{
    auto const isolated = isolated_cpu_list();
    if (!isolated) {
        return;
    }
    // Simple check: see if the CPU number appears in the isolated list.
    if (isolated->empty() || isolated->find(std::to_string(cpu)) == std::string::npos) {
        std::print(stderr, "Warning: CPU{} is not isolated. Consider adding isolcpus={} to kernel boot parameters.\n", cpu, cpu);
    }
}

#endif

}  // namespace

auto prefault_stack(size_t const bytes) noexcept -> void
{
    prefault_stack_4096(bytes);
}

auto check_realtime_capabilities() -> RealtimeCapabilities
{
    std::string isolated = isolated_cpu_list().value_or(std::string{});
    RealtimeCapabilities caps{
        .can_use_realtime = can_use_sched_fifo(),
        .is_root = (geteuid() == 0),
        .has_preempt_rt = kernel_is_preempt_rt(),
        .has_isolated_cpus = !isolated.empty(),
        .isolated_cpus = std::move(isolated),
    };
    caps.recommendations = recommendations_for(caps);
    return caps;
}

auto prepare_isolated_cpu(int const cpu) noexcept -> RealtimeResult
{
#if defined(__linux__)
    // Set timer slack to 0 for minimal timer latency
    if (prctl(PR_SET_TIMERSLACK, 0) != 0) {
        std::print(stderr, "Warning: Failed to set timer slack to 0 (errno={})\n", errno);
    }
    set_performance_governor(cpu);
    warn_if_not_isolated(cpu);
    return realtime_success();
#elif defined(__APPLE__)
    (void)cpu;
    return realtime_success();  // macOS doesn't need CPU-specific setup
#else
    (void)cpu;
    return realtime_failure(ENOTSUP, "CPU preparation not supported on this platform");
#endif
}

auto prepare_realtime_system(bool const verbose, bool const lock_future) -> RealtimeResult
{
    // Lock memory first
    auto mem_result = lock_memory_ex(lock_future);
    if (!mem_result) {
        mem_result.log_if_failed("Memory locking");
    }

#if defined(__linux__)
    // Set RT runtime to unlimited (allow RT threads to use 100% CPU)
    if (!detail::write_text("/proc/sys/kernel/sched_rt_runtime_us", "-1\n")) {
        std::print(stderr, "Warning: Failed to set sched_rt_runtime_us to -1 (errno={})\n", errno);
        std::print(stderr, "         RT threads may be throttled. Run as root or set manually.\n");
    }

    // Disable timer migration for isolated CPUs (reduces wakeup latency by 2-4us)
    if (!detail::write_text("/proc/sys/kernel/timer_migration", "0\n")) {
        std::print(stderr, "Warning: Failed to disable timer_migration (errno={})\n", errno);
        std::print(stderr, "         This may add 2-4us latency to timer wakeups.\n");
    } else {
        if (verbose) {
            std::print("Disabled timer migration for better RT performance\n");
        }
    }
#endif

    return mem_result;  // Return memory locking result as primary indicator
}

auto print_realtime_diagnostics_and_prepare(bool const verbose, bool const lock_future) -> RealtimeResult
{
    if (verbose) {
        print_capabilities(check_realtime_capabilities());
    }
    // Prepare system for realtime operation
    auto sys_result = prepare_realtime_system(verbose, lock_future);
    if (sys_result) {
        if (verbose) {
            std::print("System prepared for realtime operation\n");
        }
    } else {
        sys_result.log_if_failed("System preparation");
    }

    return sys_result;
}

auto set_realtime_affinity_ex(int const cpu) noexcept -> RealtimeResult
{
#if defined(__linux__)
    cpu_set_t set{};
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    int const err = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (err != 0) {
        return realtime_failure(err);
    }
    return realtime_success();
#elif defined(__APPLE__)
    // macOS uses affinity tags as hints, not hard constraints
    // The system will try to keep threads with the same tag on the same CPU
    thread_affinity_policy_data_t policy;
    policy.affinity_tag = cpu + 1;  // 0 means no affinity, so use cpu+1

    kern_return_t const kr = thread_policy_set(
        mach_thread_self(),
        THREAD_AFFINITY_POLICY,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — Mach API requires thread_policy_t
        reinterpret_cast<thread_policy_t>(&policy),
        THREAD_AFFINITY_POLICY_COUNT);

    if (kr != KERN_SUCCESS) {
        return realtime_failure(static_cast<int>(kr), mach_error_string(kr));
    }
    return realtime_success();
#else
    (void)cpu;
    return realtime_failure(ENOTSUP, "CPU affinity not supported on this platform");
#endif
}

#if defined(__APPLE__)

namespace {

/// The Mach time-constraint policy for these nanosecond figures:
/// absolute_time = nanoseconds * timebase.denom / timebase.numer.
[[nodiscard]] auto time_constraint_policy(
    mach_timebase_info_data_t const& timebase,
    uint32_t const period_ns,
    uint32_t const computation_ns,
    uint32_t const constraint_ns,
    bool const preemptible) noexcept -> thread_time_constraint_policy_data_t
{
    auto ns_to_abs = [&](uint32_t ns) -> uint32_t {
        return static_cast<uint32_t>((static_cast<uint64_t>(ns) * timebase.denom) / timebase.numer);
    };
    return thread_time_constraint_policy_data_t{
        .period = ns_to_abs(period_ns),
        .computation = ns_to_abs(computation_ns),
        .constraint = ns_to_abs(constraint_ns),
        .preemptible = preemptible ? TRUE : FALSE,
    };
}

}  // namespace

auto set_time_constraint_policy(
    uint32_t const period_ns, uint32_t const computation_ns, uint32_t const constraint_ns, bool const preemptible) noexcept
    -> RealtimeResult
{
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS) {
        return realtime_failure(EINVAL, "Failed to get Mach timebase info");
    }
    auto policy = time_constraint_policy(timebase, period_ns, computation_ns, constraint_ns, preemptible);
    kern_return_t const kr = thread_policy_set(
        mach_thread_self(),
        THREAD_TIME_CONSTRAINT_POLICY,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — Mach API requires thread_policy_t
        reinterpret_cast<thread_policy_t>(&policy),
        THREAD_TIME_CONSTRAINT_POLICY_COUNT);
    if (kr != KERN_SUCCESS) {
        return realtime_failure(static_cast<int>(kr), mach_error_string(kr));
    }
    return realtime_success();
}

#endif

}  // namespace statusbar::realtime
