#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A CPU's idle states and its PM QoS resume-latency limit, as sysfs gives them
/// (Documentation/admin-guide/pm/cpuidle.rst, Documentation/ABI/testing/sysfs-devices-power).
/// For start-up only: every call reads or writes files.

#include "statusbar/status/status.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::realtime {

/// Where the kernel lists the CPUs (Documentation/ABI/testing/sysfs-devices-system-cpu).
inline constexpr std::string_view CPU_SYSFS = "/sys/devices/system/cpu";

/// One cpuidle state: `cpuN/cpuidle/stateK/name` and `latency`, its exit latency in microseconds.
struct CpuIdleState
{
    std::string name;
    uint32_t latency_us{0};

    auto operator==(CpuIdleState const&) const noexcept -> bool = default;
};

/// The CPUs a sysfs CPU list names ("3,9", "0-2,8"), in its order; invalid_argument for anything else.
[[nodiscard]] auto parse_cpu_list(std::string_view text) -> StatusValue<std::vector<int>>;

/// One CPU's topology, cpuidle and PM QoS files under `root`: CPU_SYSFS, or a test's fake tree.
class CpuSysfs
{
  public:
    explicit CpuSysfs(std::string root = std::string{CPU_SYSFS});

    /// `cpu` and its SMT siblings (`topology/thread_siblings_list`); the read's error when it fails.
    [[nodiscard]] auto thread_siblings(int cpu) const -> StatusValue<std::vector<int>>;

    /// `cpu`'s idle states, shallowest first; no_such_file_or_directory when it has no cpuidle.
    [[nodiscard]] auto idle_states(int cpu) const -> StatusValue<std::vector<CpuIdleState>>;

    /// Lets `cpu` enter only idle states whose exit latency is at most `limit_us` (`power/pm_qos_resume_latency_us`);
    /// 0 is written as "n/a", since a written 0 lifts the limit. It outlives the process. The write's error.
    [[nodiscard]] auto set_resume_latency_limit(int cpu, uint32_t limit_us) const -> Status;

    /// Lifts `cpu`'s resume-latency limit (writes "0"), as a caller of set_resume_latency_limit() does at stop.
    /// The write's error when it fails.
    [[nodiscard]] auto clear_resume_latency_limit(int cpu) const -> Status;

  private:
    [[nodiscard]] auto cpu_path(int cpu, std::string_view file) const -> std::string;

    std::string root_;
};

}  // namespace statusbar::realtime
