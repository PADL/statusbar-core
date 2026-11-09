// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the CPU idle-state and PM QoS sysfs helpers, over a fake sysfs tree.

#include "statusbar/realtime/realtime_cpu_idle.hpp"

#include "statusbar/test/test.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace statusbar;
using namespace statusbar::realtime;

namespace {

/// A throwaway /sys/devices/system/cpu, removed with it.
struct FakeSysfs
{
    std::filesystem::path root;

    FakeSysfs()
    {
        std::string tmpl = (std::filesystem::temp_directory_path() / "realtime_cpu_idle_test_XXXXXX").string();
        root = ::mkdtemp(tmpl.data());
    }

    ~FakeSysfs()
    {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    FakeSysfs(FakeSysfs const&) = delete;
    auto operator=(FakeSysfs const&) -> FakeSysfs& = delete;

    void write(std::string const& file, std::string_view const text) const
    {
        auto const path = root / file;
        std::error_code ignored;
        std::filesystem::create_directories(path.parent_path(), ignored);
        std::ofstream{path} << text;
    }

    [[nodiscard]] auto read(std::string const& file) const -> std::string
    {
        std::ifstream in{root / file};
        return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    }

    /// cpuN with POLL, C1 and C1E, as intel_idle lists them on a Broadwell-EP Xeon.
    void add_cpu(int const cpu) const
    {
        auto const dir = "cpu" + std::to_string(cpu) + "/cpuidle/state";
        write(dir + "0/name", "POLL\n");
        write(dir + "0/latency", "0\n");
        write(dir + "1/name", "C1\n");
        write(dir + "1/latency", "2\n");
        write(dir + "2/name", "C1E\n");
        write(dir + "2/latency", "10\n");
    }

    [[nodiscard]] auto sysfs() const -> CpuSysfs { return CpuSysfs{root.string()}; }
};

}  // namespace

//
// parse_cpu_list
//

TEST(realtime_cpu_list, single_cpus_and_ranges_are_listed_in_order)
{
    EXPECT_TRUE(parse_cpu_list("3,9") == std::vector<int>({3, 9}));
    EXPECT_TRUE(parse_cpu_list("0-2,8") == std::vector<int>({0, 1, 2, 8}));
    EXPECT_TRUE(parse_cpu_list("5") == std::vector<int>({5}));
}

TEST(realtime_cpu_list, malformed_lists_are_refused)
{
    for (std::string_view const text : {"", "3,", "a", "-1", "3-1", "1-", "1 2", "8192"}) {
        auto const cpus = parse_cpu_list(text);
        EXPECT_TRUE(cpus.error_or(std::error_code{}) == std::errc::invalid_argument);
    }
}

//
// CpuSysfs
//

TEST(realtime_cpu_sysfs, thread_siblings_are_read_from_the_topology)
{
    FakeSysfs const fake;
    fake.write("cpu3/topology/thread_siblings_list", "3,9\n");
    EXPECT_TRUE(fake.sysfs().thread_siblings(3) == std::vector<int>({3, 9}));
}

TEST(realtime_cpu_sysfs, a_missing_topology_is_an_error)
{
    FakeSysfs const fake;
    auto const siblings = fake.sysfs().thread_siblings(3);
    EXPECT_TRUE(siblings.error_or(std::error_code{}) == std::errc::no_such_file_or_directory);
}

TEST(realtime_cpu_sysfs, idle_states_are_read_shallowest_first)
{
    FakeSysfs const fake;
    fake.add_cpu(4);
    auto const states = fake.sysfs().idle_states(4);
    EXPECT_TRUE(states.has_value());
    EXPECT_EQ(states->size(), size_t{3});
    EXPECT_TRUE(states->at(1) == (CpuIdleState{.name = "C1", .latency_us = 2}));
    EXPECT_TRUE(states->at(2) == (CpuIdleState{.name = "C1E", .latency_us = 10}));
}

TEST(realtime_cpu_sysfs, a_cpu_without_cpuidle_has_no_idle_states)
{
    FakeSysfs const fake;
    fake.write("cpu4/topology/thread_siblings_list", "4,10\n");
    auto const states = fake.sysfs().idle_states(4);
    EXPECT_TRUE(states.error_or(std::error_code{}) == std::errc::no_such_file_or_directory);
}

TEST(realtime_cpu_sysfs, a_state_without_its_latency_is_refused)
{
    FakeSysfs const fake;
    fake.add_cpu(0);
    std::error_code ignored;
    std::filesystem::remove(fake.root / "cpu0/cpuidle/state1/latency", ignored);
    auto const states = fake.sysfs().idle_states(0);
    EXPECT_TRUE(states.error_or(std::error_code{}) == std::errc::invalid_argument);
}

TEST(realtime_cpu_sysfs, a_malformed_latency_is_refused)
{
    FakeSysfs const fake;
    fake.write("cpu0/cpuidle/state0/name", "POLL\n");
    fake.write("cpu0/cpuidle/state0/latency", "fast\n");
    auto const states = fake.sysfs().idle_states(0);
    EXPECT_TRUE(states.error_or(std::error_code{}) == std::errc::invalid_argument);
}

TEST(realtime_cpu_sysfs, a_resume_latency_limit_is_written_in_microseconds)
{
    FakeSysfs const fake;
    fake.write("cpu3/power/pm_qos_resume_latency_us", "0\n");
    EXPECT_TRUE(fake.sysfs().set_resume_latency_limit(3, 2).has_value());
    EXPECT_EQ(fake.read("cpu3/power/pm_qos_resume_latency_us"), std::string{"2\n"});
}

TEST(realtime_cpu_sysfs, a_zero_limit_is_written_as_n_a)
{
    FakeSysfs const fake;
    fake.write("cpu3/power/pm_qos_resume_latency_us", "0\n");
    EXPECT_TRUE(fake.sysfs().set_resume_latency_limit(3, 0).has_value());
    EXPECT_EQ(fake.read("cpu3/power/pm_qos_resume_latency_us"), std::string{"n/a"});
}

TEST(realtime_cpu_sysfs, a_missing_pm_qos_file_is_an_error)
{
    FakeSysfs const fake;
    auto const written = fake.sysfs().set_resume_latency_limit(3, 2);
    EXPECT_TRUE(written.error_or(std::error_code{}) == std::errc::no_such_file_or_directory);
}

TEST_MAIN(statusbar_realtime, realtime_cpu_idle_test)
