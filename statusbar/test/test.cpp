// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/test/test.hpp"

namespace statusbar::test {

std::vector<TestInfo> TestRegister::tests;

int TestRegister::g_registered_test_count = 0;
int TestRegister::g_registered_test_ran_count = 0;
int TestRegister::g_test_count = 0;
int TestRegister::g_test_passed = 0;
int TestRegister::g_test_failed = 0;
int TestRegister::g_test_skipped = 0;
bool TestRegister::g_current_test_failed = false;
bool TestRegister::g_current_test_skipped = false;
char const* TestRegister::g_current_test_skip_reason = "";

auto TestRegister::run(TestInfo const info) -> bool
{
    ++g_test_count;
    bool result = false;
    g_registered_test_ran_count++;
    g_current_test_failed = false;
    g_current_test_skipped = false;
    g_current_test_skip_reason = "";
#if __cpp_exceptions
    try {
        info.func();
        result = !g_current_test_failed;
    } catch (...) {
        result = false;
    }
#else
    info.func();
    result = !g_current_test_failed;
#endif

    // A skipped test is neither: nothing was verified, so calling it a pass
    // would overstate the run and calling it a failure would break a build
    // on a machine that simply cannot host the test.
    if (g_current_test_skipped) {
        ++g_test_skipped;
        std::println("SKIP: {} {} - {}", info.group, info.name, g_current_test_skip_reason);
        return true;
    }

    if (result) {
        ++g_test_passed;
        std::println("PASS: {} {}", info.group, info.name);
    } else {
        ++g_test_failed;
        std::println("FAIL: {} {}", info.group, info.name);
    }
    return result;
}

auto TestRegister::run(std::vector<TestInfo> const& infos) -> bool
{
    bool r = true;
    for (auto const info : infos) {
        r &= run(info);
    }
    return r;
}

auto TestRegister::run_section(char const* section) -> int
{
    bool r = true;
    g_test_count = 0;
    g_test_failed = 0;
    g_test_passed = 0;
    g_test_skipped = 0;
    std::println("Running Section {} tests...\n", section != nullptr ? section : "ALL");
    for (auto const info : tests) {
        if (nullptr == section || section_matches(info.section, section)) {
            bool result = run(info);
            r &= result;
        }
    }
    print_report();

    // Return non-zero exit code if any tests failed
    return r ? 0 : 1;
}

void TestRegister::print_report()
{
    std::println("\n========================================");
    std::println("Total registered tests: {}", TestRegister::g_registered_test_count);
    std::println("Total registered tests ran: {}", TestRegister::g_registered_test_ran_count);
    std::println("Total tests: {}", TestRegister::g_test_count);
    std::println("Passed: {}", TestRegister::g_test_passed);
    std::println("Skipped: {}", TestRegister::g_test_skipped);
    std::println("Failed: {}", TestRegister::g_test_failed);
    std::println("========================================");
}

}  // namespace statusbar::test
