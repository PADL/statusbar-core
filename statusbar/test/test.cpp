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

auto TestRegister::begin_test() noexcept -> void
{
    ++g_test_count;
    g_registered_test_ran_count++;
    g_current_test_failed = false;
    g_current_test_skipped = false;
    g_current_test_skip_reason = "";
}

auto TestRegister::body_did_not_fail(TestInfo const& info) -> bool
{
#if __cpp_exceptions
    try {
        info.func();
        return !g_current_test_failed;
    } catch (...) {
        return false;
    }
#else
    info.func();
    return !g_current_test_failed;
#endif
}

auto TestRegister::report_outcome(TestInfo const& info, bool const did_not_fail) -> bool
{
    // A skipped test is neither: nothing was verified, so calling it a pass
    // would overstate the run and calling it a failure would break a build
    // on a machine that simply cannot host the test. A failure outranks the
    // skip, though: SKIP() returns from the function it is written in, so
    // one written in a helper hands control back to the test, which goes on
    // against whatever the helper could not set up - and what it then
    // reports is that failure, not the skip it meant to be.
    if (g_current_test_skipped && did_not_fail) {
        ++g_test_skipped;
        std::println("SKIP: {} {} - {}", info.group, info.name, g_current_test_skip_reason);
        return true;
    }
    if (did_not_fail) {
        ++g_test_passed;
        std::println("PASS: {} {}", info.group, info.name);
    } else if (g_current_test_skipped) {
        ++g_test_failed;
        std::println(
            "FAIL: {} {} (skipped from a helper - {} - and then went on)", info.group, info.name, g_current_test_skip_reason);
    } else {
        ++g_test_failed;
        std::println("FAIL: {} {}", info.group, info.name);
    }
    return did_not_fail;
}

auto TestRegister::run(TestInfo const info) -> bool
{
    begin_test();
    bool const did_not_fail = body_did_not_fail(info);
    return report_outcome(info, did_not_fail);
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
