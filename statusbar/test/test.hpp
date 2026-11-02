// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#pragma once

#include <exception>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

// Lightweight test framework
//
// Test functions are defined with TEST(group, name) and return void.
// The section is automatically derived from __FILE_NAME__.
// Assertion macros (EXPECT_*) throw TestFailedException on failure.
// The test runner catches exceptions to determine pass/fail status.
//
// A test that cannot run where it finds itself - no root, no hardware, a
// kernel without the feature - calls SKIP("reason") instead of returning.
// A bare return would be reported as a pass, which is a lie about work
// that was never done: the count comes out the same whether the test ran
// or not, so nobody can tell. SKIP reports the test and its reason, and
// counts it apart from the passes.
//
// Example:
//   TEST(mygroup, mytest) {
//       EXPECT_TRUE(1 + 1 == 2);
//       EXPECT_EQ(foo(), 42);
//   }

namespace statusbar::test {

struct TestInfo
{
    char const* section = "";
    char const* group = "";
    char const* name = "";
    void (*func)();
};

struct TestFailedException : std::exception
{};

/// Check if section matches filename (handles .cpp extension on either/both)
/// Compares after stripping .cpp from both arguments
constexpr auto section_matches(std::string_view sec, std::string_view file) -> bool
{
    if (sec.ends_with(".cpp")) {
        sec.remove_suffix(4);
    }
    if (file.ends_with(".cpp")) {
        file.remove_suffix(4);
    }
    return sec == file;
}

class TestRegister
{
    static std::vector<TestInfo> tests;

  public:
    explicit TestRegister(TestInfo info)
    {
        tests.push_back(info);
        g_registered_test_count++;
    }
    static auto run_all() -> bool { return run(tests); }
    static auto run_section(char const* section) -> int;
    static void print_report();
    static auto run(TestInfo info) -> bool;
    static auto run(std::vector<TestInfo> const& infos) -> bool;

    /// The three parts of run(): reset the per-test state, run the body
    /// (with or without exceptions), then count and print what happened.
    static auto begin_test() noexcept -> void;
    static auto body_did_not_fail(TestInfo const& info) -> bool;
    static auto report_outcome(TestInfo const& info, bool did_not_fail) -> bool;

    static int g_registered_test_count;
    static int g_registered_test_ran_count;
    static int g_test_count;
    static int g_test_passed;
    static int g_test_failed;
    static int g_test_skipped;

    // Per-test failure flag, used by the EXPECT_* macros so the framework works
    // with or without exceptions (under -fno-exceptions a failed EXPECT sets
    // this and returns from the void test function instead of throwing).
    static bool g_current_test_failed;
    static void fail_current() noexcept { g_current_test_failed = true; }

    // Per-test skip flag and reason, set by SKIP(). The reason is a string
    // literal owned by the caller, so nothing here allocates or copies.
    static bool g_current_test_skipped;
    static char const* g_current_test_skip_reason;
    static void skip_current(char const* reason) noexcept
    {
        g_current_test_skipped = true;
        g_current_test_skip_reason = reason;
    }
};

namespace detail {
// Overloaded helpers avoid consteval format-string validation for non-formattable types.
template <typename A, typename B>
    requires(std::is_arithmetic_v<std::remove_cvref_t<A>> && std::is_arithmetic_v<std::remove_cvref_t<B>>)
inline void print_eq_fail(char const* ea, char const* eb, A const& a, B const& b, char const* file, int line)
{
    std::println("  Expected equal: {} == {} [got {} vs {}] ({}:{})", ea, eb, a, b, file, line);
}
template <typename A, typename B>
inline void print_eq_fail(char const* ea, char const* eb, A const&, B const&, char const* file, int line)
{
    std::println("  Expected equal: {} == {} ({}:{})", ea, eb, file, line);
}
template <typename A, typename B>
    requires(std::is_arithmetic_v<std::remove_cvref_t<A>>)
inline void print_ne_fail(char const* ea, char const* eb, A const& a, B const&, char const* file, int line)
{
    std::println("  Expected not equal: {} != {} [both {}] ({}:{})", ea, eb, a, file, line);
}
template <typename A, typename B>
inline void print_ne_fail(char const* ea, char const* eb, A const&, B const&, char const* file, int line)
{
    std::println("  Expected not equal: {} != {} ({}:{})", ea, eb, file, line);
}
}  // namespace detail

}  // namespace statusbar::test

#define TEST(groupname, testname)                                                                                                  \
    static void test_##groupname##_##testname##_runner();                                                                          \
    static ::statusbar::test::TestRegister const groupname##_##testname##_(::statusbar::test::TestInfo{                            \
        .section = __FILE_NAME__, .group = #groupname, .name = #testname, .func = test_##groupname##_##testname##_runner});        \
    static void test_##groupname##_##testname##_runner()

// The failure action used by every EXPECT_* macro. With exceptions it throws
// (caught by the runner); under -fno-exceptions it records the failure and
// returns from the (void) test function, so the framework needs no exceptions.
#if __cpp_exceptions
#    define STATUSBAR_TEST_FAIL() throw ::statusbar::test::TestFailedException()
#else
#    define STATUSBAR_TEST_FAIL()                                                                                                  \
        do {                                                                                                                       \
            ::statusbar::test::TestRegister::fail_current();                                                                       \
            return;                                                                                                                \
        } while (0)
#endif

#define EXPECT_TRUE(expr)                                                                                                          \
    do {                                                                                                                           \
        if (!(expr)) {                                                                                                             \
            std::println("  Expected true: {} ({}:{})", #expr, __FILE__, __LINE__);                                                \
            STATUSBAR_TEST_FAIL();                                                                                                 \
        }                                                                                                                          \
    } while (0)

#define EXPECT_FALSE(expr)                                                                                                         \
    do {                                                                                                                           \
        if (expr) {                                                                                                                \
            std::println("  Expected false: {} ({}:{})", #expr, __FILE__, __LINE__);                                               \
            STATUSBAR_TEST_FAIL();                                                                                                 \
        }                                                                                                                          \
    } while (0)

#define EXPECT_EQ(a, b)                                                                                                            \
    do {                                                                                                                           \
        if ((a) != (b)) {                                                                                                          \
            ::statusbar::test::detail::print_eq_fail(#a, #b, (a), (b), __FILE__, __LINE__);                                        \
            STATUSBAR_TEST_FAIL();                                                                                                 \
        }                                                                                                                          \
    } while (0)

#define EXPECT_NE(a, b)                                                                                                            \
    do {                                                                                                                           \
        if ((a) == (b)) {                                                                                                          \
            ::statusbar::test::detail::print_ne_fail(#a, #b, (a), (b), __FILE__, __LINE__);                                        \
            STATUSBAR_TEST_FAIL();                                                                                                 \
        }                                                                                                                          \
    } while (0)

/// Abandon the current test, reporting it as skipped with `reason`.
///
/// For a precondition the test cannot create and is not testing: running
/// unprivileged, a missing interface, a kernel built without the feature.
/// Use it instead of a bare `return`, which the runner cannot distinguish
/// from a test that ran and passed.
///
/// Not for a precondition that *should* hold - a setup step that fails
/// where it was expected to work is a failure, and asserting on it is how
/// a broken environment gets noticed instead of papered over.
///
/// Write it in the test body. It returns from the function it is written
/// in, so from a helper it hands control back to the test, which goes on
/// without what the helper could not set up; the runner reports what
/// happens next as a failure, not as the skip. A helper reports whether it
/// managed, and the test skips on the answer.
#define SKIP(reason)                                                                                                               \
    do {                                                                                                                           \
        ::statusbar::test::TestRegister::skip_current(reason);                                                                     \
        return;                                                                                                                    \
    } while (0)

/// Test main entry point macro
///
/// Defines the test runner function expected by CMake's create_test_sourcelist.
/// The function name is constructed by concatenating path_name and section with underscore.
/// The section parameter must match the filename without .cpp extension.
/// A static_assert validates this at compile time.
///
/// @param path_name  Path prefix (e.g., statusbar_buffer for statusbar/buffer/)
/// @param section    Filename without .cpp extension (e.g., buffer_basic_test)
///
/// Example:
///   // In file statusbar/avb_entity/avb_entity_stereo_io_test.cpp:
///   TEST_MAIN(statusbar_avb_entity, avb_entity_stereo_io_test)
///
/// Expands to:
///   static_assert(section_matches("avb_entity_stereo_io_test", "avb_entity_stereo_io_test.cpp"));
///   int statusbar_avb_entity_avb_entity_stereo_io_test(int argc, char** argv) { ... }
#define TEST_MAIN(path_name, section)                                                                                              \
    static_assert(                                                                                                                 \
        ::statusbar::test::section_matches(#section, __FILE_NAME__), "TEST_MAIN section must match filename without .cpp");        \
    int path_name##_##section(int argc, char** argv)                                                                               \
    {                                                                                                                              \
        (void)argc;                                                                                                                \
        (void)argv;                                                                                                                \
        return ::statusbar::test::TestRegister::run_section(__FILE_NAME__);                                                        \
    }
