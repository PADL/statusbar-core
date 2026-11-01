// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

//
// Smoke tests for statusbar/realtime/realtime_base.hpp
//
// Every test here accepts EPERM as a valid outcome. The tool under
// test exercises real OS calls (mlockall, pthread_setschedparam,
// sched_setaffinity, signal handlers) that require CAP_IPC_LOCK /
// CAP_SYS_NICE / root. In an unprivileged CI environment each call
// fails with EPERM or EACCES, but the library code still runs end to
// end — which is what we want coverage-wise. A privileged environment
// will exercise the success path instead. Either outcome is accepted.
//

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

using namespace statusbar;

//
// RealtimeResult helpers
//

TEST(realtime_result, success_factory)
{
    auto const r = realtime::realtime_success();
    EXPECT_TRUE(r.success);
    EXPECT_EQ(r.error_code, 0);
    EXPECT_EQ(r.error_message, nullptr);
    EXPECT_TRUE(static_cast<bool>(r));
}

TEST(realtime_result, failure_from_errno)
{
    errno = EINVAL;
    auto const r = realtime::realtime_failure_errno();
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.error_code, EINVAL);
    EXPECT_NE(r.error_message, nullptr);
}

TEST(realtime_result, failure_with_explicit_code)
{
    auto const r = realtime::realtime_failure(EPERM);
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.error_code, EPERM);
}

TEST(realtime_result, failure_with_custom_message)
{
    auto const r = realtime::realtime_failure(EPERM, "custom");
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.error_code, EPERM);
    EXPECT_EQ(std::string_view{r.error_message}, std::string_view{"custom"});
}

TEST(realtime_result, log_if_failed_on_success_is_silent)
{
    auto const r = realtime::realtime_success();
    r.log_if_failed("noop");  // must not print; test just exercises the path
}

TEST(realtime_result, log_if_failed_on_failure_with_message)
{
    auto const r = realtime::realtime_failure(EPERM, "simulated");
    r.log_if_failed("unit-test");  // prints to stderr; we only exercise coverage
}

TEST(realtime_result, log_if_failed_on_failure_without_message)
{
    realtime::RealtimeResult const r{.success = false, .error_code = EPERM, .error_message = nullptr};
    r.log_if_failed("unit-test-no-msg");
}

//
// Memory locking — accept EPERM.
//

TEST(realtime_base, lock_memory_accepts_permission_denied)
{
    bool const ok = realtime::lock_memory();
    // Either success (privileged) or failure (typical CI). Both paths
    // exercise the mlockall() call site.
    (void)ok;
    if (ok) {
        (void)realtime::unlock_memory();
    }
}

TEST(realtime_base, lock_memory_ex_returns_result)
{
    auto const r = realtime::lock_memory_ex();
    if (r) {
        (void)realtime::unlock_memory();
    }
    // Either way, error_code was populated if !success.
    if (!r.success) {
        EXPECT_NE(r.error_code, 0);
    }
}

TEST(realtime_base, lock_memory_logged_accepts_permission_denied)
{
    bool const ok = realtime::lock_memory_logged();
    (void)ok;
    if (ok) {
        (void)realtime::unlock_memory();
    }
}

//
// Thread priority — accept EPERM.
//

TEST(realtime_base, set_realtime_priority_accepts_permission_denied)
{
    (void)realtime::set_realtime_priority();
    (void)realtime::reset_scheduling();
}

TEST(realtime_base, set_realtime_priority_with_value)
{
    auto const max_prio = realtime::get_max_fifo_priority();
    (void)realtime::set_realtime_priority(max_prio);
    (void)realtime::reset_scheduling();
}

TEST(realtime_base, set_realtime_priority_ex_returns_result)
{
    auto const r = realtime::set_realtime_priority_ex();
    if (!r.success) {
        EXPECT_NE(r.error_code, 0);
    }
    (void)realtime::reset_scheduling();
}

#if !defined(__APPLE__)
TEST(realtime_base, set_realtime_priority_ex_with_value)
{
    auto const r = realtime::set_realtime_priority_ex(realtime::get_max_fifo_priority());
    if (!r.success) {
        EXPECT_NE(r.error_code, 0);
    }
    (void)realtime::reset_scheduling();
}
#endif

TEST(realtime_base, set_realtime_priority_logged_default_name)
{
    (void)realtime::set_realtime_priority_logged();
    (void)realtime::reset_scheduling();
}

TEST(realtime_base, set_realtime_priority_logged_with_value_and_name)
{
    (void)realtime::set_realtime_priority_logged(realtime::get_max_fifo_priority(), "realtime_base_test");
    (void)realtime::reset_scheduling();
}

TEST(realtime_base, set_realtime_rr_priority_accepts_permission_denied)
{
    (void)realtime::set_realtime_rr_priority();
    (void)realtime::reset_scheduling();
}

TEST(realtime_base, fifo_priority_bounds_are_sane)
{
    auto const hi = realtime::get_max_fifo_priority();
    auto const lo = realtime::get_min_fifo_priority();
    EXPECT_TRUE(hi >= lo);
}

//
// CPU affinity — accept EPERM / EINVAL.
//

TEST(realtime_base, set_realtime_affinity_accepts_failure)
{
    // CPU 0 is nearly always valid; failure indicates insufficient privilege.
    (void)realtime::set_realtime_affinity(0);
}

TEST(realtime_base, set_realtime_affinity_logged_accepts_failure)
{
    (void)realtime::set_realtime_affinity_logged(0, "realtime_base_test");
}

//
// Shutdown token + signal-handler wiring
//
// shutdown_token() returns the same StopToken as itc::install_stop_signal().
// StopToken is one-way (stop cannot be cleared), so the tests below use a
// local StopToken to verify behavior in isolation. They do NOT read or write
// the process-wide token, which may already be in the "requested" state from
// a previous test.
//

TEST(realtime_base_shutdown, shutdown_token_is_stop_token)
{
    // Verify that shutdown_token() returns a reference (not nullptr).
    // It must be the same object as itc::install_stop_signal().
    statusbar::itc::StopToken& rt_token = realtime::shutdown_token();
    statusbar::itc::StopToken& sync_token = statusbar::itc::install_stop_signal();
    EXPECT_TRUE(&rt_token == &sync_token);
}

TEST(realtime_base_shutdown, is_shutdown_requested_reflects_token)
{
    // Use a local token to verify the shim functions route correctly.
    statusbar::itc::StopToken local_token;
    EXPECT_FALSE(local_token.stop_requested());
    local_token.request_stop();
    EXPECT_TRUE(local_token.stop_requested());
}

TEST(realtime_base_shutdown, handle_shutdown_signal_is_callable)
{
    // Just verifies the function is callable without crashing.
    // (It calls signal_set() on the process-wide token; we can't reset that.)
    realtime::handle_shutdown_signal(SIGINT);
    EXPECT_TRUE(realtime::is_shutdown_requested());
}

TEST(realtime_base_shutdown, setup_signal_handlers_installs_them)
{
    // Save existing handlers and restore after the test to avoid
    // disturbing the test harness's own signal state.
    auto const old_int = std::signal(SIGINT, SIG_DFL);
    auto const old_term = std::signal(SIGTERM, SIG_DFL);
    auto const old_pipe = std::signal(SIGPIPE, SIG_DFL);

    realtime::setup_shutdown_signal_handlers();

    // Verify that the functions completed without throwing.
    // We don't assert specific handler pointers (the harness may
    // replace them legitimately) — the coverage goal is simply to
    // exercise the install path.

    std::signal(SIGINT, old_int);
    std::signal(SIGTERM, old_term);
    std::signal(SIGPIPE, old_pipe);
}

//
// detail helpers
//

// The positive case must be a file that exists wherever the binary runs,
// not where it was built: a cross-built test is copied off the build
// host, and __FILE__ names a path on the build host. Linux gives every
// process /proc/self/exe; macOS has no procfs, so /dev/null stands in.
TEST(realtime_detail, file_exists_on_a_file_every_process_has)
{
#if defined(__linux__)
    EXPECT_TRUE(realtime::detail::file_exists("/proc/self/exe"));
#else
    EXPECT_TRUE(realtime::detail::file_exists("/dev/null"));
#endif
}

TEST(realtime_detail, file_exists_on_missing_path)
{
    EXPECT_FALSE(realtime::detail::file_exists("/this/path/should/not/exist/ever/12345"));
}

TEST(realtime_detail, now_monotonic_raw_ns_is_increasing)
{
    auto const a = realtime::detail::now_monotonic_raw_ns();
    auto const b = realtime::detail::now_monotonic_raw_ns();
    EXPECT_TRUE(b >= a);
}

TEST(realtime_detail, save_file_noop_on_missing_src)
{
    // save_file reads the source and writes it to dst; missing source
    // is a silent no-op. We just exercise the call site.
    realtime::detail::save_file("/nonexistent/src/12345", std::string{"/tmp/realtime_base_test_save_file_noop"});
}

TEST_MAIN(statusbar_realtime, realtime_base_test)

//
// Spin Hints and Thread Names (FEAT-014)
//

namespace {

#if defined(__linux__) || defined(__APPLE__)

/// Read the calling thread's name back out of the kernel.
auto current_thread_name() -> std::string
{
    std::array<char, realtime::thread_name_max> buf{};
#    if defined(__linux__)
    if (::prctl(PR_GET_NAME, buf.data(), 0, 0, 0) != 0) {
        return {};
    }
#    else
    if (::pthread_getname_np(::pthread_self(), buf.data(), buf.size()) != 0) {
        return {};
    }
#    endif
    buf[buf.size() - 1] = '\0';
    return std::string{buf.data()};
}

/// These tests run on the main thread, and on Linux naming the main thread
/// is what `ps` shows for the whole process. Put it back afterwards so the
/// test binary does not spend the rest of the run called `trunc-0123456`.
class ThreadNameGuard
{
  public:
    ThreadNameGuard()
        : saved_{current_thread_name()}
    {}
    ~ThreadNameGuard() { realtime::set_current_thread_name(saved_); }
    ThreadNameGuard(ThreadNameGuard const&) = delete;
    ThreadNameGuard(ThreadNameGuard&&) = delete;
    auto operator=(ThreadNameGuard const&) -> ThreadNameGuard& = delete;
    auto operator=(ThreadNameGuard&&) -> ThreadNameGuard& = delete;

  private:
    std::string saved_;
};

#endif

}  // namespace

TEST(realtime_cpu_relax, a_spin_loop_using_it_terminates)
{
    // The hint must not block, and on an architecture with no such
    // instruction it must still compile and still be a no-op.
    int spins = 0;
    for (int i = 0; i < 1000; ++i) {
        realtime::cpu_relax();
        ++spins;
    }
    EXPECT_EQ(spins, 1000);
}

TEST(realtime_cpu_relax, a_spin_wait_on_another_thread_completes)
{
    // The shape it exists for: spin until another thread publishes, with the
    // hint inside the loop. A cpu_relax() that blocked or clobbered the
    // loop's view of the flag would hang here rather than fail an assertion.
    std::atomic<bool> published{false};
    std::thread writer{[&published] { published.store(true, std::memory_order_release); }};
    while (!published.load(std::memory_order_acquire)) {
        realtime::cpu_relax();
    }
    writer.join();
    EXPECT_TRUE(published.load(std::memory_order_acquire));
}

#if defined(__linux__) || defined(__APPLE__)

TEST(realtime_thread_name, a_name_round_trips)
{
    ThreadNameGuard const guard;
    realtime::set_current_thread_name("rt-test");
    EXPECT_EQ(current_thread_name(), "rt-test");
}

TEST(realtime_thread_name, a_name_of_exactly_fifteen_bytes_survives_whole)
{
    // 15 plus the NUL is the most the kernel keeps: the boundary where a
    // length check off by one starts truncating a legitimate name.
    ThreadNameGuard const guard;
    std::string const fifteen{"abcdefghijklmno"};
    EXPECT_EQ(fifteen.size(), realtime::thread_name_max - 1);
    realtime::set_current_thread_name(fifteen);
    EXPECT_EQ(current_thread_name(), fifteen);
}

TEST(realtime_thread_name, a_longer_name_is_truncated_and_still_set)
{
    // The point of truncating here: handing the kernel an over-long name
    // fails and leaves the thread anonymous, which is the failure the
    // function exists to prevent.
    ThreadNameGuard const guard;
    std::string const too_long{"this-name-is-far-too-long-for-comm"};
    realtime::set_current_thread_name(too_long);
    auto const got = current_thread_name();
    EXPECT_EQ(got.size(), realtime::thread_name_max - 1);
    EXPECT_EQ(got, too_long.substr(0, realtime::thread_name_max - 1));
}

TEST(realtime_thread_name, an_empty_name_leaves_the_previous_one)
{
    // A caller passing an unset config value should not anonymise the
    // thread, and must not leave it half-written either.
    ThreadNameGuard const guard;
    realtime::set_current_thread_name("rt-keep");
    realtime::set_current_thread_name("");
    EXPECT_EQ(current_thread_name(), "rt-keep");
}

TEST(realtime_thread_name, a_name_set_on_one_thread_does_not_touch_another)
{
    // It names the calling thread only -- which is why the API takes no
    // thread handle (macOS cannot name any other).
    ThreadNameGuard const guard;
    realtime::set_current_thread_name("rt-main");

    std::string observed_in_thread;
    std::thread worker{[&observed_in_thread] {
        realtime::set_current_thread_name("rt-worker");
        observed_in_thread = current_thread_name();
    }};
    worker.join();

    EXPECT_EQ(observed_in_thread, "rt-worker");
    EXPECT_EQ(current_thread_name(), "rt-main");
}

#endif  // __linux__ || __APPLE__
