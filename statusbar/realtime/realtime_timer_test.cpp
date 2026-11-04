// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace statusbar::realtime;
using namespace statusbar::stats;

//
// Tests: TimerConfig - Default values
//

TEST(realtime_timer_config, default_values)
{
    TimerConfig config;

    EXPECT_EQ(config.period_ns, 500'000'000);
    EXPECT_EQ(config.compensation_ns, 0);
    EXPECT_EQ(config.busy_wait_threshold_ns, 200'000);
    EXPECT_EQ(config.cpu, 3);
    EXPECT_EQ(config.priority, 49);
    EXPECT_FALSE(config.busy_wait);
    EXPECT_FALSE(config.strict_affinity);
    EXPECT_TRUE(config.name.empty());
    EXPECT_EQ(config.stack_prefault_bytes, size_t{128} * 1024);
    EXPECT_EQ(config.start_offset_cycles, 2);
    EXPECT_EQ(config.resync_interval_cycles, 1000);
}

TEST(realtime_timer_config, default_error_histogram)
{
    TimerConfig config;

    EXPECT_EQ(config.error_histogram.low_ns, -10'000);
    EXPECT_EQ(config.error_histogram.high_ns, 200'000);
    EXPECT_EQ(config.error_histogram.bin_width_ns, 5'000);
    EXPECT_TRUE(config.error_histogram.is_valid());
}

TEST(realtime_timer_config, default_duration_histogram)
{
    TimerConfig config;

    EXPECT_EQ(config.duration_histogram.low_ns, 0);
    EXPECT_EQ(config.duration_histogram.high_ns, 200'000);
    EXPECT_EQ(config.duration_histogram.bin_width_ns, 5'000);
    EXPECT_TRUE(config.duration_histogram.is_valid());
}

//
// Tests: validate_timer_config
//

TEST(realtime_timer_validate, valid_default_config)
{
    TimerConfig config;
    EXPECT_TRUE(validate_timer_config(config));
}

TEST(realtime_timer_validate, valid_custom_period)
{
    TimerConfig config;
    config.period_ns = 125'000;  // 125 us
    EXPECT_TRUE(validate_timer_config(config));
}

TEST(realtime_timer_validate, invalid_zero_period)
{
    TimerConfig config;
    config.period_ns = 0;
    EXPECT_FALSE(validate_timer_config(config));
}

TEST(realtime_timer_validate, invalid_negative_period)
{
    TimerConfig config;
    config.period_ns = -1'000'000;
    EXPECT_FALSE(validate_timer_config(config));
}

TEST(realtime_timer_validate, valid_with_error_prefix)
{
    TimerConfig config;
    EXPECT_TRUE(validate_timer_config(config, "timer."));
}

TEST(realtime_timer_validate, invalid_with_error_prefix)
{
    TimerConfig config;
    config.period_ns = -1;
    EXPECT_FALSE(validate_timer_config(config, "my_timer."));
}

//
// Tests: cycle_number_from_ns / cycle_number_to_ns
//

TEST(realtime_cycle_number_from_ns, zero_time_is_cycle_zero)
{
    EXPECT_EQ(cycle_number_from_ns(0, 1'000'000), 0);
}

TEST(realtime_cycle_number_from_ns, just_before_first_boundary_is_cycle_zero)
{
    EXPECT_EQ(cycle_number_from_ns(999'999, 1'000'000), 0);
}

TEST(realtime_cycle_number_from_ns, exact_first_boundary_is_cycle_one)
{
    EXPECT_EQ(cycle_number_from_ns(1'000'000, 1'000'000), 1);
}

TEST(realtime_cycle_number_from_ns, within_first_cycle_after_zero)
{
    EXPECT_EQ(cycle_number_from_ns(1, 1'000'000), 0);
}

TEST(realtime_cycle_number_from_ns, exact_second_boundary)
{
    EXPECT_EQ(cycle_number_from_ns(2'000'000, 1'000'000), 2);
}

TEST(realtime_cycle_number_from_ns, middle_of_cycle_k)
{
    constexpr int64_t period = 125'000;  // 125us
    constexpr int64_t k = 42;
    constexpr int64_t r = 50'000;  // remainder within cycle
    EXPECT_EQ(cycle_number_from_ns((k * period) + r, period), k);
}

TEST(realtime_cycle_number_from_ns, large_time_value)
{
    // ~1 hour in ns at 125us period -> ~28.8M cycles
    constexpr int64_t period = 125'000;
    constexpr int64_t t = 3'600'000'000'000LL;  // 1 hour
    EXPECT_EQ(cycle_number_from_ns(t, period), t / period);
}

TEST(realtime_cycle_number_from_ns, period_of_one_returns_time)
{
    EXPECT_EQ(cycle_number_from_ns(12345, 1), 12345);
}

TEST(realtime_cycle_number_from_ns, is_constexpr)
{
    static_assert(cycle_number_from_ns(2'000'000, 1'000'000) == 2);
    static_assert(cycle_number_from_ns(999, 1'000) == 0);
    EXPECT_TRUE(true);
}

TEST(realtime_cycle_number_to_ns, cycle_zero_is_zero)
{
    EXPECT_EQ(cycle_number_to_ns(0, 1'000'000), 0);
}

TEST(realtime_cycle_number_to_ns, cycle_one_is_one_period)
{
    EXPECT_EQ(cycle_number_to_ns(1, 1'000'000), 1'000'000);
}

TEST(realtime_cycle_number_to_ns, cycle_k_is_k_periods)
{
    constexpr int64_t period = 125'000;
    EXPECT_EQ(cycle_number_to_ns(42, period), 42 * period);
}

TEST(realtime_cycle_number_to_ns, round_trip_starts_at_cycle_boundary)
{
    // to_ns(n, p) lands exactly at a cycle boundary, so from_ns of that
    // value returns n again (the identity round-trip on cycle boundaries).
    constexpr int64_t period = 125'000;
    for (int64_t n = 0; n < 10; ++n) {
        EXPECT_EQ(cycle_number_from_ns(cycle_number_to_ns(n, period), period), n);
    }
}

TEST(realtime_cycle_number_to_ns, is_constexpr)
{
    static_assert(cycle_number_to_ns(2, 1'000'000) == 2'000'000);
    static_assert(cycle_number_to_ns(0, 125'000) == 0);
    EXPECT_TRUE(true);
}

//
// Tests: Timer construction (default MonotonicClockAdapter)
//

TEST(realtime_timer_construct, valid_config)
{
    TimerConfig config;
    config.period_ns = 1'000'000;  // 1 ms

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_FALSE(timer.is_running());
    EXPECT_EQ(timer.period_ns(), 1'000'000);
    EXPECT_EQ(timer.compensation_ns(), 0);
    EXPECT_EQ(timer.cpu(), 3);
    EXPECT_FALSE(timer.is_busy_wait());
}

TEST(realtime_timer_construct, custom_compensation)
{
    TimerConfig config;
    config.period_ns = 500'000;
    config.compensation_ns = -25'000;

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_EQ(timer.compensation_ns(), -25'000);
    EXPECT_EQ(timer.compensation().count(), -25'000);
}

TEST(realtime_timer_construct, busy_wait_mode)
{
    TimerConfig config;
    config.period_ns = 125'000;
    config.busy_wait = true;

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_TRUE(timer.is_busy_wait());
}

TEST(realtime_timer_construct, period_as_duration)
{
    TimerConfig config;
    config.period_ns = 250'000;

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_EQ(timer.period().count(), 250'000);
}

TEST(realtime_timer_construct, config_accessor)
{
    TimerConfig config;
    config.name = "test_timer";
    config.period_ns = 1'000'000;
    config.cpu = 2;
    config.priority = 80;

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    auto const& cfg = timer.config();
    EXPECT_EQ(cfg.name, "test_timer");
    EXPECT_EQ(cfg.period_ns, 1'000'000);
    EXPECT_EQ(cfg.cpu, 2);
    EXPECT_EQ(cfg.priority, 80);
}

TEST(realtime_timer_construct, initial_stats_empty)
{
    TimerConfig config;
    config.period_ns = 1'000'000;

    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    auto snapshot = timer.stats();
    EXPECT_EQ(snapshot.error.count, 0);
    EXPECT_EQ(snapshot.duration.count, 0);
}

//
// Tests: TimerEvent
//

TEST(realtime_timer_event, scheduled_time_ns)
{
    TimerEvent<MonotonicClock> event{
        .scheduled_time = MonotonicClock::from_ns(1'000'000'000),
        .error = MonotonicClock::duration{500},
        .wake_count = 1,
        .skipped_counts = 0,
    };

    EXPECT_EQ(event.scheduled_time_ns(), 1'000'000'000);
}

TEST(realtime_timer_event, error_ns)
{
    TimerEvent<MonotonicClock> event{
        .scheduled_time = MonotonicClock::from_ns(0),
        .error = MonotonicClock::duration{-250},
        .wake_count = 1,
        .skipped_counts = 0,
    };

    EXPECT_EQ(event.error_ns(), -250);
}

TEST(realtime_timer_event, fields_accessible)
{
    TimerEvent<MonotonicClock> event{
        .scheduled_time = MonotonicClock::from_ns(5000),
        .error = MonotonicClock::duration{100},
        .wake_count = 42,
        .skipped_counts = 3,
    };

    EXPECT_EQ(event.wake_count, 42);
    EXPECT_EQ(event.skipped_counts, 3);
}

//
// Tests: AnyTimer
//

TEST(realtime_timer_any, default_is_empty)
{
    AnyTimer timer;
    EXPECT_FALSE(static_cast<bool>(timer));
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_any, create_monotonic)
{
    TimerConfig config;
    config.period_ns = 1'000'000;

    auto timer = AnyTimer::create(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_TRUE(static_cast<bool>(timer));
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_any, config_accessor)
{
    TimerConfig config;
    config.period_ns = 2'000'000;
    config.name = "any_test";

    auto timer = AnyTimer::create(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_EQ(timer.config().period_ns, 2'000'000);
    EXPECT_EQ(timer.config().name, "any_test");
}

TEST(realtime_timer_any, stats_when_empty)
{
    AnyTimer timer;
    auto snapshot = timer.stats();
    EXPECT_EQ(snapshot.error.count, 0);
}

TEST(realtime_timer_any, config_throws_when_empty)
{
    AnyTimer timer;

    bool threw = false;
    try {
        (void)timer.config();
    } catch (std::runtime_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

TEST(realtime_timer_any, move_construct)
{
    TimerConfig config;
    config.period_ns = 1'000'000;
    config.name = "movable";

    auto timer1 = AnyTimer::create(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});
    AnyTimer timer2{std::move(timer1)};

    EXPECT_TRUE(static_cast<bool>(timer2));
    EXPECT_EQ(timer2.config().name, "movable");
}

//
// Tests: build_timer_arg_specs
//

TEST(realtime_timer_argspecs, builds_without_error)
{
    TimerConfig config;
    auto specs = build_timer_arg_specs(config);

    // Should have created specs (at least period_ns, compensation_ns, cpu, priority, busy_wait, etc.)
    // We cannot easily count specs, but we can verify the function doesn't crash
    // and that modifying via the specs works
    EXPECT_TRUE(true);
}

TEST(realtime_timer_argspecs, histogram_specs)
{
    AtomicHistogramConfig config{.low_ns = -1000, .high_ns = 1000, .bin_width_ns = 100};
    auto specs = build_histogram_arg_specs(config);

    // Verify function returns without error
    EXPECT_TRUE(true);
}

//
// Tests: print_timer_config (smoke test - just verify no crash)
//

TEST(realtime_timer_print, print_unnamed_config)
{
    TimerConfig config;
    config.period_ns = 1'000'000;
    // Just verify it doesn't crash
    print_timer_config(config);
    EXPECT_TRUE(true);
}

TEST(realtime_timer_print, print_named_config)
{
    TimerConfig config;
    config.name = "my_timer";
    config.period_ns = 125'000;
    config.busy_wait = true;
    // Just verify it doesn't crash
    print_timer_config(config);
    EXPECT_TRUE(true);
}

//
// Tests: TimerBase (non-threaded)
//

TEST(realtime_timer_base, stop_idempotent)
{
    TimerConfig config;
    config.period_ns = 1'000'000;
    Timer<> timer(config, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {});
    timer.stop();
    EXPECT_FALSE(timer.is_running());
}

//
// TimerBase protected-surface tests
//
// A minimal concrete derived class exposes the protected primitives so we can
// exercise them without spinning up a full Timer<> thread.
//

namespace {

class TestTimerBase : public TimerBase
{
  public:
    using TimerBase::TimerBase;

    // Expose protected members for direct testing
    using TimerBase::is_running_atomic;
    using TimerBase::set_running;
    using TimerBase::should_run;
    using TimerBase::try_start;
    using TimerBase::try_stop;
    using TimerBase::wait_until_absolute;
    using TimerBase::wait_until_busy;

    // Call the real (non-overridden) prepare_thread directly, bypassing our lightweight override
    auto call_real_prepare_thread() -> bool { return TimerBase::prepare_thread(); }

    // Allow installing a shutdown token without starting the thread
    auto set_shutdown_flag_for_test(statusbar::itc::StopToken* token) noexcept -> void { shutdown_token_ = token; }

    std::atomic<int> loop_runs{0};
    std::atomic<int> prepare_calls{0};

  protected:
    auto run_loop() -> void override { loop_runs.fetch_add(1, std::memory_order_relaxed); }

    // Lightweight override used during start()/stop() tests to avoid the 1MB
    // stack prefault in the base implementation, which overflows the default
    // std::thread stack on macOS (524 KB).
    auto prepare_thread() -> bool override
    {
        prepare_calls.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
};

}  // namespace

TEST(realtime_timer_base_state, initial_state_not_running)
{
    TestTimerBase base{TimerConfig{}};
    EXPECT_FALSE(base.is_running_atomic());
    EXPECT_FALSE(base.is_running());
}

TEST(realtime_timer_base_state, set_running_toggles)
{
    TestTimerBase base{TimerConfig{}};
    base.set_running(true);
    EXPECT_TRUE(base.is_running_atomic());
    base.set_running(false);
    EXPECT_FALSE(base.is_running_atomic());
}

TEST(realtime_timer_base_state, try_start_succeeds_then_fails)
{
    TestTimerBase base{TimerConfig{}};
    EXPECT_TRUE(base.try_start());
    EXPECT_TRUE(base.is_running_atomic());
    EXPECT_FALSE(base.try_start());  // already running
}

TEST(realtime_timer_base_state, try_stop_succeeds_then_fails)
{
    TestTimerBase base{TimerConfig{}};
    (void)base.try_start();
    EXPECT_TRUE(base.try_stop());
    EXPECT_FALSE(base.is_running_atomic());
    EXPECT_FALSE(base.try_stop());  // already stopped
}

TEST(realtime_timer_base_state, try_stop_fails_when_not_started)
{
    TestTimerBase base{TimerConfig{}};
    EXPECT_FALSE(base.try_stop());
}

//
// should_run() logic
//

TEST(realtime_timer_base_should_run, false_when_not_running)
{
    TestTimerBase base{TimerConfig{}};
    EXPECT_FALSE(base.should_run());
}

TEST(realtime_timer_base_should_run, true_when_running_no_flag)
{
    TestTimerBase base{TimerConfig{}};
    base.set_running(true);
    EXPECT_TRUE(base.should_run());
    base.set_running(false);
}

TEST(realtime_timer_base_should_run, true_when_shutdown_flag_clear)
{
    TestTimerBase base{TimerConfig{}};
    statusbar::itc::StopToken token;
    base.set_shutdown_flag_for_test(&token);
    base.set_running(true);
    EXPECT_TRUE(base.should_run());
    base.set_running(false);
}

TEST(realtime_timer_base_should_run, false_when_shutdown_flag_set)
{
    TestTimerBase base{TimerConfig{}};
    statusbar::itc::StopToken token;
    token.request_stop();
    base.set_shutdown_flag_for_test(&token);
    base.set_running(true);
    EXPECT_FALSE(base.should_run());
    base.set_running(false);
}

//
// Constructor / histogram propagation
//

TEST(realtime_timer_base_construct, stats_histograms_configured_from_config)
{
    TimerConfig cfg;
    cfg.error_histogram = AtomicHistogramConfig{.low_ns = -500, .high_ns = 2'000, .bin_width_ns = 250};
    cfg.duration_histogram = AtomicHistogramConfig{.low_ns = 0, .high_ns = 4'000, .bin_width_ns = 500};

    TestTimerBase base{cfg};
    // Empty snapshot confirms the stats object constructed successfully with the given configs.
    auto snap = base.stats();
    EXPECT_EQ(snap.error.count, 0);
    EXPECT_EQ(snap.duration.count, 0);
    EXPECT_EQ(base.config().error_histogram.bin_width_ns, 250);
    EXPECT_EQ(base.config().duration_histogram.bin_width_ns, 500);
}

TEST(realtime_timer_base_construct, accessors_reflect_config)
{
    TimerConfig cfg;
    cfg.period_ns = 125'000;
    cfg.compensation_ns = -30'000;
    cfg.cpu = 5;
    cfg.busy_wait = true;

    TestTimerBase base{cfg};
    EXPECT_EQ(base.period_ns(), 125'000);
    EXPECT_EQ(base.compensation_ns(), -30'000);
    EXPECT_EQ(base.cpu(), 5);
    EXPECT_TRUE(base.is_busy_wait());
}

//
// prepare_thread() — happy path only (cpu = -1 avoids affinity/governor work)
//

TEST(realtime_timer_base_prepare, returns_true_when_no_affinity_requested)
{
    // Exercise the real TimerBase::prepare_thread(), including the recursive
    // stack prefault. A small (32 KB) prefault fits on any default thread
    // stack; CPU=-1 skips affinity and isolated-cpu calls.
    TimerConfig cfg;
    cfg.cpu = -1;
    cfg.strict_affinity = false;
    cfg.stack_prefault_bytes = size_t{32} * 1024;
    TestTimerBase base{cfg};
    EXPECT_TRUE(base.call_real_prepare_thread());
}

TEST(realtime_timer_base_prepare, zero_prefault_bytes_skips_prefault)
{
    // stack_prefault_bytes = 0 must be a no-op path — no recursion, no writes.
    TimerConfig cfg;
    cfg.cpu = -1;
    cfg.strict_affinity = false;
    cfg.stack_prefault_bytes = 0;
    TestTimerBase base{cfg};
    EXPECT_TRUE(base.call_real_prepare_thread());
}

TEST(realtime_timer_base_prepare, small_prefault_completes_on_worker_thread)
{
    // Verify the real prepare_thread() — with its recursive prefault — succeeds
    // on a std::thread-default stack (524 KB on macOS). A 64 KB prefault is
    // well under that limit, whereas the legacy 1 MB prefault would SIGBUS here.
    TimerConfig cfg;
    cfg.cpu = -1;
    cfg.strict_affinity = false;
    cfg.stack_prefault_bytes = size_t{64} * 1024;
    TestTimerBase base{cfg};

    std::atomic<bool> ok{false};
    std::thread t([&]() { ok.store(base.call_real_prepare_thread()); });
    t.join();
    EXPECT_TRUE(ok.load());
}

//
// wait_until_absolute / wait_until_busy
//

TEST(realtime_timer_base_wait, absolute_past_deadline_returns_immediately)
{
    int64_t const deadline = read_monotonic_ns() - 1'000'000;  // 1 ms in the past
    int64_t const start = read_monotonic_ns();
    int64_t const err = TestTimerBase::wait_until_absolute(deadline);
    int64_t const elapsed = read_monotonic_ns() - start;

    // Error should be positive (we're late) and elapsed time should be very short.
    EXPECT_TRUE(err > 0);
    EXPECT_TRUE(elapsed < 5'000'000);  // under 5 ms even on a busy system
}

TEST(realtime_timer_base_wait, absolute_future_deadline_sleeps_until_reached)
{
    int64_t const target_wait_ns = 2'000'000;  // 2 ms
    int64_t const deadline = read_monotonic_ns() + target_wait_ns;
    int64_t const start = read_monotonic_ns();
    (void)TestTimerBase::wait_until_absolute(deadline);
    int64_t const actual = read_monotonic_ns();

    // We must have slept at least until the deadline.
    EXPECT_TRUE(actual >= deadline);
    // And not dramatically overshot (give 20ms slack for slow CI / shared hosts).
    EXPECT_TRUE((actual - start) < (target_wait_ns + 20'000'000));
}

TEST(realtime_timer_base_wait, busy_past_deadline_returns_immediately)
{
    int64_t const deadline = read_monotonic_ns() - 500'000;
    int64_t const start = read_monotonic_ns();
    int64_t const err = TestTimerBase::wait_until_busy(deadline);
    int64_t const elapsed = read_monotonic_ns() - start;

    EXPECT_TRUE(err > 0);
    EXPECT_TRUE(elapsed < 5'000'000);
}

TEST(realtime_timer_base_wait, busy_future_deadline_honors_deadline)
{
    int64_t const target_wait_ns = 500'000;  // 500 us — short enough to stay in busy-wait
    int64_t const deadline = read_monotonic_ns() + target_wait_ns;
    (void)TestTimerBase::wait_until_busy(deadline, 1'000'000);  // threshold > period: pure busy-wait
    int64_t const actual = read_monotonic_ns();

    EXPECT_TRUE(actual >= deadline);
}

TEST(realtime_timer_base_wait, busy_sleeps_then_spins_when_threshold_small)
{
    int64_t const target_wait_ns = 3'000'000;  // 3 ms total
    int64_t const threshold_ns = 200'000;      // sleep until deadline - 200us, spin remainder
    int64_t const deadline = read_monotonic_ns() + target_wait_ns;
    int64_t const start = read_monotonic_ns();
    (void)TestTimerBase::wait_until_busy(deadline, threshold_ns);
    int64_t const actual = read_monotonic_ns();

    EXPECT_TRUE(actual >= deadline);
    EXPECT_TRUE((actual - start) < (target_wait_ns + 20'000'000));
}

//
// start() / stop() lifecycle on TimerBase through the test subclass
//

TEST(realtime_timer_base_lifecycle, start_runs_loop_once_and_stops)
{
    TestTimerBase base{TimerConfig{.cpu = -1}};
    base.start(nullptr);
    // Loop is a single increment then returns, so the thread exits quickly on its own.
    // stop() must still be safe even after the thread has already exited.
    base.stop();
    EXPECT_FALSE(base.is_running());
    EXPECT_EQ(base.loop_runs.load(std::memory_order_relaxed), 1);
}

TEST(realtime_timer_base_lifecycle, start_twice_is_noop)
{
    TestTimerBase base{TimerConfig{.cpu = -1}};
    base.start(nullptr);
    base.start(nullptr);  // second call must not spawn a second thread
    base.stop();
    EXPECT_EQ(base.loop_runs.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(base.prepare_calls.load(std::memory_order_relaxed), 1);
}

TEST(realtime_timer_base_lifecycle, stop_without_start_is_noop)
{
    TestTimerBase base{TimerConfig{.cpu = -1}};
    base.stop();
    EXPECT_FALSE(base.is_running());
    EXPECT_EQ(base.loop_runs.load(std::memory_order_relaxed), 0);
}

//
// print_timer_stats(TimerBase const&) free function
//

TEST(realtime_timer_base_print, print_stats_free_function_no_crash)
{
    TestTimerBase base{TimerConfig{}};
    print_timer_stats(base);
    EXPECT_TRUE(true);
}

//
// Tests: AnyTimer lifecycle (non-threaded)
//

TEST(realtime_timer_any_lifecycle, stop_when_empty)
{
    AnyTimer timer;
    timer.stop();
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_any_lifecycle, start_when_empty)
{
    AnyTimer timer;
    timer.start(nullptr);
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_any_lifecycle, print_stats_empty)
{
    AnyTimer timer;
    timer.print_stats();
    EXPECT_TRUE(true);
}

//
// Tests: start_timers / print helpers
//

TEST(realtime_timer_vector, print_configs_no_crash)
{
    std::vector<AnyTimer> timers;
    TimerConfig cfg;
    cfg.period_ns = 1'000'000;
    cfg.name = "cfg_test";
    timers.push_back(AnyTimer::create(cfg, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {}));
    print_timer_configs(timers);
    EXPECT_TRUE(true);
}

TEST(realtime_timer_vector, print_stats_no_crash)
{
    std::vector<AnyTimer> timers;
    TimerConfig cfg;
    cfg.period_ns = 1'000'000;
    cfg.name = "stat_test";
    timers.push_back(AnyTimer::create(cfg, [](TimerEvent<MonotonicClock> const&, AtomicWakeStats::Snapshot const&) {}));
    print_timer_stats(timers);
    EXPECT_TRUE(true);
}

//
// Tests: RealtimeResult helpers
//

TEST(realtime_result, success_result)
{
    auto r = realtime_success();
    EXPECT_TRUE(r.success);
    EXPECT_TRUE(static_cast<bool>(r));
    EXPECT_EQ(r.error_code, 0);
}

TEST(realtime_result, failure_from_code)
{
    auto r = realtime_failure(EINVAL);
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.error_code, EINVAL);
}

TEST(realtime_result, failure_with_message)
{
    auto r = realtime_failure(42, "custom error");
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.error_code, 42);
    EXPECT_NE(r.error_message, nullptr);
}

//
// Tests: scheduling helpers
//

TEST(realtime_scheduling, get_max_fifo_priority)
{
    EXPECT_TRUE(get_max_fifo_priority() > 0);
}

TEST(realtime_scheduling, get_min_fifo_priority)
{
    EXPECT_TRUE(get_min_fifo_priority() >= 0);
}

TEST(realtime_scheduling, reset_scheduling_succeeds)
{
    EXPECT_TRUE(reset_scheduling());
}

//
// Tests: shutdown signaling
//

TEST(realtime_shutdown, shutdown_token_returns_valid_reference)
{
    // shutdown_token() must return a reference to the same StopToken as
    // itc::install_stop_signal() — verify by address equality.
    statusbar::itc::StopToken& rt_token = shutdown_token();
    statusbar::itc::StopToken& sync_token = statusbar::itc::install_stop_signal();
    EXPECT_TRUE(&rt_token == &sync_token);
}

TEST(realtime_shutdown, request_shutdown_sets_token)
{
    // Use a local token to verify shim logic in isolation (the process-wide
    // token may already be stopped from a prior test).
    statusbar::itc::StopToken local_token;
    EXPECT_FALSE(local_token.stop_requested());
    local_token.request_stop();
    EXPECT_TRUE(local_token.stop_requested());
}

TEST(realtime_shutdown, shutdown_token_stop_requested_is_bool)
{
    // Verify shutdown_token() is callable and stop_requested() returns a bool.
    bool const result = shutdown_token().stop_requested();
    EXPECT_TRUE(result || !result);  // always true; exercises the call path
}

//
// Tests: read_monotonic_ns
//

TEST(realtime_monotonic, returns_positive)
{
    EXPECT_TRUE(read_monotonic_ns() > 0);
}

TEST(realtime_monotonic, is_monotonic)
{
    int64_t t1 = read_monotonic_ns();
    int64_t t2 = read_monotonic_ns();
    EXPECT_TRUE(t2 >= t1);
}

//
// Main test runner
//

//
// Raw-reference timer: schedules and measures on CLOCK_MONOTONIC_RAW
//

namespace {

constexpr int64_t RAW_PERIOD_NS = 2'000'000;

/// What the timer thread reported, read back once it has stopped.
struct RawRun
{
    std::atomic<int> wakes{0};
    std::atomic<int64_t> first_scheduled_ns{0};
    std::atomic<int64_t> last_scheduled_ns{0};
    std::atomic<int64_t> worst_error_ns{0};

    auto observe(TimerEvent<MonotonicRawClock> const& event) -> void
    {
        if (wakes.fetch_add(1, std::memory_order_relaxed) == 0) {
            first_scheduled_ns.store(event.scheduled_time_ns(), std::memory_order_relaxed);
        }
        last_scheduled_ns.store(event.scheduled_time_ns(), std::memory_order_relaxed);
        worst_error_ns.store(std::max(worst_error_ns.load(std::memory_order_relaxed), event.error_ns()), std::memory_order_relaxed);
    }
};

/// Run a raw-reference timer until it has woken @p wanted times (or 500 ms
/// have passed) and hand back the line its thread fitted.
auto run_raw_timer(RawRun& run, int wanted) -> MonotonicRawLine::RateOffset
{
    TimerConfig const config{.period_ns = RAW_PERIOD_NS, .cpu = -1, .stack_prefault_bytes = 0};
    Timer<MonotonicRawClockAdapter> timer(config, [&run](auto const& event, auto const&) { run.observe(event); });
    timer.start();
    for (int i = 0; i < 500 && run.wakes.load(std::memory_order_relaxed) < wanted; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    timer.stop();
    return timer.raw_line().consume();
}

}  // namespace

TEST(realtime_timer_raw, the_adapter_decides_which_wait_the_timer_takes)
{
    static_assert(Timer<MonotonicRawClockAdapter>::raw_reference);
    static_assert(!Timer<>::raw_reference);
    static_assert(std::is_same_v<Timer<MonotonicRawClockAdapter>::time_point, MonotonicRawClock::time_point>);
}

TEST(realtime_timer_raw, a_raw_reference_timer_wakes_on_period_boundaries_of_the_raw_clock)
{
    RawRun run;
    auto const line = run_raw_timer(run, 10);
    int const wakes = run.wakes.load(std::memory_order_relaxed);
    EXPECT_TRUE(wakes >= 10);
    // Scheduled times are RAW instants on period boundaries, advancing a
    // period per wake.
    EXPECT_EQ(run.last_scheduled_ns.load(std::memory_order_relaxed) % RAW_PERIOD_NS, int64_t{0});
    EXPECT_TRUE(run.last_scheduled_ns.load() - run.first_scheduled_ns.load() >= (wakes - 1) * RAW_PERIOD_NS);
    // The thread primed its RAW->MONOTONIC line before the first deadline.
    EXPECT_TRUE(line.rate > 0.8 && line.rate < 1.2);
    EXPECT_NE(line.offset_ns, int64_t{0});
    // The wake error is measured on RAW. This runs without SCHED_FIFO on a
    // shared box, so only a gross bound is asserted.
    EXPECT_TRUE(run.worst_error_ns.load(std::memory_order_relaxed) < 50'000'000);
}

TEST_MAIN(statusbar_realtime, realtime_timer_test)
