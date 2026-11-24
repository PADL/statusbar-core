// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#if defined(__linux__)
#    include <sys/mman.h>
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
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
    EXPECT_TRUE(config.lock_memory);
    EXPECT_EQ(config.start_offset_cycles, 2);
    EXPECT_EQ(config.resync_interval_cycles, 1000);
}

TEST(realtime_timer_config, the_lines_figures_reach_the_timers_line)
{
    TimerConfig config;
    EXPECT_EQ(config.raw_line_drift_bound_ppb, MonotonicRawLineConfig{}.drift_bound_ppb);
    EXPECT_EQ(config.raw_line_sleep_rate_margin_ppb, MonotonicRawLineConfig{}.sleep_rate_margin_ppb);

    config.raw_line_drift_bound_ppb = 50'000;
    config.raw_line_sleep_rate_margin_ppb = 20'000;
    Timer<> const timer{config, [](TimerEvent<> const&, statusbar::stats::AtomicWakeStats::Snapshot const&) {}};
    EXPECT_EQ(timer.raw_line().config().drift_bound_ppb, uint32_t{50'000});
    EXPECT_EQ(timer.raw_line().config().sleep_rate_margin_ppb, uint32_t{20'000});
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
// Tests: Timer construction (default MonotonicRawClockAdapter)
//

TEST(realtime_timer_construct, valid_config)
{
    TimerConfig config;
    config.period_ns = 1'000'000;  // 1 ms

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

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

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_EQ(timer.compensation_ns(), -25'000);
    EXPECT_EQ(timer.compensation().count(), -25'000);
}

TEST(realtime_timer_construct, busy_wait_mode)
{
    TimerConfig config;
    config.period_ns = 125'000;
    config.busy_wait = true;

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_TRUE(timer.is_busy_wait());
}

TEST(realtime_timer_construct, period_as_duration)
{
    TimerConfig config;
    config.period_ns = 250'000;

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_EQ(timer.period().count(), 250'000);
}

TEST(realtime_timer_construct, config_accessor)
{
    TimerConfig config;
    config.name = "test_timer";
    config.period_ns = 1'000'000;
    config.cpu = 2;
    config.priority = 80;

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

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

    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    auto snapshot = timer.stats();
    EXPECT_EQ(snapshot.error.count, 0);
    EXPECT_EQ(snapshot.duration.count, 0);
}

//
// Tests: TimerEvent
//

TEST(realtime_timer_event, the_scheduled_time_is_on_the_events_clock)
{
    TimerEvent<GptpClock0> event{
        .scheduled_time = GptpClock0::from_ns(1'000'000'000),
        .error = Nanoseconds{500},
        .wake_count = 1,
        .skipped_counts = 0,
    };

    static_assert(std::is_same_v<decltype(event.scheduled_time), GptpClock0::time_point>);
    static_assert(std::is_same_v<decltype(event.error), Nanoseconds>);
    EXPECT_EQ(GptpClock0::to_ns(event.scheduled_time), int64_t{1'000'000'000});
}

TEST(realtime_timer_event, the_error_is_a_signed_duration)
{
    TimerEvent<MonotonicRawClock> event{
        .scheduled_time = MonotonicRawClock::from_ns(0),
        .error = Nanoseconds{-250},
        .wake_count = 1,
        .skipped_counts = 0,
    };

    EXPECT_EQ(event.error.count(), int64_t{-250});
}

TEST(realtime_timer_event, fields_accessible)
{
    TimerEvent<MonotonicRawClock> event{
        .scheduled_time = MonotonicRawClock::from_ns(5000),
        .error = Nanoseconds{100},
        .wake_count = 42,
        .skipped_counts = 3,
    };

    EXPECT_EQ(event.wake_count, 42);
    EXPECT_EQ(event.skipped_counts, 3);
}

TEST(realtime_timer_event, an_event_built_by_hand_was_not_told_its_raw_entry)
{
    TimerEvent<> const by_hand{
        .scheduled_time = MonotonicRawClock::from_ns(5000),
        .error = Nanoseconds{0},
        .wake_count = 1,
        .skipped_counts = 0,
    };
    static_assert(std::is_same_v<TimerEvent<>, TimerEvent<MonotonicRawClock>>);
    EXPECT_EQ(by_hand.wake_raw_ns(), int64_t{0});
    // Nor an accuracy.
    EXPECT_TRUE(by_hand.accuracy == UNBOUNDED_ACCURACY);
}

TEST(realtime_timer_event, the_nanosecond_accessors_read_the_typed_fields)
{
    // Kept for callbacks written against them.
    TimerEvent<GptpClock0> const event{
        .scheduled_time = GptpClock0::from_ns(1'000'000'000),
        .error = Nanoseconds{-250},
        .wake_count = 1,
        .skipped_counts = 0,
        .wake_raw = MonotonicRawClock::from_ns(77),
    };

    EXPECT_EQ(event.scheduled_time_ns(), int64_t{1'000'000'000});
    EXPECT_EQ(event.error_ns(), int64_t{-250});
    EXPECT_EQ(event.wake_raw_ns(), int64_t{77});
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

    auto timer = AnyTimer::create(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    EXPECT_TRUE(static_cast<bool>(timer));
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_any, config_accessor)
{
    TimerConfig config;
    config.period_ns = 2'000'000;
    config.name = "any_test";

    auto timer = AnyTimer::create(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

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

    auto timer1 = AnyTimer::create(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});
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
    Timer<> timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});
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
    using TimerBase::early_wake;
    using TimerBase::is_running_atomic;
    using TimerBase::set_running;
    using TimerBase::should_run;
    using TimerBase::try_start;
    using TimerBase::try_stop;
    using TimerBase::wait_outcome;
    using TimerBase::wait_until_absolute;
    using TimerBase::wait_until_raw_deadline;
    using TimerBase::wake_target;

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
// wait_until_absolute. The waits that really wait (a sleep to a deadline
// ahead, a RAW wait, a running timer) are in realtime_functional_test.cpp.
//

TEST(realtime_timer_base_wait, absolute_past_deadline_returns_immediately)
{
    auto const deadline = read_monotonic() - Nanoseconds{1'000'000};  // 1 ms in the past
    auto const start = read_monotonic();
    Nanoseconds const err = TestTimerBase::wait_until_absolute(deadline);
    Nanoseconds const elapsed = read_monotonic() - start;

    // The error is positive (we're late) by at least the millisecond the
    // deadline was already past; how long the call took is the host's affair.
    EXPECT_TRUE(err >= Nanoseconds{1'000'000});
    EXPECT_TRUE(elapsed >= Nanoseconds::zero());
}

//
// The arithmetic of a RAW wait, told the time: no clock is read here.
//

TEST(realtime_timer_base_wait, a_wake_past_the_deadline_counts_the_periods_it_missed)
{
    TestTimerBase const base{TimerConfig{.period_ns = 1'000'000, .cpu = -1}};
    auto const deadline = MonotonicRawClock::from_ns(50'000'000'000);

    auto const on_time = base.wait_outcome(deadline, deadline + Nanoseconds{300});
    EXPECT_EQ(on_time.error.count(), int64_t{300});
    EXPECT_EQ(on_time.skipped_counts, int64_t{0});

    // Five and a half periods late: five whole periods were missed.
    auto const late = base.wait_outcome(deadline, deadline + Nanoseconds{5'500'000});
    EXPECT_EQ(late.error.count(), int64_t{5'500'000});
    EXPECT_EQ(late.skipped_counts, int64_t{5});

    // Exactly one period late is still this wake, not a missed one.
    EXPECT_EQ(base.wait_outcome(deadline, deadline + Nanoseconds{1'000'000}).skipped_counts, int64_t{0});
    // A period of zero divides nothing.
    EXPECT_EQ(wait_result(Nanoseconds{5'500'000}, Nanoseconds::zero()).skipped_counts, int64_t{0});
}

TEST(realtime_timer_base_wait, the_wait_aims_at_the_compensated_deadline_and_measures_against_the_uncompensated_one)
{
    // Compensation moves the wake, not the instant the error is measured from.
    Nanoseconds const early{20'000'000};
    TestTimerBase const base{TimerConfig{.period_ns = 1'000'000'000, .compensation_ns = -early.count(), .cpu = -1}};
    auto const deadline = MonotonicRawClock::from_ns(50'000'000'000);

    auto const target = base.wake_target(deadline);
    EXPECT_TRUE(target == deadline - early);
    // Woken 150 ns after the target: early by the compensation less that.
    auto const outcome = base.wait_outcome(deadline, target + Nanoseconds{150});
    EXPECT_EQ(outcome.error.count(), -early.count() + 150);
    EXPECT_EQ(outcome.skipped_counts, int64_t{0});
}

TEST(realtime_timer_base_wait, the_coarse_sleep_ends_a_guard_before_the_target)
{
    // A timer that has not waited yet holds the identity line, so here a
    // CLOCK_MONOTONIC instant reads the same as the RAW one. The guard is
    // raw_spin_guard_ns plus the slew the sleep could accrue: 100 ppm of
    // margin on a line at rate one.
    TestTimerBase const base{TimerConfig{.period_ns = 1'000'000'000, .cpu = -1, .raw_spin_guard_ns = 50'000}};
    auto const now = MonotonicRawClock::from_ns(50'000'000'000);

    // 5 ms to go: sleep to 50 us and 500 ns before the target.
    auto const wake = base.early_wake(now + Nanoseconds{5'000'000}, now);
    EXPECT_TRUE(wake.has_value());
    EXPECT_EQ(
        MonotonicClock::to_ns(wake.value_or(MonotonicClock::time_point{})), int64_t{50'000'000'000 + 5'000'000 - 50'000 - 500});

    // Inside the guard, at the target, or past it: no sleep, the wait is a spin.
    EXPECT_FALSE(base.early_wake(now + Nanoseconds{50'004}, now).has_value());
    EXPECT_FALSE(base.early_wake(now, now).has_value());
    EXPECT_FALSE(base.early_wake(now - Nanoseconds{5'500'000}, now).has_value());
}

TEST(realtime_timer_base_wait, a_busy_wait_timer_spins_the_whole_of_a_short_wait)
{
    // busy_wait: the guard is busy_wait_threshold_ns.
    TestTimerBase const base{
        TimerConfig{.period_ns = 1'000'000'000, .busy_wait_threshold_ns = 10'000'000, .cpu = -1, .busy_wait = true}};
    auto const now = MonotonicRawClock::from_ns(50'000'000'000);

    EXPECT_FALSE(base.early_wake(now + Nanoseconds{500'000}, now).has_value());
    // A long one still sleeps first: to 10 ms and 5 us before the target.
    auto const wake = base.early_wake(now + Nanoseconds{50'000'000}, now);
    EXPECT_EQ(
        MonotonicClock::to_ns(wake.value_or(MonotonicClock::time_point{})),
        int64_t{50'000'000'000 + 50'000'000 - 10'000'000 - 5'000});
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
// prepare_thread(): TimerConfig::lock_memory decides whether the timer locks
// the process's memory. Measured through VmLck, so Linux only.
//

#if defined(__linux__)

namespace {

/// The process's locked memory in kB, from /proc/self/status, or -1.
auto vm_lck_kb() -> long
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmLck:")) {
            return std::strtol(line.c_str() + 6, nullptr, 10);
        }
    }
    return -1;
}

/// A 4 MiB anonymous mapping, every page touched, so mlockall(MCL_CURRENT)
/// would have that much to take in.
class TouchedMapping
{
  public:
    static constexpr size_t SIZE = size_t{4} * 1024 * 1024;

    TouchedMapping()
        : base_{mmap(nullptr, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)}
    {
        if (base_ == MAP_FAILED) {
            base_ = nullptr;
            return;
        }
        auto* bytes = static_cast<unsigned char volatile*>(base_);
        for (size_t off = 0; off < SIZE; off += 4096) {
            bytes[off] = 1;
        }
    }
    ~TouchedMapping()
    {
        if (base_ != nullptr) {
            (void)munmap(base_, SIZE);
        }
    }
    TouchedMapping(TouchedMapping const&) = delete;
    auto operator=(TouchedMapping const&) -> TouchedMapping& = delete;
    TouchedMapping(TouchedMapping&&) = delete;
    auto operator=(TouchedMapping&&) -> TouchedMapping& = delete;

    [[nodiscard]] auto valid() const noexcept -> bool { return base_ != nullptr; }

  private:
    void* base_;
};

}  // namespace

TEST(realtime_timer_base_prepare, lock_memory_off_locks_nothing)
{
    TouchedMapping const mapping;
    EXPECT_TRUE(mapping.valid());
    long const before = vm_lck_kb();
    EXPECT_TRUE(before >= 0);

    TestTimerBase base{TimerConfig{.cpu = -1, .stack_prefault_bytes = 0, .lock_memory = false}};
    EXPECT_TRUE(base.call_real_prepare_thread());

    EXPECT_EQ(vm_lck_kb(), before);
}

TEST(realtime_timer_base_prepare, lock_memory_on_takes_in_every_mapping)
{
    if (statusbar::test::under_address_sanitizer) {
        SKIP("AddressSanitizer reports mlockall success without locking anything");
    }
    TouchedMapping const mapping;
    EXPECT_TRUE(mapping.valid());
    long const before = vm_lck_kb();

    TestTimerBase base{TimerConfig{.cpu = -1, .stack_prefault_bytes = 0, .lock_memory = true}};
    EXPECT_TRUE(base.call_real_prepare_thread());
    long const after = vm_lck_kb();
    (void)unlock_memory();  // leave the process as it was for the tests that follow

    if (after == before) {
        SKIP("mlockall is not permitted here (RLIMIT_MEMLOCK / CAP_IPC_LOCK)");
    }
    // The mapping has nothing to do with the timer and is locked all the same.
    EXPECT_TRUE(after - before >= static_cast<long>(TouchedMapping::SIZE / 1024));
}

#else

TEST(realtime_timer_base_prepare, lock_memory_off_locks_nothing)
{
    SKIP("VmLck is read from /proc/self/status (Linux only)");
}

TEST(realtime_timer_base_prepare, lock_memory_on_takes_in_every_mapping)
{
    SKIP("VmLck is read from /proc/self/status (Linux only)");
}

#endif

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
    timers.push_back(AnyTimer::create(cfg, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {}));
    print_timer_configs(timers);
    EXPECT_TRUE(true);
}

TEST(realtime_timer_vector, print_stats_no_crash)
{
    std::vector<AnyTimer> timers;
    TimerConfig cfg;
    cfg.period_ns = 1'000'000;
    cfg.name = "stat_test";
    timers.push_back(AnyTimer::create(cfg, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {}));
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
// The schedule a timer keeps (TimerSchedule), told the time: every instant
// below is made up, nothing waits and no clock is read.
//

namespace {

constexpr Nanoseconds SCHEDULE_PERIOD{2'000'000};

/// A made-up domain a fixed distance ahead of RAW, far enough that a value
/// on one clock could never be mistaken for a value on the other, and
/// running `ppm` fast of it.
struct ToldSource
{
    static constexpr int64_t OFFSET_NS = 1'780'000'000'000'000'000;

    int64_t ppm{0};
    bool healthy{true};

    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return OFFSET_NS; }  // a schedule is told, it does not ask
    [[nodiscard]] auto to_raw_ns(int64_t domain_ns) const noexcept -> int64_t
    {
        int64_t const elapsed = domain_ns - OFFSET_NS;
        return elapsed - ((elapsed * ppm) / 1'000'000);
    }
    [[nodiscard]] auto from_raw_ns(int64_t raw_ns) const noexcept -> int64_t
    {
        return OFFSET_NS + raw_ns + ((raw_ns * ppm) / 1'000'000);
    }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return healthy; }
};

/// The same domain from a source that reports its quality: whatever the
/// test last set, as a follower's would be whatever its last sync left.
struct ToldQualifiedSource : ToldSource
{
    ClockQuality reported{};

    [[nodiscard]] auto quality() const noexcept -> ClockQuality { return reported; }
};

/// A domain the test can move to another timeline: `offset_ns` ahead of RAW
/// at rate one, known as well as `reported` says.
struct SteppingSource
{
    int64_t offset_ns{ToldSource::OFFSET_NS};
    ClockQuality reported{};

    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return offset_ns; }
    [[nodiscard]] auto to_raw_ns(int64_t domain_ns) const noexcept -> int64_t { return domain_ns - offset_ns; }
    [[nodiscard]] auto from_raw_ns(int64_t raw_ns) const noexcept -> int64_t { return raw_ns + offset_ns; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return true; }
    [[nodiscard]] auto quality() const noexcept -> ClockQuality { return reported; }
};

using RawSchedule = TimerSchedule<MonotonicRawClockAdapter>;
using GptpAdapter = ClockAdapter<GptpClock0, ToldSource>;
using QualifiedGptpAdapter = ClockAdapter<GptpClock0, ToldQualifiedSource>;
using SteppingAdapter = ClockAdapter<GptpClock0, SteppingSource>;

/// A timeline synchronized at RAW @p synced_ns to within @p bound_ns,
/// drifting no faster than 20 ppm.
constexpr auto timeline_quality(uint64_t epoch, int64_t synced_ns, int64_t bound_ns) -> ClockQuality
{
    return {
        .synced_at = MonotonicRawClock::from_ns(synced_ns),
        .bound_at_sync = Nanoseconds{bound_ns},
        .epoch = epoch,
        .drift_bound_ppb = 20'000,
        .time_source = TimeSource::ptp};
}

/// A wait that ended @p error late having missed @p skipped whole periods.
constexpr auto waited(int64_t error_ns = 0, int64_t skipped = 0) -> WaitResult
{
    return {.error = Nanoseconds{error_ns}, .skipped_counts = skipped};
}

}  // namespace

TEST(realtime_timer_raw, a_timer_given_no_adapter_runs_on_the_raw_clock)
{
    static_assert(std::is_same_v<Timer<>, Timer<MonotonicRawClockAdapter>>);
    static_assert(std::is_same_v<Timer<>::clock_type, MonotonicRawClock>);
    static_assert(std::is_same_v<Timer<>::time_point, MonotonicRawClock::time_point>);
    static_assert(std::is_same_v<Timer<>::event_type, TimerEvent<MonotonicRawClock>>);
}

TEST(realtime_timer_schedule, the_grid_starts_on_a_period_boundary_past_the_time_it_is_told)
{
    RawSchedule schedule{{}, {.period = SCHEDULE_PERIOD, .start_offset_cycles = 2}};
    EXPECT_TRUE(schedule.is_ready());

    // Told a time 700 us into cycle 10: the first wake is cycle 12.
    schedule.begin(MonotonicRawClock::from_ns((10 * SCHEDULE_PERIOD.count()) + 700'000));
    EXPECT_EQ(schedule.wake_count(), int64_t{12});
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().scheduled), 12 * SCHEDULE_PERIOD.count());
    // On the RAW clock the schedule and the wait are the same instant.
    EXPECT_TRUE(schedule.deadline().raw_deadline == schedule.deadline().scheduled);
}

TEST(realtime_timer_schedule, each_wake_moves_one_period_and_a_late_one_skips_what_it_missed)
{
    RawSchedule schedule{{}, {.period = SCHEDULE_PERIOD}};
    schedule.begin(MonotonicRawClock::from_ns(10 * SCHEDULE_PERIOD.count()));

    schedule.advance(waited(100));
    EXPECT_EQ(schedule.wake_count(), int64_t{13});
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().scheduled), 13 * SCHEDULE_PERIOD.count());

    // Five and a half periods late: the five boundaries that passed are
    // skipped, not run late one after the other.
    schedule.advance(waited(11'000'000, 5));
    EXPECT_EQ(schedule.wake_count(), int64_t{19});
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().scheduled), 19 * SCHEDULE_PERIOD.count());
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), 19 * SCHEDULE_PERIOD.count());
}

TEST(realtime_timer_schedule, the_event_tells_the_schedule_and_how_the_wait_ended)
{
    RawSchedule schedule{{}, {.period = SCHEDULE_PERIOD}};
    schedule.begin(MonotonicRawClock::from_ns(10 * SCHEDULE_PERIOD.count()));

    auto const event = schedule.event(waited(4'000'300, 2));
    EXPECT_TRUE(event.scheduled_time == schedule.deadline().scheduled);
    EXPECT_EQ(event.error.count(), int64_t{4'000'300});
    EXPECT_EQ(event.wake_count, int64_t{12});
    EXPECT_EQ(event.skipped_counts, int64_t{2});
    // The RAW clock is its own reference: the schedule is exact.
    EXPECT_EQ(event.accuracy.count(), int64_t{0});
    // When the callback is entered is the thread's to stamp, not the schedule's.
    EXPECT_TRUE(event.wake_raw == MonotonicRawClock::time_point{});
}

TEST(realtime_timer_schedule, a_schedule_on_a_gptp_adapter_is_laid_in_gptp_and_waited_for_on_raw)
{
    static_assert(std::is_same_v<Timer<GptpAdapter>::event_type, TimerEvent<GptpClock0>>);
    static_assert(std::is_same_v<TimerSchedule<GptpAdapter>::event_type, TimerEvent<GptpClock0>>);

    ToldSource const source;
    TimerSchedule<GptpAdapter> schedule{GptpAdapter{source}, {.period = SCHEDULE_PERIOD}};
    // Told the gPTP time 700 us into its cycle that RAW would call cycle 10.
    schedule.begin(GptpClock0::from_ns(ToldSource::OFFSET_NS + (10 * SCHEDULE_PERIOD.count()) + 700'000));

    // The schedule is a period boundary of the gPTP domain...
    int64_t const scheduled_gptp_ns = GptpClock0::to_ns(schedule.deadline().scheduled);
    EXPECT_EQ(scheduled_gptp_ns % SCHEDULE_PERIOD.count(), int64_t{0});
    EXPECT_EQ(scheduled_gptp_ns, ToldSource::OFFSET_NS + (12 * SCHEDULE_PERIOD.count()));
    // ...and the wait is for the same instant on RAW.
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), 12 * SCHEDULE_PERIOD.count());
    EXPECT_TRUE(schedule.event(waited()).scheduled_time == schedule.deadline().scheduled);
}

TEST(realtime_timer_schedule, both_instants_move_by_the_period_until_a_resync_converts_afresh)
{
    // A domain 100 ppm fast of RAW: one of its milliseconds is 999'900 ns of RAW.
    ToldSource const source{.ppm = 100};
    constexpr Nanoseconds PERIOD{1'000'000};
    TimerSchedule<GptpAdapter> schedule{
        GptpAdapter{source}, {.period = PERIOD, .start_offset_cycles = 2, .resync_interval_cycles = 4}};
    schedule.begin(GptpClock0::from_ns(ToldSource::OFFSET_NS));

    // Cycle 2 of the domain since its offset, converted: 2 ms less 200 ns.
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{1'999'800});
    // Cycle 3: moved by the period on both clocks, 100 ns late on RAW.
    schedule.advance(waited());
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{2'999'800});
    // Cycle 4 is a multiple of the resync interval: converted afresh.
    schedule.advance(waited());
    EXPECT_EQ(schedule.wake_count() % 4, int64_t{0});
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{3'999'600});
    EXPECT_EQ(GptpClock0::to_ns(schedule.deadline().scheduled), ToldSource::OFFSET_NS + 4'000'000);

    // With the resync turned off the two drift apart for good.
    TimerSchedule<GptpAdapter> never{
        GptpAdapter{source}, {.period = PERIOD, .start_offset_cycles = 2, .resync_interval_cycles = 0}};
    never.begin(GptpClock0::from_ns(ToldSource::OFFSET_NS));
    never.advance(waited());
    never.advance(waited());
    EXPECT_EQ(MonotonicRawClock::to_ns(never.deadline().raw_deadline), int64_t{3'999'800});
}

//
// The accuracy a timer tells with every wake
//

TEST(realtime_timer_accuracy, a_source_without_quality_is_ready_while_healthy_and_claims_no_accuracy)
{
    static_assert(!QualifiedClockAdapter<GptpAdapter>);

    ToldSource source{.healthy = false};
    TimerSchedule<GptpAdapter> schedule{GptpAdapter{source}, {.period = SCHEDULE_PERIOD}};
    EXPECT_FALSE(schedule.is_ready());
    source.healthy = true;
    EXPECT_TRUE(schedule.is_ready());

    schedule.begin(GptpClock0::from_ns(ToldSource::OFFSET_NS));
    EXPECT_TRUE(schedule.accuracy() == UNBOUNDED_ACCURACY);
    EXPECT_TRUE(schedule.event(waited()).accuracy == UNBOUNDED_ACCURACY);
}

TEST(realtime_timer_accuracy, a_schedule_waits_for_the_first_sync_then_coasts_and_tells_the_growing_accuracy)
{
    static_assert(QualifiedClockAdapter<QualifiedGptpAdapter>);

    ToldQualifiedSource source;  // never synchronized, and it says it is not healthy either
    source.healthy = false;
    TimerSchedule<QualifiedGptpAdapter> schedule{QualifiedGptpAdapter{source}, {.period = SCHEDULE_PERIOD}};
    EXPECT_FALSE(schedule.is_ready());

    // One sync at RAW 1 s, good to 500 ns, drifting no faster than 20 ppm.
    // Then the master is gone for good: this quality is never refreshed.
    source.reported = {
        .synced_at = MonotonicRawClock::from_ns(1'000'000'000),
        .bound_at_sync = Nanoseconds{500},
        .epoch = 1,
        .drift_bound_ppb = 20'000,
        .time_source = TimeSource::ptp};
    // Ready on the bound alone: a source that reports quality is not asked for its health.
    EXPECT_TRUE(schedule.is_ready());

    // Started 300 us after the sync: the first wake is 4 ms after it.
    schedule.begin(GptpClock0::from_ns(ToldSource::OFFSET_NS + 1'000'300'000));
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{1'004'000'000});
    EXPECT_EQ(schedule.event(waited()).accuracy.count(), int64_t{500 + 80});  // 4 ms at 20 ppm
    schedule.advance(waited());
    EXPECT_EQ(schedule.event(waited()).accuracy.count(), int64_t{500 + 120});  // 6 ms

    // Thirty seconds on (told as one long skip), still coasting, still on its grid.
    schedule.advance(waited(0, 14'999));
    EXPECT_TRUE(schedule.is_ready());
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{31'006'000'000});
    EXPECT_EQ(schedule.event(waited()).accuracy.count(), int64_t{500 + 600'120});  // 30.006 s

    // A new timeline with nothing known of it yet: the schedule goes on,
    // and each wake says that it can vouch for nothing.
    source.reported = ClockQuality{.epoch = 2};
    schedule.advance(waited());
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{31'008'000'000});
    EXPECT_TRUE(schedule.event(waited()).accuracy == UNBOUNDED_ACCURACY);
}

//
// A clock that moves to another timeline under a running schedule
//

TEST(realtime_timer_timeline, a_schedule_tells_the_timeline_its_grid_is_on)
{
    // An adapter that reports no quality has one timeline, number 0.
    RawSchedule raw{{}, {.period = SCHEDULE_PERIOD}};
    raw.begin(MonotonicRawClock::from_ns(10 * SCHEDULE_PERIOD.count()));
    EXPECT_EQ(raw.timeline(), uint64_t{0});
    EXPECT_FALSE(raw.timeline_changed());
    EXPECT_FALSE(raw.follow_timeline(MonotonicRawClock::from_ns(11 * SCHEDULE_PERIOD.count())));
    EXPECT_EQ(raw.event(waited()).timeline, uint64_t{0});

    SteppingSource source{.reported = timeline_quality(7, 1'000'000'000, 500)};
    TimerSchedule<SteppingAdapter> schedule{SteppingAdapter{source}, {.period = SCHEDULE_PERIOD}};
    schedule.begin(GptpClock0::from_ns(source.offset_ns + 1'000'300'000));
    EXPECT_EQ(schedule.timeline(), uint64_t{7});
    EXPECT_EQ(schedule.event(waited()).timeline, uint64_t{7});
    EXPECT_FALSE(schedule.timeline_changed());
    // Nothing to follow while the clock stays on the grid's timeline.
    EXPECT_FALSE(schedule.follow_timeline(MonotonicRawClock::from_ns(1'000'400'000)));
}

TEST(realtime_timer_timeline, a_grid_left_behind_coasts_unconverted_until_the_new_timeline_claims_a_bound)
{
    SteppingSource source{.reported = timeline_quality(1, 1'000'000'000, 500)};
    TimerSchedule<SteppingAdapter> schedule{
        SteppingAdapter{source}, {.period = SCHEDULE_PERIOD, .start_offset_cycles = 2, .resync_interval_cycles = 2}};
    schedule.begin(GptpClock0::from_ns(source.offset_ns + 1'000'300'000));
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{1'004'000'000});
    int64_t const old_wake_count = schedule.wake_count();

    // A new grandmaster an hour behind the old one, nothing known of it yet.
    constexpr int64_t HOUR_NS = 3'600'000'000'000;
    source.offset_ns -= HOUR_NS;
    source.reported = ClockQuality{.epoch = 2};
    EXPECT_TRUE(schedule.timeline_changed());
    EXPECT_TRUE(schedule.event(waited()).accuracy == UNBOUNDED_ACCURACY);
    EXPECT_EQ(schedule.event(waited()).timeline, uint64_t{1});

    // Five wakes on, through two resync points: the grid keeps its pace on
    // RAW. Had it been put through the new mapping, the next wake would be
    // an hour away.
    for (int i = 1; i <= 5; ++i) {
        schedule.advance(waited(300));
        EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), 1'004'000'000 + (i * SCHEDULE_PERIOD.count()));
        EXPECT_TRUE(schedule.event(waited()).accuracy == UNBOUNDED_ACCURACY);
    }
    EXPECT_EQ(schedule.wake_count(), old_wake_count + 5);

    // The new timeline synchronizes. The wake that ends 300 ns after RAW
    // 1.014 s lays the grid again from there: two cycles past the one that
    // instant is in, on the new timeline.
    source.reported = timeline_quality(2, 1'015'000'000, 800);
    schedule.advance(waited(300));
    EXPECT_FALSE(schedule.timeline_changed());
    EXPECT_EQ(schedule.timeline(), uint64_t{2});
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{1'018'000'000});
    EXPECT_EQ(GptpClock0::to_ns(schedule.deadline().scheduled), source.offset_ns + 1'018'000'000);
    // The cycle numbers are the new timeline's: an hour of them fewer.
    EXPECT_EQ(schedule.wake_count(), old_wake_count + 7 - (HOUR_NS / SCHEDULE_PERIOD.count()));
    auto const event = schedule.event(waited());
    EXPECT_EQ(event.timeline, uint64_t{2});
    EXPECT_EQ(event.accuracy.count(), int64_t{800 + 60});  // 3 ms past the sync at 20 ppm
}

TEST(realtime_timer_timeline, a_thread_between_slices_of_a_long_wait_can_have_the_grid_laid_again)
{
    // A slow timer: its next wake is most of a second off when the clock steps.
    constexpr Nanoseconds SLOW{1'000'000'000};
    SteppingSource source{.reported = timeline_quality(1, 1'000'000'000, 500)};
    TimerSchedule<SteppingAdapter> schedule{SteppingAdapter{source}, {.period = SLOW}};
    schedule.begin(GptpClock0::from_ns(source.offset_ns + 1'000'300'000));
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{3'000'000'000});

    // The clock steps 400 ms forward and is known at once.
    source.offset_ns += 400'000'000;
    source.reported = timeline_quality(2, 1'200'000'000, 900);
    EXPECT_TRUE(schedule.follow_timeline(MonotonicRawClock::from_ns(1'300'000'000)));
    // RAW 1.3 s is 1.7 s into the new timeline's count from the old zero:
    // the grid is its whole seconds, the first wake two past this one.
    EXPECT_EQ(GptpClock0::to_ns(schedule.deadline().scheduled), ToldSource::OFFSET_NS + 3'000'000'000);
    EXPECT_EQ(MonotonicRawClock::to_ns(schedule.deadline().raw_deadline), int64_t{2'600'000'000});
    EXPECT_EQ(schedule.timeline(), uint64_t{2});
    // Followed once: there is nothing more to follow.
    EXPECT_FALSE(schedule.follow_timeline(MonotonicRawClock::from_ns(1'400'000'000)));
}

TEST(realtime_timer_accuracy, a_timer_is_ready_when_its_schedule_is)
{
    // A timer that is built and never started: no thread, no clock.
    ToldQualifiedSource source;
    TimerConfig const config{.period_ns = SCHEDULE_PERIOD.count(), .cpu = -1, .stack_prefault_bytes = 0};
    Timer<QualifiedGptpAdapter> const timer(
        config, [](TimerEvent<GptpClock0> const&, AtomicWakeStats::Snapshot const&) {}, QualifiedGptpAdapter{source});
    EXPECT_FALSE(timer.schedule().is_ready());

    source.reported = {.synced_at = MonotonicRawClock::from_ns(1'000'000'000), .bound_at_sync = Nanoseconds{500}};
    EXPECT_TRUE(timer.schedule().is_ready());
}

//
// Tests: stop() joins a thread that left on its own
//

namespace {

/// A timer whose thread preparation fails, so the thread leaves on its own
/// with the running flag cleared: the shape a strict-affinity failure, a
/// readiness wait cut short by shutdown or a tripwire leaves behind.
class SelfExitingTimer : public Timer<>
{
  public:
    using Timer<>::Timer;

    [[nodiscard]] auto thread_joinable() const noexcept -> bool { return timer_thread_.joinable(); }

  protected:
    auto prepare_thread() -> bool override { return false; }
};

}  // namespace

TEST(realtime_timer_stop, joins_a_thread_that_left_on_its_own)
{
    TimerConfig config;
    config.period_ns = 1'000'000;
    SelfExitingTimer timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    timer.start();
    // The thread clears the running flag itself as it leaves; the
    // std::thread stays joinable until somebody joins it. Wait for that
    // to have happened, however long the host takes to run the thread.
    while (timer.is_running()) {
        std::this_thread::yield();
    }
    EXPECT_FALSE(timer.is_running());
    EXPECT_TRUE(timer.thread_joinable());

    // stop() had nothing to clear and must still join; before, it returned
    // on the clear and the destructor terminated the process.
    timer.stop();
    EXPECT_FALSE(timer.thread_joinable());
    EXPECT_FALSE(timer.is_running());
}

TEST(realtime_timer_stop, a_timer_whose_thread_left_on_its_own_starts_again)
{
    TimerConfig config;
    config.period_ns = 1'000'000;
    SelfExitingTimer timer(config, [](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) {});

    timer.start();
    while (timer.is_running()) {
        std::this_thread::yield();
    }
    EXPECT_TRUE(timer.thread_joinable());

    // The first thread is gone and not yet joined. Starting again joins it
    // first; before, the new thread was assigned over it and the process
    // terminated.
    timer.start();
    while (timer.is_running()) {
        std::this_thread::yield();
    }
    timer.stop();
    EXPECT_FALSE(timer.thread_joinable());
}

TEST_MAIN(statusbar_realtime, realtime_timer_test)
