// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

using namespace statusbar::realtime;

//
// Tests: Tripwire - Construction and initial state
//

TEST(tripwire_construct, default_thresholds)
{
    Tripwire tripwire;

    EXPECT_EQ(tripwire.threshold_ns, 30000);       // Default 30us
    EXPECT_EQ(tripwire.duration_threshold_ns, 0);  // Disabled by default
    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_construct, custom_thresholds)
{
    Tripwire tripwire{.threshold_ns = 50000, .duration_threshold_ns = 100000};

    EXPECT_EQ(tripwire.threshold_ns, 50000);
    EXPECT_EQ(tripwire.duration_threshold_ns, 100000);
    EXPECT_FALSE(tripwire.has_fired());
}

//
// Tests: Tripwire - observe() wake latency detection
//

TEST(tripwire_observe, below_threshold_no_fire)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Wake 29us late - should not fire
    tripwire.observe(1, 1000000, 1029000);

    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_observe, at_threshold_no_fire)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Wake exactly 30us late - should not fire (threshold is exclusive)
    tripwire.observe(1, 1000000, 1030000);

    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_observe, above_threshold_fires)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Wake 31us late - should fire
    tripwire.observe(1, 1000000, 1031000);

    EXPECT_TRUE(tripwire.has_fired());
    EXPECT_FALSE(tripwire.was_duration_trip());
    EXPECT_EQ(tripwire.late_ns(), 31000);
    EXPECT_EQ(tripwire.tick(), 1U);
    EXPECT_EQ(tripwire.sched_ns(), 1000000);
    EXPECT_EQ(tripwire.now_ns(), 1031000);
}

TEST(tripwire_observe, early_wake_no_fire)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Wake 10us early - should not fire (negative latency)
    tripwire.observe(1, 1000000, 990000);

    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_observe, only_first_fire_recorded)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // First violation
    tripwire.observe(1, 1000000, 1040000);  // 40us late

    EXPECT_TRUE(tripwire.has_fired());
    EXPECT_EQ(tripwire.late_ns(), 40000);
    EXPECT_EQ(tripwire.tick(), 1U);

    // Second violation should not update values
    tripwire.observe(2, 2000000, 2100000);  // 100us late

    EXPECT_TRUE(tripwire.has_fired());
    EXPECT_EQ(tripwire.late_ns(), 40000);  // Still first value
    EXPECT_EQ(tripwire.tick(), 1U);        // Still first tick
}

//
// Tests: Tripwire - observe_duration() callback duration detection
//

TEST(tripwire_duration, disabled_no_fire)
{
    Tripwire tripwire{.duration_threshold_ns = 0};  // Disabled

    // Even a very long duration should not fire when disabled
    tripwire.observe_duration(1, 1000000000);

    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_duration, below_threshold_no_fire)
{
    Tripwire tripwire{.duration_threshold_ns = 100000};

    // 50us duration - should not fire
    tripwire.observe_duration(1, 50000);

    EXPECT_FALSE(tripwire.has_fired());
}

TEST(tripwire_duration, above_threshold_fires)
{
    Tripwire tripwire{.duration_threshold_ns = 100000};

    // 150us duration - should fire
    tripwire.observe_duration(1, 150000);

    EXPECT_TRUE(tripwire.has_fired());
    EXPECT_TRUE(tripwire.was_duration_trip());
    EXPECT_EQ(tripwire.duration_ns(), 150000);
    EXPECT_EQ(tripwire.tick(), 1U);
}

//
// Tests: Tripwire - reset() and trigger()
//

TEST(tripwire_reset, clears_fired_state)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Fire the tripwire
    tripwire.observe(1, 1000000, 1050000);
    EXPECT_TRUE(tripwire.has_fired());

    // Reset
    tripwire.reset();

    EXPECT_FALSE(tripwire.has_fired());
    EXPECT_EQ(tripwire.late_ns(), 0);
    EXPECT_EQ(tripwire.tick(), 0U);
}

TEST(tripwire_reset, can_fire_again)
{
    Tripwire tripwire{.threshold_ns = 30000};

    // Fire and reset
    tripwire.observe(1, 1000000, 1050000);
    tripwire.reset();

    // Fire again
    tripwire.observe(2, 2000000, 2060000);  // 60us late

    EXPECT_TRUE(tripwire.has_fired());
    EXPECT_EQ(tripwire.late_ns(), 60000);
    EXPECT_EQ(tripwire.tick(), 2U);
}

TEST(tripwire_trigger, manual_trigger)
{
    Tripwire tripwire;

    EXPECT_FALSE(tripwire.has_fired());

    tripwire.trigger();

    EXPECT_TRUE(tripwire.has_fired());
}

//
// Tests: Tripwire - TripwireEvent triple-buffer channel
//

TEST(tripwire_event, not_ready_before_fire)
{
    Tripwire tripwire{.threshold_ns = 30000};

    EXPECT_FALSE(tripwire.event_ready());
}

TEST(tripwire_event, ready_after_wake_fire_with_coherent_payload)
{
    Tripwire tripwire{.threshold_ns = 30000};

    tripwire.observe(7, 1000000, 1100000);  // 100us late

    EXPECT_TRUE(tripwire.event_ready());

    TripwireEvent const ev = tripwire.consume_event();
    EXPECT_FALSE(ev.fired_on_duration);
    EXPECT_EQ(ev.tick, 7U);
    EXPECT_EQ(ev.late_ns, 100000);
    EXPECT_EQ(ev.now_ns, 1100000);
    EXPECT_EQ(ev.sched_ns, 1000000);
    EXPECT_EQ(ev.duration_ns, 0);
}

TEST(tripwire_event, ready_after_duration_fire_with_coherent_payload)
{
    Tripwire tripwire{.duration_threshold_ns = 100000};

    tripwire.observe_duration(42, 150000);  // 150us duration

    EXPECT_TRUE(tripwire.event_ready());

    TripwireEvent const ev = tripwire.consume_event();
    EXPECT_TRUE(ev.fired_on_duration);
    EXPECT_EQ(ev.tick, 42U);
    EXPECT_EQ(ev.duration_ns, 150000);
    EXPECT_EQ(ev.late_ns, 0);
}

TEST(tripwire_event, consume_advances_past_event)
{
    Tripwire tripwire{.threshold_ns = 30000};

    tripwire.observe(1, 1000000, 1050000);
    EXPECT_TRUE(tripwire.event_ready());

    (void)tripwire.consume_event();

    // Nothing published since the consume - no longer ready.
    EXPECT_FALSE(tripwire.event_ready());
}

TEST(tripwire_event, manual_trigger_publishes_event)
{
    Tripwire tripwire;

    tripwire.trigger();

    EXPECT_TRUE(tripwire.event_ready());
    TripwireEvent const ev = tripwire.consume_event();
    EXPECT_EQ(ev.tick, 0U);
    EXPECT_FALSE(ev.fired_on_duration);
}

TEST(tripwire_event, threaded_publish_consume_is_coherent)
{
    // Exercise the RT-producer -> monitor-consumer split many times.
    // If the migration were torn-read-prone, a consumer could observe
    // a half-written event; the triple buffer guarantees it cannot.
    constexpr uint64_t k_tick = 0xABCDEF12U;
    constexpr int64_t k_sched = 1'000'000;
    constexpr int64_t k_now = 1'100'000;  // 100us late

    for (int iter = 0; iter < 200; ++iter) {
        Tripwire tripwire{.threshold_ns = 30000};
        std::atomic<bool> go{false};

        std::thread producer{[&]() noexcept {
            while (!go.load(std::memory_order_acquire)) {
            }
            tripwire.observe(k_tick, k_sched, k_now);
        }};

        go.store(true, std::memory_order_release);

        while (!tripwire.event_ready()) {
        }
        TripwireEvent const ev = tripwire.consume_event();
        producer.join();

        EXPECT_EQ(ev.tick, k_tick);
        EXPECT_EQ(ev.sched_ns, k_sched);
        EXPECT_EQ(ev.now_ns, k_now);
        EXPECT_EQ(ev.late_ns, k_now - k_sched);
        EXPECT_FALSE(ev.fired_on_duration);
    }
}

//
// Tests: TraceConfig - construction and defaults
//

TEST(trace_config, defaults)
{
    TraceConfig config;

    EXPECT_EQ(config.tracer, "wakeup_rt");
    EXPECT_EQ(config.cpu, 3);
    EXPECT_EQ(config.tripwire_threshold_ns, 50000);  // 50us
    EXPECT_TRUE(config.enable_tracing);
}

//
// Tests: TripwireMonitor - construction and lifecycle
//

TEST(tripwire_monitor_construct, inherits_thresholds)
{
    TraceConfig config;
    config.tripwire_threshold_ns = 75000;
    config.tripwire_duration_threshold_ns = 200000;

    TripwireMonitor monitor(config);

    EXPECT_EQ(monitor.tripwire().threshold_ns, 75000);
    EXPECT_EQ(monitor.tripwire().duration_threshold_ns, 200000);
    EXPECT_EQ(monitor.config().tripwire_threshold_ns, 75000);
}

TEST(tripwire_monitor_construct, not_running_initially)
{
    TraceConfig config;
    TripwireMonitor monitor(config);

    EXPECT_FALSE(monitor.is_running());
}

TEST(tripwire_monitor_lifecycle, start_stop)
{
    TraceConfig config;
    config.enable_tracing = false;  // Skip actual ftrace setup

    TripwireMonitor monitor(config);

    // Start monitor
    statusbar::itc::StopToken shutdown;
    monitor.start(&shutdown);

    EXPECT_TRUE(monitor.is_running());

    // Let the monitor thread start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Stop monitor - should exit cleanly
    monitor.stop();

    EXPECT_FALSE(monitor.is_running());
}

TEST(tripwire_monitor_lifecycle, stop_without_shutdown_flag)
{
    TraceConfig config;
    config.enable_tracing = false;

    TripwireMonitor monitor(config);

    // Start without shutdown flag
    monitor.start(nullptr);

    EXPECT_TRUE(monitor.is_running());

    // Let the monitor thread start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Stop should work via local running flag
    monitor.stop();

    EXPECT_FALSE(monitor.is_running());
}

TEST(tripwire_monitor_lifecycle, destructor_stops)
{
    TraceConfig config;
    config.enable_tracing = false;

    std::atomic<bool> was_running = false;
    {
        TripwireMonitor monitor(config);
        monitor.start(nullptr);
        was_running = monitor.is_running();
        // Destructor should call stop()
    }

    EXPECT_TRUE(was_running.load());
    // If we get here without hanging, destructor worked
}

//
// Tests: TripwireMonitor - check_and_handle_fired
//

TEST(monitor_check_handle, not_fired_returns_false)
{
    TraceConfig config;
    config.enable_tracing = false;

    TripwireMonitor monitor(config);

    EXPECT_FALSE(monitor.check_and_handle_fired(1, 1000));
}

TEST(monitor_check_handle, fired_returns_true)
{
    TraceConfig config;
    config.enable_tracing = false;
    config.tripwire_threshold_ns = 30000;

    TripwireMonitor monitor(config);

    // Fire the tripwire
    monitor.tripwire().observe(1, 1000000, 1050000);  // 50us late

    EXPECT_TRUE(monitor.check_and_handle_fired(1, 50000));
}

TEST(monitor_check_handle, sets_shutdown_flag)
{
    TraceConfig config;
    config.enable_tracing = false;
    config.tripwire_threshold_ns = 30000;

    statusbar::itc::StopToken shutdown;
    TripwireMonitor monitor(config);
    monitor.start(&shutdown);

    // Fire the tripwire
    monitor.tripwire().observe(1, 1000000, 1050000);

    // check_and_handle_fired should request stop on shutdown token
    monitor.check_and_handle_fired(1, 50000);

    EXPECT_TRUE(shutdown.stop_requested());

    monitor.stop();
}

//
// Tests: the TimerEvent bridge measures duration on RAW from the told start
//

namespace {

/// A gPTP-scheduled event whose RAW entry instant is the one the timer
/// would have told: scheduled time 2026-ish in TAI nanoseconds, far from
/// any RAW value this machine will ever produce.
[[nodiscard]] auto gptp_event_told_now() -> TimerEvent<GptpClock0>
{
    return TimerEvent<GptpClock0>{
        .scheduled_time = GptpClock0::from_ns(1'780'000'000'000'000'000),
        .error = GptpClock0::duration{0},
        .wake_count = 7,
        .skipped_counts = 0,
        .wake_raw = MonotonicRawClock::from_ns(read_monotonic_raw_ns()),
    };
}

[[nodiscard]] auto duration_only_monitor_config(int64_t duration_threshold_ns) -> TraceConfig
{
    TraceConfig config;
    config.enable_tracing = false;
    config.tripwire_threshold_ns = 1'000'000'000'000;  // never the wake
    config.tripwire_duration_threshold_ns = duration_threshold_ns;
    return config;
}

void spin_raw_for(int64_t ns)
{
    int64_t const until = read_monotonic_raw_ns() + ns;
    while (read_monotonic_raw_ns() < until) {
    }
}

}  // namespace

TEST(tripwire_bridge, the_wake_hands_back_the_told_raw_start_not_a_schedule_clock_value)
{
    TripwireMonitor monitor(duration_only_monitor_config(1'000'000));
    auto const event = gptp_event_told_now();

    int64_t const start = observe_wake_and_handle_tripwire(monitor, event);

    EXPECT_EQ(start, event.wake_raw_ns());
    EXPECT_NE(start, event.scheduled_time_ns() + event.error_ns());
}

TEST(tripwire_bridge, a_gptp_scheduled_callback_that_overruns_trips_the_duration_tripwire)
{
    TripwireMonitor monitor(duration_only_monitor_config(1'000'000));  // 1 ms budget
    auto const event = gptp_event_told_now();

    int64_t const start = observe_wake_and_handle_tripwire(monitor, event);
    spin_raw_for(3'000'000);  // 3 ms of "work"

    EXPECT_TRUE(observe_duration_and_handle_tripwire(monitor, event, start));
    EXPECT_TRUE(monitor.tripwire().has_fired());
    EXPECT_TRUE(monitor.tripwire().was_duration_trip());
}

TEST(tripwire_bridge, a_gptp_scheduled_callback_within_budget_does_not_trip)
{
    TripwireMonitor monitor(duration_only_monitor_config(500'000'000));  // 500 ms budget
    auto const event = gptp_event_told_now();

    int64_t const start = observe_wake_and_handle_tripwire(monitor, event);

    EXPECT_FALSE(observe_duration_and_handle_tripwire(monitor, event, start));
    EXPECT_FALSE(monitor.tripwire().has_fired());
}

TEST(tripwire_bridge, an_event_not_told_its_raw_entry_is_stamped_with_one_raw_read)
{
    TripwireMonitor monitor(duration_only_monitor_config(1'000'000));
    TimerEvent<GptpClock0> const event{
        .scheduled_time = GptpClock0::from_ns(1'780'000'000'000'000'000),
        .error = GptpClock0::duration{0},
        .wake_count = 1,
        .skipped_counts = 0,
    };

    int64_t const before = read_monotonic_raw_ns();
    int64_t const start = observe_wake_and_handle_tripwire(monitor, event);
    int64_t const after = read_monotonic_raw_ns();

    EXPECT_TRUE(start >= before);
    EXPECT_TRUE(start <= after);
}

//
// Test runner
//

TEST_MAIN(statusbar_realtime, realtime_tripwire_test)