// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/benchmark/benchmark.hpp"

#include "statusbar/test/test.hpp"

#include <chrono>
#include <cstdint>
#include <type_traits>
#include <vector>

using namespace statusbar::benchmark;

//
// Timer - Basic Tests
//
// The stopwatch is run on a clock the test sets, so each elapsed time is
// exact and nothing waits.
//

namespace {

/// A clock that reads whatever the test last told it.
struct ToldClock
{
    using duration = std::chrono::nanoseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<ToldClock>;
    static constexpr bool is_steady = true;

    static inline time_point told{};

    static auto now() noexcept -> time_point { return told; }
    static auto advance(duration by) noexcept -> void { told += by; }
};

using ToldTimer = BasicTimer<ToldClock>;

}  // namespace

TEST(timer_basic, start_and_elapsed)
{
    auto const timer = ToldTimer::start();
    EXPECT_EQ(timer.elapsed_ns(), int64_t{0});
    ToldClock::advance(std::chrono::milliseconds(10));
    EXPECT_EQ(timer.elapsed_ns(), int64_t{10'000'000});
    EXPECT_TRUE(timer.elapsed() == std::chrono::milliseconds(10));
}

TEST(timer_basic, elapsed_us)
{
    auto const timer = ToldTimer::start();
    ToldClock::advance(std::chrono::nanoseconds(5'000'500));
    EXPECT_TRUE(timer.elapsed_us() == 5000.5);
}

TEST(timer_basic, elapsed_ms)
{
    auto const timer = ToldTimer::start();
    ToldClock::advance(std::chrono::microseconds(5'250));
    EXPECT_TRUE(timer.elapsed_ms() == 5.25);
}

TEST(timer_basic, elapsed_s)
{
    auto const timer = ToldTimer::start();
    ToldClock::advance(std::chrono::milliseconds(1'500));
    EXPECT_TRUE(timer.elapsed_s() == 1.5);
}

TEST(timer_basic, reset)
{
    auto timer = ToldTimer::start();
    ToldClock::advance(std::chrono::milliseconds(10));
    timer.reset();
    // After reset, the count starts again from the reset.
    EXPECT_EQ(timer.elapsed_ns(), int64_t{0});
    ToldClock::advance(std::chrono::microseconds(3));
    EXPECT_EQ(timer.elapsed_ns(), int64_t{3'000});
}

TEST(timer_basic, the_default_stopwatch_is_on_steady_clock)
{
    static_assert(std::is_same_v<Timer, BasicTimer<std::chrono::steady_clock>>);
    static_assert(std::is_same_v<Timer::Clock, std::chrono::steady_clock>);
    // A real clock never runs backwards, whatever the load.
    auto const timer = Timer::start();
    EXPECT_TRUE(timer.elapsed_ns() >= 0);
}

//
// do_not_optimize - Tests
//

TEST(do_not_optimize_test, const_reference)
{
    int value = 42;
    do_not_optimize(value);
    // Just verify it doesn't crash - the point is to prevent optimization
    EXPECT_EQ(value, 42);
}

TEST(do_not_optimize_test, mutable_reference)
{
    int value = 42;
    do_not_optimize(value);
    value = 100;
    do_not_optimize(value);
    EXPECT_EQ(value, 100);
}

TEST(do_not_optimize_test, complex_type)
{
    std::vector<int> vec{1, 2, 3, 4, 5};
    do_not_optimize(vec);
    EXPECT_EQ(vec.size(), 5);
}

//
// BenchmarkConfig - Tests
//

TEST(config_test, default_values)
{
    BenchmarkConfig config;
    EXPECT_EQ(config.warmup_iterations, 100);
    EXPECT_EQ(config.measurement_iterations, 1000);
    EXPECT_EQ(config.batch_size, 1);
    EXPECT_EQ(config.verbose, false);
}

//
// run() - Benchmark Execution Tests
//

TEST(run_test, simple_function)
{
    int counter = 0;
    BenchmarkConfig config;
    config.warmup_iterations = 5;
    config.measurement_iterations = 10;

    auto stats = run(
        "test",
        [&counter]() {
            counter++;
            do_not_optimize(counter);
        },
        config);

    EXPECT_EQ(stats.sample_count, 10);
    // Counter should be warmup + measurement iterations
    EXPECT_EQ(counter, 15);
}

TEST(run_test, with_batch_size)
{
    int counter = 0;
    BenchmarkConfig config;
    config.warmup_iterations = 2;
    config.measurement_iterations = 3;
    config.batch_size = 4;

    auto stats = run(
        "test_batch",
        [&counter]() {
            counter++;
            do_not_optimize(counter);
        },
        config);

    EXPECT_EQ(stats.sample_count, 3);
    // Counter should be (warmup + measurement) * batch_size
    EXPECT_EQ(counter, (2 + 3) * 4);
}

//
// HardwareTimer - Basic Tests
//

TEST(hw_timer_basic, ticks_per_second_nonzero)
{
    EXPECT_TRUE(HardwareTimer::ticks_per_second() > 0);
}

TEST(hw_timer_basic, elapsed_ticks_monotonic)
{
    auto timer = HardwareTimer::start();
    auto t1 = timer.elapsed_ticks();
    // Do a tiny bit of work so the counter advances
    uint64_t volatile sum = 0;
    for (int i = 0; i < 1000; ++i) {
        sum += static_cast<uint64_t>(i);
    }
    do_not_optimize(sum);
    auto t2 = timer.elapsed_ticks();
    EXPECT_TRUE(t2 >= t1);
}

// The conversions below are told the counter's reading, so each is exact:
// the counter itself is only read by start().
TEST(hw_timer_basic, elapsed_ns_is_the_told_ticks_at_the_counters_rate)
{
    auto const timer = HardwareTimer::start();
    uint64_t const per_second = HardwareTimer::ticks_per_second();
    EXPECT_EQ(timer.elapsed_ticks_at(timer.start_tick()), uint64_t{0});
    EXPECT_EQ(timer.elapsed_ns_at(timer.start_tick()), int64_t{0});
    // One second of ticks later, and three.
    EXPECT_EQ(timer.elapsed_ns_at(timer.start_tick() + per_second), int64_t{1'000'000'000});
    EXPECT_EQ(timer.elapsed_ns_at(timer.start_tick() + (3 * per_second)), int64_t{3'000'000'000});
    EXPECT_EQ(timer.elapsed_ticks_at(timer.start_tick() + per_second), per_second);
}

TEST(hw_timer_basic, reset_starts_again_from_the_counter_as_it_stands)
{
    auto timer = HardwareTimer::start();
    uint64_t const first = timer.start_tick();
    timer.reset();
    // The counter does not run backwards, whatever the load.
    EXPECT_TRUE(timer.start_tick() >= first);
}

TEST(hw_timer_basic, ticks_to_ns_is_whole_seconds_plus_the_remainder)
{
    uint64_t const per_second = HardwareTimer::ticks_per_second();
    EXPECT_EQ(HardwareTimer::ticks_to_ns(0), int64_t{0});
    EXPECT_EQ(HardwareTimer::ticks_to_ns(per_second), int64_t{1'000'000'000});
    // A count far past where ticks * 1e9 would overflow 64 bits.
    EXPECT_EQ(HardwareTimer::ticks_to_ns(100'000 * per_second), int64_t{100'000} * 1'000'000'000);
    // Half a second, to the tick.
    int64_t const half = HardwareTimer::ticks_to_ns(per_second / 2);
    EXPECT_TRUE(half >= 499'999'999 && half <= 500'000'000);
}

TEST_MAIN(statusbar_benchmark, benchmark_test)