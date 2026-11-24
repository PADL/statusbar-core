// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The realtime module against the real clocks and a real thread: the
// sleeps, the RAW wait, the sampled line and a running timer. Every other
// realtime test is told its time; these few are the asking forms tried on
// the host. None of them says how long anything took, only what no amount
// of load can change.

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#include <atomic>
#include <cstdint>

using namespace statusbar::realtime;
using namespace statusbar::stats;

namespace {

/// TimerBase with its waits made callable and its thread preparation left
/// out (no stack prefault, no scheduling change).
class WaitingTimerBase : public TimerBase
{
  public:
    using TimerBase::TimerBase;
    using TimerBase::wait_slice;
    using TimerBase::wait_until_absolute;
    using TimerBase::wait_until_raw_deadline;

  protected:
    auto run_loop() -> void override {}
    auto prepare_thread() -> bool override { return true; }
};

/// A Timer<> that skips the thread preparation, so it runs unprivileged
/// with the default thread stack.
class PlainTimer : public Timer<>
{
  public:
    using Timer<>::Timer;

  protected:
    auto prepare_thread() -> bool override { return true; }
};

}  // namespace

TEST(clock_reads, sleeping_to_a_monotonic_deadline_reaches_it)
{
    auto const deadline = read_monotonic() + Nanoseconds{2'000'000};
    EXPECT_EQ(sleep_until_monotonic(deadline), 0);
    EXPECT_TRUE(read_monotonic() >= deadline);

    // A deadline already passed returns at once.
    EXPECT_EQ(sleep_until_monotonic(read_monotonic() - Nanoseconds{1'000'000}), 0);
}

TEST(realtime_timer_base_wait, absolute_future_deadline_sleeps_until_reached)
{
    auto const deadline = read_monotonic() + Nanoseconds{2'000'000};
    (void)WaitingTimerBase::wait_until_absolute(deadline);
    // Slept at least until the deadline. By how much it was overshot
    // depends on the host's load and is not asserted.
    EXPECT_TRUE(read_monotonic() >= deadline);
}

TEST(realtime_timer_base_wait, a_real_wait_never_ends_before_its_deadline)
{
    WaitingTimerBase base{TimerConfig{.period_ns = 1'000'000'000, .cpu = -1}};
    auto const deadline = read_monotonic_raw() + Nanoseconds{2'000'000};
    auto const result = base.wait_until_raw_deadline(deadline);

    EXPECT_TRUE(read_monotonic_raw() >= deadline);
    EXPECT_TRUE(result.error >= Nanoseconds::zero());
    // The thread kept a line for the sleep, and the line says how good it is.
    EXPECT_NE(base.raw_line().consume().offset_ns, int64_t{0});
    EXPECT_TRUE(base.raw_line().quality().is_bounded());
}

TEST(realtime_timer_base_wait, a_slice_of_a_long_wait_returns_with_the_deadline_still_ahead)
{
    WaitingTimerBase base{TimerConfig{.period_ns = 1'000'000'000, .cpu = -1}};
    auto const deadline = read_monotonic_raw() + std::chrono::hours{1};

    // An hour to go and 5 ms to sleep: no result, and the hour is not over.
    auto const before = read_monotonic();
    EXPECT_FALSE(base.wait_slice(deadline, Nanoseconds{5'000'000}).has_value());
    EXPECT_TRUE(read_monotonic() >= before + Nanoseconds{5'000'000});
    EXPECT_TRUE(read_monotonic_raw() < deadline);

    // A deadline inside the slice is the whole wait.
    auto const near = read_monotonic_raw() + Nanoseconds{2'000'000};
    auto const result = base.wait_slice(near, Nanoseconds{50'000'000});
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(read_monotonic_raw() >= near);
}

TEST(monotonic_raw_tracker, sampling_the_clocks_gives_a_line_through_the_live_offset)
{
    MonotonicRawLine line;
    MonotonicRawTracker tracker{line};
    auto const sampled = read_monotonic_raw();
    int64_t const bracket = tracker.sample().count();
    EXPECT_TRUE(bracket >= 0);
    // The line says how good it is: half the bracket it was read in.
    EXPECT_TRUE(line.quality().is_bounded());
    EXPECT_EQ(line.quality().bound_at_sync.count(), (bracket + 1) / 2);

    // A second pairing, read between two RAW reads, puts the live offset
    // in a range. One sample makes a line at rate one, so its offset lies
    // in that range give or take the first bracket and what a slewed
    // CLOCK_MONOTONIC gained since: at most a fifth of the time that
    // passed, the widest rate the tracker itself accepts. Every term is
    // measured, so a loaded host widens the range instead of failing; the
    // one constant covers the step the clocks count in (CLOCK_MONOTONIC
    // counts whole microseconds on macOS).
    int64_t const raw_before = read_monotonic_raw_ns();
    int64_t const mono = read_monotonic_ns();
    int64_t const raw_after = read_monotonic_raw_ns();
    int64_t const slack = bracket + ((raw_after - MonotonicRawClock::to_ns(sampled)) / 5) + 2'000;
    int64_t const offset = line.consume_fixed().offset_ns;
    EXPECT_TRUE(offset >= mono - raw_after - slack);
    EXPECT_TRUE(offset <= mono - raw_before + slack);
}

TEST(realtime_timer_event, a_running_timer_tells_the_raw_instant_it_entered_the_callback)
{
    TimerConfig config;
    config.period_ns = 1'000'000;  // 1 ms
    config.cpu = -1;

    std::atomic<int64_t> told_raw{0};
    std::atomic<int64_t> read_raw{0};
    std::atomic<bool> told{false};
    int64_t const raw_before_start = read_monotonic_raw_ns();
    PlainTimer timer(config, [&](TimerEvent<MonotonicRawClock> const& event, AtomicWakeStats::Snapshot const&) {
        if (!told.load()) {
            told_raw.store(event.wake_raw_ns());
            read_raw.store(read_monotonic_raw_ns());
            told.store(true);
            told.notify_all();
        }
    });
    timer.start();
    // Block until the first wake has been told, however long that takes.
    told.wait(false);
    timer.stop();

    // An instant of the RAW clock, between the start of the timer and the
    // callback's own read. Nothing here says how far apart those were.
    EXPECT_TRUE(told_raw.load() >= raw_before_start);
    EXPECT_TRUE(read_raw.load() >= told_raw.load());
}

TEST(realtime_timer_stop, a_timer_an_hour_from_its_first_wake_stops)
{
    // The first wake is two periods off. stop() must not wait for it: the
    // thread looks at its running flag between slices of the wait. Were it
    // parked on the deadline, this test would not come back.
    TimerConfig config;
    config.period_ns = 1'800'000'000'000;  // half an hour
    config.cpu = -1;

    std::atomic<int> wakes{0};
    PlainTimer timer(config, [&](TimerEvent<MonotonicRawClock> const&, AtomicWakeStats::Snapshot const&) { ++wakes; });
    timer.start();
    timer.stop();
    EXPECT_FALSE(timer.is_running());
    EXPECT_EQ(wakes.load(), 0);
}

TEST_MAIN(statusbar_realtime, realtime_functional_test)
