// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_stop_token.hpp"

#include "statusbar/test/test.hpp"

#include <atomic>
#include <chrono>
#include <thread>

using statusbar::itc::StopToken;
using namespace std::chrono_literals;

TEST(sync_stop_token_init, fresh_token_is_not_requested)
{
    StopToken t;
    EXPECT_FALSE(t.stop_requested());
    EXPECT_FALSE(t.wait_for_stop(0ms));
}

TEST(sync_stop_token_request, request_stop_sets_flag)
{
    StopToken t;
    t.request_stop();
    EXPECT_TRUE(t.stop_requested());
}

TEST(sync_stop_token_request, signal_set_sets_flag)
{
    StopToken t;
    t.signal_set();
    EXPECT_TRUE(t.stop_requested());
}

TEST(sync_stop_token_wait, wait_returns_true_when_already_set)
{
    StopToken t;
    t.request_stop();
    EXPECT_TRUE(t.wait_for_stop(0ms));
}

TEST(sync_stop_token_wait, wait_times_out_when_not_set)
{
    StopToken t;
    auto const start = std::chrono::steady_clock::now();
    bool const got = t.wait_for_stop(10ms);
    auto const elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_FALSE(got);
    EXPECT_TRUE(elapsed >= 10ms);
}

// The waiters below wait "for an hour": a wake-up that never came would hang
// the test and the runner's timeout would report it. None of them asserts
// how long anything took, and none sleeps to let a thread get somewhere.
TEST(sync_stop_token_wakeup, request_stop_wakes_waiter)
{
    StopToken t;
    std::atomic<bool> waiting{false};
    std::atomic<bool> waiter_returned{false};
    std::thread waiter{[&]() noexcept {
        waiting.store(true);
        waiting.notify_all();
        bool const got = t.wait_for_stop(1h);
        waiter_returned.store(got, std::memory_order_relaxed);
    }};
    waiting.wait(false);
    t.request_stop();
    waiter.join();
    EXPECT_TRUE(waiter_returned.load(std::memory_order_relaxed));
}

TEST(sync_stop_token_wakeup, a_flag_set_from_a_signal_handler_is_seen_by_the_next_wait)
{
    // signal_set() only stores the flag: it is all a signal handler may do,
    // so it notifies nobody and a waiter already blocked notices at its own
    // timeout. What can be said without a clock: the flag is set, and a
    // wait that starts after it returns at once.
    StopToken t;
    t.signal_set();
    EXPECT_TRUE(t.stop_requested());
    EXPECT_TRUE(t.wait_for_stop(1h));
    EXPECT_TRUE(t.wait_for_stop(0ms));
}

TEST(sync_stop_token_wakeup, multiple_waiters_all_wake_on_request_stop)
{
    StopToken t;
    std::atomic<int> waiting{0};
    std::atomic<int> woken{0};
    auto run_waiter = [&]() noexcept {
        waiting.fetch_add(1);
        waiting.notify_all();
        if (t.wait_for_stop(1h)) {
            woken.fetch_add(1, std::memory_order_relaxed);
        }
    };
    std::thread a{run_waiter};
    std::thread b{run_waiter};
    std::thread c{run_waiter};
    for (int seen = waiting.load(); seen < 3; seen = waiting.load()) {
        waiting.wait(seen);
    }
    t.request_stop();
    a.join();
    b.join();
    c.join();
    EXPECT_EQ(woken.load(std::memory_order_relaxed), 3);
}

TEST_MAIN(statusbar_itc, itc_stop_token_test)
