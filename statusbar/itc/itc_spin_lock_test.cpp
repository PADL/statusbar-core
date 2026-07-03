// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_spin_lock.hpp"

#include "statusbar/test/test.hpp"

#include <mutex>
#include <thread>
#include <vector>

using namespace statusbar;

TEST(spin_lock, try_lock_excludes_until_unlock)
{
    itc::SpinLock lock;
    EXPECT_TRUE(lock.try_lock());   // free -> taken
    EXPECT_FALSE(lock.try_lock());  // held -> denied
    lock.unlock();
    EXPECT_TRUE(lock.try_lock());  // released -> taken again
    lock.unlock();
}

TEST(spin_lock, scoped_lock_serializes_concurrent_increments)
{
    // Mutual exclusion under real contention: if the lock failed to serialize,
    // lost updates would leave the counter below the expected total.
    itc::SpinLock lock;
    constexpr int threads = 8;
    constexpr int iters = 50'000;
    long counter = 0;
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&] {
            for (int i = 0; i < iters; ++i) {
                std::scoped_lock const g(lock);
                ++counter;  // protected by the spin lock
            }
        });
    }
    for (auto& th : pool) {
        th.join();
    }
    EXPECT_EQ(counter, static_cast<long>(threads) * iters);
}

TEST_MAIN(statusbar_itc, itc_spin_lock_test)
