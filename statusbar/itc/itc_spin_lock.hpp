#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A minimal test-and-set spin lock. Encapsulates the bare `std::atomic_flag`
/// spin-lock pattern that was otherwise open-coded on RT/reactor paths, so the
/// atomic lives in one audited place and call sites use standard RAII
/// (std::scoped_lock) instead of hand-rolled test_and_set / clear pairs.
///
/// Satisfies the C++ Lockable requirement (lock / try_lock / unlock), so it
/// composes with std::scoped_lock / std::unique_lock. Intended for VERY short
/// critical sections (a few instructions) where a blocking mutex's syscall
/// overhead is not worth it and contention is rare — e.g. an RT media thread
/// briefly excluding a reactor thread. It is NOT fair and does NOT sleep, so
/// never hold it across a long or blocking operation.
///
/// try_lock() lets an RT thread attempt the lock and bail out on contention
/// (do other work) instead of spinning, preserving its deadline.

#include <atomic>

namespace statusbar::itc {

class SpinLock
{
  public:
    SpinLock() noexcept = default;
    SpinLock(SpinLock const&) = delete;
    SpinLock(SpinLock&&) = delete;
    SpinLock& operator=(SpinLock const&) = delete;
    SpinLock& operator=(SpinLock&&) = delete;

    /// Acquire, spinning until the lock is free. Bounded only if the holder's
    /// critical section is short (the intended use).
    void lock() noexcept
    {
        while (flag_.test_and_set(std::memory_order_acquire)) {
            // spin
        }
    }

    /// Try to acquire without spinning. Returns true iff the lock was taken.
    [[nodiscard]] auto try_lock() noexcept -> bool { return !flag_.test_and_set(std::memory_order_acquire); }

    /// Release. Must be called by the thread that currently holds the lock.
    void unlock() noexcept { flag_.clear(std::memory_order_release); }

  private:
    std::atomic_flag flag_{};
};

}  // namespace statusbar::itc
