// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace statusbar::itc {

/// Single-writer / multi-reader holder of the latest published value of a
/// trivially-copyable T, implemented as a seqlock.
///
/// Unlike AtomicTripleBuffer (which is strictly SPSC -- consume() acquires a read
/// slot, so only ONE reader thread may call it), SeqlockValue lets ANY number of
/// threads call load() concurrently, with each other and with a single writer's
/// store(). Use it for a slowly-changing value (a clock rate/offset mapping, a
/// calibration, a status snapshot) that many threads need to read but that no
/// reader should "consume".
///
/// Reads are lock-free but not wait-free: a load() that overlaps a store() retries
/// until it observes a stable snapshot. With an infrequent writer (the usual case)
/// retries are vanishingly rare, so load() is effectively O(1) -- this is the same
/// technique the Linux kernel uses for gettimeofday() timekeeping, and it is safe
/// on a real-time reader thread.
///
/// The payload is stored as an array of lock-free 64-bit words and copied in/out
/// with memcpy, so every byte access is a relaxed atomic and there is no data race
/// on the payload itself; the sequence counter's acquire/release ordering makes each
/// observed snapshot a consistent whole value.
///
/// Threading contract: exactly ONE thread may call store() at a time (single
/// writer). Any thread may call load().
template <class T>
class SeqlockValue
{
    static_assert(std::is_trivially_copyable_v<T>, "SeqlockValue<T> requires trivially copyable T");

    static constexpr std::size_t k_word_bytes = sizeof(std::uint64_t);
    static constexpr std::size_t k_words = (sizeof(T) + k_word_bytes - 1) / k_word_bytes;

  public:
    SeqlockValue() noexcept { store(T{}); }
    explicit SeqlockValue(T const& initial) noexcept { store(initial); }

    /// Writer side (single thread). Publish the new latest value.
    void store(T const& value) noexcept
    {
        std::uint64_t const s = seq_.load(std::memory_order_relaxed);
        // Enter the write: bump the sequence to odd. A reader that observes an odd
        // sequence (or a changed sequence across its read) retries.
        seq_.store(s + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);

        std::array<std::uint64_t, k_words> words{};
        std::memcpy(words.data(), &value, sizeof(T));
        for (std::size_t i = 0; i < k_words; ++i) {
            data_[i].store(words[i], std::memory_order_relaxed);
        }

        std::atomic_thread_fence(std::memory_order_release);
        seq_.store(s + 2, std::memory_order_release);  // leave the write: back to even
    }

    /// Reader side (any thread, any number). Returns the latest published value.
    [[nodiscard]] auto load() const noexcept -> T
    {
        std::array<std::uint64_t, k_words> words{};
        for (;;) {
            std::uint64_t const s1 = seq_.load(std::memory_order_acquire);
            if ((s1 & 1U) != 0U) {
                continue;  // a store is in progress
            }
            for (std::size_t i = 0; i < k_words; ++i) {
                words[i] = data_[i].load(std::memory_order_relaxed);
            }
            std::atomic_thread_fence(std::memory_order_acquire);
            if (seq_.load(std::memory_order_relaxed) == s1) {
                break;  // stable snapshot: no store overlapped this read
            }
        }
        T out{};
        std::memcpy(&out, words.data(), sizeof(T));
        return out;
    }

  private:
    std::atomic<std::uint64_t> seq_{0};
    std::array<std::atomic<std::uint64_t>, k_words> data_{};
};

}  // namespace statusbar::itc
