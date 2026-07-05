#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Thread-safe atomic time measurement statistics.
/// Lock-free accumulator for count, sum, min, max, and variance.
///
/// The sum-of-squares accumulator saturates at INT64_MAX rather than
/// wrapping, and per-sample magnitudes above ~3.037 s (floor(sqrt(INT64_MAX))
/// ns) are clamped before squaring. Once saturated, stddev_ns() degrades
/// deterministically instead of returning wrapped garbage; reset() clears
/// the saturation.

#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>

namespace statusbar::stats {

/// Non-template base class for AtomicTimeStats.
/// Holds atomic state with implementations in .cpp to avoid module inlining issues.
class AtomicTimeStatsBase
{
  public:
    AtomicTimeStatsBase() noexcept;
    ~AtomicTimeStatsBase() = default;

    AtomicTimeStatsBase(AtomicTimeStatsBase const&) = delete;
    auto operator=(AtomicTimeStatsBase const&) -> AtomicTimeStatsBase& = delete;
    AtomicTimeStatsBase(AtomicTimeStatsBase&&) = delete;
    auto operator=(AtomicTimeStatsBase&&) -> AtomicTimeStatsBase& = delete;

  protected:
    auto reset_atomics() noexcept -> void;
    auto update_atomics(int64_t value_ns) noexcept -> void;
    [[nodiscard]] auto load_count() const noexcept -> int64_t;
    [[nodiscard]] auto load_sum_ns() const noexcept -> int64_t;
    [[nodiscard]] auto load_sum_sq() const noexcept -> int64_t;
    [[nodiscard]] auto load_min_ns() const noexcept -> int64_t;
    [[nodiscard]] auto load_max_ns() const noexcept -> int64_t;

  private:
    std::atomic<int64_t> count_{0};
    std::atomic<int64_t> sum_ns_{0};
    std::atomic<int64_t> sum_sq_{0};
    std::atomic<int64_t> min_ns_{std::numeric_limits<int64_t>::max()};
    std::atomic<int64_t> max_ns_{std::numeric_limits<int64_t>::min()};
};

/// Thread-safe time measurement statistics tracker.
/// Tracks count, sum, min, max, and variance using atomic operations.
class AtomicTimeStats : public AtomicTimeStatsBase
{
  public:
    AtomicTimeStats() noexcept = default;

    void update(int64_t value_ns) noexcept { update_atomics(value_ns); }
    void reset() noexcept { reset_atomics(); }

    [[nodiscard]] auto count() const noexcept -> int64_t { return load_count(); }
    [[nodiscard]] auto sum_ns() const noexcept -> int64_t { return load_sum_ns(); }
    [[nodiscard]] auto min_ns() const noexcept -> int64_t { return load_min_ns(); }
    [[nodiscard]] auto max_ns() const noexcept -> int64_t { return load_max_ns(); }

    /// Non-atomic snapshot for consistent multi-field reads.
    struct Snapshot
    {
        int64_t count = 0;
        int64_t sum_ns = 0;
        int64_t sum_sq = 0;
        int64_t min_ns = std::numeric_limits<int64_t>::max();
        int64_t max_ns = std::numeric_limits<int64_t>::min();

        [[nodiscard]] auto average_ns() const noexcept -> double
        {
            return count == 0 ? 0.0 : static_cast<double>(sum_ns) / static_cast<double>(count);
        }

        [[nodiscard]] auto stddev_ns() const noexcept -> double
        {
            if (count < 2) {
                return 0.0;
            }
            double const n = static_cast<double>(count);
            double const mean = average_ns();
            double const variance = (static_cast<double>(sum_sq) / n) - (mean * mean);
            return variance < 0.0 ? 0.0 : std::sqrt(variance);
        }

        [[nodiscard]] auto has_samples() const noexcept -> bool { return count > 0; }
    };

    [[nodiscard]] auto snapshot() const noexcept -> Snapshot
    {
        return Snapshot{
            .count = load_count(),
            .sum_ns = load_sum_ns(),
            .sum_sq = load_sum_sq(),
            .min_ns = load_min_ns(),
            .max_ns = load_max_ns(),
        };
    }
};

}  // namespace statusbar::stats
