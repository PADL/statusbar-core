// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/stats/stats_atomic_time_stats.hpp"

namespace statusbar::stats {

AtomicTimeStatsBase::AtomicTimeStatsBase() noexcept
{
    reset_atomics();
}

auto AtomicTimeStatsBase::reset_atomics() noexcept -> void
{
    count_.store(0, std::memory_order_relaxed);
    sum_ns_.store(0, std::memory_order_relaxed);
    sum_sq_.store(0, std::memory_order_relaxed);
    min_ns_.store(std::numeric_limits<int64_t>::max(), std::memory_order_relaxed);
    max_ns_.store(std::numeric_limits<int64_t>::min(), std::memory_order_relaxed);
}

namespace {

// floor(sqrt(INT64_MAX)): the largest magnitude whose square fits int64_t.
constexpr uint64_t max_exact_square_root = 3'037'000'499U;

}  // namespace

auto AtomicTimeStatsBase::update_atomics(int64_t value_ns) noexcept -> void
{
    count_.fetch_add(1, std::memory_order_relaxed);
    sum_ns_.fetch_add(value_ns, std::memory_order_relaxed);

    // Square without signed-overflow UB: |value_ns| above ~3.037 s would
    // overflow the multiply, so take the magnitude in uint64 (well-defined
    // even for INT64_MIN) and clamp it first. A clamped square is ~INT64_MAX
    // and saturates the accumulator below on its own.
    uint64_t const mag = value_ns < 0 ? 0U - static_cast<uint64_t>(value_ns) : static_cast<uint64_t>(value_ns);
    uint64_t const capped = mag < max_exact_square_root ? mag : max_exact_square_root;
    uint64_t const sq = capped * capped;

    // Accumulate with saturation at INT64_MAX instead of two's-complement
    // wrapping: a wrapped sum of squares silently yields garbage stddev,
    // a saturated one degrades deterministically. sum_sq_ is monotone
    // non-negative, so the unsigned addition below cannot wrap
    // (INT64_MAX + INT64_MAX < UINT64_MAX).
    int64_t cur = sum_sq_.load(std::memory_order_relaxed);
    while (true) {
        uint64_t const total = static_cast<uint64_t>(cur) + sq;
        int64_t const next = total > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
            ? std::numeric_limits<int64_t>::max()
            : static_cast<int64_t>(total);
        if (sum_sq_.compare_exchange_weak(cur, next, std::memory_order_relaxed)) {
            break;
        }
    }

    int64_t current_min = min_ns_.load(std::memory_order_relaxed);
    while (value_ns < current_min && !min_ns_.compare_exchange_weak(current_min, value_ns, std::memory_order_relaxed)) {
    }

    int64_t current_max = max_ns_.load(std::memory_order_relaxed);
    while (value_ns > current_max && !max_ns_.compare_exchange_weak(current_max, value_ns, std::memory_order_relaxed)) {
    }
}

auto AtomicTimeStatsBase::load_count() const noexcept -> int64_t
{
    return count_.load(std::memory_order_relaxed);
}
auto AtomicTimeStatsBase::load_sum_ns() const noexcept -> int64_t
{
    return sum_ns_.load(std::memory_order_relaxed);
}
auto AtomicTimeStatsBase::load_sum_sq() const noexcept -> int64_t
{
    return sum_sq_.load(std::memory_order_relaxed);
}
auto AtomicTimeStatsBase::load_min_ns() const noexcept -> int64_t
{
    return min_ns_.load(std::memory_order_relaxed);
}
auto AtomicTimeStatsBase::load_max_ns() const noexcept -> int64_t
{
    return max_ns_.load(std::memory_order_relaxed);
}

}  // namespace statusbar::stats
