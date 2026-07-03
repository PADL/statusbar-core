#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Timing Sample Window - Fixed-size ring buffer for timing samples
// No dynamic allocation, O(1) push and indexed access
// Designed for realtime-safe sampling in timing bridges

#include <array>
#include <cstddef>

namespace statusbar::realtime {

/// Maximum window size for timing samples
inline constexpr size_t max_timing_sample_window_size = 512;

/// Ring buffer of timing samples for regression or statistical analysis
/// Fixed-size array with no dynamic allocation
/// Not thread-safe - intended for single-threaded access (e.g., sampler thread)
///
/// @tparam T Sample type (must be default-constructible and copyable)
template <typename T>
class TimingSampleWindow
{
  public:
    explicit TimingSampleWindow(size_t max_size) noexcept
        // Clamp to [1, max]: 0 would make every ring operation divide by max_size_
        // (`% max_size_`) — undefined behavior / SIGFPE.
        : max_size_{
              max_size == 0 ? size_t{1} : (max_size > max_timing_sample_window_size ? max_timing_sample_window_size : max_size)}
    {}

    void push(T sample) noexcept
    {
        samples_[head_] = sample;
        head_ = (head_ + 1) % max_size_;
        if (count_ < max_size_) {
            ++count_;
        }
    }

    void clear() noexcept
    {
        head_ = 0;
        count_ = 0;
    }

    [[nodiscard]] auto size() const noexcept -> size_t { return count_; }
    [[nodiscard]] auto empty() const noexcept -> bool { return count_ == 0; }

    /// Get sample at logical index (0 = oldest, count-1 = newest)
    /// @param idx Logical index into the window
    [[nodiscard]] auto operator[](size_t idx) const noexcept -> T const&
    {
        // Calculate physical index: oldest is at (head_ - count_ + max_size_) % max_size_
        size_t const oldest = (head_ + max_size_ - count_) % max_size_;
        return samples_[(oldest + idx) % max_size_];
    }

  private:
    std::array<T, max_timing_sample_window_size> samples_{};
    size_t head_{0};   // Next write position
    size_t count_{0};  // Current number of samples
    size_t max_size_;  // Configured maximum (clamped to max_timing_sample_window_size)
};

}  // namespace statusbar::realtime
