#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/realtime/realtime_timer.hpp"
#include "statusbar/realtime/realtime_timer_base.hpp"
#include "statusbar/realtime/realtime_timer_config.hpp"
#include "statusbar/realtime/realtime_timer_event.hpp"
#include "statusbar/stats/stats.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <atomic>
#include <memory>
#include <print>
#include <stdexcept>
#include <vector>

namespace statusbar::realtime {

/// Type-erased timer container.
/// Allows storing and using timers with different clock adapters uniformly
/// by holding them through the non-template TimerBase interface.
class AnyTimer
{
  public:
    AnyTimer() = default;

    /// Construct from a Timer with any clock adapter type
    /// @param timer Pointer to a heap-allocated Timer; AnyTimer takes ownership
    template <ClockAdapterType ClockAdapterT>
    explicit AnyTimer(Timer<ClockAdapterT>* timer)
        : impl_{std::unique_ptr<TimerBase>(timer)}
    {}

    /// Construct from an existing unique_ptr to any TimerBase-derived timer
    explicit AnyTimer(std::unique_ptr<TimerBase> impl) noexcept
        : impl_{std::move(impl)}
    {}

    /// Create an AnyTimer scheduled on the reference clock (CLOCK_MONOTONIC_RAW)
    /// @param config Timer configuration
    /// @param callback Callback function
    static auto create(TimerConfig const& config, TimerCallback<MonotonicRawClock> callback) -> AnyTimer
    {
        return AnyTimer{std::make_unique<Timer<>>(config, std::move(callback))};
    }

    /// Create an AnyTimer with a custom clock adapter
    /// @param config Timer configuration
    /// @param adapter Clock adapter (moved into timer)
    /// @param callback Callback function
    template <ClockAdapterType ClockAdapterT>
    static auto create(TimerConfig const& config, ClockAdapterT adapter, TimerCallback<typename ClockAdapterT::clock_type> callback)
        -> AnyTimer
    {
        return AnyTimer{std::make_unique<Timer<ClockAdapterT>>(config, std::move(callback), std::move(adapter))};
    }

    ~AnyTimer() = default;

    // Move-only
    AnyTimer(AnyTimer&&) noexcept = default;
    auto operator=(AnyTimer&&) noexcept -> AnyTimer& = default;
    AnyTimer(AnyTimer const&) = delete;
    auto operator=(AnyTimer const&) -> AnyTimer& = delete;

    /// Check if this AnyTimer holds a timer
    [[nodiscard]] explicit operator bool() const noexcept { return impl_ != nullptr; }

    /// Start the timer thread
    /// @param shutdown_token Optional external stop token to signal shutdown
    auto start(statusbar::itc::StopToken* shutdown_token = nullptr) -> void
    {
        if (impl_) {
            impl_->start(shutdown_token);
        }
    }

    /// Stop the timer thread
    auto stop() noexcept -> void
    {
        if (impl_) {
            impl_->stop();
        }
    }

    /// Check if timer is running
    [[nodiscard]] auto is_running() const noexcept -> bool { return impl_ && impl_->is_running(); }

    /// Get statistics snapshot
    [[nodiscard]] auto stats() const noexcept -> stats::AtomicWakeStats::Snapshot
    {
        if (impl_) {
            return impl_->stats();
        }
        return {};
    }

    /// Get timer configuration
    [[nodiscard]] auto config() const -> TimerConfig const&
    {
        if (!impl_) {
            throw_or_abort(std::errc::operation_not_permitted, "AnyTimer is empty");
        }
        return impl_->config();
    }

    /// Print statistics report
    auto print_stats() const -> void
    {
        if (impl_) {
            print_timer_stats(*impl_);
        }
    }

  private:
    std::unique_ptr<TimerBase> impl_;
};

/// RAII wrapper that starts an AnyTimer on construction and stops on destruction
struct AnyTimerStart
{
    explicit AnyTimerStart(AnyTimer& timer, statusbar::itc::StopToken* shutdown_token = nullptr)
        : timer_{timer}
    {
        timer_.start(shutdown_token);
    }

    ~AnyTimerStart() noexcept { timer_.stop(); }

    AnyTimerStart(AnyTimerStart const&) = delete;
    auto operator=(AnyTimerStart const&) -> AnyTimerStart& = delete;
    AnyTimerStart(AnyTimerStart&&) = delete;
    auto operator=(AnyTimerStart&&) -> AnyTimerStart& = delete;

  private:
    AnyTimer& timer_;
};

/// Start all timers in a vector and return RAII guards
/// @param timers Vector of timers to start
/// @param shutdown_token Optional stop token to pass to each timer
/// @return Vector of unique_ptr to AnyTimerStart guards (timers stop when guards are destroyed)
inline auto start_timers(std::vector<AnyTimer>& timers, statusbar::itc::StopToken* shutdown_token = nullptr)
    -> std::vector<std::unique_ptr<AnyTimerStart>>
{
    std::vector<std::unique_ptr<AnyTimerStart>> guards;
    guards.reserve(timers.size());
    for (auto& timer : timers) {
        guards.push_back(std::make_unique<AnyTimerStart>(timer, shutdown_token));
    }
    return guards;
}

/// Print configuration for all timers in a vector
/// @param timers Vector of timers to print configs for
inline auto print_timer_configs(std::vector<AnyTimer> const& timers) -> void
{
    for (auto const& timer : timers) {
        print_timer_config(timer.config());
    }
    std::print("\n");
}

/// Print statistics for all timers in a vector
/// @param timers Vector of timers to print stats for
inline auto print_timer_stats(std::vector<AnyTimer> const& timers) -> void
{
    for (auto const& timer : timers) {
        std::print("\n=== {} Stats ===\n", timer.config().name);
        timer.print_stats();
    }
}

}  // namespace statusbar::realtime
