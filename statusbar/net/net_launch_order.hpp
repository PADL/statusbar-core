#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The launch times one AF_XDP socket's frames carry, kept in commit order for a driver whose
/// launch-time queue is a FIFO (igc), and the system's CLOCK_TAI as an untimed frame's time.
/// See docs/NET_MODULE.md ("launch time").

#if defined(__linux__)
#    include <time.h>
#endif

#include <atomic>
#include <cstdint>

namespace statusbar::net {

/// CLOCK_TAI now in ns (vDSO, no syscall): an untimed frame's launch time on a socket whose host has
/// checked that the system clock follows the NIC's PHC. 0 off Linux.
[[nodiscard]] inline auto tai_now_ns() noexcept -> uint64_t
{
#if defined(__linux__)
    timespec now{};
    ::clock_gettime(CLOCK_TAI, &now);
    return (static_cast<uint64_t>(now.tv_sec) * 1'000'000'000U) + static_cast<uint64_t>(now.tv_nsec);
#else
    return 0;
#endif
}

/// The launch times one socket's frames carry, in commit order: never decreasing, as igc's
/// launch-time queue is a FIFO; an untimed frame (0), or one wanted at or before now (a late commit),
/// goes at now(). next() on the transmitting thread only; the counters from any thread.
class LaunchOrder
{
  public:
    /// A wanted time this far behind the last is a clock step, not rounding between sources (nor a
    /// launch lead, at most half this): the floor goes.
    static constexpr uint64_t STEP_NS = 1'000'000;
    /// A frame held back by more than this (a 125 us packet) is counted: by design, two sources on one
    /// socket differ by under a packet.
    static constexpr uint64_t CLAMP_TOLERANCE_NS = 125'000;

    /// The time for a frame asked for at @p requested_ns (0: untimed), given @p now() in ns, read once
    /// per batch: now when the request is 0 or already past (counted late), else the request; at least
    /// the last time given, unless that is more than STEP_NS ahead of it (a backward step).
    template <typename Now>
    [[nodiscard]] auto next(uint64_t const requested_ns, Now const& now) noexcept -> uint64_t
    {
        uint64_t const wanted = not_past(requested_ns, now);
        if (wanted >= last_ns_ || last_ns_ - wanted > STEP_NS) {
            count_step(wanted < last_ns_);
            last_ns_ = wanted;
            return wanted;
        }
        count_clamp(last_ns_ - wanted);
        return last_ns_;
    }
    /// Forget the last time (a new socket); the counters stay.
    void reset() noexcept { last_ns_ = 0; }
    /// Frames held back to the last time by more than CLAMP_TOLERANCE_NS, the most one was held (ns), and
    /// floors dropped for a step (STEP_NS): each means trouble, not the design's rounding.
    [[nodiscard]] auto clamped() const noexcept -> uint64_t { return clamped_.load(std::memory_order_relaxed); }
    [[nodiscard]] auto max_clamp_ns() const noexcept -> uint64_t { return max_clamp_ns_.load(std::memory_order_relaxed); }
    [[nodiscard]] auto steps() const noexcept -> uint64_t { return steps_.load(std::memory_order_relaxed); }
    /// Frames wanted at or before now (committed late), sent at now instead.
    [[nodiscard]] auto launched_late() const noexcept -> uint64_t { return late_.load(std::memory_order_relaxed); }
    /// The most a late frame's wanted time was behind now, ns.
    [[nodiscard]] auto max_late_ns() const noexcept -> uint64_t { return max_late_ns_.load(std::memory_order_relaxed); }

  private:
    /// @p requested_ns unless it is 0 or at or before now (a late commit, counted): then now.
    template <typename Now>
    [[nodiscard]] auto not_past(uint64_t const requested_ns, Now const& now) noexcept -> uint64_t
    {
        if (requested_ns == 0) {
            return now();
        }
        uint64_t const now_ns = now();
        if (requested_ns > now_ns) {
            return requested_ns;
        }
        count_late(now_ns - requested_ns);
        return now_ns;
    }
    void count_clamp(uint64_t const ns) noexcept
    {
        if (ns <= CLAMP_TOLERANCE_NS) {
            return;
        }
        clamped_.store(clamped_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
        if (ns > max_clamp_ns_.load(std::memory_order_relaxed)) {
            max_clamp_ns_.store(ns, std::memory_order_relaxed);
        }
    }
    void count_late(uint64_t const ns) noexcept
    {
        late_.store(late_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
        if (ns > max_late_ns_.load(std::memory_order_relaxed)) {
            max_late_ns_.store(ns, std::memory_order_relaxed);
        }
    }
    void count_step(bool const stepped) noexcept
    {
        if (stepped) {
            steps_.store(steps_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
        }
    }

    uint64_t last_ns_{0};
    std::atomic<uint64_t> clamped_{0};       ///< written by the transmitting thread only
    std::atomic<uint64_t> max_clamp_ns_{0};  ///< written by the transmitting thread only
    std::atomic<uint64_t> steps_{0};         ///< written by the transmitting thread only
    std::atomic<uint64_t> late_{0};          ///< written by the transmitting thread only
    std::atomic<uint64_t> max_late_ns_{0};   ///< written by the transmitting thread only
};

}  // namespace statusbar::net
