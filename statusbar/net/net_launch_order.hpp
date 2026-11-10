#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Launch times in commit order, and the TAI clock they are read against.
///
/// A NIC in launch-time mode (an offloaded `etf`, see net_tc_launch_time.hpp)
/// holds each frame until the time the frame carries. The queue behind it is
/// still a FIFO: the hardware does not reorder, it waits. So a frame handed in
/// with a time *earlier* than the frame before it does not go out early — it
/// goes out at its turn, and everything queued behind it waits for the earlier
/// time to pass. On igc a single frame with a stale time therefore stalls the
/// queue rather than being dropped or sent late on its own.
///
/// That makes "never hand out a time before the last one" a property the
/// talker must maintain, not something the driver will fix. `LaunchOrder` is
/// that one rule, plus the counters that say how often it had to intervene:
///
///   * a clamp of less than one packet is two senders committing in the same
///     tick, which is ordinary;
///   * a longer clamp is a frame that missed its slot, which is worth seeing;
///   * a jump backwards of a second or more is the *clock* moving, not a late
///     frame, so the ordering follows it instead of stalling the talker for
///     the length of the step.
///
/// `next()` runs on the real-time thread and does no allocation, no syscall
/// and no locking. The counters are atomic because a soak test reads them from
/// another thread while it runs.

#include <atomic>
#include <cstdint>
#include <ctime>
#include <type_traits>

namespace statusbar::net {

/// CLOCK_TAI now, in nanoseconds since the epoch.
///
/// TAI and not CLOCK_REALTIME: a launch time is compared against the clock the
/// NIC keeps, which gPTP drives, and TAI has no leap second to step over. A
/// host whose `CLOCK_TAI` offset was never set reads the same as
/// `CLOCK_REALTIME`, which is wrong by the current 37 seconds — that is a
/// configuration fault (`adjtimex`, or a PTP daemon that sets it), and it is
/// visible as every frame being refused by the NIC as too far in the past.
///
/// A host with no TAI clock at all - Darwin - answers CLOCK_REALTIME plus the
/// TAI-UTC offset, 37 s since 2017 and unchanged by any leap second since.
/// No NIC takes a launch time from such a host; the value is for the
/// LaunchOrder logic and its tests, which build everywhere.
[[nodiscard]] inline auto tai_now_ns() noexcept -> std::uint64_t
{
    timespec now{};
#if defined(CLOCK_TAI)
    if (::clock_gettime(CLOCK_TAI, &now) != 0) {
        return 0;
    }
#else
    constexpr std::int64_t TaiMinusUtcSeconds = 37;
    if (::clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return 0;
    }
    now.tv_sec += TaiMinusUtcSeconds;
#endif
    return (static_cast<std::uint64_t>(now.tv_sec) * 1'000'000'000ULL) + static_cast<std::uint64_t>(now.tv_nsec);
}

/// Hands out launch times that never go backwards, and counts when it had to
/// hold one.
class LaunchOrder
{
  public:
    /// A clamp shorter than this is not counted. One packet time at 48 kHz
    /// with six samples to the packet: the shortest packet a talker in this tree
    /// sends, so a clamp below it means two senders in one tick rather than a
    /// frame that missed its slot.
    static constexpr std::uint64_t PACKET_NS = 125'000;

    /// The last time handed out standing this far ahead of `now` is the
    /// clock having stepped back under the ordering, not a late frame. One
    /// second is far longer than any queue this holds and far shorter than a
    /// PTP lock acquiring or a domain change. A wanted time that far behind
    /// with `now` where it was is a stale frame - a talker that stalled and
    /// then committed the departures it had queued - and is held like any
    /// other, or the FIFO would stall behind every one of them.
    static constexpr std::uint64_t STEP_NS = 1'000'000'000;

    /// The time to give a frame whose departure is @p wanted_ns, or @p now_ns
    /// when @p wanted_ns is 0 (the caller has no departure for it). Never
    /// before the time last handed out, unless the clock stepped back.
    ///
    /// @param now_ns The launch-time clock as the caller read it for this
    ///        commit: it is what tells a stale frame from a clock that
    ///        stepped. Told, not asked (see "told the time"): a nanosecond
    ///        count like @p wanted_ns, because the clock is whichever one
    ///        the NIC keeps - CLOCK_TAI, or a PHC - and no one clock tag
    ///        names both. 0 is a failed read (`tai_now_ns` and a PHC read
    ///        both answer 0 then), not a time: see unclocked().
    [[nodiscard]] auto next(std::uint64_t const wanted_ns, std::uint64_t const now_ns) noexcept -> std::uint64_t
    {
        if (now_ns == 0) {
            return unclocked(wanted_ns);
        }
        std::uint64_t const asked = wanted_ns == 0 ? now_ns : wanted_ns;
        std::uint64_t const given = ordered(asked, now_ns);
        last_ns_ = given;
        return given;
    }

    /// next(wanted_ns, now()) for a caller that holds a clock rather than a
    /// time, e.g. `tai_now_ns`; the clock is read once per call.
    template <typename Now>
        requires std::is_invocable_r_v<std::uint64_t, Now const&>
    [[nodiscard]] auto next(std::uint64_t const wanted_ns, Now const& now) noexcept -> std::uint64_t
    {
        return next(wanted_ns, now());
    }

    /// Frames held at the previous time by more than one packet.
    [[nodiscard]] auto clamped() const noexcept -> std::uint64_t { return clamped_.load(std::memory_order_relaxed); }

    /// The largest such hold, in nanoseconds.
    [[nodiscard]] auto max_clamp_ns() const noexcept -> std::uint64_t { return max_clamp_ns_.load(std::memory_order_relaxed); }

    /// Times the clock stepped backwards under us.
    [[nodiscard]] auto steps() const noexcept -> std::uint64_t { return steps_.load(std::memory_order_relaxed); }

    /// Zero the counters. The ordering itself is kept, so this is safe to call
    /// on a live socket.
    auto reset() noexcept -> void
    {
        clamped_.store(0, std::memory_order_relaxed);
        max_clamp_ns_.store(0, std::memory_order_relaxed);
        steps_.store(0, std::memory_order_relaxed);
    }

  private:
    /// The commit whose clock read failed. Without a `now` nothing can tell
    /// a stale frame from a clock that stepped, so nothing is counted and no
    /// time is invented: an untimed frame stays untimed (0, which the NIC
    /// sends at once) and leaves the ordering alone; a timed frame is held at
    /// the last time handed out, so it cannot launch ahead of the frames
    /// already queued. (Before this a 0 `now` read as the clock having
    /// stepped back a whole epoch: any earlier time went through as asked,
    /// the ordering followed it down, and steps() counted a step that never
    /// happened.)
    [[nodiscard]] auto unclocked(std::uint64_t const wanted_ns) noexcept -> std::uint64_t
    {
        if (wanted_ns == 0) {
            return 0;
        }
        std::uint64_t const given = wanted_ns < last_ns_ ? last_ns_ : wanted_ns;
        last_ns_ = given;
        return given;
    }

    /// @p asked, held at the last time handed out where it must be, with the
    /// counters moved on.
    [[nodiscard]] auto ordered(std::uint64_t const asked, std::uint64_t const now_ns) noexcept -> std::uint64_t
    {
        if (asked >= last_ns_) {
            return asked;
        }
        if (last_ns_ >= now_ns + STEP_NS) {
            // The clock, not the frame, went back: follow it.
            steps_.fetch_add(1, std::memory_order_relaxed);
            return asked;
        }
        std::uint64_t const behind = last_ns_ - asked;
        if (behind > PACKET_NS) {
            count_clamp(behind);
        }
        return last_ns_;
    }

    auto count_clamp(std::uint64_t const behind) noexcept -> void
    {
        clamped_.fetch_add(1, std::memory_order_relaxed);
        if (behind > max_clamp_ns_.load(std::memory_order_relaxed)) {
            max_clamp_ns_.store(behind, std::memory_order_relaxed);
        }
    }

    /// Only next() touches this, and only from the real-time thread.
    std::uint64_t last_ns_{0};

    std::atomic<std::uint64_t> clamped_{0};
    std::atomic<std::uint64_t> max_clamp_ns_{0};
    std::atomic<std::uint64_t> steps_{0};
};

}  // namespace statusbar::net
