#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Launch time on a TX queue (tc-etf(8)): what a host wants of etf given the driver's one answer and,
/// on an interface with no other shaping, an mqprio root that keeps one TX queue for an AF_XDP
/// socket's timed frames, with an offloaded etf on it, and PTP event traffic on a queue of its own.
/// See docs/NET_MODULE.md ("launch time").

#include "statusbar/net/net_tc_qdisc.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <optional>

namespace statusbar::net::tc {

/// What a host does with etf on its AF_XDP socket's queue.
enum class LaunchTimeMode : uint8_t
{
    unsupported,  ///< the driver honours no AF_XDP launch time: etf is neither installed nor looked for
    off,          ///< none wanted: an etf an earlier run left is removed
    on,           ///< an offloaded etf on the socket's queue
};

/// The mode for launch time @p wanted given @p driver (netdev::launch_time_supported(), asked once):
/// on only when the driver honours it; a failed query is off when not wanted (a leftover etf must
/// go) and unsupported when wanted.
[[nodiscard]] auto launch_time_mode(bool wanted, StatusValue<bool> const& driver) noexcept -> LaunchTimeMode;

/// etf's default delta: how long before its launch time a frame queued in etf goes to the driver.
inline constexpr int32_t DEFAULT_ETF_DELTA_NS = 150'000;

#if defined(__linux__)

/// One TX queue kept for an AF_XDP socket's timed frames, on an interface no other qdisc shapes.
struct LaunchTimeQueue
{
    uint16_t major{0};                           ///< our mqprio root's handle major (its classes are major:1..N)
    uint16_t queue{0};                           ///< the socket's TX queue
    uint16_t tx_queues{0};                       ///< the interface's TX queues (tx_queue_count()), at least 2
    int32_t etf_delta_ns{DEFAULT_ETF_DELTA_NS};  ///< bounds only frames that pass through etf
    /// PTP event traffic's own queue, past the socket's with at least one queue past it (none: shared).
    std::optional<uint16_t> ptp_queue{};
    uint8_t ptp_priority{PTP_PRIORITY};  ///< the skb priority mapped to ptp_queue
    /// The root stays without launch time: off lays or keeps it and removes only an etf on the queue.
    bool persistent_root{false};
};

/// The mqprio root for @p queue (hw 0): no priority maps to the socket's queue; with ptp_queue, PTP has
/// its class, the rest the queues past it, any other idle (docs/NET_MODULE.md). Errors: invalid_argument
/// for major 0, under 2 TX queues, a queue past them, or a ptp_queue not past the socket's with one past it.
[[nodiscard]] auto launch_time_mqprio(LaunchTimeQueue const& queue) noexcept -> StatusValue<MqprioQdisc>;

/// The class the socket's queue hangs on: major:(queue + 1).
[[nodiscard]] constexpr auto launch_time_class(LaunchTimeQueue const& queue) noexcept -> uint32_t
{
    return make_handle(queue.major, static_cast<uint16_t>(queue.queue + 1));
}

/// The etf on that class: offloaded (the queue in launch-time mode), CLOCK_TAI, skip_sock_check.
[[nodiscard]] auto launch_time_etf(LaunchTimeQueue const& queue) noexcept -> EtfQdisc;

/// What settle_launch_time_queue() did.
enum class LaunchTimeQueueAction : uint8_t
{
    none,       ///< nothing asked for (unsupported), or nothing of ours to remove (off)
    kept,       ///< our root (and etf, when on) were already there (an earlier run left them)
    installed,  ///< our root, our etf or both laid
    removed,    ///< our root deleted, its etf with it (persistent_root: only our etf)
};

/// Bring @p ifindex's qdiscs to @p mode for @p queue. on: our root and etf, each kept when there; off: our
/// root deleted with its etf (persistent_root: the root laid or kept, only the etf deleted); unsupported:
/// no request. Errors: the first refused request (TcControl::last_message()).
[[nodiscard]] auto settle_launch_time_queue(TcControl& tc, int ifindex, LaunchTimeQueue const& queue, LaunchTimeMode mode)
    -> StatusValue<LaunchTimeQueueAction>;

#endif  // __linux__

}  // namespace statusbar::net::tc
