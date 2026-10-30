#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Launch time on a TX queue (tc-etf(8)): what a host wants of etf given the driver's one answer and,
/// on an interface with no other shaping, an mqprio root that keeps one TX queue for an AF_XDP
/// socket's timed frames, with an offloaded etf on it. See docs/NET_MODULE.md ("launch time").

#include "statusbar/net/net_tc_qdisc.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>

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
};

/// The mqprio root for @p queue: the socket's queue a traffic class of its own that no skb priority
/// maps to, so the kernel's frames, which an etf would drop untimed, take the other queues; not
/// offloaded (hw 0). Errors: invalid_argument for major 0, under 2 TX queues, or the queue past them.
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
    kept,       ///< our root and etf were already there (an earlier run left them)
    installed,  ///< our root, our etf or both laid
    removed,    ///< our root deleted, its etf with it
};

/// Bring @p ifindex's qdiscs to @p mode for @p queue. on: our mqprio root (kept when already so) and
/// our etf on the queue's class (kept when already there); off: our root, if there, deleted with its
/// etf; unsupported: no request. Errors: the first refused request (TcControl::last_message()).
[[nodiscard]] auto settle_launch_time_queue(TcControl& tc, int ifindex, LaunchTimeQueue const& queue, LaunchTimeMode mode)
    -> StatusValue<LaunchTimeQueueAction>;

#endif  // __linux__

}  // namespace statusbar::net::tc
