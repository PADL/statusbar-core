#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One TX queue kept for an AF_XDP socket's timed frames.
///
/// An offloaded `etf` puts a driver's queue in launch-time mode: each frame
/// carries a time and the NIC holds it until then. Getting there needs two
/// qdiscs and a queue layout, and every part of it has a way to look like it
/// worked while doing nothing:
///
///   * The etf must be **offloaded**, or the timing happens in the qdisc
///     layer, which AF_XDP frames never enter.
///   * It must **skip the socket check**, because an AF_XDP socket puts its
///     launch time in the UMEM's TX metadata and never calls `SO_TXTIME`.
///   * It hangs on the class of the socket's own TX queue, so the layout has
///     to be known — which means laying an `mqprio` root ourselves.
///   * That root must **not** ask the driver to offload the priority map.
///     igb and igc reset the adapter when hardware TC offload appears and
///     when it goes, taking the link down for seconds and losing gPTP lock.
///     The root here is a queue *layout*, nothing more.
///   * Nothing may be steered to the socket's queue, or an ordinary skb
///     queues among the timed frames.
///
/// What the layout buys beyond that is a queue for PTP. gPTP event messages
/// go at priority 7 (`PTP_PRIORITY`), and on a NIC with queues to spare they
/// get one to themselves rather than sharing with bulk traffic.
///
/// `settle_launch_time_queue()` is the whole thing in one call, and is
/// idempotent: a talker restarting finds its own root and etf and leaves them
/// alone, because rewriting them is what costs the link.
///
/// Linux only. Writing any of it needs CAP_NET_ADMIN; reading does not.

#include "statusbar/net/net_tc_qdisc.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <optional>

namespace statusbar::net::tc {

/// What a host does with etf on its AF_XDP socket's queue.
enum class LaunchTimeMode : std::uint8_t
{
    unsupported,  ///< no driver support: an etf is neither installed nor looked for
    off,          ///< none wanted; an etf an earlier run left is removed
    on,           ///< an offloaded etf on the socket's queue
};

/// The mode for launch time @p wanted, given what the driver said when asked
/// whether it honours it (@p driver, asked once).
///
/// A query that *failed* is not an answer, and the two cases differ: not
/// wanting launch time still has to clear an etf an earlier run left, so an
/// unknown driver is `off` when nothing was wanted and `unsupported` when it
/// was.
[[nodiscard]] auto launch_time_mode(bool wanted, StatusValue<bool> const& driver) noexcept -> LaunchTimeMode;

/// etf's default delta: how long before its launch time a frame queued in etf
/// is handed to the driver.
inline constexpr std::int32_t DEFAULT_ETF_DELTA_NS = 150'000;

#if defined(__linux__)

/// One TX queue kept for an AF_XDP socket's timed frames, on an interface no
/// other qdisc shapes.
struct LaunchTimeQueue
{
    /// Our mqprio root's handle major; its classes are `major:1..N`. Not 0.
    std::uint16_t major{0};

    /// The socket's TX queue. Nothing is steered to it.
    std::uint16_t queue{0};

    /// The interface's TX queues (`net::tx_queue_count()`), at least 2: one
    /// for the socket and one for everything else.
    std::uint16_t tx_queues{0};

    /// Bounds only the frames that pass through etf.
    std::int32_t etf_delta_ns{DEFAULT_ETF_DELTA_NS};

    /// PTP event traffic's own queue. Must be past the socket's and must
    /// leave a queue past itself for everything else; unset means PTP shares
    /// the rest.
    std::optional<std::uint16_t> ptp_queue{};

    /// The skb priority mapped to `ptp_queue`.
    std::uint8_t ptp_priority{PTP_PRIORITY};

    /// The root stays when launch time is off: `off` then lays or keeps it
    /// and removes only the etf. Worth setting when the layout is wanted for
    /// its own sake - it is what keeps PTP off the socket's queue.
    bool persistent_root{false};
};

/// The mqprio root for @p queue: a queue layout with the map **not** offloaded
/// (see this file's header comment), no priority on the socket's queue, PTP on
/// its own where there is one, everything else on the queues past it, and any
/// queue between left idle.
///
/// @return The root, or `NetError::invalid_argument` for a `major` of 0, fewer
///         than 2 TX queues, a `queue` not among them, or a `ptp_queue` that
///         is not past the socket's with at least one queue past itself.
[[nodiscard]] auto launch_time_mqprio(LaunchTimeQueue const& queue) noexcept -> StatusValue<MqprioQdisc>;

/// The class the socket's queue hangs on: `major:(queue + 1)`.
[[nodiscard]] constexpr auto launch_time_class(LaunchTimeQueue const& queue) noexcept -> std::uint32_t
{
    return make_handle(queue.major, static_cast<std::uint16_t>(queue.queue + 1));
}

/// The etf for that class: offloaded, on CLOCK_TAI, taking frames from a
/// socket that never set `SO_TXTIME`, with @p queue's delta.
[[nodiscard]] auto launch_time_etf(LaunchTimeQueue const& queue) noexcept -> EtfQdisc;

/// What `settle_launch_time_queue()` did.
enum class LaunchTimeQueueAction : std::uint8_t
{
    none,       ///< nothing asked for (`unsupported`), or nothing of ours to remove (`off`)
    kept,       ///< ours were already in place, and were left alone
    installed,  ///< our root, our etf or both were laid
    removed,    ///< our root was deleted, its etf with it (`persistent_root`: only the etf)
};

/// Bring @p ifindex's qdiscs to @p mode for @p queue.
///
/// Idempotent, and deliberately so: what is already ours is read and left,
/// because replacing a root is what takes an igb link down. `on` lays the root
/// and the etf, each only if missing. `off` deletes our root, which takes its
/// etf with it — or, with `persistent_root`, lays or keeps the root and
/// deletes only the etf. `unsupported` makes no request at all, so a host
/// without launch time needs neither privilege nor an interface that exists.
///
/// A root that is not ours is never deleted, and on `on` is replaced: the
/// layout behind it is unknown, so the class the etf would hang on may not be
/// the socket's queue. One under our handle that is not what this run wants -
/// an older layout of ours, or no layout at all - is deleted and then laid,
/// because the kernel will not change an mqprio in place: a replace under a
/// handle the interface already holds is refused.
///
/// @return What it did, or the first refusal — whose reason is in
///         `TcControl::last_message()`. The layout is checked before anything
///         is written.
[[nodiscard]] auto settle_launch_time_queue(TcControl& tc, int ifindex, LaunchTimeQueue const& queue, LaunchTimeMode mode)
    -> StatusValue<LaunchTimeQueueAction>;

#endif  // __linux__

}  // namespace statusbar::net::tc
