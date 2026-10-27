#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The NIC's RSS indirection table, and steering every hash bucket of it to a
/// single RX queue.
///
/// An AF_XDP socket binds to one RX queue. A NIC with RSS hashes incoming
/// flows across all of its queues, so by default most of a multicast stream
/// lands on queues the socket is not watching and those frames go to the
/// kernel instead - a receiver that works on a single-queue NIC and silently
/// loses most of its packets on a normal one. Pointing every bucket at the
/// socket's queue is what `ethtool -X <if> equal 1` does by hand.

#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace statusbar::net {

/// A NIC's RSS indirection table: entry i is the RX queue that hash bucket i
/// is steered to.
using RssIndirection = std::vector<uint32_t>;

/// Point every RSS hash bucket of `interface_name` at `queue_id`, and return
/// the table as it was.
///
/// The previous table is returned so the caller can put it back with
/// set_rss_indirection(). Doing so matters: the change is to the NIC, not to
/// our socket, and it degrades every other user of that interface - the host's
/// own traffic included - until someone runs `ethtool -X <if> default`. A
/// caller that drops the returned table has reconfigured the machine
/// permanently.
///
/// Nothing is written when every bucket already goes to `queue_id`, which
/// avoids a privileged syscall and, on some drivers, a link reset.
///
/// Writing needs CAP_NET_ADMIN; reading does not. An interface with no
/// indirection table - `lo`, a veth, most virtual interfaces - fails with
/// `std::errc::operation_not_supported`, distinguishably, because for a
/// caller that is "nothing to steer" rather than a fault.
/// @param interface_name The interface to steer, 1 to IFNAMSIZ-1 bytes
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto set_rss_indirection_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection>;

/// Write `table` as the interface's RSS indirection table: the counterpart of
/// set_rss_indirection_all, for restoring what it returned. An empty table
/// asks the driver for its own default, as `ethtool -X <if> default` does.
/// Needs CAP_NET_ADMIN.
/// @param interface_name The interface to write to
/// @param table One RX queue index per hash bucket
[[nodiscard]] auto set_rss_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status;

namespace detail {

/// What set_rss_indirection_all decides once it has the current table. Split
/// out with no syscall in it so the decision can be tested without a NIC.
struct RssSteerPlan
{
    /// The table as it was, for the caller to restore.
    RssIndirection previous;
    /// The table to write, or nullopt when every bucket already goes there.
    std::optional<RssIndirection> wanted;
};

/// Decide what to write given the table the NIC reports, how many RX queues
/// it has, and the queue we want.
///
/// `operation_not_supported` for an empty table: the NIC has no RSS, so there
/// is nothing to steer. `invalid_argument` for a queue the NIC does not have,
/// refused here rather than offered to a driver that may do something worse
/// than reject it.
/// @param current The table as the NIC reports it
/// @param rx_queues The NIC's RX queue count, or 0 when it would not say
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto plan_rss_steer(std::span<uint32_t const> current, uint32_t rx_queues, uint32_t queue_id)
    -> StatusValue<RssSteerPlan>;

/// Whether every bucket of a non-empty table already goes to `queue_id`.
/// @param table The table to examine
/// @param queue_id The RX queue to test for
[[nodiscard]] auto is_steered_to(std::span<uint32_t const> table, uint32_t queue_id) noexcept -> bool;

/// A table of `entries` buckets, every one of them `queue_id`.
/// @param entries How many hash buckets the table has
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto make_steered_table(size_t entries, uint32_t queue_id) -> RssIndirection;

}  // namespace detail

}  // namespace statusbar::net
