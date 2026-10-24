#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_rss.hpp
/// @brief A NIC's RSS indirection table (ethtool -x / -X): which RX queue each
/// hash bucket lands on, read and written with ETHTOOL_GRXFHINDIR /
/// ETHTOOL_SRXFHINDIR. An AF_XDP socket bound to one queue steers every bucket to it.

#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace statusbar::net {

/// An RSS indirection table: entry i is the RX queue hash bucket i lands on.
using RssIndirection = std::vector<uint32_t>;

/// A table of @p size entries, every one @p queue_id (ethtool -X weight with
/// only @p queue_id's weight set).
[[nodiscard]] auto rss_indirection_all(size_t size, uint32_t queue_id) -> RssIndirection;

/// True when every entry of @p table is @p queue_id; false for an empty table.
[[nodiscard]] auto rss_steered_to(std::span<uint32_t const> table, uint32_t queue_id) noexcept -> bool;

#if defined(__linux__)

/// The interface's RSS indirection table (ETHTOOL_GRXFHINDIR); no privilege needed.
/// Errors: operation_not_supported for a NIC without one (lo, veth); otherwise the ioctl's errno.
[[nodiscard]] auto rss_indirection(std::string_view interface_name) -> StatusValue<RssIndirection>;

/// Write the table (ETHTOOL_SRXFHINDIR); an empty @p table restores the driver's
/// default spread. Needs CAP_NET_ADMIN. Errors: invalid_argument for a table
/// of the wrong size or naming a queue the NIC lacks; otherwise the ioctl's errno.
[[nodiscard]] auto set_rss_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status;

/// Steer every RSS bucket to @p queue_id, writing only when the table is not so already.
/// Returns the table as it was, for set_rss_indirection to put back. Errors: as
/// rss_indirection, then as set_rss_indirection.
[[nodiscard]] auto set_rss_indirection_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection>;

#endif  // __linux__

}  // namespace statusbar::net
