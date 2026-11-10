#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A NIC driver's statistics (`ethtool -S <if>`: ETHTOOL_GSTRINGS and ETHTOOL_GSTATS), and the per-queue
/// packet counters among them, under the names the common drivers give them.

#include "statusbar/sg14/inplace_function.h"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::net {

/// One driver statistic: its name and its value.
struct EthtoolStat
{
    std::string name;
    uint64_t value{0};

    auto operator==(EthtoolStat const&) const noexcept -> bool = default;
};

/// The driver's statistics of `interface_name`, in the driver's order. No privilege. Errors: the ioctl's errno
/// (`operation_not_supported` for a driver with none), `resource_unavailable_try_again` when the count changed
/// while it was read, twice running.
[[nodiscard]] auto ethtool_stats(std::string_view interface_name) -> StatusValue<std::vector<EthtoolStat>>;

/// One SIOCETHTOOL request: an ethtool command and its data in `payload`, rewritten in place by the driver.
using EthtoolRequest = sg14::inplace_function<Status(std::span<uint8_t> payload), 32>;

/// ethtool_stats() made through `request`, for a test to stand in for the driver. Linux only.
[[nodiscard]] auto ethtool_stats(EthtoolRequest const& request) -> StatusValue<std::vector<EthtoolStat>>;

/// The bytes of one ETH_SS_STATS name (ETH_GSTRING_LEN).
inline constexpr size_t ETHTOOL_STAT_NAME_SIZE = 32;

/// The `count` names in an ETHTOOL_GSTRINGS payload, each up to its first NUL. Errors: `bad_message` when
/// `blob` holds fewer than `count` names.
[[nodiscard]] auto parse_stat_names(std::span<uint8_t const> blob, size_t count) -> StatusValue<std::vector<std::string>>;

/// One queue's packet counters, where the driver keeps them.
struct QueuePackets
{
    uint32_t queue{0};
    std::optional<uint64_t> rx{};
    std::optional<uint64_t> tx{};

    auto operator==(QueuePackets const&) const noexcept -> bool = default;
};

/// A per-queue packet counter's direction and queue, from its name: `rx_queue_N_packets` (igb, igc, ixgbe,
/// ice), `rx-N.packets` (i40e, iavf) or `rxN_packets` (mlx5), and the same for tx; nullopt for any other.
struct QueueStatName
{
    bool tx{false};
    uint32_t queue{0};

    auto operator==(QueueStatName const&) const noexcept -> bool = default;
};
[[nodiscard]] auto queue_stat_name(std::string_view name) noexcept -> std::optional<QueueStatName>;

/// The per-queue packet counters among `stats`, by queue; empty when the driver keeps none.
[[nodiscard]] auto queue_packets(std::span<EthtoolStat const> stats) -> std::vector<QueuePackets>;

}  // namespace statusbar::net
