#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// What a host needs to know about a NIC before it lays out its TX queues: the driver's name, the TX
/// queue count, the link speed and the MTU. Linux only (sysfs and SIOCETHTOOL); no privilege needed.

#if defined(__linux__)

#    include "statusbar/status/status.hpp"

#    include <cstdint>
#    include <string>
#    include <string_view>
#    include <system_error>

namespace statusbar::net {

/// The interface's ifindex (if_nametoindex). Errors: no_such_device.
[[nodiscard]] auto interface_index(std::string_view interface_name) -> StatusValue<int>;

/// The number of TX queues the interface has: the `tx-*` entries of
/// /sys/class/net/<if>/queues. Errors: the directory's errno (no_such_file_or_directory
/// for an unknown interface).
[[nodiscard]] auto tx_queue_count(std::string_view interface_name) -> StatusValue<uint16_t>;

/// The kernel driver bound to the interface ("igb", "igc", "mv88e6085", "dsa"
/// for a DSA user port...), from ETHTOOL_GDRVINFO. Errors: the ioctl's errno.
[[nodiscard]] auto driver_name(std::string_view interface_name) -> StatusValue<std::string>;

/// link_speed_mbps's error when the kernel has no speed (EINVAL on read: link down, or a NIC that never
/// reports one; or SPEED_UNKNOWN): std::errc::network_down, "speed unknown" rather than a fault.
[[nodiscard]] inline auto make_unknown_link_speed() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::network_down);
}

/// The link speed in Mbit/s from /sys/class/net/<if>/speed. Errors: make_unknown_link_speed(); the
/// open/read errno (ENOENT for an unknown interface); bad_message for text that is not a number.
[[nodiscard]] auto link_speed_mbps(std::string_view interface_name) -> StatusValue<uint32_t>;

/// The interface MTU in bytes (SIOCGIFMTU). Errors: the ioctl's errno.
[[nodiscard]] auto interface_mtu(std::string_view interface_name) -> StatusValue<uint32_t>;

}  // namespace statusbar::net

#endif  // __linux__
