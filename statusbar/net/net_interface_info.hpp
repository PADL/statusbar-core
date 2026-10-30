#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Facts about a network interface, from sysfs and unprivileged ioctls.
///
/// A traffic shaper cannot be configured without these. The TX queue
/// count bounds an mqprio map — writing one without knowing how many
/// queues exist produces a request the kernel rejects, or worse, one it
/// accepts with a traffic class pointing at a queue that is never
/// serviced. The link speed sets the scale of a credit-based shaper's
/// idle-slope: the same stream needs ten times the credit at 100 Mbit/s
/// that it needs at 1 Gbit/s, so assuming 1 Gbit/s on a link that
/// negotiated 100 under-reserves by a factor of ten. The driver name is
/// the only way to find out we are on igb or igc, which need specific
/// handling. And every rtnetlink request is addressed by ifindex, not by
/// name.
///
/// None of these needs a privilege, a dependency beyond libc, or a real
/// NIC to exercise: `lo` answers some and cleanly refuses the rest,
/// which is what the tests rely on.
///
/// Linux only. The module does not exist elsewhere rather than stub out,
/// so a caller that needs it fails to compile rather than silently
/// receiving plausible-looking nonsense.

#include "statusbar/status/status.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace statusbar::net {

#if defined(__linux__)

/// The error reported when an interface has no link speed to give.
///
/// This is not a fault and must not be treated as one. A daemon that
/// starts before its link comes up hits it every time, so confusing it
/// with a broken NIC means an intermittent startup failure; and reporting
/// 0 instead would make an idle-slope calculation silently reserve
/// nothing. Callers wait for the link rather than give up.
[[nodiscard]] auto make_unknown_link_speed() noexcept -> std::error_code;

/// The kernel's index for an interface, as every rtnetlink request needs.
/// @param interface_name Interface name, e.g. "eth0"
/// @return The ifindex, or `no_such_device` / `filename_too_long`.
[[nodiscard]] auto interface_index(std::string_view interface_name) -> StatusValue<int>;

/// How many TX queues the interface has, counted from
/// /sys/class/net/<if>/queues/tx-*.
///
/// Read from sysfs on purpose: it is cheap, needs no ioctl, and counts
/// the queues that exist. `ETHTOOL_GCHANNELS` reports *configured
/// channels*, which is a subtly different number and the wrong source
/// for an mqprio map.
///
/// @param interface_name Interface name
/// @return The count (never 0 — an interface with no TX queue reports
///         `not_supported`), or `no_such_device` / `filename_too_long`.
[[nodiscard]] auto tx_queue_count(std::string_view interface_name) -> StatusValue<uint16_t>;

/// The interface's driver name, from ETHTOOL_GDRVINFO.
/// @param interface_name Interface name
/// @return The driver name, or `operation_not_supported` for an
///         interface with no ethtool operations (`lo`, some virtual
///         devices), or `no_such_device` / `filename_too_long`.
[[nodiscard]] auto driver_name(std::string_view interface_name) -> StatusValue<std::string>;

/// Interpret the text of a sysfs `speed` attribute.
///
/// Exposed because it is the whole down-link verdict in pure form: a
/// caller gets it for free, and the test for "a link with no speed does
/// not report 0" needs neither a NIC nor a privilege nor sysfs.
///
/// @param text Decimal digits, optionally followed by anything (a
///        trailing newline is normal).
/// @return The speed, `make_unknown_link_speed()` for a value that is not
///         a speed (0, or SPEED_UNKNOWN's -1), or `bad_message` if the
///         text does not begin with a number.
[[nodiscard]] auto parse_link_speed(std::string_view text) -> StatusValue<uint32_t>;

/// The interface's negotiated link speed in Mbit/s.
/// @param interface_name Interface name
/// @return The speed, or `make_unknown_link_speed()` when there is no
///         speed to report (link down, or a device with no notion of
///         one), or `no_such_device` / `filename_too_long`.
[[nodiscard]] auto link_speed_mbps(std::string_view interface_name) -> StatusValue<uint32_t>;

/// The interface's MTU, for frame-size validation before we build a
/// descriptor we cannot send.
/// @param interface_name Interface name
/// @return The MTU, or `no_such_device` / `filename_too_long`.
[[nodiscard]] auto interface_mtu(std::string_view interface_name) -> StatusValue<uint32_t>;

#endif  // __linux__

}  // namespace statusbar::net
