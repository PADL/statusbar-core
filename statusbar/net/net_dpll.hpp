#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A generic-netlink client for the kernel's dpll family
/// (Documentation/netlink/specs/dpll.yaml, Linux 6.7): the digital PLLs a
/// NIC offers - the E810's PPS DPLL that disciplines its clock from an SMA
/// input, an EEC for SyncE - and above all their lock status. A clock being
/// driven from an external reference is only as good as that reference, and
/// the lock status is how the hardware says whether it has one.
///
/// `DpllClient` lists the devices and reads one; `DpllWatch` joins the
/// family's `monitor` multicast group and reports every device change the
/// kernel announces, as a reactor Pollable, so a daemon follows the lock
/// without polling. Both resolve the family through the generic-netlink
/// controller, which also names the multicast group's id.
///
/// The framing (constants, builders, parsers) builds everywhere and is tested
/// against hand-laid replies; the client and the watch are Linux only. A
/// kernel without the family answers the controller with ENOENT. The family's
/// requests, and the monitor group, are for CAP_NET_ADMIN: without it a query
/// is refused with EPERM, the family resolved all the same.

#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_netdev_features.hpp"
#include "statusbar/net/net_netlink.hpp"
#include "statusbar/sg14/inplace_function.h"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::net::dpll {

//
// Wire constants - linux/dpll.h and linux/genetlink.h, checked against them
// on Linux where the headers have them
//

/// DPLL_FAMILY_NAME, DPLL_FAMILY_VERSION, DPLL_MCGRP_MONITOR.
inline constexpr std::string_view FAMILY_NAME = "dpll";
inline constexpr uint8_t FAMILY_VERSION = 1;
inline constexpr std::string_view MONITOR_GROUP = "monitor";

/// DPLL_CMD_*: the device commands, and the notifications the monitor group carries.
inline constexpr uint8_t CMD_DEVICE_GET = 2;
inline constexpr uint8_t CMD_DEVICE_CREATE_NTF = 4;
inline constexpr uint8_t CMD_DEVICE_DELETE_NTF = 5;
inline constexpr uint8_t CMD_DEVICE_CHANGE_NTF = 6;

/// DPLL_A_*: a device's attributes.
inline constexpr uint16_t A_ID = 1;                  ///< u32
inline constexpr uint16_t A_MODULE_NAME = 2;         ///< a NUL-terminated string
inline constexpr uint16_t A_CLOCK_ID = 4;            ///< u64 (with a DPLL_A_PAD before it)
inline constexpr uint16_t A_MODE = 5;                ///< u32, Mode
inline constexpr uint16_t A_LOCK_STATUS = 7;         ///< u32, LockStatus
inline constexpr uint16_t A_TEMP = 8;                ///< s32, millidegrees Celsius
inline constexpr uint16_t A_TYPE = 9;                ///< u32, Type
inline constexpr uint16_t A_LOCK_STATUS_ERROR = 10;  ///< u32, LockStatusError

/// CTRL_ATTR_MCAST_GROUPS, and the attributes of each group within it.
inline constexpr uint16_t CTRL_MCAST_GROUPS = 7;
inline constexpr uint16_t CTRL_MCAST_GRP_NAME = 1;
inline constexpr uint16_t CTRL_MCAST_GRP_ID = 2;

/// dpll_mode. `unknown` is the value of an attribute the kernel did not send.
enum class Mode : uint32_t
{
    unknown = 0,
    manual = 1,     ///< the input is chosen by the user
    automatic = 2,  ///< the input is chosen by priority among the valid ones
};

/// dpll_lock_status.
enum class LockStatus : uint32_t
{
    unknown = 0,
    unlocked = 1,                  ///< free running, or no valid input
    locked = 2,                    ///< locked to a valid input, holdover not yet available
    locked_holdover_acquired = 3,  ///< locked, and holdover is available should the input go
    holdover = 4,                  ///< the input went; running on what was learnt from it
};

/// dpll_lock_status_error: why, when not locked.
enum class LockStatusError : uint32_t
{
    unknown = 0,
    none = 1,
    undefined = 2,
    media_down = 3,
    fractional_frequency_offset_too_high = 4,
};

/// dpll_type.
enum class Type : uint32_t
{
    unknown = 0,
    pps = 1,  ///< a PPS DPLL: phase, from a pulse per second
    eec = 2,  ///< an Ethernet Equipment Clock: frequency, SyncE
};

/// Whether a lock status is one a clock can be relied on in.
[[nodiscard]] constexpr auto is_locked(LockStatus const status) noexcept -> bool
{
    return status == LockStatus::locked || status == LockStatus::locked_holdover_acquired;
}

[[nodiscard]] auto lock_status_name(LockStatus status) noexcept -> std::string_view;
[[nodiscard]] auto type_name(Type type) noexcept -> std::string_view;

/// One device as DPLL_CMD_DEVICE_GET reports it, and as a change notification
/// describes it. An attribute the kernel did not send reads as its `unknown`,
/// 0 or nullopt.
struct Device
{
    uint32_t id{0};
    uint64_t clock_id{0};  ///< the clock identity (an EUI-64) the device belongs to
    std::string module_name{};
    Mode mode{Mode::unknown};
    LockStatus lock_status{LockStatus::unknown};
    LockStatusError lock_status_error{LockStatusError::unknown};
    Type type{Type::unknown};
    std::optional<int32_t> temperature_millicelsius{};

    [[nodiscard]] auto operator==(Device const&) const noexcept -> bool = default;
};

/// What the controller says of the family: its id and its monitor group's.
struct Family
{
    uint16_t id{0};
    /// The `monitor` multicast group's id, 0 when the family has none.
    uint32_t monitor_group{0};

    [[nodiscard]] constexpr auto operator==(Family const&) const noexcept -> bool = default;
};

/// A device message: which command carried it, and the device.
struct DeviceMessage
{
    uint8_t cmd{0};  ///< CMD_DEVICE_GET, or one of the notifications
    Device device{};
};

using RequestBuffer = netlink::RequestBuffer;

//
// Framing
//

/// CTRL_CMD_GETFAMILY for "dpll", written into `out`: the message's length.
[[nodiscard]] auto build_get_family(std::span<uint8_t> out, uint32_t seq) -> StatusValue<size_t>;

/// DPLL_CMD_DEVICE_GET as a dump (every device), addressed to `family_id`.
[[nodiscard]] auto build_device_dump(std::span<uint8_t> out, uint16_t family_id, uint32_t seq) -> StatusValue<size_t>;

/// DPLL_CMD_DEVICE_GET for the device `id`, addressed to `family_id`.
[[nodiscard]] auto build_device_get(std::span<uint8_t> out, uint16_t family_id, uint32_t id, uint32_t seq) -> StatusValue<size_t>;

/// The family's id and monitor group from one CTRL_CMD_NEWFAMILY message.
/// bad_message when it is truncated, malformed, another message, or carries
/// no id; a family with no `monitor` group reads as monitor_group 0.
[[nodiscard]] auto parse_family(std::span<uint8_t const> message) -> StatusValue<Family>;

/// The device in one message of family `family_id`: a DPLL_CMD_DEVICE_GET
/// reply or a device notification. bad_message when it is truncated,
/// malformed, of another family or command, or carries no DPLL_A_ID.
[[nodiscard]] auto parse_device(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<DeviceMessage>;

#if defined(__linux__)

//
// The client and the watch - Linux only
//

/// CTRL_CMD_GETFAMILY "dpll" over `socket` (open on NETLINK_GENERIC), its
/// replies read into `reply`: the family. Errors: the request's; ENOENT
/// when the kernel has no dpll family (before 6.7, or no driver registered one).
[[nodiscard]] auto resolve_family(netlink::Socket& socket, std::span<uint8_t> reply) -> StatusValue<Family>;

/// A NETLINK_GENERIC socket for dpll queries: open() resolves the family,
/// then each query sends one request and waits (about a second at most) for
/// its replies. Not thread-safe; not for a real-time thread.
class DpllClient
{
  public:
    DpllClient() noexcept = default;

    /// Open the socket and resolve the family. Errors: the socket's errno;
    /// ENOENT when the kernel has no dpll family. Closed again on failure.
    [[nodiscard]] auto open() -> Status;
    [[nodiscard]] auto is_open() const noexcept -> bool { return socket_.is_open(); }
    void close() noexcept { socket_.close(); }

    /// Every device the kernel has (a DPLL_CMD_DEVICE_GET dump): none is an
    /// empty list, not an error. Errors: the request's; EPERM without
    /// CAP_NET_ADMIN.
    [[nodiscard]] auto devices() -> StatusValue<std::vector<Device>>;

    /// The device `id`. Errors: ENODEV for no such device, else the request's.
    [[nodiscard]] auto device(uint32_t id) -> StatusValue<Device>;

    /// The family as open() resolved it (zeros when closed).
    [[nodiscard]] auto family() const noexcept -> Family { return family_; }

    /// The kernel's extended-ack reason for the last request that failed (empty: none given).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return socket_.last_message(); }

  private:
    netlink::Socket socket_{};
    Family family_{};
    std::array<uint8_t, 8192> reply_{};  ///< a dump of a few devices is well under this
};

/// What the monitor group announced about a device.
enum class DeviceEvent : uint8_t
{
    created,
    changed,
    deleted,
};

/// The family's `monitor` multicast group on the reactor: every device
/// notification the kernel sends is parsed and handed to the callback, with
/// the reactor time it arrived at. A lock status that moved shows as a
/// `changed` event carrying the whole device, so the callback compares with
/// what it last saw. Notifications are not acknowledged and not replayed:
/// read the devices once through DpllClient after open(), then follow.
class DpllWatch : public Pollable
{
  public:
    /// Allocation-free; captures must fit in 64 bytes.
    using OnEvent = statusbar::sg14::inplace_function<void(DeviceEvent event, Device const& device, int64_t now_ns), 64>;

    explicit DpllWatch(OnEvent on_event) noexcept
        : on_event_{std::move(on_event)}
    {}

    /// Test seam: a watch that knows its family without asking the kernel,
    /// so deliver() can be fed bytes. Not open; open() replaces the family.
    DpllWatch(OnEvent on_event, Family const& family) noexcept
        : on_event_{std::move(on_event)}
        , family_{family}
    {}

    /// Resolve the family, open a non-blocking NETLINK_GENERIC socket and
    /// join the monitor group. Errors: ENOENT when the kernel has no dpll
    /// family; `not_supported` when the family has no monitor group; else
    /// the socket's errno. Closed again on failure.
    [[nodiscard]] auto open() -> Status;
    void close() noexcept;
    [[nodiscard]] auto is_open() const noexcept -> bool { return fd_.valid(); }
    [[nodiscard]] auto family() const noexcept -> Family { return family_; }

    /// Notifications read and handed on so far; for a test, and a log line.
    [[nodiscard]] auto events() const noexcept -> uint64_t { return events_; }

    /// One datagram's worth of notifications, parsed and handed to the
    /// callback. Public so a test can feed the watch bytes without a kernel.
    void deliver(std::span<uint8_t const> datagram, int64_t now_ns);

    // -- Pollable --
    [[nodiscard]] auto fd() const noexcept -> int override { return fd_.get(); }
    void on_ready(int64_t now_ns) override;
    void tick(int64_t /*now_ns*/) override {}
    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

  private:
    OnEvent on_event_;
    FileDescriptor fd_{};
    Family family_{};
    uint64_t events_{0};
    std::array<uint8_t, 8192> buffer_{};
};

#endif  // __linux__

}  // namespace statusbar::net::dpll
