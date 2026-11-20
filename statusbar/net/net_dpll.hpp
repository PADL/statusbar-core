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
/// `DpllClient` lists the devices and reads one, and the same for the pins:
/// the signals a device takes in or puts out (the E810's SMA and U.FL
/// connectors, a port's recovered clock, the internal oscillator), each with
/// the frequency it runs at and, per device it is wired to, its direction,
/// priority and state. A pin is set through the client too: a frequency, a
/// phase adjustment, and on one of its devices a state, a priority or a
/// direction - which is how an SMA becomes a word-clock output. `DpllWatch`
/// joins the family's `monitor` multicast group and reports every device and
/// pin change the kernel announces, as a reactor Pollable, so a daemon follows
/// the lock without polling. Both resolve the family through the
/// generic-netlink controller, which also names the multicast group's id.
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

/// DPLL_CMD_PIN_*: the pin commands, and the pin notifications the monitor group carries.
inline constexpr uint8_t CMD_PIN_GET = 8;
inline constexpr uint8_t CMD_PIN_SET = 9;
inline constexpr uint8_t CMD_PIN_CREATE_NTF = 10;
inline constexpr uint8_t CMD_PIN_DELETE_NTF = 11;
inline constexpr uint8_t CMD_PIN_CHANGE_NTF = 12;

/// DPLL_A_PIN_*: a pin's attributes. The nested ones (`parent-device`,
/// `parent-pin`, `frequency-supported`) carry attributes of this same set.
inline constexpr uint16_t A_PIN_ID = 1;                            ///< u32
inline constexpr uint16_t A_PIN_PARENT_ID = 2;                     ///< u32, in a parent nest: the device's or pin's id
inline constexpr uint16_t A_PIN_MODULE_NAME = 3;                   ///< string
inline constexpr uint16_t A_PIN_CLOCK_ID = 5;                      ///< u64 (with a DPLL_A_PIN_PAD before it)
inline constexpr uint16_t A_PIN_BOARD_LABEL = 6;                   ///< string, "SMA1"
inline constexpr uint16_t A_PIN_PANEL_LABEL = 7;                   ///< string
inline constexpr uint16_t A_PIN_PACKAGE_LABEL = 8;                 ///< string
inline constexpr uint16_t A_PIN_TYPE = 9;                          ///< u32, PinType
inline constexpr uint16_t A_PIN_DIRECTION = 10;                    ///< u32, PinDirection, in a parent-device nest
inline constexpr uint16_t A_PIN_FREQUENCY = 11;                    ///< u64, Hz
inline constexpr uint16_t A_PIN_FREQUENCY_SUPPORTED = 12;          ///< nest, one per range: MIN and MAX
inline constexpr uint16_t A_PIN_FREQUENCY_MIN = 13;                ///< u64, Hz
inline constexpr uint16_t A_PIN_FREQUENCY_MAX = 14;                ///< u64, Hz
inline constexpr uint16_t A_PIN_PRIO = 15;                         ///< u32, in a parent-device nest
inline constexpr uint16_t A_PIN_STATE = 16;                        ///< u32, PinState, in a parent nest
inline constexpr uint16_t A_PIN_CAPABILITIES = 17;                 ///< u32, PIN_CAN_* flags
inline constexpr uint16_t A_PIN_PARENT_DEVICE = 18;                ///< nest, one per device the pin is wired to
inline constexpr uint16_t A_PIN_PARENT_PIN = 19;                   ///< nest, one per mux pin the pin is behind
inline constexpr uint16_t A_PIN_PHASE_ADJUST_MIN = 20;             ///< s32, ps
inline constexpr uint16_t A_PIN_PHASE_ADJUST_MAX = 21;             ///< s32, ps
inline constexpr uint16_t A_PIN_PHASE_ADJUST = 22;                 ///< s32, ps
inline constexpr uint16_t A_PIN_PHASE_OFFSET = 23;                 ///< s64, in a parent-device nest, fs
inline constexpr uint16_t A_PIN_FRACTIONAL_FREQUENCY_OFFSET = 24;  ///< s32 or s64, ppm
inline constexpr uint16_t A_PIN_PHASE_ADJUST_GRAN = 29;            ///< u32, ps

/// DPLL_PIN_CAPABILITIES_*: what a PIN_SET may change, as flags in A_PIN_CAPABILITIES.
inline constexpr uint32_t PIN_CAN_CHANGE_DIRECTION = 1;
inline constexpr uint32_t PIN_CAN_CHANGE_PRIORITY = 2;
inline constexpr uint32_t PIN_CAN_CHANGE_STATE = 4;

/// DPLL_PIN_FREQUENCY_*: the frequencies the family names; the E810's SMA and
/// U.FL pins take the first and the last.
inline constexpr uint64_t FREQUENCY_1_HZ = 1;
inline constexpr uint64_t FREQUENCY_10_KHZ = 10'000;
inline constexpr uint64_t FREQUENCY_10_MHZ = 10'000'000;

/// DPLL_PHASE_OFFSET_DIVIDER: a phase offset is reported in thousandths of a
/// picosecond, which is to say femtoseconds.
inline constexpr int64_t PHASE_OFFSET_DIVIDER = 1000;

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

/// dpll_pin_type.
enum class PinType : uint32_t
{
    unknown = 0,
    mux = 1,             ///< a layer of selectable pins behind it
    ext = 2,             ///< an external connector: SMA, U.FL
    synce_eth_port = 3,  ///< a port PHY's recovered clock
    int_oscillator = 4,  ///< the device's own oscillator
    gnss = 5,            ///< a GNSS receiver's clock
};

/// dpll_pin_direction: which way a signal goes through a pin, per device.
enum class PinDirection : uint32_t
{
    unknown = 0,
    input = 1,
    output = 2,
};

/// dpll_pin_state: what a pin is to its device. An input in manual mode is
/// `connected` or `disconnected`; in automatic mode `selectable` or
/// `disconnected`. An output is `connected` when it drives its connector.
enum class PinState : uint32_t
{
    unknown = 0,
    connected = 1,
    disconnected = 2,
    selectable = 3,
};

[[nodiscard]] auto pin_type_name(PinType type) noexcept -> std::string_view;
[[nodiscard]] auto pin_direction_name(PinDirection direction) noexcept -> std::string_view;
[[nodiscard]] auto pin_state_name(PinState state) noexcept -> std::string_view;

/// One DPLL_A_PIN_FREQUENCY_SUPPORTED range, in Hz; a single frequency has min == max.
struct FrequencyRange
{
    uint64_t min{0};
    uint64_t max{0};

    [[nodiscard]] constexpr auto contains(uint64_t const hz) const noexcept -> bool { return min <= hz && hz <= max; }
    [[nodiscard]] constexpr auto operator==(FrequencyRange const&) const noexcept -> bool = default;
};

/// A pin as one device sees it: one DPLL_A_PIN_PARENT_DEVICE nest. An
/// attribute the kernel did not send reads as `unknown` or nullopt.
struct PinOnDevice
{
    uint32_t device_id{0};
    PinDirection direction{PinDirection::unknown};
    PinState state{PinState::unknown};
    std::optional<uint32_t> prio{};  ///< lower is preferred, in automatic mode
    /// The phase of the pin's signal against the device's, in femtoseconds
    /// (the kernel's picoseconds times PHASE_OFFSET_DIVIDER); negative when
    /// the pin's is earlier.
    std::optional<int64_t> phase_offset_fs{};
    /// The pin's frequency against the device's, in parts per million.
    std::optional<int64_t> fractional_frequency_offset_ppm{};

    [[nodiscard]] constexpr auto operator==(PinOnDevice const&) const noexcept -> bool = default;
};

/// A pin as one mux pin above it sees it: one DPLL_A_PIN_PARENT_PIN nest.
struct PinOnPin
{
    uint32_t pin_id{0};
    PinState state{PinState::unknown};

    [[nodiscard]] constexpr auto operator==(PinOnPin const&) const noexcept -> bool = default;
};

/// One pin as DPLL_CMD_PIN_GET reports it, and as a pin notification
/// describes it. A pin is wired either to devices (`on_devices`) or, behind
/// a mux, to pins (`on_pins`), and the kernel sends one list or the other.
struct Pin
{
    uint32_t id{0};
    uint64_t clock_id{0};  ///< the clock identity (an EUI-64) the pin belongs to
    std::string module_name{};
    std::string board_label{};    ///< what the board calls it: "SMA1", "U.FL2"
    std::string panel_label{};    ///< what the panel calls it
    std::string package_label{};  ///< what the chip's package calls it
    PinType type{PinType::unknown};
    uint32_t capabilities{0};  ///< PIN_CAN_* flags
    std::optional<uint64_t> frequency_hz{};
    std::vector<FrequencyRange> frequencies_supported{};
    std::optional<int32_t> phase_adjust_min_ps{};
    std::optional<int32_t> phase_adjust_max_ps{};
    std::optional<int32_t> phase_adjust_ps{};
    std::optional<uint32_t> phase_adjust_granularity_ps{};
    /// The RX against the TX symbol rate of the pin's media, in parts per million.
    std::optional<int64_t> fractional_frequency_offset_ppm{};
    std::vector<PinOnDevice> on_devices{};
    std::vector<PinOnPin> on_pins{};

    [[nodiscard]] auto can_change_direction() const noexcept -> bool { return (capabilities & PIN_CAN_CHANGE_DIRECTION) != 0; }
    [[nodiscard]] auto can_change_priority() const noexcept -> bool { return (capabilities & PIN_CAN_CHANGE_PRIORITY) != 0; }
    [[nodiscard]] auto can_change_state() const noexcept -> bool { return (capabilities & PIN_CAN_CHANGE_STATE) != 0; }
    /// Whether `hz` is in one of the supported ranges (no ranges: nothing is).
    [[nodiscard]] auto supports_frequency(uint64_t hz) const noexcept -> bool;
    /// The pin as device `device_id` sees it, nullptr when it is not wired to that device.
    [[nodiscard]] auto on_device(uint32_t device_id) const noexcept -> PinOnDevice const*;

    [[nodiscard]] auto operator==(Pin const&) const noexcept -> bool = default;
};

/// A pin message: which command carried it, and the pin.
struct PinMessage
{
    uint8_t cmd{0};  ///< CMD_PIN_GET, or one of the pin notifications
    Pin pin{};
};

/// What a DPLL_CMD_PIN_SET changes on one device the pin is wired to; each
/// field left unset is left alone. The kernel takes a state, a priority and
/// a direction only this way, by device, since a pin may be wired to several.
struct PinOnDeviceChange
{
    uint32_t device_id{0};
    std::optional<PinState> state{};
    std::optional<uint32_t> prio{};
    std::optional<PinDirection> direction{};

    [[nodiscard]] constexpr auto operator==(PinOnDeviceChange const&) const noexcept -> bool = default;
};

/// What a DPLL_CMD_PIN_SET changes on one mux pin the pin is behind.
struct PinOnPinChange
{
    uint32_t pin_id{0};
    PinState state{PinState::unknown};

    [[nodiscard]] constexpr auto operator==(PinOnPinChange const&) const noexcept -> bool = default;
};

/// Everything one DPLL_CMD_PIN_SET may ask of a pin; what is unset or empty
/// is left alone, and a request that asks nothing is one the kernel merely
/// acknowledges. The kernel refuses a frequency outside the supported ranges
/// and a phase adjustment outside its range or off its granularity with
/// EINVAL, and a change the hardware cannot make with EOPNOTSUPP.
struct PinChange
{
    std::optional<uint64_t> frequency_hz{};
    std::optional<int32_t> phase_adjust_ps{};
    std::vector<PinOnDeviceChange> on_devices{};
    std::vector<PinOnPinChange> on_pins{};

    [[nodiscard]] auto operator==(PinChange const&) const noexcept -> bool = default;
};

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

/// The devices of one DPLL_CMD_DEVICE_GET dump, taken reply by reply. The
/// socket sends a request again when a reply did not fit or a transient
/// error cut it short, and the dump starts over with it: restart() forgets
/// the devices of the attempt before, or they would be listed twice.
struct DeviceDump
{
    std::vector<Device> devices{};

    /// A new attempt at the dump: nothing read so far counts.
    void restart() noexcept { devices.clear(); }

    /// One reply, of netlink type `type`: a device of family `family_id` is
    /// kept, a message of another family ignored. Errors: parse_device()'s.
    [[nodiscard]] auto take(std::span<uint8_t const> message, uint16_t type, uint16_t family_id) -> Status;
};

/// DPLL_CMD_PIN_GET as a dump (every pin), addressed to `family_id`.
[[nodiscard]] auto build_pin_dump(std::span<uint8_t> out, uint16_t family_id, uint32_t seq) -> StatusValue<size_t>;

/// DPLL_CMD_PIN_GET for the pin `id`, addressed to `family_id`.
[[nodiscard]] auto build_pin_get(std::span<uint8_t> out, uint16_t family_id, uint32_t id, uint32_t seq) -> StatusValue<size_t>;

/// DPLL_CMD_PIN_SET for the pin `id`: the frequency and the phase adjustment
/// as attributes of the pin, each device and mux-pin change as a nest. The
/// request has to fit `out` (a RequestBuffer takes a change on a handful of
/// devices); one that does not is the builder's error.
[[nodiscard]] auto build_pin_set(std::span<uint8_t> out, uint16_t family_id, uint32_t id, PinChange const& change, uint32_t seq)
    -> StatusValue<size_t>;

/// The pin in one message of family `family_id`: a DPLL_CMD_PIN_GET reply or
/// a pin notification. bad_message when it is truncated, malformed, of
/// another family or command, or carries no DPLL_A_PIN_ID. Attributes the
/// kernel adds later are passed over, as are nests of other attributes.
[[nodiscard]] auto parse_pin(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<PinMessage>;

/// The pins of one DPLL_CMD_PIN_GET dump, taken reply by reply; see DeviceDump.
struct PinDump
{
    std::vector<Pin> pins{};

    void restart() noexcept { pins.clear(); }
    [[nodiscard]] auto take(std::span<uint8_t const> message, uint16_t type, uint16_t family_id) -> Status;
};

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

    /// Every pin the kernel has (a DPLL_CMD_PIN_GET dump), with how each of
    /// its devices sees it. Errors: the request's; EPERM without CAP_NET_ADMIN.
    [[nodiscard]] auto pins() -> StatusValue<std::vector<Pin>>;

    /// The pin `id`. Errors: ENODEV for no such pin, else the request's.
    [[nodiscard]] auto pin(uint32_t id) -> StatusValue<Pin>;

    /// Change the pin `id` as `change` says (DPLL_CMD_PIN_SET). Errors: ENODEV
    /// for no such pin; EINVAL for a frequency or phase adjustment the pin
    /// cannot take, or a device it is not wired to; EOPNOTSUPP for a change
    /// the hardware has no way to make; else the request's. last_message()
    /// has the kernel's reason.
    [[nodiscard]] auto set_pin(uint32_t id, PinChange const& change) -> Status;

    /// The pin's frequency: set_pin() with only that.
    [[nodiscard]] auto set_frequency(uint32_t id, uint64_t hz) -> Status;
    /// The pin's phase adjustment, in picoseconds: set_pin() with only that.
    [[nodiscard]] auto set_phase_adjust(uint32_t id, int32_t ps) -> Status;
    /// The pin's state on one device: set_pin() with only that. An output
    /// pin `connected` to its device drives its connector; an input
    /// `connected` in manual mode is the one the device follows.
    [[nodiscard]] auto set_state(uint32_t id, uint32_t device_id, PinState state) -> Status;
    /// The pin's priority on one device, for automatic selection: set_pin() with only that.
    [[nodiscard]] auto set_priority(uint32_t id, uint32_t device_id, uint32_t prio) -> Status;
    /// The pin's direction on one device: set_pin() with only that.
    [[nodiscard]] auto set_direction(uint32_t id, uint32_t device_id, PinDirection direction) -> Status;

    /// The family as open() resolved it (zeros when closed).
    [[nodiscard]] auto family() const noexcept -> Family { return family_; }

    /// The kernel's extended-ack reason for the last request that failed (empty: none given).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return socket_.last_message(); }

  private:
    netlink::Socket socket_{};
    Family family_{};
    /// A pin dump of an E810 (two dozen pins, each with two device nests) is
    /// a few kilobytes; a datagram larger than this is refused as message_size.
    std::array<uint8_t, 16384> reply_{};
};

/// What the monitor group announced about a device or a pin.
enum class Event : uint8_t
{
    created,
    changed,
    deleted,
};
/// The name the device events had before pins were watched too.
using DeviceEvent = Event;

/// What a watch could not hand on. Notifications are not replayed, so after
/// an `overrun` or a `truncated` loss the devices are read again through
/// DpllClient to learn what was missed; after `failed` the watch is
/// finished() and is opened again.
enum class Loss : uint8_t
{
    overrun,    ///< ENOBUFS: the socket's queue overflowed, notifications are gone
    truncated,  ///< a datagram larger than the buffer, dropped whole
    failed,     ///< a lasting socket error: the watch reads no more
};

/// The family's `monitor` multicast group on the reactor: every device
/// notification the kernel sends is parsed and handed to the callback, with
/// the reactor time it arrived at, and every pin notification to the pin
/// callback when one is set (unset: pin notifications are passed over). A
/// lock status that moved shows as a `changed` event carrying the whole
/// device, so the callback compares with what it last saw; a pin's
/// frequency or state that moved is a `changed` pin the same way.
/// Notifications are not acknowledged and not replayed: read the devices
/// (and pins) once through DpllClient after open(), then follow, and read
/// them again when on_loss() says some were missed.
class DpllWatch : public Pollable
{
  public:
    /// Allocation-free; captures must fit in 64 bytes.
    using OnEvent = statusbar::sg14::inplace_function<void(Event event, Device const& device, int64_t now_ns), 64>;
    using OnPinEvent = statusbar::sg14::inplace_function<void(Event event, Pin const& pin, int64_t now_ns), 64>;
    /// A loss, with the socket's error (ENOBUFS, the lasting error; zero
    /// for a truncated datagram) and the reactor time.
    using OnLoss = statusbar::sg14::inplace_function<void(Loss loss, std::error_code error, int64_t now_ns), 64>;

    explicit DpllWatch(OnEvent on_event) noexcept
        : on_event_{std::move(on_event)}
    {}

    /// Test seam: a watch that knows its family without asking the kernel,
    /// so deliver() can be fed bytes. Not open; open() replaces the family.
    DpllWatch(OnEvent on_event, Family const& family) noexcept
        : on_event_{std::move(on_event)}
        , family_{family}
    {}

    /// Test seam: a watch reading `fd` as if it were the member socket, so
    /// on_ready() can be driven without a kernel. open() replaces it.
    DpllWatch(OnEvent on_event, Family const& family, FileDescriptor fd) noexcept
        : on_event_{std::move(on_event)}
        , fd_{std::move(fd)}
        , family_{family}
    {}

    /// Told of every loss (unset: losses are counted and nothing more).
    void on_loss(OnLoss on_loss) noexcept { on_loss_ = std::move(on_loss); }

    /// Told of every pin notification (unset: they are passed over, uncounted).
    void on_pin(OnPinEvent on_pin) noexcept { on_pin_ = std::move(on_pin); }

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
    /// Losses so far, reported or not.
    [[nodiscard]] auto losses() const noexcept -> uint64_t { return losses_; }

    /// One datagram's worth of notifications, parsed and handed to the
    /// callback. Public so a test can feed the watch bytes without a kernel.
    void deliver(std::span<uint8_t const> datagram, int64_t now_ns);

    // -- Pollable --
    [[nodiscard]] auto fd() const noexcept -> int override { return fd_.get(); }
    void on_ready(int64_t now_ns) override;
    void tick(int64_t /*now_ns*/) override {}
    /// True after a lasting socket error: the reactor drops the watch, and
    /// open() starts it over.
    [[nodiscard]] auto finished() const noexcept -> bool override { return failed_; }

  private:
    /// One message of the family: a device event to the callback, a pin event
    /// to the pin callback when there is one.
    void deliver_one(std::span<uint8_t const> message, int64_t now_ns);
    /// One recv(): true when there may be more to read, false when drained
    /// or failed.
    [[nodiscard]] auto read_one(int64_t now_ns) -> bool;
    void lose(Loss loss, std::error_code error, int64_t now_ns);

    OnEvent on_event_;
    OnPinEvent on_pin_{};
    OnLoss on_loss_{};
    FileDescriptor fd_{};
    Family family_{};
    uint64_t events_{0};
    uint64_t losses_{0};
    bool failed_{false};
    std::array<uint8_t, 8192> buffer_{};
};

#endif  // __linux__

}  // namespace statusbar::net::dpll
