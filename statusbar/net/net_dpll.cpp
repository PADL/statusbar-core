// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_dpll.hpp"

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/buffer/span_utils.hpp"

#include <algorithm>
#include <cerrno>
#include <system_error>
#include <utility>

#if defined(__linux__)
#    include <unistd.h>

#    include <linux/genetlink.h>
#    include <linux/netlink.h>
#    include <sys/socket.h>
#    if __has_include(<linux/dpll.h>)
#        include <linux/dpll.h>
#    endif
#endif

namespace statusbar::net::dpll {

#if defined(__linux__)
static_assert(CTRL_MCAST_GROUPS == CTRL_ATTR_MCAST_GROUPS && CTRL_MCAST_GRP_NAME == CTRL_ATTR_MCAST_GRP_NAME);
static_assert(CTRL_MCAST_GRP_ID == CTRL_ATTR_MCAST_GRP_ID);
#    if defined(DPLL_FAMILY_VERSION)
// The dpll header spells its attributes and commands as enumerators, so they
// are checked here, where the build's headers have the family (Linux 6.7).
static_assert(FAMILY_NAME == DPLL_FAMILY_NAME && FAMILY_VERSION == DPLL_FAMILY_VERSION && MONITOR_GROUP == DPLL_MCGRP_MONITOR);
static_assert(CMD_DEVICE_GET == DPLL_CMD_DEVICE_GET && CMD_DEVICE_CREATE_NTF == DPLL_CMD_DEVICE_CREATE_NTF);
static_assert(CMD_DEVICE_DELETE_NTF == DPLL_CMD_DEVICE_DELETE_NTF && CMD_DEVICE_CHANGE_NTF == DPLL_CMD_DEVICE_CHANGE_NTF);
static_assert(A_ID == DPLL_A_ID && A_MODULE_NAME == DPLL_A_MODULE_NAME && A_CLOCK_ID == DPLL_A_CLOCK_ID && A_MODE == DPLL_A_MODE);
static_assert(A_LOCK_STATUS == DPLL_A_LOCK_STATUS && A_TEMP == DPLL_A_TEMP && A_TYPE == DPLL_A_TYPE);
static_assert(A_LOCK_STATUS_ERROR == DPLL_A_LOCK_STATUS_ERROR);
static_assert(
    static_cast<uint32_t>(Mode::manual) == DPLL_MODE_MANUAL && static_cast<uint32_t>(Mode::automatic) == DPLL_MODE_AUTOMATIC);
static_assert(static_cast<uint32_t>(LockStatus::unlocked) == DPLL_LOCK_STATUS_UNLOCKED);
static_assert(static_cast<uint32_t>(LockStatus::locked) == DPLL_LOCK_STATUS_LOCKED);
static_assert(static_cast<uint32_t>(LockStatus::locked_holdover_acquired) == DPLL_LOCK_STATUS_LOCKED_HO_ACQ);
static_assert(static_cast<uint32_t>(LockStatus::holdover) == DPLL_LOCK_STATUS_HOLDOVER);
static_assert(static_cast<uint32_t>(LockStatusError::none) == DPLL_LOCK_STATUS_ERROR_NONE);
static_assert(static_cast<uint32_t>(LockStatusError::media_down) == DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN);
static_assert(
    static_cast<uint32_t>(LockStatusError::fractional_frequency_offset_too_high) ==
    DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH);
static_assert(static_cast<uint32_t>(Type::pps) == DPLL_TYPE_PPS && static_cast<uint32_t>(Type::eec) == DPLL_TYPE_EEC);
static_assert(CMD_PIN_GET == DPLL_CMD_PIN_GET && CMD_PIN_SET == DPLL_CMD_PIN_SET && CMD_PIN_CREATE_NTF == DPLL_CMD_PIN_CREATE_NTF);
static_assert(CMD_PIN_DELETE_NTF == DPLL_CMD_PIN_DELETE_NTF && CMD_PIN_CHANGE_NTF == DPLL_CMD_PIN_CHANGE_NTF);
static_assert(A_PIN_ID == DPLL_A_PIN_ID && A_PIN_PARENT_ID == DPLL_A_PIN_PARENT_ID && A_PIN_MODULE_NAME == DPLL_A_PIN_MODULE_NAME);
static_assert(A_PIN_CLOCK_ID == DPLL_A_PIN_CLOCK_ID && A_PIN_BOARD_LABEL == DPLL_A_PIN_BOARD_LABEL);
static_assert(A_PIN_PANEL_LABEL == DPLL_A_PIN_PANEL_LABEL && A_PIN_PACKAGE_LABEL == DPLL_A_PIN_PACKAGE_LABEL);
static_assert(A_PIN_TYPE == DPLL_A_PIN_TYPE && A_PIN_DIRECTION == DPLL_A_PIN_DIRECTION && A_PIN_FREQUENCY == DPLL_A_PIN_FREQUENCY);
static_assert(A_PIN_FREQUENCY_SUPPORTED == DPLL_A_PIN_FREQUENCY_SUPPORTED && A_PIN_FREQUENCY_MIN == DPLL_A_PIN_FREQUENCY_MIN);
static_assert(A_PIN_FREQUENCY_MAX == DPLL_A_PIN_FREQUENCY_MAX && A_PIN_PRIO == DPLL_A_PIN_PRIO && A_PIN_STATE == DPLL_A_PIN_STATE);
static_assert(A_PIN_CAPABILITIES == DPLL_A_PIN_CAPABILITIES && A_PIN_PARENT_DEVICE == DPLL_A_PIN_PARENT_DEVICE);
static_assert(A_PIN_PHASE_OFFSET == DPLL_A_PIN_PHASE_OFFSET && PHASE_OFFSET_DIVIDER == DPLL_PHASE_OFFSET_DIVIDER);
static_assert(
    CAN_CHANGE_DIRECTION == DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE &&
    CAN_CHANGE_PRIORITY == DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE && CAN_CHANGE_STATE == DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE);
static_assert(
    static_cast<uint32_t>(PinDirection::input) == DPLL_PIN_DIRECTION_INPUT &&
    static_cast<uint32_t>(PinDirection::output) == DPLL_PIN_DIRECTION_OUTPUT);
static_assert(
    static_cast<uint32_t>(PinState::connected) == DPLL_PIN_STATE_CONNECTED &&
    static_cast<uint32_t>(PinState::disconnected) == DPLL_PIN_STATE_DISCONNECTED &&
    static_cast<uint32_t>(PinState::selectable) == DPLL_PIN_STATE_SELECTABLE);
#    endif
#endif

namespace {

using netdev::GENL_CONTROLLER_ID;
using netdev::GENL_HEADER;

/// A fixed-size attribute's value into `out`; bad_message when the payload is another size.
template <typename T>
[[nodiscard]] auto read_scalar(std::span<uint8_t const> const payload, T& out) -> Status
{
    if (payload.size() != sizeof(T)) {
        return failure(netlink::bad_message());
    }
    out = netlink::load<T>(payload, 0);
    return success();
}

/// A u32 attribute into an enum of that width.
template <typename E>
[[nodiscard]] auto read_enum(std::span<uint8_t const> const payload, E& out) -> Status
{
    uint32_t value = 0;
    if (auto read = read_scalar(payload, value); !read) {
        return read;
    }
    out = static_cast<E>(value);
    return success();
}

/// A string attribute, its NUL and anything after it dropped.
[[nodiscard]] auto read_string(std::span<uint8_t const> const payload) -> std::string
{
    std::string text{};
    for (auto const octet : payload) {
        if (octet == 0) {
            break;
        }
        text.push_back(static_cast<char>(octet));
    }
    return text;
}

/// One DPLL_A_* attribute into `device`; the id into `id`, so a message
/// without one is told from a device 0.
[[nodiscard]] auto read_device_attribute(
    uint16_t const type, std::span<uint8_t const> const payload, Device& device, std::optional<uint32_t>& id) -> Status
{
    switch (type & netlink::TYPE_MASK) {
        case A_ID:
            return read_scalar(payload, id.emplace());
        case A_MODULE_NAME:
            device.module_name = read_string(payload);
            return success();
        case A_CLOCK_ID:
            return read_scalar(payload, device.clock_id);
        case A_MODE:
            return read_enum(payload, device.mode);
        case A_LOCK_STATUS:
            return read_enum(payload, device.lock_status);
        case A_LOCK_STATUS_ERROR:
            return read_enum(payload, device.lock_status_error);
        case A_TYPE:
            return read_enum(payload, device.type);
        case A_TEMP:
            return read_scalar(payload, device.temperature_millicelsius.emplace());
        default:
            return success();  // the pad, the supported modes, the quality level, whatever a later kernel adds
    }
}

/// `found`, or the error that stopped the walk, or bad_message when the walk
/// finished without finding what the message had to carry.
template <typename T>
[[nodiscard]] auto required(Status const& walked, std::optional<T> const& found) -> StatusValue<T>
{
    if (!walked) {
        return failure(walked.error());
    }
    if (!found) {
        return failure(netlink::bad_message());
    }
    return *found;
}

/// One attribute of an A_PIN_PARENT_DEVICE nest into `parent`; the parent's id into `id`.
[[nodiscard]] auto read_parent_attribute(
    uint16_t const type, std::span<uint8_t const> const payload, PinParent& parent, std::optional<uint32_t>& id) -> Status
{
    switch (type & netlink::TYPE_MASK) {
        case A_PIN_PARENT_ID:
            return read_scalar(payload, id.emplace());
        case A_PIN_DIRECTION:
            return read_enum(payload, parent.direction);
        case A_PIN_STATE:
            return read_enum(payload, parent.state);
        case A_PIN_PRIO:
            return read_scalar(payload, parent.prio.emplace());
        case A_PIN_PHASE_OFFSET:
            return read_scalar(payload, parent.phase_offset.emplace());
        default:
            return success();
    }
}

/// An A_PIN_PARENT_DEVICE nest appended to `parents`; bad_message without the parent's id.
[[nodiscard]] auto read_parent(std::span<uint8_t const> const nest, std::vector<PinParent>& parents) -> Status
{
    PinParent parent{};
    std::optional<uint32_t> id;
    auto const walked = netlink::walk_attributes(nest, [&](uint16_t const type, std::span<uint8_t const> const payload) {
        return read_parent_attribute(type, payload, parent, id);
    });
    return required(walked, id).transform([&](uint32_t const device_id) {
        parent.device_id = device_id;
        parents.push_back(parent);
    });
}

/// An A_PIN_FREQUENCY_SUPPORTED nest appended to `ranges`; bad_message without both bounds.
[[nodiscard]] auto read_range(std::span<uint8_t const> const nest, std::vector<FrequencyRange>& ranges) -> Status
{
    std::optional<uint64_t> min;
    std::optional<uint64_t> max;
    auto const walked = netlink::walk_attributes(nest, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
        auto const masked = type & netlink::TYPE_MASK;
        return masked == A_PIN_FREQUENCY_MIN ? read_scalar(payload, min.emplace())
            : masked == A_PIN_FREQUENCY_MAX  ? read_scalar(payload, max.emplace())
                                             : success();
    });
    if (walked && (!min || !max)) {
        return failure(netlink::bad_message());
    }
    return walked.transform([&] { ranges.push_back({.min_hz = *min, .max_hz = *max}); });
}

/// One DPLL_A_PIN_* attribute into `pin`; the id into `id`.
[[nodiscard]] auto read_pin_attribute(
    uint16_t const type, std::span<uint8_t const> const payload, Pin& pin, std::optional<uint32_t>& id) -> Status
{
    switch (type & netlink::TYPE_MASK) {
        case A_PIN_ID:
            return read_scalar(payload, id.emplace());
        case A_PIN_MODULE_NAME:
            pin.module_name = read_string(payload);
            return success();
        case A_PIN_CLOCK_ID:
            return read_scalar(payload, pin.clock_id);
        case A_PIN_BOARD_LABEL:
            pin.board_label = read_string(payload);
            return success();
        case A_PIN_PANEL_LABEL:
            pin.panel_label = read_string(payload);
            return success();
        case A_PIN_PACKAGE_LABEL:
            pin.package_label = read_string(payload);
            return success();
        case A_PIN_TYPE:
            return read_scalar(payload, pin.type);
        case A_PIN_FREQUENCY:
            return read_scalar(payload, pin.frequency_hz.emplace());
        case A_PIN_FREQUENCY_SUPPORTED:
            return read_range(payload, pin.frequencies);
        case A_PIN_CAPABILITIES:
            return read_scalar(payload, pin.capabilities);
        case A_PIN_PARENT_DEVICE:
            return read_parent(payload, pin.parents);
        default:
            return success();  // parent pins, phase adjustment, esync, whatever a later kernel adds
    }
}

/// One multicast group of a CTRL_ATTR_MCAST_GROUPS list: its name and id.
struct Group
{
    std::string name{};
    std::optional<uint32_t> id{};
};

[[nodiscard]] auto read_group(std::span<uint8_t const> const attributes) -> StatusValue<Group>
{
    Group group{};
    auto const walked =
        netlink::walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            switch (type & netlink::TYPE_MASK) {
                case CTRL_MCAST_GRP_NAME:
                    group.name = read_string(payload);
                    return success();
                case CTRL_MCAST_GRP_ID:
                    return read_scalar(payload, group.id.emplace());
                default:
                    return success();
            }
        });
    if (!walked) {
        return failure(walked.error());
    }
    return group;
}

/// The id of the group called MONITOR_GROUP in a CTRL_ATTR_MCAST_GROUPS list,
/// written to `monitor` when found.
[[nodiscard]] auto read_groups(std::span<uint8_t const> const groups, uint32_t& monitor) -> Status
{
    return netlink::walk_attributes(groups, [&](uint16_t, std::span<uint8_t const> const entry) -> Status {
        auto const group = read_group(entry);
        if (!group) {
            return failure(group.error());
        }
        if (group->name == MONITOR_GROUP && group->id.has_value()) {
            monitor = *group->id;
        }
        return success();
    });
}

/// One request of `length` octets into `out`: the netlink header under
/// `flags`, the generic-netlink header for `cmd`, then what `attributes` appends.
template <typename Attributes>
[[nodiscard]] auto build_message(
    std::span<uint8_t> const out,
    size_t const length,
    uint16_t const type,
    uint16_t const flags,
    uint32_t const seq,
    uint8_t const cmd,
    Attributes const& attributes) -> StatusValue<size_t>
{
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, length, type, flags, seq);
    b.append(cmd).append(FAMILY_VERSION).append(uint16_t{0});
    attributes(b);
    return netlink::finish(b, length);
}

[[nodiscard]] constexpr auto is_device_command(uint8_t const cmd) noexcept -> bool
{
    return cmd == CMD_DEVICE_GET || cmd == CMD_DEVICE_CREATE_NTF || cmd == CMD_DEVICE_DELETE_NTF || cmd == CMD_DEVICE_CHANGE_NTF;
}

[[nodiscard]] constexpr auto is_pin_command(uint8_t const cmd) noexcept -> bool
{
    return cmd == CMD_PIN_GET || cmd == CMD_PIN_CREATE_NTF || cmd == CMD_PIN_DELETE_NTF || cmd == CMD_PIN_CHANGE_NTF;
}

/// The pin command a message carries in its generic-netlink header, or
/// nullopt when the message is too short to have one or carries another.
[[nodiscard]] auto pin_command_for(std::span<uint8_t const> const message) noexcept -> std::optional<uint8_t>
{
    if (message.size() < GENL_HEADER || !is_pin_command(message[netlink::MESSAGE_HEADER])) {
        return std::nullopt;
    }
    return message[netlink::MESSAGE_HEADER];
}

/// A u32 attribute appended.
void put_u32(BufferSerializerBuilder& b, uint16_t const type, uint32_t const value)
{
    netlink::put_attribute(b, type, make_const_span(value));
}

constexpr uint16_t REQUEST_ACK = netlink::FLAG_REQUEST | netlink::FLAG_ACK;
constexpr size_t U32_ATTRIBUTE = netlink::attribute_size(sizeof(uint32_t));
constexpr size_t U64_ATTRIBUTE = netlink::attribute_size(sizeof(uint64_t));

/// The device command a message carries in its generic-netlink header, or
/// nullopt when the message is too short to have one or carries another.
[[nodiscard]] auto device_command_of(std::span<uint8_t const> const message) noexcept -> std::optional<uint8_t>
{
    if (message.size() < GENL_HEADER || !is_device_command(message[netlink::MESSAGE_HEADER])) {
        return std::nullopt;
    }
    return message[netlink::MESSAGE_HEADER];
}

}  // namespace

auto lock_status_name(LockStatus const status) noexcept -> std::string_view
{
    switch (status) {
        case LockStatus::unlocked:
            return "unlocked";
        case LockStatus::locked:
            return "locked";
        case LockStatus::locked_holdover_acquired:
            return "locked-ho-acq";
        case LockStatus::holdover:
            return "holdover";
        case LockStatus::unknown:
            break;
    }
    return "unknown";
}

auto type_name(Type const type) noexcept -> std::string_view
{
    switch (type) {
        case Type::pps:
            return "pps";
        case Type::eec:
            return "eec";
        case Type::unknown:
            break;
    }
    return "unknown";
}

auto pin_direction_name(PinDirection const direction) noexcept -> std::string_view
{
    switch (direction) {
        case PinDirection::input:
            return "input";
        case PinDirection::output:
            return "output";
        case PinDirection::unknown:
            break;
    }
    return "unknown";
}

auto pin_state_name(PinState const state) noexcept -> std::string_view
{
    switch (state) {
        case PinState::connected:
            return "connected";
        case PinState::disconnected:
            return "disconnected";
        case PinState::selectable:
            return "selectable";
        case PinState::unknown:
            break;
    }
    return "unknown";
}

//
// Pin
//

auto Pin::label() const noexcept -> std::string_view
{
    if (!board_label.empty()) {
        return board_label;
    }
    return panel_label.empty() ? std::string_view{package_label} : std::string_view{panel_label};
}

auto Pin::parent(uint32_t const device_id) const -> std::optional<PinParent>
{
    auto const it = std::ranges::find(parents, device_id, &PinParent::device_id);
    return it == parents.end() ? std::nullopt : std::optional{*it};
}

auto Pin::supports_frequency(uint64_t const hz) const noexcept -> bool
{
    return std::ranges::any_of(frequencies, [hz](FrequencyRange const& r) { return r.min_hz <= hz && hz <= r.max_hz; });
}

//
// Framing
//

auto build_get_family(std::span<uint8_t> const out, uint32_t const seq) -> StatusValue<size_t>
{
    return netdev::build_get_family(out, FAMILY_NAME, seq);
}

auto build_device_dump(std::span<uint8_t> const out, uint16_t const family_id, uint32_t const seq) -> StatusValue<size_t>
{
    constexpr uint16_t FLAGS = netlink::FLAG_REQUEST | netlink::FLAG_ACK | netlink::FLAG_DUMP;
    return build_message(out, GENL_HEADER, family_id, FLAGS, seq, CMD_DEVICE_GET, [](BufferSerializerBuilder&) {});
}

auto build_device_get(std::span<uint8_t> const out, uint16_t const family_id, uint32_t const id, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t LENGTH = GENL_HEADER + netlink::attribute_size(sizeof(uint32_t));
    constexpr uint16_t FLAGS = netlink::FLAG_REQUEST | netlink::FLAG_ACK;
    return build_message(out, LENGTH, family_id, FLAGS, seq, CMD_DEVICE_GET, [&](BufferSerializerBuilder& b) {
        netlink::put_attribute(b, A_ID, make_const_span(id));
    });
}

auto build_pin_dump(std::span<uint8_t> const out, uint16_t const family_id, uint32_t const seq) -> StatusValue<size_t>
{
    constexpr uint16_t FLAGS = netlink::FLAG_REQUEST | netlink::FLAG_ACK | netlink::FLAG_DUMP;
    return build_message(out, GENL_HEADER, family_id, FLAGS, seq, CMD_PIN_GET, [](BufferSerializerBuilder&) {});
}

auto build_pin_parent_set(
    std::span<uint8_t> const out, uint16_t const family_id, uint32_t const pin_id, ParentSetting const& setting, uint32_t const seq)
    -> StatusValue<size_t>
{
    size_t const nest = U32_ATTRIBUTE * (1U + (setting.direction ? 1U : 0U) + (setting.state ? 1U : 0U));
    size_t const length = GENL_HEADER + U32_ATTRIBUTE + netlink::ATTRIBUTE_HEADER + nest;
    return build_message(out, length, family_id, REQUEST_ACK, seq, CMD_PIN_SET, [&](BufferSerializerBuilder& b) {
        put_u32(b, A_PIN_ID, pin_id);
        netlink::put_attribute_header(b, nest, A_PIN_PARENT_DEVICE | netlink::ATTRIBUTE_NESTED);
        put_u32(b, A_PIN_PARENT_ID, setting.device_id);
        if (setting.direction) {
            put_u32(b, A_PIN_DIRECTION, std::to_underlying(*setting.direction));
        }
        if (setting.state) {
            put_u32(b, A_PIN_STATE, std::to_underlying(*setting.state));
        }
    });
}

auto build_pin_frequency_set(
    std::span<uint8_t> const out, uint16_t const family_id, uint32_t const pin_id, uint64_t const hz, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t LENGTH = GENL_HEADER + U32_ATTRIBUTE + U64_ATTRIBUTE;
    return build_message(out, LENGTH, family_id, REQUEST_ACK, seq, CMD_PIN_SET, [&](BufferSerializerBuilder& b) {
        put_u32(b, A_PIN_ID, pin_id);
        netlink::put_attribute(b, A_PIN_FREQUENCY, make_const_span(hz));
    });
}

auto parse_family(std::span<uint8_t const> const message) -> StatusValue<Family>
{
    std::optional<uint16_t> id;
    uint32_t monitor = 0;
    auto const walked = netdev::genl_attributes(message, GENL_CONTROLLER_ID, netdev::CTRL_NEWFAMILY)
                            .and_then([&](std::span<uint8_t const> const attributes) {
                                return netlink::walk_attributes(
                                    attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
                                        switch (type & netlink::TYPE_MASK) {
                                            case netdev::CTRL_FAMILY_ID:
                                                return read_scalar(payload, id.emplace());
                                            case CTRL_MCAST_GROUPS:
                                                return read_groups(payload, monitor);
                                            default:
                                                return success();
                                        }
                                    });
                            });
    return required(walked, id).transform([&](uint16_t const family_id) {
        return Family{.id = family_id, .monitor_group = monitor};
    });
}

auto parse_device(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<DeviceMessage>
{
    auto const cmd = device_command_of(message);
    if (!cmd) {
        return failure(netlink::bad_message());
    }
    DeviceMessage out{.cmd = *cmd, .device = {}};
    std::optional<uint32_t> id;
    auto const walked = netdev::genl_attributes(message, family_id, *cmd).and_then([&](std::span<uint8_t const> const attributes) {
        return netlink::walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            return read_device_attribute(type, payload, out.device, id);
        });
    });
    return required(walked, id).transform([&](uint32_t const device_id) {
        out.device.id = device_id;
        return out;
    });
}

auto DeviceDump::take(std::span<uint8_t const> const message, uint16_t const type, uint16_t const family_id) -> Status
{
    if (type != family_id) {
        return success();
    }
    return parse_device(message, family_id).transform([&](DeviceMessage const& got) { devices.push_back(got.device); });
}

auto PinDump::read(std::span<uint8_t const> const message, uint16_t const type, uint16_t const family_id) -> Status
{
    if (type != family_id) {
        return success();
    }
    return parse_pin(message, family_id).transform([&](PinMessage got) { pins.push_back(std::move(got.pin)); });
}

auto parse_pin(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<PinMessage>
{
    auto const cmd = pin_command_for(message);
    if (!cmd) {
        return failure(netlink::bad_message());
    }
    PinMessage out{.cmd = *cmd, .pin = {}};
    std::optional<uint32_t> id;
    auto const walked = netdev::genl_attributes(message, family_id, *cmd).and_then([&](std::span<uint8_t const> const attributes) {
        return netlink::walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            return read_pin_attribute(type, payload, out.pin, id);
        });
    });
    return required(walked, id).transform([&](uint32_t const pin_id) {
        out.pin.id = pin_id;
        return std::move(out);
    });
}

#if defined(__linux__)

//
// The client
//

auto resolve_family(netlink::Socket& socket, std::span<uint8_t> const reply) -> StatusValue<Family>
{
    std::optional<Family> family;
    auto const asked = socket.request(
        reply,
        [](std::span<uint8_t> const out, uint32_t const seq) { return build_get_family(out, seq); },
        [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            if (type != GENL_CONTROLLER_ID) {
                return success();
            }
            return parse_family(message).transform([&](Family const& got) { family = got; });
        });
    return required(asked, family);
}

auto DpllClient::open() -> Status
{
    if (auto opened = socket_.open(NETLINK_GENERIC); !opened) {
        return opened;
    }
    auto const family = resolve_family(socket_, reply_);
    if (!family) {
        socket_.close();
        return failure(family.error());
    }
    family_ = *family;
    return success();
}

auto DpllClient::devices() -> StatusValue<std::vector<Device>>
{
    DeviceDump dump;
    auto const asked = socket_.request(
        reply_,
        [&](std::span<uint8_t> const out, uint32_t const seq) {
            dump.restart();  // built once per attempt: a request sent again starts the dump over
            return build_device_dump(out, family_.id, seq);
        },
        [&](std::span<uint8_t const> const message, uint16_t const type) { return dump.take(message, type, family_.id); });
    if (!asked) {
        return failure(asked.error());
    }
    return std::move(dump.devices);
}

auto DpllClient::device(uint32_t const id) -> StatusValue<Device>
{
    std::optional<Device> device;
    auto const asked = socket_.request(
        reply_,
        [&](std::span<uint8_t> const out, uint32_t const seq) { return build_device_get(out, family_.id, id, seq); },
        [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            if (type != family_.id) {
                return success();
            }
            return parse_device(message, family_.id).transform([&](DeviceMessage const& got) { device = got.device; });
        });
    return required(asked, device);
}

auto DpllClient::pins() -> StatusValue<std::vector<Pin>>
{
    PinDump dump;
    auto const asked = socket_.request(
        reply_,
        [&](std::span<uint8_t> const out, uint32_t const seq) {
            dump.restart();  // built once per attempt: a request sent again starts the dump over
            return build_pin_dump(out, family_.id, seq);
        },
        [&](std::span<uint8_t const> const message, uint16_t const type) { return dump.read(message, type, family_.id); });
    if (!asked) {
        return failure(asked.error());
    }
    return std::move(dump.pins);
}

auto DpllClient::set_parent(uint32_t const pin_id, ParentSetting const& setting) -> Status
{
    return socket_.request(reply_, [&](std::span<uint8_t> const out, uint32_t const seq) {
        return build_pin_parent_set(out, family_.id, pin_id, setting, seq);
    });
}

auto DpllClient::set_frequency(uint32_t const pin_id, uint64_t const hz) -> Status
{
    return socket_.request(reply_, [&](std::span<uint8_t> const out, uint32_t const seq) {
        return build_pin_frequency_set(out, family_.id, pin_id, hz, seq);
    });
}

//
// The watch
//

namespace {

[[nodiscard]] auto errno_failure() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected{std::error_code{errno, std::system_category()}};
}

/// A NETLINK_GENERIC socket of our own, non-blocking, bound to a port the
/// kernel picks, joined to multicast group `group`.
[[nodiscard]] auto open_member_socket(uint32_t const group) -> StatusValue<FileDescriptor>
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_GENERIC)};
    if (!fd.valid()) {
        return errno_failure();
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(fd.get(), reinterpret_cast<sockaddr const*>(&local), sizeof(local)) != 0) {
        return errno_failure();
    }
    // The membership, not nl_groups in the bind: group ids above 31 have no
    // bit there, and the controller hands out ids as it pleases.
    if (::setsockopt(fd.get(), SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) != 0) {
        return errno_failure();
    }
    return fd;
}

[[nodiscard]] constexpr auto event_of(uint8_t const cmd) noexcept -> std::optional<DeviceEvent>
{
    switch (cmd) {
        case CMD_DEVICE_CREATE_NTF:
            return DeviceEvent::created;
        case CMD_DEVICE_CHANGE_NTF:
            return DeviceEvent::changed;
        case CMD_DEVICE_DELETE_NTF:
            return DeviceEvent::deleted;
        default:
            return std::nullopt;  // a pin notification, or a reply to somebody's request
    }
}

}  // namespace

auto DpllWatch::open() -> Status
{
    close();
    Family family{};
    {
        // The controller is asked on a socket of its own, closed again: the
        // member socket below is for notifications and nothing else.
        netlink::Socket control;
        if (auto opened = control.open(NETLINK_GENERIC); !opened) {
            return opened;
        }
        auto const resolved = resolve_family(control, buffer_);
        if (!resolved) {
            return failure(resolved.error());
        }
        family = *resolved;
    }
    if (family.monitor_group == 0) {
        return failure(std::make_error_code(std::errc::not_supported));
    }
    auto fd = open_member_socket(family.monitor_group);
    if (!fd) {
        return failure(fd.error());
    }
    fd_ = std::move(*fd);
    family_ = family;
    return success();
}

void DpllWatch::close() noexcept
{
    fd_ = FileDescriptor{};
    family_ = Family{};
    failed_ = false;
}

void DpllWatch::deliver(std::span<uint8_t const> const datagram, int64_t const now_ns)
{
    for (size_t at = 0; at + netlink::MESSAGE_HEADER <= datagram.size();) {
        size_t const length = netlink::load<uint32_t>(datagram, at + netlink::OFFSET_LENGTH);
        if (length < netlink::MESSAGE_HEADER || length > datagram.size() - at) {
            return;  // a datagram that lies about its lengths is dropped from here on
        }
        auto const message = datagram.subspan(at, length);
        if (netlink::load<uint16_t>(message, netlink::OFFSET_TYPE) == family_.id) {
            if (auto const parsed = parse_device(message, family_.id)) {
                if (auto const event = event_of(parsed->cmd)) {
                    ++events_;
                    on_event_(*event, parsed->device, now_ns);
                }
            }
        }
        at += netlink::align4(length);
    }
}

void DpllWatch::lose(Loss const loss, std::error_code const error, int64_t const now_ns)
{
    ++losses_;
    if (on_loss_) {
        on_loss_(loss, error, now_ns);
    }
}

auto DpllWatch::read_one(int64_t const now_ns) -> bool
{
    // MSG_TRUNC: a notification too big for the buffer is known to have
    // been cut, and is dropped whole rather than parsed in part.
    ssize_t const received = ::recv(fd_.get(), buffer_.data(), buffer_.size(), MSG_TRUNC);
    if (received >= 0) {
        if (static_cast<size_t>(received) > buffer_.size()) {
            lose(Loss::truncated, {}, now_ns);
        } else {
            deliver(std::span<uint8_t const>{buffer_.data(), static_cast<size_t>(received)}, now_ns);
        }
        return true;
    }
    int const error = errno;
    if (error == EAGAIN || error == EWOULDBLOCK) {
        return false;  // drained
    }
    if (error == EINTR) {
        return true;
    }
    if (error == ENOBUFS) {
        // The queue overflowed: what was queued is still there to read, what
        // arrived while it was full is gone.
        lose(Loss::overrun, std::error_code{error, std::system_category()}, now_ns);
        return true;
    }
    failed_ = true;
    lose(Loss::failed, std::error_code{error, std::system_category()}, now_ns);
    return false;
}

void DpllWatch::on_ready(int64_t const now_ns)
{
    while (read_one(now_ns)) {
    }
}

#endif  // __linux__

}  // namespace statusbar::net::dpll
