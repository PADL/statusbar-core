// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The dpll generic-netlink framing against bytes laid out by hand from
// linux/genetlink.h and linux/dpll.h, the parsers against replies framed as
// the kernel's ctrl_fill_info() and dpll_msg_add_dev_handle() write them,
// and, on Linux, the client and the watch against the running kernel.
// Netlink is host byte order: the vectors are little-endian.

#include "statusbar/net/net_dpll.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

using namespace statusbar;
using namespace statusbar::net::dpll;

namespace {

constexpr bool LITTLE = std::endian::native == std::endian::little;

/// The id a kernel happened to give the dpll family.
constexpr uint16_t DPLL_ID = 0x1a;

auto same_bytes(std::span<uint8_t const> const got, std::span<uint8_t const> const want) -> bool
{
    if (got.size() != want.size()) {
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            return false;
        }
    }
    return true;
}

// clang-format off
/// CTRL_CMD_NEWFAMILY for "dpll": the name, the id 0x1a, the version, and the
/// multicast groups - one, "monitor", id 5 - as nested attributes.
constexpr std::array<uint8_t, 76> FAMILY_REPLY{
    0x4c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00,                                                        // CTRL_CMD_NEWFAMILY, version 2
    0x09, 0x00, 0x02, 0x00, 'd', 'p', 'l', 'l', 0x00, 0x00, 0x00, 0x00,            // CTRL_ATTR_FAMILY_NAME
    0x06, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00,                                // CTRL_ATTR_FAMILY_ID
    0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,                                // CTRL_ATTR_VERSION
    0x1c, 0x00, 0x07, 0x80,                                                        // CTRL_ATTR_MCAST_GROUPS (nested)
        0x18, 0x00, 0x01, 0x80,                                                    //   group 1 (nested)
            0x0c, 0x00, 0x01, 0x00, 'm', 'o', 'n', 'i', 't', 'o', 'r', 0x00,       //     CTRL_ATTR_MCAST_GRP_NAME
            0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00,                        //     CTRL_ATTR_MCAST_GRP_ID
};

/// DPLL_CMD_DEVICE_GET for device 0: an ice PPS DPLL on clock 00:11:22:ff:fe:33:44:55,
/// automatic, locked with holdover acquired, no error, 46.5 degrees.
constexpr std::array<uint8_t, 100> DEVICE_REPLY{
    0x64, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x01, 0x00, 0x00,                                                        // DPLL_CMD_DEVICE_GET, version 1
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,                                // DPLL_A_ID 0
    0x08, 0x00, 0x02, 0x00, 'i', 'c', 'e', 0x00,                                   // DPLL_A_MODULE_NAME
    0x04, 0x00, 0x03, 0x00,                                                        // DPLL_A_PAD
    0x0c, 0x00, 0x04, 0x00, 0x55, 0x44, 0x33, 0xfe, 0xff, 0x22, 0x11, 0x00,        // DPLL_A_CLOCK_ID
    0x08, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00,                                // DPLL_A_MODE automatic
    0x08, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00,                                // DPLL_A_MODE_SUPPORTED (ignored)
    0x08, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,                                // DPLL_A_LOCK_STATUS locked-ho-acq
    0x08, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00,                                // DPLL_A_LOCK_STATUS_ERROR none
    0x08, 0x00, 0x08, 0x00, 0xa4, 0xb5, 0x00, 0x00,                                // DPLL_A_TEMP 46500
    0x08, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00,                                // DPLL_A_TYPE pps
};

/// DPLL_CMD_DEVICE_CHANGE_NTF: device 0 went to holdover, the media down.
constexpr std::array<uint8_t, 44> CHANGE_NOTIFICATION{
    0x2c, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x01, 0x00, 0x00,                                                        // DPLL_CMD_DEVICE_CHANGE_NTF
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,                                // DPLL_A_ID 0
    0x08, 0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00,                                // DPLL_A_LOCK_STATUS holdover
    0x08, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00,                                // DPLL_A_LOCK_STATUS_ERROR media down
};

/// DPLL_CMD_PIN_GET for an E810-T's pin 76: SMA1, ext, 8 kHz of 1 Hz to 25 MHz, every capability,
/// an output of devices 6 (disconnected) and 7 (connected, phase offset -66750650).
constexpr std::array<uint8_t, 212> PIN_SMA1{
    0xd4, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x01, 0x00, 0x00,                                                        // DPLL_CMD_PIN_GET
    0x08, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x00, 0x00,                                // DPLL_A_PIN_ID 76
    0x08, 0x00, 0x03, 0x00, 'i', 'c', 'e', 0x00,                                   // DPLL_A_PIN_MODULE_NAME
    0x0c, 0x00, 0x05, 0x00, 0xb8, 0xc4, 0x69, 0xff, 0xff, 0x6f, 0x7c, 0x50,        // DPLL_A_PIN_CLOCK_ID
    0x09, 0x00, 0x06, 0x00, 'S', 'M', 'A', '1', 0x00, 0x00, 0x00, 0x00,            // DPLL_A_PIN_BOARD_LABEL
    0x08, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00,                                // DPLL_A_PIN_TYPE ext
    0x0c, 0x00, 0x0b, 0x00, 0x40, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        // DPLL_A_PIN_FREQUENCY 8000
    0x1c, 0x00, 0x0c, 0x00,                                                        // DPLL_A_PIN_FREQUENCY_SUPPORTED
        0x0c, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    //   _MIN 1
        0x0c, 0x00, 0x0e, 0x00, 0x40, 0x78, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00,    //   _MAX 25000000
    0x08, 0x00, 0x11, 0x00, 0x07, 0x00, 0x00, 0x00,                                // DPLL_A_PIN_CAPABILITIES
    0x30, 0x00, 0x12, 0x00,                                                        // DPLL_A_PIN_PARENT_DEVICE
        0x08, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00,                            //   _PARENT_ID 6
        0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00,                            //   _DIRECTION output
        0x08, 0x00, 0x0f, 0x00, 0xff, 0x00, 0x00, 0x00,                            //   _PRIO 255
        0x08, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00,                            //   _STATE disconnected
        0x0c, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    //   _PHASE_OFFSET 0
    0x30, 0x00, 0x12, 0x00,                                                        // DPLL_A_PIN_PARENT_DEVICE
        0x08, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00,                            //   _PARENT_ID 7
        0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00,                            //   _DIRECTION output
        0x08, 0x00, 0x0f, 0x00, 0xff, 0x00, 0x00, 0x00,                            //   _PRIO 255
        0x08, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,                            //   _STATE connected
        0x0c, 0x00, 0x17, 0x00, 0x46, 0x77, 0x05, 0xfc, 0xff, 0xff, 0xff, 0xff,    //   _PHASE_OFFSET
};
// clang-format on

}  // namespace

TEST(dpll, the_family_reply_names_the_id_and_the_monitor_group)
{
    auto const family = parse_family(FAMILY_REPLY);
    EXPECT_TRUE(family.has_value());
    EXPECT_TRUE((family && *family == Family{.id = DPLL_ID, .monitor_group = 5}));
}

TEST(dpll, a_family_without_a_monitor_group_reads_as_group_zero)
{
    // The same reply cut before the groups, its length fixed up.
    std::array<uint8_t, 48> without{};
    for (size_t i = 0; i < without.size(); ++i) {
        without[i] = FAMILY_REPLY[i];
    }
    without[0] = 0x30;
    auto const family = parse_family(without);
    EXPECT_TRUE(family.has_value());
    EXPECT_TRUE((family && *family == Family{.id = DPLL_ID, .monitor_group = 0}));
}

TEST(dpll, every_device_attribute_is_read_and_the_rest_ignored)
{
    auto const got = parse_device(DEVICE_REPLY, DPLL_ID);
    EXPECT_TRUE(got.has_value());
    if (!got) {
        return;
    }
    EXPECT_EQ(got->cmd, CMD_DEVICE_GET);
    Device const want{
        .id = 0,
        .clock_id = 0x001122fffe334455ULL,
        .module_name = "ice",
        .mode = Mode::automatic,
        .lock_status = LockStatus::locked_holdover_acquired,
        .lock_status_error = LockStatusError::none,
        .type = Type::pps,
        .temperature_millicelsius = 46500,
    };
    EXPECT_TRUE(got->device == want);
    EXPECT_TRUE(is_locked(got->device.lock_status));
}

TEST(dpll, a_change_notification_carries_its_command_and_what_it_says)
{
    auto const got = parse_device(CHANGE_NOTIFICATION, DPLL_ID);
    EXPECT_TRUE(got.has_value());
    if (!got) {
        return;
    }
    EXPECT_EQ(got->cmd, CMD_DEVICE_CHANGE_NTF);
    EXPECT_TRUE(got->device.lock_status == LockStatus::holdover);
    EXPECT_TRUE(got->device.lock_status_error == LockStatusError::media_down);
    EXPECT_TRUE(got->device.type == Type::unknown);  // not sent: unknown, not a guess
    EXPECT_TRUE(got->device.module_name.empty());
    EXPECT_FALSE(got->device.temperature_millicelsius.has_value());
    EXPECT_FALSE(is_locked(got->device.lock_status));
}

TEST(dpll, a_message_that_is_not_a_device_of_this_family_is_refused)
{
    EXPECT_FALSE(parse_device(DEVICE_REPLY, uint16_t{0x1b}).has_value());  // another family
    auto pin = CHANGE_NOTIFICATION;
    pin[16] = 12;  // DPLL_CMD_PIN_CHANGE_NTF
    EXPECT_FALSE(parse_device(pin, DPLL_ID).has_value());
    EXPECT_FALSE(parse_device(std::span<uint8_t const>{DEVICE_REPLY}.first(30), DPLL_ID).has_value());  // truncated
    auto no_id = CHANGE_NOTIFICATION;
    no_id[22] = 0x0b;  // the id attribute renamed: a device with no id is no device
    EXPECT_FALSE(parse_device(no_id, DPLL_ID).has_value());
    auto missized = CHANGE_NOTIFICATION;
    missized[28] = 0x06;  // the lock status cut to a u16
    EXPECT_FALSE(parse_device(missized, DPLL_ID).has_value());
    EXPECT_FALSE(parse_family(DEVICE_REPLY).has_value());
}

TEST(dpll, the_requests_as_the_kernel_reads_them)
{
    if (!LITTLE) {
        SKIP("the expected bytes are little-endian");
    }
    // clang-format off
    constexpr std::array<uint8_t, 20> dump{
        0x14, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x05, 0x03, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x01, 0x00, 0x00,
    };
    constexpr std::array<uint8_t, 28> one{
        0x1c, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    constexpr std::array<uint8_t, 32> family{
        0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x01, 0x00, 0x00,
        0x09, 0x00, 0x02, 0x00, 'd', 'p', 'l', 'l', 0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto length = build_device_dump(out, DPLL_ID, 11);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), dump));
    length = build_device_get(out, DPLL_ID, 3, 12);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), one));
    length = build_get_family(out, 7);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), family));
}

TEST(dpll, the_names_of_the_states)
{
    EXPECT_EQ(lock_status_name(LockStatus::locked), std::string_view{"locked"});
    EXPECT_EQ(lock_status_name(LockStatus::holdover), std::string_view{"holdover"});
    EXPECT_EQ(lock_status_name(static_cast<LockStatus>(99)), std::string_view{"unknown"});
    EXPECT_EQ(type_name(Type::eec), std::string_view{"eec"});
    EXPECT_FALSE(is_locked(LockStatus::unlocked));
    EXPECT_FALSE(is_locked(LockStatus::unknown));
}

TEST(dpll_pin, a_pin_reads_with_its_ranges_and_parents)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto const got = parse_pin(PIN_SMA1, DPLL_ID);
    EXPECT_TRUE(got.has_value());
    if (!got) {
        return;
    }
    auto const& pin = got->pin;
    EXPECT_EQ(got->cmd, CMD_PIN_GET);
    EXPECT_TRUE(pin.id == 76 && pin.module_name == "ice" && pin.clock_id == 0x507c6fffff69c4b8ULL && pin.label() == "SMA1");
    EXPECT_TRUE(pin.type == 2 && pin.capabilities == 7 && pin.frequency_hz == std::optional<uint64_t>{8000});
    EXPECT_TRUE((pin.frequencies.size() == 1 && pin.frequencies[0] == FrequencyRange{.min_hz = 1, .max_hz = 25'000'000}));
    EXPECT_EQ(pin.parents.size(), size_t{2});
    auto const pps = pin.parent(7);
    EXPECT_TRUE(pps && pps->direction == PinDirection::output && pps->state == PinState::connected && pps->prio == 255U);
    EXPECT_TRUE(pps && pps->phase_offset == std::optional<int64_t>{-66'750'650});
    auto const eec = pin.parent(6);
    EXPECT_TRUE(eec && eec->state == PinState::disconnected);
    EXPECT_FALSE(pin.parent(8).has_value());
}

TEST(dpll_pin, a_pin_message_with_a_nest_cut_short_or_of_another_kind_is_refused)
{
    auto no_max = PIN_SMA1;
    no_max[98] = 0x0f;  // DPLL_A_PIN_FREQUENCY_MAX becomes an attribute nobody reads: a range without its maximum
    EXPECT_FALSE(parse_pin(no_max, DPLL_ID).has_value());
    auto no_parent_id = PIN_SMA1;
    no_parent_id[122] = 0x03;  // the first parent's id renamed
    EXPECT_FALSE(parse_pin(no_parent_id, DPLL_ID).has_value());
    EXPECT_FALSE(parse_pin(DEVICE_REPLY, DPLL_ID).has_value());
    EXPECT_FALSE(parse_device(PIN_SMA1, DPLL_ID).has_value());
    EXPECT_FALSE(parse_pin(std::span<uint8_t const>{PIN_SMA1}.first(60), DPLL_ID).has_value());
}

TEST(dpll_pin, a_frequency_is_supported_within_a_range)
{
    Pin const pin{.frequencies = {{.min_hz = 1, .max_hz = 1}, {.min_hz = 10'000'000, .max_hz = 10'000'000}}};
    EXPECT_TRUE(pin.supports_frequency(1));
    EXPECT_TRUE(pin.supports_frequency(10'000'000));
    EXPECT_FALSE(pin.supports_frequency(8000));
    EXPECT_FALSE(Pin{}.supports_frequency(1));
}

TEST(dpll_pin, the_label_is_the_board_then_panel_then_package_one)
{
    EXPECT_TRUE((Pin{.board_label = "SMA1", .panel_label = "A"}.label() == "SMA1"));
    EXPECT_TRUE((Pin{.panel_label = "A", .package_label = "B"}.label() == "A"));
    EXPECT_TRUE((Pin{.package_label = "B"}.label() == "B"));
    EXPECT_TRUE(Pin{}.label().empty());
    EXPECT_EQ(pin_direction_name(PinDirection::output), std::string_view{"output"});
    EXPECT_EQ(pin_state_name(PinState::selectable), std::string_view{"selectable"});
    EXPECT_EQ(pin_state_name(static_cast<PinState>(9)), std::string_view{"unknown"});
}

TEST(dpll_pin, the_pin_requests_as_the_kernel_reads_them)
{
    if (!LITTLE) {
        SKIP("the expected bytes are little-endian");
    }
    // clang-format off
    constexpr std::array<uint8_t, 48> output{
        0x30, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x01, 0x00, 0x00,                                                    // DPLL_CMD_PIN_SET
        0x08, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x00, 0x00,                            // DPLL_A_PIN_ID 76
        0x14, 0x00, 0x12, 0x80,                                                    // DPLL_A_PIN_PARENT_DEVICE (nested)
            0x08, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00,                        //   _PARENT_ID 7
            0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00,                        //   _DIRECTION output
    };
    constexpr std::array<uint8_t, 40> frequency{
        0x28, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x01, 0x00, 0x00,                                                    // DPLL_CMD_PIN_SET
        0x08, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x00, 0x00,                            // DPLL_A_PIN_ID 76
        0x0c, 0x00, 0x0b, 0x00, 0x40, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // DPLL_A_PIN_FREQUENCY 8000
    };
    // clang-format on
    RequestBuffer out{};
    auto length = build_pin_parent_set(out, DPLL_ID, 76, {.device_id = 7, .direction = PinDirection::output}, 1);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), output));
    length = build_pin_frequency_set(out, DPLL_ID, 76, 8000, 2);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), frequency));
    length = build_pin_dump(out, DPLL_ID, 3);
    EXPECT_TRUE(length && *length == 20 && out[16] == CMD_PIN_GET && out[7] == 0x03);
}

TEST(dpll_pin, a_parent_setting_carries_only_what_it_sets)
{
    RequestBuffer out{};
    auto const both = build_pin_parent_set(
        out, DPLL_ID, 76, {.device_id = 7, .direction = PinDirection::output, .state = PinState::connected}, 1);
    EXPECT_TRUE(both && *both == 56);
    auto const state = build_pin_parent_set(out, DPLL_ID, 76, {.device_id = 7, .state = PinState::connected}, 1);
    EXPECT_TRUE(state && *state == 48);
    std::array<uint8_t, 16> small{};
    EXPECT_FALSE(build_pin_parent_set(small, DPLL_ID, 76, {.device_id = 7}, 1).has_value());
}

#if defined(__linux__)

TEST(dpll_watch, a_datagram_of_notifications_is_handed_on_one_event_each)
{
    struct Seen
    {
        DeviceEvent event;
        Device device;
        int64_t now_ns;
    };
    std::vector<Seen> seen;
    DpllWatch watch{
        [&](DeviceEvent const event, Device const& device, int64_t const now_ns) { seen.push_back({event, device, now_ns}); },
        Family{.id = DPLL_ID, .monitor_group = 5}};

    // Two messages in one datagram: the change, then a device-get reply to
    // somebody else's request, which is not an event.
    std::vector<uint8_t> datagram(CHANGE_NOTIFICATION.begin(), CHANGE_NOTIFICATION.end());
    datagram.insert(datagram.end(), DEVICE_REPLY.begin(), DEVICE_REPLY.end());
    watch.deliver(datagram, 1234);
    EXPECT_EQ(seen.size(), size_t{1});
    EXPECT_EQ(watch.events(), uint64_t{1});
    if (seen.size() == 1) {
        EXPECT_TRUE(seen[0].event == DeviceEvent::changed);
        EXPECT_TRUE(seen[0].device.lock_status == LockStatus::holdover);
        EXPECT_EQ(seen[0].now_ns, int64_t{1234});
    }

    // A datagram whose first message overruns it delivers nothing.
    auto lying = CHANGE_NOTIFICATION;
    lying[0] = 0xff;
    watch.deliver(lying, 1235);
    EXPECT_EQ(seen.size(), size_t{1});
    // Another family's notification is not ours.
    auto theirs = CHANGE_NOTIFICATION;
    theirs[4] = 0x1b;
    watch.deliver(theirs, 1236);
    EXPECT_EQ(seen.size(), size_t{1});
    EXPECT_FALSE(watch.is_open());
}

TEST(dpll_watch, an_overrun_or_a_cut_datagram_is_a_loss_and_an_empty_socket_is_drained)
{
    EXPECT_TRUE(received_kind(-1, ENOBUFS, 8192) == Received::lost);
    EXPECT_TRUE(received_kind(9000, 0, 8192) == Received::lost);  // MSG_TRUNC: longer than the buffer
    EXPECT_TRUE(received_kind(8192, 0, 8192) == Received::datagram);
    EXPECT_TRUE(received_kind(0, 0, 8192) == Received::datagram);
    EXPECT_TRUE(received_kind(-1, EAGAIN, 8192) == Received::drained);
    EXPECT_TRUE(received_kind(-1, EBADF, 8192) == Received::drained);
}

TEST(dpll_watch, a_closed_watch_is_drained_and_reports_no_loss)
{
    int64_t lost_at = 0;
    DpllWatch watch{[](DeviceEvent, Device const&, int64_t) {}, Family{.id = DPLL_ID, .monitor_group = 5}};
    watch.on_ready(1);  // closed: drained at once, and no loss
    watch.set_on_loss([&lost_at](int64_t const now_ns) { lost_at = now_ns; });
    watch.on_ready(2);
    EXPECT_EQ(lost_at, int64_t{0});
}

TEST(dpll_client, the_kernels_devices_are_listed_and_read_back)
{
    DpllClient client;
    auto const opened = client.open();
    if (!opened) {
        if (opened.error() == std::errc::no_such_file_or_directory) {
            SKIP("this kernel has no dpll family");
        }
        SKIP("no generic netlink socket here");
    }
    EXPECT_TRUE(client.is_open());
    EXPECT_NE(client.family().id, uint16_t{0});
    auto const devices = client.devices();
    if (!devices && devices.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    if (!devices && devices.error() == std::errc::operation_not_permitted) {
        SKIP("the dpll family's requests need CAP_NET_ADMIN");
    }
    if (!devices) {
        EXPECT_EQ(devices.error().message(), std::string{"<a reply>"});  // the reason, in the failure
        return;
    }
    for (auto const& device : *devices) {
        auto const again = client.device(device.id);
        EXPECT_TRUE(again.has_value());
        EXPECT_TRUE(again && again->id == device.id && again->clock_id == device.clock_id);
    }
    auto const missing = client.device(0x7fff'fff0);
    EXPECT_FALSE(missing.has_value());
    EXPECT_TRUE(client.pins().has_value());

    DpllWatch watch{[](DeviceEvent, Device const&, int64_t) {}};
    auto const watching = watch.open();
    bool const refused_cleanly =
        !watching && (watching.error() == std::errc::not_supported || watching.error() == std::errc::operation_not_permitted);
    EXPECT_TRUE(watching.has_value() || refused_cleanly);
    if (!watching && !refused_cleanly) {
        EXPECT_EQ(watching.error().message(), std::string{"<joined>"});
    }
    if (watching) {
        EXPECT_TRUE(watch.fd() >= 0);
        EXPECT_EQ(watch.family().id, client.family().id);
        watch.on_ready(0);  // nothing pending: drains and returns
        EXPECT_EQ(watch.events(), uint64_t{0});
        watch.close();
        EXPECT_FALSE(watch.is_open());
    }
}

TEST(dpll_client, a_closed_client_answers_nothing)
{
    DpllClient client;
    EXPECT_FALSE(client.is_open());
    EXPECT_EQ(client.family().id, uint16_t{0});
    auto const refused = client.devices();
    EXPECT_TRUE(!refused && refused.error() == std::errc::bad_file_descriptor);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_dpll_test)
