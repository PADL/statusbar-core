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
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include "statusbar/buffer/file_descriptor.hpp"

#    include <fcntl.h>

#    include <sys/socket.h>
#    include <sys/types.h>
#endif

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

TEST(dpll, a_dump_sent_again_forgets_the_devices_of_the_attempt_before)
{
    DeviceDump dump;
    EXPECT_TRUE(dump.take(DEVICE_REPLY, DPLL_ID, DPLL_ID).has_value());
    EXPECT_TRUE(dump.take(DEVICE_REPLY, uint16_t{0x10}, DPLL_ID).has_value());  // another family: ignored
    EXPECT_EQ(dump.devices.size(), size_t{1});
    // The socket's second attempt builds the request again, and the dump
    // starts over: one device, not the first attempt's and the second's.
    dump.restart();
    EXPECT_TRUE(dump.take(DEVICE_REPLY, DPLL_ID, DPLL_ID).has_value());
    EXPECT_EQ(dump.devices.size(), size_t{1});
    // Without the restart the same reply read twice is two devices.
    EXPECT_TRUE(dump.take(DEVICE_REPLY, DPLL_ID, DPLL_ID).has_value());
    EXPECT_EQ(dump.devices.size(), size_t{2});
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

/// A loss the test saw.
struct SeenLoss
{
    Loss loss;
    std::error_code error;
    int64_t now_ns;
};

/// A non-blocking datagram pair: the watch reads `watched`, the test writes `feed`.
struct DatagramPair
{
    FileDescriptor watched{};
    FileDescriptor feed{};
};

[[nodiscard]] auto a_datagram_pair() -> DatagramPair
{
    std::array<int, 2> fds{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, fds.data()) != 0) {
        return {};
    }
    return {.watched = FileDescriptor{fds[0]}, .feed = FileDescriptor{fds[1]}};
}

TEST(dpll_watch, a_truncated_notification_is_a_loss_the_caller_is_told_of)
{
    auto pair = a_datagram_pair();
    EXPECT_TRUE(pair.watched.valid() && pair.feed.valid());
    if (!pair.watched.valid()) {
        return;
    }
    int events = 0;
    std::vector<SeenLoss> losses;
    DpllWatch watch{
        [&](DeviceEvent, Device const&, int64_t) { ++events; }, Family{.id = DPLL_ID, .monitor_group = 5}, std::move(pair.watched)};
    watch.on_loss(
        [&](Loss const loss, std::error_code const error, int64_t const now_ns) { losses.push_back({loss, error, now_ns}); });

    // A notification, then one larger than the watch's buffer, then another notification.
    std::vector<uint8_t> const too_big(9000, 0);
    EXPECT_TRUE(::send(pair.feed.get(), CHANGE_NOTIFICATION.data(), CHANGE_NOTIFICATION.size(), 0) > 0);
    auto const sent_big = ::send(pair.feed.get(), too_big.data(), too_big.size(), 0);
    if (sent_big < 0) {
        SKIP("this host's datagram sockets refuse a 9000-byte message");
    }
    EXPECT_TRUE(::send(pair.feed.get(), CHANGE_NOTIFICATION.data(), CHANGE_NOTIFICATION.size(), 0) > 0);
    watch.on_ready(777);
    // Both notifications were handed on; the big one was dropped whole and said so.
    EXPECT_EQ(events, 2);
    EXPECT_EQ(watch.events(), uint64_t{2});
    EXPECT_EQ(watch.losses(), uint64_t{1});
    EXPECT_EQ(losses.size(), size_t{1});
    if (losses.size() == 1) {
        EXPECT_TRUE(losses[0].loss == Loss::truncated);
        EXPECT_FALSE(static_cast<bool>(losses[0].error));
        EXPECT_EQ(losses[0].now_ns, int64_t{777});
    }
    // Drained, not failed: the reactor keeps the watch.
    EXPECT_FALSE(watch.finished());
}

TEST(dpll_watch, a_lasting_socket_error_finishes_the_watch_and_is_reported)
{
    FileDescriptor not_a_socket{::open("/dev/null", O_RDONLY)};
    EXPECT_TRUE(not_a_socket.valid());
    std::vector<SeenLoss> losses;
    DpllWatch watch{[](DeviceEvent, Device const&, int64_t) {}, Family{.id = DPLL_ID, .monitor_group = 5}, std::move(not_a_socket)};
    uint64_t silent = 0;
    // Unset, a loss is counted and nothing more.
    watch.on_ready(1);
    EXPECT_TRUE(watch.finished());
    EXPECT_EQ(watch.losses(), uint64_t{1});
    EXPECT_EQ(losses.size(), silent);

    FileDescriptor another{::open("/dev/null", O_RDONLY)};
    DpllWatch told{[](DeviceEvent, Device const&, int64_t) {}, Family{.id = DPLL_ID, .monitor_group = 5}, std::move(another)};
    told.on_loss(
        [&](Loss const loss, std::error_code const error, int64_t const now_ns) { losses.push_back({loss, error, now_ns}); });
    told.on_ready(2);
    EXPECT_TRUE(told.finished());
    EXPECT_EQ(losses.size(), size_t{1});
    if (losses.size() == 1) {
        EXPECT_TRUE(losses[0].loss == Loss::failed);
        EXPECT_TRUE(losses[0].error == std::errc::not_a_socket);  // the socket's errno, as a condition
        EXPECT_EQ(losses[0].now_ns, int64_t{2});
    }
    // close() takes the failure with it, so open() can start the watch over.
    told.close();
    EXPECT_FALSE(told.finished());
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
