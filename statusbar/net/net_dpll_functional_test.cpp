// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The dpll generic-netlink framing against bytes laid out by hand from
// linux/genetlink.h and linux/dpll.h, the parsers against replies framed as
// the kernel's ctrl_fill_info(), dpll_device_get_one() and
// dpll_cmd_pin_get_one() write them (the pin's parents, labels and frequency
// ranges as nests, a pad before each u64), and, on Linux, the client and the
// watch against the running kernel. Netlink is host byte order: the vectors
// are little-endian.

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

/// The id a kernel happened to give the dpll family.
constexpr uint16_t DPLL_ID = 0x1a;

// clang-format off

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

#if defined(__linux__)

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

namespace {

/// Set a pin to the frequency it reports, which changes nothing on the
/// device, and check the answer against the order the kernel decides in
/// (dpll_pin_freq_set): a frequency outside the pin's own supported ranges is
/// refused with EINVAL before anything else is looked at, and a pin may well
/// report one (a mux or SyncE pin with no ranges at all, an output at 0 Hz);
/// then a pin whose driver cannot set a frequency is refused with EOPNOTSUPP;
/// only then is the unchanged frequency acknowledged.
auto expect_own_frequency_answered_as_the_kernel_does(DpllClient& client, Pin const& pin) -> void
{
    auto const answer = client.set_frequency(pin.id, *pin.frequency_hz);
    if (!pin.supports_frequency(*pin.frequency_hz)) {
        EXPECT_TRUE(!answer && answer.error() == std::errc::invalid_argument);
        return;
    }
    EXPECT_TRUE(answer.has_value() || answer.error() == std::errc::operation_not_supported);
}

}  // namespace

TEST(dpll_client, the_kernels_pins_are_listed_and_read_back)
{
    DpllClient client;
    auto const opened = client.open();
    if (!opened) {
        SKIP("no dpll family, or no generic netlink socket here");
    }
    auto const pins = client.pins();
    if (!pins && pins.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    if (!pins && pins.error() == std::errc::operation_not_permitted) {
        SKIP("the dpll family's requests need CAP_NET_ADMIN");
    }
    if (!pins) {
        EXPECT_EQ(pins.error().message(), std::string{"<a reply>"});  // the reason, in the failure
        return;
    }
    for (auto const& pin : *pins) {
        auto const again = client.pin(pin.id);
        EXPECT_TRUE(again.has_value());
        EXPECT_TRUE(again && again->id == pin.id && again->clock_id == pin.clock_id && again->board_label == pin.board_label);
        // Every pin is wired one way or the other, and knows its devices by id.
        EXPECT_TRUE(!pin.on_devices.empty() || !pin.on_pins.empty());
        for (auto const& on : pin.on_devices) {
            EXPECT_TRUE(client.device(on.device_id).has_value());
        }
        if (pin.frequency_hz) {
            expect_own_frequency_answered_as_the_kernel_does(client, pin);
        }
    }
    auto const missing = client.pin(0x7fff'fff0);
    EXPECT_FALSE(missing.has_value());
    auto const unwired = client.set_pin(0x7fff'fff0, PinChange{.frequency_hz = FREQUENCY_1_HZ});
    EXPECT_FALSE(unwired.has_value());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_dpll_functional_test)
