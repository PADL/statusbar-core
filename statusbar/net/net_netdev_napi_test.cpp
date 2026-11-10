// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The netdev queue and NAPI builders against bytes checked by hand from linux/netlink.h,
// linux/genetlink.h and Linux 6.19's linux/netdev.h, and the parsers against replies framed as
// netdev_nl_queue_fill_one and netdev_nl_napi_fill_one write them. The expected bytes are little-endian.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_netdev_napi.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <span>
#    include <system_error>

namespace {

using namespace statusbar::net::netdev;

constexpr bool LITTLE = std::endian::native == std::endian::little;
constexpr uint16_t NETDEV_ID = 0x19;
constexpr uint32_t NAPI = 8197;  // 0x2005

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
/// NETDEV_CMD_QUEUE_GET's reply for ifindex 3's RX queue 0: id, type, ifindex, napi-id 8197, an empty xsk nest.
constexpr std::array<uint8_t, 56> QUEUE_REPLY{
    0x38, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x01, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x05, 0x20, 0x00, 0x00,
    0x04, 0x00, 0x07, 0x80,
};

/// NETDEV_CMD_NAPI_GET's reply for NAPI 8197: id, ifindex 3, irq 140, pid 1234, defer-hard-irqs 0,
/// gro-flush-timeout as an 8-octet uint, threaded busy-poll (2).
constexpr std::array<uint8_t, 80> NAPI_REPLY{
    0x50, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x01, 0x00, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x05, 0x20, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x03, 0x00, 0x8c, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0xd2, 0x04, 0x00, 0x00,
    0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
};
// clang-format on

/// `reply` with the octet at `at` replaced by `value`.
template <size_t N>
auto patched(std::array<uint8_t, N> reply, size_t const at, uint8_t const value) -> std::array<uint8_t, N>
{
    reply[at] = value;
    return reply;
}

}  // namespace

TEST(netdev_napi, queue_get_request)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // clang-format off
    constexpr std::array<uint8_t, 44> want{
        0x2c, 0x00, 0x00, 0x00, 0x19, 0x00, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_queue_get(out, NETDEV_ID, 3, 2, QueueType::tx, 9);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), want));
}

TEST(netdev_napi, napi_get_request)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // clang-format off
    constexpr std::array<uint8_t, 28> want{
        0x1c, 0x00, 0x00, 0x00, 0x19, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0b, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x05, 0x20, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_napi_get(out, NETDEV_ID, NAPI, 10);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), want));
}

TEST(netdev_napi, napi_set_carries_the_threaded_mode)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // clang-format off
    constexpr std::array<uint8_t, 36> busy_poll{
        0x24, 0x00, 0x00, 0x00, 0x19, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0e, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x05, 0x20, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_napi_set_threaded(out, NETDEV_ID, NAPI, NapiThreaded::busy_poll, 11);
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), busy_poll));
    auto const disabled = build_napi_set_threaded(out, NETDEV_ID, NAPI, NapiThreaded::disabled, 11);
    EXPECT_TRUE(disabled && *disabled == busy_poll.size() && out[32] == 0);
}

TEST(netdev_napi, a_short_buffer_is_refused)
{
    std::array<uint8_t, 30> small{};
    EXPECT_FALSE(build_queue_get(small, NETDEV_ID, 3, 0, QueueType::rx, 1).has_value());
    EXPECT_FALSE(build_napi_set_threaded(small, NETDEV_ID, NAPI, NapiThreaded::busy_poll, 1).has_value());
}

TEST(netdev_napi, a_queue_reply_names_its_napi)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const queue = parse_queue(QUEUE_REPLY, NETDEV_ID);
    EXPECT_TRUE(queue.has_value());
    EXPECT_TRUE(queue && queue->id == 0 && queue->ifindex == 3 && queue->type == QueueType::rx);
    EXPECT_TRUE(queue && queue->napi_id == NAPI);
}

TEST(netdev_napi, a_queue_without_napi_has_none)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // The napi-id attribute retyped to an unknown one (dmabuf, 5) and so skipped.
    auto const queue = parse_queue(patched(QUEUE_REPLY, 46, 0x05), NETDEV_ID);
    EXPECT_TRUE(queue && !queue->napi_id);
}

TEST(netdev_napi, a_malformed_queue_reply_is_refused)
{
    EXPECT_FALSE(parse_queue(QUEUE_REPLY, NETDEV_ID + 1).has_value());
    EXPECT_FALSE(parse_queue(patched(QUEUE_REPLY, 16, 0x0b), NETDEV_ID).has_value());    // napi-get's command
    EXPECT_FALSE(parse_queue(patched(QUEUE_REPLY, 30, 0x09), NETDEV_ID).has_value());    // no type
    EXPECT_FALSE(parse_queue(patched(QUEUE_REPLY, 32, 0x02), NETDEV_ID).has_value());    // type past tx
    EXPECT_FALSE(parse_queue(patched(QUEUE_REPLY, 44, 0x10), NETDEV_ID).has_value());    // overruns
    EXPECT_FALSE(parse_queue(std::span{QUEUE_REPLY}.first(18), NETDEV_ID).has_value());  // truncated
}

TEST(netdev_napi, a_napi_reply_names_its_kthread_and_mode)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const napi = parse_napi(NAPI_REPLY, NETDEV_ID);
    EXPECT_TRUE(napi.has_value());
    EXPECT_TRUE(napi && napi->id == NAPI && napi->ifindex == 3);
    EXPECT_TRUE(napi && napi->pid == 1234u && napi->threaded == NapiThreaded::busy_poll);
}

TEST(netdev_napi, an_unknown_threaded_mode_is_left_unset)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const napi = parse_napi(patched(NAPI_REPLY, 76, 0x09), NETDEV_ID);
    EXPECT_TRUE(napi && !napi->threaded && napi->pid == 1234u);
}

TEST(netdev_napi, a_malformed_napi_reply_is_refused)
{
    EXPECT_FALSE(parse_napi(NAPI_REPLY, NETDEV_ID + 1).has_value());
    EXPECT_FALSE(parse_napi(patched(NAPI_REPLY, 22, 0x09), NETDEV_ID).has_value());  // no id
    EXPECT_FALSE(parse_napi(patched(NAPI_REPLY, 44, 0x06), NETDEV_ID).has_value());  // pid of 2 octets
    EXPECT_FALSE(parse_napi(std::span{NAPI_REPLY}.first(40), NETDEV_ID).has_value());
}

TEST(netdev_napi, the_client_answers_for_a_missing_device)
{
    // Host-dependent: skipped where netlink or the netdev family is missing.
    NapiClient client;
    if (!client.open().has_value()) {
        SKIP("netlink or the netdev family is not available here");
    }
    EXPECT_FALSE(client.queue_napis(0x7fff'fff0, 0).has_value());
    EXPECT_FALSE(client.napi(0x7fff'fff0).has_value());
    EXPECT_FALSE(set_queue_threaded(client, 0x7fff'fff0, 0, NapiThreaded::busy_poll, 0).has_value());
}

TEST(netdev_napi, a_cpu_out_of_range_is_refused)
{
    EXPECT_EQ(pin_napi_thread(1, -1).error(), std::make_error_code(std::errc::invalid_argument));
    EXPECT_EQ(pin_napi_thread(1, 1 << 20).error(), std::make_error_code(std::errc::invalid_argument));
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netdev_napi_test)
