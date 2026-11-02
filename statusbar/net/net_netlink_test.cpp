// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// netlink::end_status against crafted messages, and netlink::Socket::request against the kernel's
// RTM_GETLINK (unprivileged; skipped where NETLINK_ROUTE is unavailable). The bytes are little-endian.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/net/net_netlink.hpp"

#    include <array>
#    include <bit>
#    include <cstdint>
#    include <span>
#    include <string>
#    include <system_error>

#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>

namespace {

using namespace statusbar;
using namespace statusbar::net;

constexpr bool LITTLE = std::endian::native == std::endian::little;

/// RTM_GETLINK of `ifindex` asking for an ack, as a Socket::request builder.
auto get_link(int const ifindex)
{
    return [ifindex](std::span<uint8_t> const out, uint32_t const seq) {
        constexpr size_t LENGTH = netlink::MESSAGE_HEADER + 16;
        MutableBuffer buffer{out};
        BufferSerializerBuilder b{buffer};
        netlink::put_header(b, LENGTH, RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
        b.append(uint8_t{AF_UNSPEC}).append(uint8_t{0}).append(uint16_t{0}).append(int32_t{ifindex});
        b.append(uint32_t{0}).append(uint32_t{0});
        return netlink::finish(b, LENGTH);
    };
}

}  // namespace

TEST(netlink_end_status, an_ack_a_done_and_anything_else)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 36> error{
        0x24, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xea, 0xff, 0xff, 0xff,  // -EINVAL
        0x10, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    std::array<uint8_t, 20> done{
        0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    std::string text;
    auto const refused = netlink::end_status(error, NLMSG_ERROR, NLM_F_CAPPED, 16, text);
    EXPECT_TRUE(refused && !*refused && refused->error() == std::errc::invalid_argument);
    error[16] = 0;
    error[17] = 0;
    error[18] = 0;
    error[19] = 0;
    auto const acked = netlink::end_status(error, NLMSG_ERROR, NLM_F_CAPPED, 16, text);
    EXPECT_TRUE(acked && acked->has_value());
    auto const complete = netlink::end_status(done, NLMSG_DONE, NLM_F_MULTI, 16, text);
    EXPECT_TRUE(complete && complete->has_value());
    EXPECT_FALSE(netlink::end_status(done, RTM_NEWLINK, 0, 16, text).has_value());
}

TEST(netlink_socket, a_request_hands_its_replies_over_and_ends_at_the_ack)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        return;
    }
    std::array<uint8_t, 8192> buffer{};
    int links = 0;
    auto const status = socket.request(buffer, get_link(1), [&](std::span<uint8_t const>, uint16_t const type) {
        links += type == RTM_NEWLINK ? 1 : 0;
        return success();
    });
    if (!status && (status.error() == std::errc::timed_out || status.error() == std::errc::operation_not_supported)) {
        return;  // a sandbox that opens the socket but answers nothing
    }
    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(links, 1);
    EXPECT_TRUE(socket.last_message().empty());
}

TEST(netlink_socket, the_kernels_refusal_is_the_result)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        return;
    }
    std::array<uint8_t, 8192> buffer{};
    int replies = 0;
    auto const status = socket.request(buffer, get_link(0x7FFFFFF0), [&](std::span<uint8_t const>, uint16_t) {
        ++replies;
        return success();
    });
    EXPECT_TRUE(!status && status.error() == std::errc::no_such_device);
    EXPECT_EQ(replies, 0);
}

TEST(netlink_socket, a_reply_refused_by_the_caller_ends_the_request)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        return;
    }
    std::array<uint8_t, 8192> buffer{};
    auto const status = socket.request(buffer, get_link(1), [](std::span<uint8_t const>, uint16_t) -> Status {
        return failure(std::make_error_code(std::errc::bad_message));
    });
    EXPECT_TRUE(!status && status.error() == std::errc::bad_message);
    int links = 0;  // the refused request's ack, still queued, is not the next one's
    auto const next = socket.request(buffer, get_link(1), [&](std::span<uint8_t const>, uint16_t const type) {
        links += type == RTM_NEWLINK ? 1 : 0;
        return success();
    });
    EXPECT_TRUE(next.has_value());
    EXPECT_EQ(links, 1);
}

TEST(netlink_socket, a_closed_socket_and_a_failed_builder_send_nothing)
{
    netlink::Socket socket;
    std::array<uint8_t, 64> buffer{};
    auto const none = [](std::span<uint8_t const>, uint16_t) { return success(); };
    auto const closed = socket.request(buffer, get_link(1), none);
    EXPECT_TRUE(!closed && closed.error() == std::errc::bad_file_descriptor);
    EXPECT_TRUE(!socket.request(buffer, get_link(1)).has_value());  // the ack-only form, as closed
    auto const refused = socket.request(
        buffer,
        [](std::span<uint8_t>, uint32_t) -> StatusValue<size_t> {
            return failure(std::make_error_code(std::errc::invalid_argument));
        },
        none);
    EXPECT_TRUE(!refused && refused.error() == std::errc::invalid_argument);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netlink_test)
