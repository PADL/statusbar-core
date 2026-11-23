// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The netlink framing against bytes laid out by hand from linux/netlink.h
// (host byte order: the vectors are little-endian), and netlink::Socket
// against the kernel's RTM_GETLINK, which needs no privilege.

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/net/net_netlink.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

// clang-format off
// clang-format on

}  // namespace

#if defined(__linux__)

namespace {

/// RTM_GETLINK of `ifindex` asking for an ack: a Socket::request builder.
auto get_link(int const ifindex)
{
    return [ifindex](std::span<uint8_t> const out, uint32_t const seq) {
        constexpr size_t LENGTH = netlink::MESSAGE_HEADER + sizeof(ifinfomsg);
        MutableBuffer buffer{out};
        BufferSerializerBuilder b{buffer};
        netlink::put_header(b, LENGTH, RTM_GETLINK, netlink::FLAG_REQUEST | netlink::FLAG_ACK, seq);
        ifinfomsg info{};
        info.ifi_family = AF_UNSPEC;
        info.ifi_index = ifindex;
        b.append(make_const_span(info));
        return netlink::finish(b, LENGTH);
    };
}

}  // namespace

TEST(netlink_socket, a_request_hands_its_replies_over_and_ends_at_the_ack)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    EXPECT_TRUE(socket.is_open());
    EXPECT_NE(socket.port_id(), uint32_t{0});
    std::array<uint8_t, 8192> buffer{};
    int links = 0;
    auto const status = socket.request(buffer, get_link(1), [&](std::span<uint8_t const>, uint16_t const type) {
        links += type == RTM_NEWLINK ? 1 : 0;
        return success();
    });
    if (!status && (status.error() == std::errc::timed_out || status.error() == std::errc::operation_not_supported)) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(links, 1);
    EXPECT_TRUE(socket.last_message().empty());
    socket.close();
    EXPECT_FALSE(socket.is_open());
}

TEST(netlink_socket, the_kernels_refusal_is_the_result)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    std::array<uint8_t, 8192> buffer{};
    int replies = 0;
    auto const status = socket.request(buffer, get_link(0x7FFFFFF0), [&](std::span<uint8_t const>, uint16_t) {
        ++replies;
        return success();
    });
    if (!status && status.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    EXPECT_TRUE(!status && status.error() == std::errc::no_such_device);
    EXPECT_EQ(replies, 0);
}

TEST(netlink_socket, a_reply_the_caller_refuses_ends_the_request_and_the_next_one_is_clean)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    std::array<uint8_t, 8192> buffer{};
    auto const status = socket.request(buffer, get_link(1), [](std::span<uint8_t const>, uint16_t) -> Status {
        return failure(std::make_error_code(std::errc::bad_message));
    });
    if (!status && status.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    EXPECT_TRUE(!status && status.error() == std::errc::bad_message);
    int links = 0;  // the refused request's ack, still queued, is skipped: it is not this request's
    auto const next = socket.request(buffer, get_link(1), [&](std::span<uint8_t const>, uint16_t const type) {
        links += type == RTM_NEWLINK ? 1 : 0;
        return success();
    });
    EXPECT_TRUE(next.has_value());
    EXPECT_EQ(links, 1);
}

TEST(netlink_socket, a_reply_that_does_not_fit_is_message_size_after_the_attempts)
{
    netlink::Socket socket;
    if (!socket.open(NETLINK_ROUTE)) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    std::array<uint8_t, 64> small{};  // an RTM_NEWLINK for lo is hundreds of octets
    auto const status =
        socket.request(std::span<uint8_t>{small}, get_link(1), [](std::span<uint8_t const>, uint16_t) { return success(); });
    if (!status && status.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    EXPECT_TRUE(!status && status.error() == std::errc::message_size);
}

TEST(netlink_socket, a_closed_socket_and_a_failed_builder_send_nothing)
{
    netlink::Socket socket;
    std::array<uint8_t, 64> buffer{};
    auto const none = [](std::span<uint8_t const>, uint16_t) { return success(); };
    auto const closed = socket.request(buffer, get_link(1), none);
    EXPECT_TRUE(!closed && closed.error() == std::errc::bad_file_descriptor);
    EXPECT_FALSE(socket.request(buffer, get_link(1)).has_value());
    if (!socket.open(NETLINK_ROUTE)) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    auto const refused = socket.request(
        buffer,
        [](std::span<uint8_t>, uint32_t) -> StatusValue<size_t> {
            return failure(std::make_error_code(std::errc::invalid_argument));
        },
        none);
    EXPECT_TRUE(!refused && refused.error() == std::errc::invalid_argument);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netlink_functional_test)
