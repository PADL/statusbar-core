// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_socket.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <system_error>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

using namespace statusbar;
using namespace statusbar::net;

TEST(multicast_all, a_receiver_turns_host_wide_delivery_off)
{
    int const fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(fd >= 0);
    EXPECT_TRUE(set_multicast_all(fd, false).has_value());
#if defined(IP_MULTICAST_ALL)
    int value = -1;
    socklen_t len = sizeof(value);
    EXPECT_EQ(::getsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &value, &len), 0);
    EXPECT_EQ(value, 0);
    EXPECT_TRUE(set_multicast_all(fd, true).has_value());
    EXPECT_EQ(::getsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &value, &len), 0);
    EXPECT_EQ(value, 1);
#else
    // No such option here: the stack filters per socket, so "off" is the
    // state in force and "on" cannot be had.
    auto const on = set_multicast_all(fd, true);
    EXPECT_FALSE(on.has_value());
    if (!on) {
        EXPECT_TRUE((on.error() == std::error_code{ENOPROTOOPT, std::system_category()}));
    }
#endif
    (void)::close(fd);
}

TEST(pktinfo, a_datagram_is_known_by_the_address_and_interface_it_arrived_on)
{
    // A receiver bound to INADDR_ANY on a port, asked for IP_PKTINFO; a
    // sender on loopback. The control message names 127.0.0.1 and the
    // loopback interface, and destined_for() reads exactly that.
    int const rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    int const tx = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(rx >= 0 && tx >= 0);
    EXPECT_TRUE(set_receive_pktinfo(rx).has_value());
    sockaddr_in any = ipv4_sockaddr_in(statusbar::ip::IPv4Address{0, 0, 0, 0}, 0);
    EXPECT_EQ(
        ::bind(rx, reinterpret_cast<sockaddr const*>(&any), sizeof(any)),
        0);  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    socklen_t any_len = sizeof(any);
    EXPECT_EQ(
        ::getsockname(rx, reinterpret_cast<sockaddr*>(&any), &any_len), 0);  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    uint16_t const port = ipv4_endpoint(any).port;
    EXPECT_TRUE(port != 0);

    statusbar::ip::IPv4Address const loopback{127, 0, 0, 1};
    sockaddr_in const to = ipv4_sockaddr_in(loopback, port);
    std::array<uint8_t, 4> const payload{0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(
        ::sendto(tx, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr const*>(&to), sizeof(to)),
        4);  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    std::array<uint8_t, 64> buffer{};
    alignas(cmsghdr) std::array<uint8_t, CMSG_SPACE(sizeof(in_pktinfo)) + CMSG_SPACE(64)> control{};
    iovec iov{.iov_base = buffer.data(), .iov_len = buffer.size()};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();
    ssize_t const got = ::recvmsg(rx, &msg, 0);
    EXPECT_EQ(got, 4);

    auto const info = pktinfo_of(msg);
    EXPECT_TRUE(info.has_value());
    unsigned int lo_index = if_nametoindex("lo");
    if (lo_index == 0) {
        lo_index = if_nametoindex("lo0");
    }
    EXPECT_TRUE(lo_index != 0);
    EXPECT_TRUE(destined_for(msg, loopback, 0));
    EXPECT_TRUE(destined_for(msg, loopback, lo_index));
    EXPECT_FALSE(destined_for(msg, statusbar::ip::IPv4Address{127, 0, 0, 2}, 0));  // another address
    EXPECT_FALSE(destined_for(msg, loopback, lo_index + 1000));                    // another interface

    // Without the control message nothing is accepted.
    msghdr bare{};
    EXPECT_FALSE(pktinfo_of(bare).has_value());
    EXPECT_FALSE(destined_for(bare, loopback, 0));

    (void)::close(rx);
    (void)::close(tx);
}

TEST(group_membership, a_group_is_joined_on_the_named_interface_and_held)
{
#if defined(__linux__)
    auto const lo = ::if_nametoindex("lo");
#else
    auto const lo = ::if_nametoindex("lo0");  // what Darwin and the BSDs call it
#endif
    EXPECT_TRUE(lo > 0);
    if (lo == 0) {
        return;
    }
    auto membership = open_group_membership(statusbar::ip::IPv4Address{239, 69, 1, 2}, lo);
    EXPECT_TRUE(membership.has_value());
    if (membership) {
        EXPECT_TRUE(membership->valid());
    }
}

// The membership lasts exactly as long as the value: an AF_XDP receiver has no
// kernel socket on the group, so this is the only thing telling the switch to
// keep forwarding it.
TEST(group_membership, letting_the_membership_go_closes_its_socket)
{
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }
    int borrowed = -1;
    {
        auto membership = open_group_membership(statusbar::ip::IPv4Address{239, 69, 1, 3}, lo);
        EXPECT_TRUE(membership.has_value());
        if (!membership) {
            return;
        }
        borrowed = membership->get();
        EXPECT_TRUE(borrowed >= 0);
    }
    // The descriptor is closed, so asking the kernel about it fails. (A later
    // open may reuse the number, which is why the assertion is on the call and
    // not on the number.)
    EXPECT_TRUE(::fcntl(borrowed, F_GETFD) == -1);
}

// A unicast address is not a group. The kernel refuses it, and the refusal is
// reported rather than a socket with no membership being handed back.
TEST(group_membership, an_address_that_is_not_a_group_is_refused)
{
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }
    auto const membership = open_group_membership(statusbar::ip::IPv4Address{192, 168, 1, 1}, lo);
    EXPECT_FALSE(membership.has_value());
}

// An interface index nothing answers to is refused too.
TEST(group_membership, an_interface_that_is_not_there_is_refused)
{
    constexpr unsigned int NO_SUCH_INTERFACE = 0x7FFFFFFF;
    auto const membership = open_group_membership(statusbar::ip::IPv4Address{239, 69, 1, 4}, NO_SUCH_INTERFACE);
    EXPECT_FALSE(membership.has_value());
}

//
// Source-specific groups (RFC 4607)
//

// A join is refused before the kernel sees it when the group is not a group,
// or the source is not a host: silence on the socket later would be the only
// other symptom.
TEST(source_group_membership, a_bad_group_or_source_is_refused_as_invalid_argument)
{
    using statusbar::ip::IPv4Address;
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    auto const invalid = std::make_error_code(std::errc::invalid_argument);
    auto const unicast_group = join_source_group(socket->get(), IPv4Address{192, 0, 2, 9}, IPv4Address{192, 0, 2, 1}, 0);
    EXPECT_FALSE(unicast_group.has_value());
    EXPECT_EQ(unicast_group.error(), invalid);
    auto const multicast_source = join_source_group(socket->get(), IPv4Address{232, 1, 2, 3}, IPv4Address{239, 0, 0, 1}, 0);
    EXPECT_FALSE(multicast_source.has_value());
    EXPECT_EQ(multicast_source.error(), invalid);
    auto const unspecified_source = join_source_group(socket->get(), IPv4Address{232, 1, 2, 3}, IPv4Address{0, 0, 0, 0}, 0);
    EXPECT_FALSE(unspecified_source.has_value());
    EXPECT_EQ(unspecified_source.error(), invalid);
    auto const membership = open_source_group_membership(IPv4Address{192, 0, 2, 9}, IPv4Address{192, 0, 2, 1}, 0);
    EXPECT_FALSE(membership.has_value());
}

// A real INCLUDE-mode join on the loopback interface, held by its socket. A
// stack that cannot take one on loopback says so with an errno, which is
// reported rather than failed: the join itself is the kernel's to grant.
TEST(source_group_membership, a_source_specific_group_is_joined_on_loopback_and_held)
{
    using statusbar::ip::IPv4Address;
#if defined(__linux__)
    auto const lo = ::if_nametoindex("lo");
#else
    auto const lo = ::if_nametoindex("lo0");
#endif
    if (lo == 0) {
        SKIP("no loopback interface by either name");
    }
    auto membership = open_source_group_membership(IPv4Address{232, 1, 2, 3}, IPv4Address{192, 0, 2, 1}, lo);
    if (!membership) {
        auto const err = membership.error();
        bool const platform_said_no = err == std::make_error_code(std::errc::address_not_available) ||
            err == std::make_error_code(std::errc::no_such_device) ||
            err == std::make_error_code(std::errc::operation_not_permitted) ||
            err == std::make_error_code(std::errc::operation_not_supported);
        if (platform_said_no) {
            SKIP("the stack refused a source-specific join on loopback");
        }
    }
    EXPECT_TRUE(membership.has_value());
    if (membership) {
        EXPECT_TRUE(membership->valid());
    }
}

TEST_MAIN(statusbar_net, net_group_membership_functional_test)
