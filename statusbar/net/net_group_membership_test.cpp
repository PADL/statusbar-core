// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_address.hpp"
#include "statusbar/net/net_socket.hpp"
#include "statusbar/test/test.hpp"

#include <poll.h>

#include <net/if.h>

using namespace statusbar;
using namespace statusbar::net;

// Joining on loopback needs no privilege and no hardware, so the whole path -
// socket, setsockopt, the ip_mreqn the platform wants - is exercised here.
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

// RFC 4607 Section 1: 232.0.0.0/8 is IPv4's source-specific range.
TEST(group_membership, only_232_slash_8_is_source_specific)
{
    EXPECT_TRUE(is_source_specific_group(statusbar::ip::IPv4Address{232, 0, 0, 1}));
    EXPECT_TRUE(is_source_specific_group(statusbar::ip::IPv4Address{232, 255, 255, 255}));
    EXPECT_FALSE(is_source_specific_group(statusbar::ip::IPv4Address{239, 69, 1, 2}));
    EXPECT_FALSE(is_source_specific_group(statusbar::ip::IPv4Address{233, 0, 0, 1}));
}

TEST(group_membership, a_source_specific_join_on_loopback_is_held)
{
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }
    auto membership =
        open_source_group_membership(statusbar::ip::IPv4Address{232, 69, 1, 2}, statusbar::ip::IPv4Address{127, 0, 0, 1}, lo);
    EXPECT_TRUE(membership.has_value());
}

TEST(group_membership, a_source_specific_join_needs_a_group_and_a_unicast_source)
{
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }
    statusbar::ip::IPv4Address const source{127, 0, 0, 1};
    EXPECT_FALSE(open_source_group_membership(statusbar::ip::IPv4Address{192, 168, 1, 1}, source, lo).has_value());
    EXPECT_FALSE(
        open_source_group_membership(statusbar::ip::IPv4Address{232, 69, 1, 3}, statusbar::ip::IPv4Address{239, 1, 1, 1}, lo)
            .has_value());
    EXPECT_FALSE(
        open_source_group_membership(statusbar::ip::IPv4Address{232, 69, 1, 3}, statusbar::ip::IPv4Address{}, lo).has_value());
}

#if defined(__linux__)
namespace {

/// A UDP socket bound to `group`:`port`, joined on loopback for `source` alone, non-blocking.
auto source_joined_socket(statusbar::ip::IPv4Address const& group, statusbar::ip::IPv4Address const& source, uint16_t const port)
    -> StatusValue<FileDescriptor>
{
    auto socket = make_udp_socket();
    if (!socket || !set_reuse_addr(socket->get()) || !set_nonblocking(socket->get())) {
        return failure(std::errc::io_error);
    }
    auto const local = SocketAddress::ipv4(group.to_uint32(), port);
    if (::bind(socket->get(), local.sockaddr(), local.length()) != 0) {
        return failure(errno_code());
    }
    if (auto joined = join_source_group(socket->get(), group, source, ::if_nametoindex("lo")); !joined) {
        return failure(joined.error());
    }
    return socket;
}

/// Send one datagram from 127.0.0.1 (bound: the route would pick the host's address) to `group`:`port` out of
/// loopback, looped back to this host's members.
auto send_on_loopback(statusbar::ip::IPv4Address const& group, uint16_t const port) -> bool
{
    auto socket = make_udp_socket();
    if (!socket || !set_multicast_send(socket->get(), ::if_nametoindex("lo"), 1, true)) {
        return false;
    }
    auto const from = SocketAddress::ipv4_loopback(0);
    if (::bind(socket->get(), from.sockaddr(), from.length()) != 0) {
        return false;
    }
    auto const to = SocketAddress::ipv4(group.to_uint32(), port);
    char const byte = 1;
    return ::sendto(socket->get(), &byte, 1, 0, to.sockaddr(), to.length()) == 1;
}

/// Whether a datagram is waiting on `fd`, within about 100 ms.
auto received(int const fd) -> bool
{
    pollfd ready{.fd = fd, .events = POLLIN, .revents = 0};
    return ::poll(&ready, 1, 100) == 1;
}

}  // namespace

// The join is the kernel's filter: a member for 127.0.0.1 hears it, a member for another source does not.
TEST(group_membership, a_source_specific_member_hears_its_source_alone)
{
    statusbar::ip::IPv4Address const group{232, 69, 1, 9};
    constexpr uint16_t PORT = 45'232;
    auto ours = source_joined_socket(group, statusbar::ip::IPv4Address{127, 0, 0, 1}, PORT);
    auto theirs = source_joined_socket(group, statusbar::ip::IPv4Address{127, 0, 0, 2}, PORT);
    EXPECT_TRUE(ours.has_value());
    EXPECT_TRUE(theirs.has_value());
    if (!ours || !theirs || !send_on_loopback(group, PORT)) {
        return;  // a host whose loopback carries no multicast: the joins above are what is checked
    }
    EXPECT_TRUE(received(ours->get()));
    EXPECT_FALSE(received(theirs->get()));
}
#endif

TEST_MAIN(statusbar_net, net_group_membership_test)
