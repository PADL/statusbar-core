// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_socket.hpp"
#include "statusbar/test/test.hpp"

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

TEST_MAIN(statusbar_net, net_group_membership_test)
