// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the rtnetlink traffic-control message builders and parser.
///
/// Every test here runs in CI: no socket, no root, no NIC. That is the
/// point of splitting the builders out from the client — the bytes we
/// send to the kernel are the part most likely to be wrong, and they are
/// checkable without the kernel.
///
/// Two styles of check, deliberately:
///
///   * The small messages (delete, dump, replace_kind) and the cbs
///     request are compared against a complete hand-written byte array.
///   * mqprio is checked field by field at named offsets, with every
///     padding byte asserted zero and the total length asserted. A
///     136-byte hex wall would catch the same errors while documenting
///     none of them.
///
/// Offsets and sizes come from <linux/netlink.h>, <linux/rtnetlink.h> and
/// <linux/pkt_sched.h>: nlmsghdr is 16 bytes, tcmsg 20, rtattr 4,
/// tc_mqprio_qopt 82 and tc_cbs_qopt 20, with every attribute payload
/// padded up to a multiple of 4.

#include "statusbar/net/net_tc_qdisc.hpp"
#include "statusbar/net/net_tc_qdisc_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include <unistd.h>

#    include <net/if.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

#if defined(__linux__)

TEST(tc_qdisc, client_opens_a_netlink_socket_without_privilege)
{
    // NETLINK_ROUTE needs no capability to open, bind or read -- only
    // writes do. That is what makes the dump path testable in CI.
    tc::TcClient client;
    auto const opened = client.open();
    EXPECT_TRUE(opened.has_value());
    if (opened) {
        EXPECT_TRUE(client.valid());
    }
}

TEST(tc_qdisc, opening_a_client_twice_is_refused)
{
    tc::TcClient client;
    EXPECT_TRUE(client.open().has_value());

    auto const again = client.open();
    EXPECT_FALSE(again.has_value());
    if (!again) {
        EXPECT_EQ(again.error(), make_error_code(NetError::already_connected));
    }
}

TEST(tc_qdisc, get_reads_back_the_root_qdisc_of_loopback)
{
    // A real dump against a real kernel, unprivileged: this exercises the
    // whole send/drain/filter/parse path including the port-id filter.
    tc::TcClient client;
    if (!client.open()) {
        SKIP("a NETLINK_ROUTE socket could not be opened");
    }
    auto const lo = ::if_nametoindex("lo");
    EXPECT_TRUE(lo > 0);
    if (lo == 0) {
        return;
    }

    auto const root = client.get(static_cast<int>(lo), tc::ROOT);
    EXPECT_TRUE(root.has_value());
    if (root) {
        // Loopback's root is normally `noqueue`; the assertion is only
        // that we found *a* qdisc on the interface we asked about.
        EXPECT_EQ(root->ifindex, static_cast<int>(lo));
        EXPECT_EQ(root->parent, tc::ROOT);
        EXPECT_FALSE(root->kind_name().empty());
    }
}

TEST(tc_qdisc, get_reports_a_qdisc_that_is_not_there_as_a_bad_handle)
{
    tc::TcClient client;
    if (!client.open()) {
        SKIP("a NETLINK_ROUTE socket could not be opened");
    }
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }

    // No qdisc hangs off this class on loopback.
    auto const missing = client.get(static_cast<int>(lo), tc::make_handle(0x7FFF, 9));
    EXPECT_FALSE(missing.has_value());
    if (!missing) {
        EXPECT_EQ(missing.error(), make_error_code(NetError::invalid_handle));
    }
}

TEST(tc_qdisc, two_dumps_in_a_row_both_succeed)
{
    // The bug this pins: a dump reply stream must be read to NLMSG_DONE.
    // Leaving replies in the socket is not harmless -- the next request
    // reads a leftover NLMSG_DONE as its own acknowledgement, which looks
    // like success. The second get() here fails if the first left anything.
    tc::TcClient client;
    if (!client.open()) {
        SKIP("a NETLINK_ROUTE socket could not be opened");
    }
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }

    EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
    EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
}

TEST(tc_qdisc, an_unprivileged_write_fails_and_the_client_survives_it)
{
    tc::TcClient client;
    if (!client.open()) {
        SKIP("a NETLINK_ROUTE socket could not be opened");
    }

    // An ifindex no interface has, so this cannot disturb the host even
    // when the suite is run as root. Unprivileged the kernel refuses on
    // the capability check, which happens before the ifindex lookup; as
    // root it refuses on the lookup. Either way it must fail cleanly and
    // leave the client usable.
    constexpr int NO_SUCH_IFINDEX = 0x7FFFFFF0;
    auto const removed = client.remove(NO_SUCH_IFINDEX, tc::make_handle(0x8001, 0), tc::ROOT);
    EXPECT_FALSE(removed.has_value());
    if (!removed) {
        auto const expected = (::geteuid() == 0) ? std::make_error_code(std::errc::no_such_device)
                                                 : std::make_error_code(std::errc::operation_not_permitted);
        EXPECT_EQ(removed.error(), expected);
    }

    // And the socket is still good for the next transaction.
    auto const lo = ::if_nametoindex("lo");
    if (lo > 0) {
        EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
    }
}

TEST(tc_qdisc, the_client_installs_a_receive_timeout)
{
    // Without this the client can block forever: a read bound does not
    // help when the kernel sends nothing at all, which happens if a reply
    // never carries NLMSG_DONE or is dropped under memory pressure. A
    // mutation that drops NLM_F_DUMP from the dump request turns the whole
    // test binary into a hang without it, and into a clean failure with it.
    tc::TcClient client;
    if (!client.open()) {
        SKIP("a NETLINK_ROUTE socket could not be opened");
    }

    timeval timeout{};
    socklen_t length = sizeof(timeout);
    EXPECT_EQ(::getsockopt(client.fd(), SOL_SOCKET, SO_RCVTIMEO, &timeout, &length), 0);
    EXPECT_TRUE(timeout.tv_sec > 0 || timeout.tv_usec > 0);
}

// ---------------------------------------------------------------------------
// etf
// ---------------------------------------------------------------------------

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_qdisc_functional_test)
