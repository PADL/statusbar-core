// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the AF_PACKET talker path: transmit-only open, the AVTP
/// subtype filter, and SO_PRIORITY.
///
/// Argument validation is tested with no privilege at all, on a closed
/// context — the checks run before anything touches a socket, which is
/// deliberate and is what makes them testable here.
///
/// The rest needs CAP_NET_RAW. Following the house idiom in
/// net_linux_xdp_test.cpp, a privileged test whose setup fails returns
/// quietly rather than failing, so an unprivileged `make test` stays
/// green. The root run is where they actually assert.

#include "statusbar/net/net_rawnet.hpp"

#include "statusbar/ieee/ieee_protocols.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_rawnet_filter.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#if defined(__linux__)
#    include <fcntl.h>

#    include <sys/socket.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr std::uint16_t AVTP = ieee::protocols::ETHERTYPE_AVTP;
constexpr std::uint8_t SUBTYPE_AAF = 0x02;
constexpr std::uint8_t SUBTYPE_CRF = 0x04;
constexpr std::uint8_t SUBTYPE_ADP = 0x7A;

#if defined(__linux__)

/// Open a context on `lo`. AF_PACKET needs CAP_NET_RAW, so unprivileged
/// every test below can only skip - with SKIP(), which the runner counts
/// apart from the passes, so "6 of 10 asserted" stays visible instead of a
/// root-only test quietly ceasing to be run at all.
[[nodiscard]] auto open_on_loopback(RawnetContext& ctx, bool transmit_only = false) -> bool
{
    return ctx.open("lo", AVTP, nullptr, /*qdisc_bypass=*/false, transmit_only).has_value();
}

constexpr char const* NEEDS_CAP_NET_RAW = "needs CAP_NET_RAW (AF_PACKET open refused)";

#endif  // __linux__

}  // namespace

TEST(rawnet_talker, set_subtype_filter_refuses_an_empty_set_without_a_socket)
{
    // Validation happens before the socket is consulted, so a closed
    // context reports the argument fault and not "not connected".
    RawnetContext ctx;
    std::span<std::uint8_t const> const none{};

    auto const status = ctx.set_subtype_filter(none);
    EXPECT_FALSE(status.has_value());
    if (status) {
        return;
    }
    EXPECT_EQ(status.error(), make_error_code(NetError::invalid_argument));
}

TEST(rawnet_talker, set_subtype_filter_refuses_more_than_max_subtypes_without_a_socket)
{
    RawnetContext ctx;
    std::array<std::uint8_t const, rawnet_filter::MAX_SUBTYPES + 1> const too_many{0, 1, 2, 3, 4, 5, 6, 7, 8};

    auto const status = ctx.set_subtype_filter(too_many);
    EXPECT_FALSE(status.has_value());
    if (status) {
        return;
    }
    EXPECT_EQ(status.error(), make_error_code(NetError::invalid_argument));
}

TEST(rawnet_talker, a_valid_filter_on_a_closed_socket_is_not_connected)
{
    // The complement of the two tests above: with the arguments in order,
    // the next thing to fail is the socket. If this returned
    // invalid_argument too, the tests above would prove nothing.
    RawnetContext ctx;
    std::array<std::uint8_t const, 1> const subtypes{SUBTYPE_AAF};

    auto const status = ctx.set_subtype_filter(subtypes);
    EXPECT_FALSE(status.has_value());
    if (status) {
        return;
    }
    EXPECT_EQ(status.error(), make_error_code(NetError::not_connected));
}

TEST(rawnet_talker, set_priority_on_a_closed_socket_is_not_connected)
{
    RawnetContext ctx;

    auto const status = ctx.set_priority(3);
    EXPECT_FALSE(status.has_value());
    if (status) {
        return;
    }
    EXPECT_EQ(status.error(), make_error_code(NetError::not_connected));
}

TEST(rawnet_talker, set_priority_rejects_a_negative_priority)
{
    RawnetContext ctx;

    // Checked before the socket, like the filter's subtype count.
    auto const status = ctx.set_priority(-1);
    EXPECT_FALSE(status.has_value());
    if (status) {
        return;
    }
    EXPECT_EQ(status.error(), make_error_code(NetError::invalid_argument));
}

#if defined(__linux__)

TEST(rawnet_talker, transmit_only_refuses_join_leave_and_subtype_filter)
{
    RawnetContext ctx;
    if (!open_on_loopback(ctx, /*transmit_only=*/true)) {
        SKIP(NEEDS_CAP_NET_RAW);
    }

    Eui48 const group{0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80};

    // Joining a group binds the socket, which re-registers it for receive
    // and defeats the whole point of the mode. Refusing is the contract.
    auto const joined = ctx.join_multicast(group);
    EXPECT_FALSE(joined.has_value());
    if (!joined) {
        EXPECT_EQ(joined.error(), make_error_code(NetError::invalid_argument));
    }

    auto const left = ctx.leave_multicast(group);
    EXPECT_FALSE(left.has_value());
    if (!left) {
        EXPECT_EQ(left.error(), make_error_code(NetError::invalid_argument));
    }

    std::array<std::uint8_t const, 1> const subtypes{SUBTYPE_AAF};
    auto const filtered = ctx.set_subtype_filter(subtypes);
    EXPECT_FALSE(filtered.has_value());
    if (!filtered) {
        EXPECT_EQ(filtered.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(rawnet_talker, a_transmit_only_socket_can_still_send)
{
    RawnetContext ctx;
    if (!open_on_loopback(ctx, /*transmit_only=*/true)) {
        SKIP(NEEDS_CAP_NET_RAW);
    }

    // Refusing join/leave/filter must not have cost us the one thing the
    // mode exists for.
    Eui48 const dest{0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80};
    std::array<std::uint8_t, 64> payload{};
    payload[0] = SUBTYPE_AAF;

    auto const sent = ctx.send(&dest, payload);
    EXPECT_TRUE(sent.has_value());
}

TEST(rawnet_talker, set_priority_is_readable_back_from_the_socket)
{
    RawnetContext ctx;
    if (!open_on_loopback(ctx)) {
        SKIP(NEEDS_CAP_NET_RAW);
    }

    EXPECT_TRUE(ctx.set_priority(3).has_value());

    // SO_PRIORITY is what packet_pick_tx_queue reads to choose the TX
    // queue for a bypass frame, so reading it back off the socket is the
    // part we can verify without an mqprio map and a NIC.
    int priority = -1;
    socklen_t length = sizeof(priority);
    EXPECT_EQ(::getsockopt(ctx.fd(), SOL_SOCKET, SO_PRIORITY, &priority, &length), 0);
    EXPECT_EQ(priority, 3);

    // And it is settable again, so a caller can re-prioritise a live socket.
    EXPECT_TRUE(ctx.set_priority(5).has_value());
    EXPECT_EQ(::getsockopt(ctx.fd(), SOL_SOCKET, SO_PRIORITY, &priority, &length), 0);
    EXPECT_EQ(priority, 5);
}

TEST(rawnet_talker, set_priority_works_on_a_transmit_only_socket)
{
    // A talker is exactly the socket that needs a priority, and it is
    // also the one that should be transmit-only; refusing here would
    // make the two features mutually exclusive.
    RawnetContext ctx;
    if (!open_on_loopback(ctx, /*transmit_only=*/true)) {
        SKIP(NEEDS_CAP_NET_RAW);
    }

    EXPECT_TRUE(ctx.set_priority(4).has_value());

    int priority = -1;
    socklen_t length = sizeof(priority);
    EXPECT_EQ(::getsockopt(ctx.fd(), SOL_SOCKET, SO_PRIORITY, &priority, &length), 0);
    EXPECT_EQ(priority, 4);
}

TEST(rawnet_talker, a_filtered_socket_receives_only_in_set_subtypes)
{
    RawnetContext receiver;
    if (!open_on_loopback(receiver)) {
        SKIP(NEEDS_CAP_NET_RAW);
    }

    RawnetContext sender;
    if (!sender.open("lo", AVTP)) {
        return;
    }

    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};
    EXPECT_TRUE(receiver.set_subtype_filter(subtypes).has_value());

    // Read without blocking: the whole point is that out-of-set frames
    // never arrive, so there is nothing to wait for.
    int const flags = ::fcntl(receiver.fd(), F_GETFL, 0);
    EXPECT_EQ(::fcntl(receiver.fd(), F_SETFL, flags | O_NONBLOCK), 0);

    Eui48 const dest{0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80};
    std::array<std::uint8_t const, 4> const to_send{SUBTYPE_AAF, SUBTYPE_ADP, SUBTYPE_CRF, SUBTYPE_ADP};
    for (auto const subtype : to_send) {
        std::array<std::uint8_t, 64> payload{};
        payload[0] = subtype;
        EXPECT_TRUE(sender.send(&dest, payload).has_value());
    }

    // Drain. Loopback delivers each frame to a ptype_all socket more than
    // once (ingress plus the egress tap), so count rather than match
    // one-for-one.
    int in_set = 0;
    int out_of_set = 0;
    for (int i = 0; i < 64; ++i) {
        Eui48 src{};
        Eui48 dst{};
        std::array<std::uint8_t, 128> payload{};
        auto const received = receiver.recv(&src, &dst, payload);
        if (!received) {
            break;
        }
        if (*received < 1) {
            continue;
        }
        if (payload[0] == SUBTYPE_AAF || payload[0] == SUBTYPE_CRF) {
            ++in_set;
        } else {
            ++out_of_set;
        }
    }

    EXPECT_EQ(out_of_set, 0);
    EXPECT_TRUE(in_set > 0);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_rawnet_test)
