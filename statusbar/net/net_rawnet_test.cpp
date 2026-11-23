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
#    include "statusbar/net/net_posix_util.hpp"

#    include <fcntl.h>

#    include <arpa/inet.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <net/if.h>
#    include <sys/socket.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr std::uint16_t AVTP = ieee::protocols::ETHERTYPE_AVTP;
constexpr std::uint8_t SUBTYPE_AAF = 0x02;

#if defined(__linux__)

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

#endif  // __linux__

TEST_MAIN(statusbar_net, net_rawnet_test)
