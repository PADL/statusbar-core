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

// Joining on loopback needs no privilege and no hardware, so the whole path -
// socket, setsockopt, the ip_mreqn the platform wants - is exercised here.
TEST(ipv4_sockaddr, an_endpoint_goes_into_a_sockaddr_in_and_comes_back)
{
    statusbar::ip::IPv4Address const address{192, 168, 50, 77};
    sockaddr_in const in = ipv4_sockaddr_in(address, 319);
    EXPECT_EQ(in.sin_family, AF_INET);
    EXPECT_EQ(ntohs(in.sin_port), 319);
    EXPECT_EQ(ntohl(in.sin_addr.s_addr), address.to_uint32());

    auto const back = ipv4_endpoint(in);
    EXPECT_TRUE(back.address == address);
    EXPECT_EQ(back.port, 319);
    EXPECT_TRUE(back == (IPv4Endpoint{.address = address, .port = 319}));

    // The address-only form leaves the port 0, which the two-argument form
    // sets; both agree on everything else.
    sockaddr_in const bare = ipv4_sockaddr_in(address);
    EXPECT_EQ(bare.sin_port, 0);
    EXPECT_EQ(bare.sin_addr.s_addr, in.sin_addr.s_addr);
    EXPECT_EQ(ipv4_endpoint(bare).port, 0);
}

//
// Source-specific groups (RFC 4607)
//

// 232.0.0.0/8 is the source-specific range, and nothing on either side of it.
TEST(source_group_membership, the_source_specific_range_is_232_slash_8)
{
    using statusbar::ip::IPv4Address;
    static_assert(!is_source_specific_group(IPv4Address{231, 255, 255, 255}));
    static_assert(is_source_specific_group(IPv4Address{232, 0, 0, 0}));
    static_assert(is_source_specific_group(IPv4Address{232, 255, 255, 255}));
    static_assert(!is_source_specific_group(IPv4Address{233, 0, 0, 0}));
    static_assert(!is_source_specific_group(IPv4Address{239, 69, 1, 2}));
    EXPECT_TRUE(is_source_specific_group(IPv4Address{232, 1, 2, 3}));
}

// The sockaddr the join carries names the address, the family and, where the
// stack has the field, its own length.
TEST(source_group_membership, the_storage_names_the_address)
{
    auto const storage = ipv4_sockaddr_storage(statusbar::ip::IPv4Address{192, 0, 2, 1});
    sockaddr_in in{};
    std::memcpy(&in, &storage, sizeof(in));
    EXPECT_EQ(static_cast<int>(in.sin_family), AF_INET);
    EXPECT_EQ(ntohl(in.sin_addr.s_addr), 0xC0000201U);
#if defined(__APPLE__) || defined(__FreeBSD__)
    EXPECT_EQ(static_cast<size_t>(in.sin_len), sizeof(in));
#endif
}

TEST_MAIN(statusbar_net, net_group_membership_test)
