// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The rtnetlink VLAN link request builders, against bytes checked by hand
// from linux/rtnetlink.h (nlmsghdr, ifinfomsg, rtattr) and linux/if_link.h
// (IFLA_IFNAME, IFLA_LINK, IFLA_LINKINFO > IFLA_INFO_KIND + IFLA_INFO_DATA >
// IFLA_VLAN_ID), framed as iproute2's `ip link add ... type vlan id N` frames
// them. Netlink is host byte order: the expected bytes are little-endian.
// Nothing is created (that needs CAP_NET_ADMIN).

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_vlan_link.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <print>
#    include <span>

namespace {

using namespace statusbar::net;
using namespace statusbar::net::vlan;

constexpr bool LITTLE = std::endian::native == std::endian::little;

/// Byte-exact compare with a dump of the first difference.
auto same_bytes(std::span<uint8_t const> const got, std::span<uint8_t const> const want) -> bool
{
    if (got.size() != want.size()) {
        std::println("  length {} want {}", got.size(), want.size());
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            std::println("  byte {}: {:02x} want {:02x}", i, got[i], want[i]);
            return false;
        }
    }
    return true;
}

TEST(vlan_link, names)
{
    EXPECT_TRUE(vlan_link_name("enp8s0", 2) == "enp8s0.2");
    EXPECT_TRUE(vlan_link_name("eth1", 4094) == "eth1.4094");
    // 15 characters at most: the interface is cut short, the VID kept.
    EXPECT_TRUE(vlan_link_name("enx001122334455", 2) == "enx0011223344.2");
    EXPECT_TRUE(vlan_link_name("enx001122334455", 4094) == "enx0011223.4094");
    EXPECT_EQ(vlan_link_name("enx001122334455", 4094).size(), MAX_LINK_NAME);
}

// `ip link add link <if3> name enp8s0.2 type vlan id 2`
TEST(vlan_link, new_vlan)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 84> const want{
        // nlmsghdr: len 84, RTM_NEWLINK (16), REQUEST|ACK|EXCL|CREATE (0x0605), seq 5, pid 0
        0x54, 0x00, 0x00, 0x00,  0x10, 0x00,  0x05, 0x06,  0x05, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // ifinfomsg: family 0, pad, type 0, index 0, flags 0, change 0
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // IFLA_IFNAME (3), len 4 + 9: "enp8s0.2\0", 3 pad bytes
        0x0d, 0x00, 0x03, 0x00,  'e', 'n', 'p', '8', 's', '0', '.', '2', 0x00,  0x00, 0x00, 0x00,
        // IFLA_LINK (5), len 4 + 4: parent ifindex 3
        0x08, 0x00, 0x05, 0x00,  0x03, 0x00, 0x00, 0x00,
        // IFLA_LINKINFO (18, nest), len 4 + 24
        0x1c, 0x00, 0x12, 0x00,
        // IFLA_INFO_KIND (1), len 4 + 5: "vlan\0", 3 pad bytes
        0x09, 0x00, 0x01, 0x00,  'v', 'l', 'a', 'n', 0x00,  0x00, 0x00, 0x00,
        // IFLA_INFO_DATA (2, nest), len 4 + 8
        0x0c, 0x00, 0x02, 0x00,
        // IFLA_VLAN_ID (1), len 4 + 2: VID 2, 2 pad bytes
        0x06, 0x00, 0x01, 0x00,  0x02, 0x00,  0x00, 0x00,
    };
    // clang-format on
    tc::RequestBuffer out{};
    auto const length = build_new_vlan(out, 3, "enp8s0.2", 2, 5);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
}

TEST(vlan_link, new_vlan_refuses_bad_arguments)
{
    tc::RequestBuffer out{};
    EXPECT_FALSE(build_new_vlan(out, 0, "enp8s0.2", 2, 5).has_value());           // no parent
    EXPECT_FALSE(build_new_vlan(out, 3, "", 2, 5).has_value());                   // no name
    EXPECT_FALSE(build_new_vlan(out, 3, "a_name_too_long_x", 2, 5).has_value());  // over IFNAMSIZ - 1
    EXPECT_FALSE(build_new_vlan(out, 3, "enp8s0.0", 0, 5).has_value());           // VID 0 is priority tagging
    EXPECT_FALSE(build_new_vlan(out, 3, "enp8s0.4095", 4095, 5).has_value());     // reserved
    EXPECT_TRUE(build_new_vlan(out, 3, "enp8s0.4094", 4094, 5).has_value());
    std::array<uint8_t, 40> small{};
    EXPECT_FALSE(build_new_vlan(small, 3, "enp8s0.2", 2, 5).has_value());
}

// `ip link del enp8s0.2`
TEST(vlan_link, delete_link)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 48> const want{
        // nlmsghdr: len 48, RTM_DELLINK (17), REQUEST|ACK (0x0005), seq 6, pid 0
        0x30, 0x00, 0x00, 0x00,  0x11, 0x00,  0x05, 0x00,  0x06, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // ifinfomsg: index 0 (the link is named)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // IFLA_IFNAME (3), len 4 + 9: "enp8s0.2\0", 3 pad bytes
        0x0d, 0x00, 0x03, 0x00,  'e', 'n', 'p', '8', 's', '0', '.', '2', 0x00,  0x00, 0x00, 0x00,
    };
    // clang-format on
    tc::RequestBuffer out{};
    auto const length = build_delete_link(out, "enp8s0.2", 6);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
    EXPECT_FALSE(build_delete_link(out, "", 6).has_value());
    EXPECT_FALSE(build_delete_link(out, "a_name_too_long_x", 6).has_value());
}

}  // namespace

#endif  // __linux__

TEST_MAIN(statusbar_net, net_vlan_link_test)
