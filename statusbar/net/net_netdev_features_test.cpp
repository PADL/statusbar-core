// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The netdev generic-netlink builders against bytes checked by hand from
// linux/netlink.h, linux/genetlink.h and linux/netdev.h, and the parsers against
// replies framed as the kernel's ctrl_fill_info and netdev_nl_dev_fill write them.
// Netlink is host byte order: the expected bytes are little-endian.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_netdev_features.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <span>
#    include <system_error>

namespace {

using namespace statusbar::net::netdev;

constexpr bool LITTLE = std::endian::native == std::endian::little;
constexpr uint16_t NETDEV_ID = 0x19;

auto same_bytes(std::span<uint8_t const> const got, std::span<uint8_t const> const want) -> bool
{
    if (got.size() != want.size()) {
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            return false;
        }
    }
    return true;
}

// clang-format off
/// CTRL_CMD_NEWFAMILY for "netdev": name, id 0x19, version 1 (ops and groups left out).
constexpr std::array<uint8_t, 48> FAMILY_REPLY{
    0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00,
    0x0b, 0x00, 0x02, 0x00, 'n', 'e', 't', 'd', 'e', 'v', 0x00, 0x00,
    0x06, 0x00, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
};

/// NETDEV_CMD_DEV_GET for ifindex 3 (an igc port): xdp-features 0x7f, xdp-zc-max-segs 1,
/// xsk-features (6) timestamp | checksum | launch time.
constexpr std::array<uint8_t, 60> DEV_REPLY{
    0x3c, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x03, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
// clang-format on

}  // namespace

TEST(netdev_features, get_family_request)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    constexpr std::array<uint8_t, 32> want{
        0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x01, 0x00, 0x00,
        0x0b, 0x00, 0x02, 0x00, 'n', 'e', 't', 'd', 'e', 'v', 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_get_family(out, FAMILY_NAME, 7);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), want));
}

TEST(netdev_features, a_family_name_must_fit_genl_namsiz)
{
    RequestBuffer out{};
    EXPECT_FALSE(build_get_family(out, "", 1).has_value());
    EXPECT_FALSE(build_get_family(out, "sixteen-octets-x", 1).has_value());
    EXPECT_TRUE(build_get_family(out, "fifteen-octetsx", 1).has_value());
}

TEST(netdev_features, dev_get_request)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    constexpr std::array<uint8_t, 28> want{
        0x1c, 0x00, 0x00, 0x00, 0x19, 0x00, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_dev_get(out, NETDEV_ID, 3, 9);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), want));
}

TEST(netdev_features, a_short_buffer_is_refused)
{
    std::array<uint8_t, 20> out{};
    EXPECT_FALSE(build_dev_get(out, NETDEV_ID, 3, 9).has_value());
    EXPECT_FALSE(build_get_family(out, FAMILY_NAME, 7).has_value());
}

TEST(netdev_features, family_id_from_newfamily)
{
    if (!LITTLE) {
        return;
    }
    auto const id = parse_family_id(FAMILY_REPLY);
    EXPECT_TRUE(id.has_value());
    EXPECT_TRUE(id && *id == NETDEV_ID);
}

TEST(netdev_features, a_newfamily_without_an_id_is_malformed)
{
    if (!LITTLE) {
        return;
    }
    auto reply = FAMILY_REPLY;
    reply[34] = 0x09;  // CTRL_ATTR_FAMILY_ID becomes an attribute we ignore
    EXPECT_FALSE(parse_family_id(reply).has_value());
}

TEST(netdev_features, launch_time_reported_by_xsk_features)
{
    if (!LITTLE) {
        return;
    }
    auto const device = parse_dev(DEV_REPLY, NETDEV_ID);
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->ifindex == 3);
    EXPECT_TRUE(device && device->xdp_features == 0x7f);
    EXPECT_TRUE(device && (device->xdp_features & XDP_ACT_XSK_ZEROCOPY) != 0);
    EXPECT_TRUE(device && device->xsk.tx_timestamp() && device->xsk.tx_checksum() && device->xsk.launch_time());
}

TEST(netdev_features, absent_xsk_features_mean_none)
{
    if (!LITTLE) {
        return;
    }
    auto reply = DEV_REPLY;
    reply[0] = 48;  // drop the trailing xsk-features attribute, as a kernel before 6.8 sends
    auto const device = parse_dev(std::span{reply}.first(48), NETDEV_ID);
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->xsk.flags == 0 && !device->xsk.launch_time());
    EXPECT_TRUE(device && device->xdp_features == 0x7f);
}

TEST(netdev_features, rx_metadata_features_are_not_xsk_features)
{
    if (!LITTLE) {
        return;
    }
    auto reply = DEV_REPLY;
    reply[50] = 0x05;  // the last attribute becomes xdp-rx-metadata-features: 4, vlan-tag
    reply[52] = 0x04;
    auto const device = parse_dev(reply, NETDEV_ID);
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->xsk.flags == 0 && !device->xsk.launch_time());
}

TEST(netdev_features, malformed_dev_replies_are_refused)
{
    if (!LITTLE) {
        return;
    }
    EXPECT_FALSE(parse_dev(std::span{DEV_REPLY}.first(19), NETDEV_ID).has_value());  // inside the headers
    EXPECT_FALSE(parse_dev(std::span{DEV_REPLY}.first(56), NETDEV_ID).has_value());  // nlmsg_len past the end
    EXPECT_FALSE(parse_dev(DEV_REPLY, NETDEV_ID + 1).has_value());                   // another family
    auto long_attribute = DEV_REPLY;
    long_attribute[48] = 0x10;  // xsk-features claims more than is left
    EXPECT_FALSE(parse_dev(long_attribute, NETDEV_ID).has_value());
    auto short_u64 = DEV_REPLY;
    short_u64[48] = 0x08;  // a 4-octet u64
    EXPECT_FALSE(parse_dev(short_u64, NETDEV_ID).has_value());
    auto no_ifindex = DEV_REPLY;
    no_ifindex[22] = 0x07;  // NETDEV_A_DEV_IFINDEX becomes an attribute we ignore
    EXPECT_FALSE(parse_dev(no_ifindex, NETDEV_ID).has_value());
    auto other_command = DEV_REPLY;
    other_command[16] = 0x02;  // NETDEV_CMD_DEV_ADD_NTF
    EXPECT_FALSE(parse_dev(other_command, NETDEV_ID).has_value());
}

TEST(netdev_features, xsk_feature_bits)
{
    EXPECT_FALSE(XskFeatures{}.launch_time());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_LAUNCH_TIME_FIFO}.launch_time());
    EXPECT_FALSE(XskFeatures{.flags = XSK_TX_LAUNCH_TIME_FIFO}.tx_timestamp());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_TIMESTAMP}.tx_timestamp());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_CHECKSUM}.tx_checksum());
}

TEST(netdev_features, loopback_has_no_launch_time)
{
    // Host-dependent: skipped where netlink, the netdev family or ifindex 1 is not as expected.
    NetdevClient client;
    if (!client.open().has_value()) {
        return;
    }
    auto const device = client.features(1);
    if (!device || device->ifindex != 1) {
        return;
    }
    EXPECT_FALSE(device->xsk.launch_time());
    auto const missing = client.features(0x7fff'fff0);
    EXPECT_FALSE(missing.has_value());
    auto const once = launch_time_supported(1);
    EXPECT_TRUE(once.has_value() && !*once);
    EXPECT_FALSE(launch_time_supported(0x7fff'fff0).has_value());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netdev_features_test)
