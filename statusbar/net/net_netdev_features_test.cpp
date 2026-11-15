// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The netdev generic-netlink framing against bytes laid out by hand from
// linux/genetlink.h and linux/netdev.h, the parsers against replies framed as
// the kernel's ctrl_fill_info() and netdev_nl_dev_fill() write them, and, on
// Linux, the client against the running kernel. Netlink is host byte order:
// the vectors are little-endian.

#include "statusbar/net/net_netdev_features.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#if defined(__linux__) && __has_include(<linux/netdev.h>)
#    include <linux/netdev.h>
#endif

using namespace statusbar;
using namespace statusbar::net::netdev;

namespace {

constexpr bool LITTLE = std::endian::native == std::endian::little;
/// The id a kernel happened to give the netdev family.
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
/// CTRL_CMD_NEWFAMILY for "netdev": the name, the id 0x19, the version 1 (the
/// ops and multicast groups the kernel also sends left out).
constexpr std::array<uint8_t, 48> FAMILY_REPLY{
    0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00,                                                   // CTRL_CMD_NEWFAMILY, version 2
    0x0b, 0x00, 0x02, 0x00, 'n', 'e', 't', 'd', 'e', 'v', 0x00, 0x00,          // CTRL_ATTR_FAMILY_NAME
    0x06, 0x00, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00,                            // CTRL_ATTR_FAMILY_ID
    0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,                            // CTRL_ATTR_VERSION
};

/// NETDEV_CMD_DEV_GET for ifindex 3 (an igc port): xdp-features 0x7f,
/// xdp-zc-max-segs 1, xdp-rx-metadata-features 3, xsk-features timestamp |
/// checksum | launch time.
constexpr std::array<uint8_t, 72> DEV_REPLY{
    0x48, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00,                                                    // NETDEV_CMD_DEV_GET, version 1
    0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,                            // ifindex 3
    0x0c, 0x00, 0x03, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // xdp-features
    0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,                            // xdp-zc-max-segs
    0x0c, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // xdp-rx-metadata-features
    0x0c, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // xsk-features
};
// clang-format on

constexpr size_t XSK_ATTRIBUTE_AT = 60;  ///< where the xsk-features attribute starts in DEV_REPLY

}  // namespace

// The header's mirrors of the UAPI enumerators, checked at run time as well
// as by the static_asserts in net_netdev_features.cpp: those sit behind the
// configure-time probes, and this is what shows the probes fired.
TEST(netdev_features, the_mirrored_constants_match_the_kernel_uapi)
{
#if defined(__linux__) && defined(HAVE_NETDEV_XSK_FEATURES)
    EXPECT_EQ(static_cast<uint64_t>(DEV_XDP_RX_METADATA_FEATURES), static_cast<uint64_t>(NETDEV_A_DEV_XDP_RX_METADATA_FEATURES));
    EXPECT_EQ(static_cast<uint64_t>(DEV_XSK_FEATURES), static_cast<uint64_t>(NETDEV_A_DEV_XSK_FEATURES));
    EXPECT_EQ(XSK_TX_TIMESTAMP, static_cast<uint64_t>(NETDEV_XSK_FLAGS_TX_TIMESTAMP));
    EXPECT_EQ(XSK_TX_CHECKSUM, static_cast<uint64_t>(NETDEV_XSK_FLAGS_TX_CHECKSUM));
#    if defined(HAVE_NETDEV_XSK_LAUNCH_TIME)
    EXPECT_EQ(XSK_TX_LAUNCH_TIME_FIFO, static_cast<uint64_t>(NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO));
#    endif
#else
    SKIP("the build's linux/netdev.h predates the xsk-features attribute (Linux 6.8), or this is not Linux");
#endif
}

TEST(netdev_features, the_get_family_request_as_the_controller_reads_it)
{
    if (!LITTLE) {
        SKIP("the expected bytes are little-endian");
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

TEST(netdev_features, a_family_name_fits_genl_namsiz_or_is_refused)
{
    RequestBuffer out{};
    auto const empty = build_get_family(out, "", 1);
    EXPECT_TRUE(!empty && empty.error() == std::errc::invalid_argument);
    EXPECT_FALSE(build_get_family(out, "sixteen-octets-x", 1).has_value());
    auto const longest = build_get_family(out, "fifteen-octetsx", 1);
    EXPECT_TRUE(longest.has_value());
    EXPECT_TRUE(longest && *longest == GENL_HEADER + 20);  // 4 + 16 octets of name and NUL, already aligned
    auto const short_name = build_get_family(out, "tc", 1);
    EXPECT_TRUE(short_name && *short_name == GENL_HEADER + 8);  // 4 + 3, padded to 8
}

TEST(netdev_features, the_dev_get_request_as_the_family_reads_it)
{
    if (!LITTLE) {
        SKIP("the expected bytes are little-endian");
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

TEST(netdev_features, a_short_buffer_refuses_both_requests)
{
    std::array<uint8_t, 20> out{};
    EXPECT_FALSE(build_dev_get(out, NETDEV_ID, 3, 9).has_value());
    EXPECT_FALSE(build_get_family(out, FAMILY_NAME, 7).has_value());
}

TEST(netdev_features, the_family_id_is_read_from_newfamily)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto const id = parse_family_id(FAMILY_REPLY);
    EXPECT_TRUE(id.has_value());
    EXPECT_TRUE(id && *id == NETDEV_ID);
    auto const attributes = genl_attributes(FAMILY_REPLY, GENL_CONTROLLER_ID, CTRL_NEWFAMILY);
    EXPECT_TRUE(attributes && attributes->size() == 28);
}

TEST(netdev_features, a_newfamily_without_an_id_or_with_a_wrong_sized_one_is_malformed)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto renamed = FAMILY_REPLY;
    renamed[34] = 0x09;  // CTRL_ATTR_FAMILY_ID becomes an attribute nobody asked about
    auto const none = parse_family_id(renamed);
    EXPECT_TRUE(!none && none.error() == std::errc::bad_message);
    auto wide = FAMILY_REPLY;
    wide[32] = 0x08;  // a 4-octet family id
    EXPECT_FALSE(parse_family_id(wide).has_value());
}

TEST(netdev_features, a_short_reply_a_refusal_or_another_family_answers_neither_parse)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    EXPECT_FALSE(parse_family_id(std::span{FAMILY_REPLY}.first(19)).has_value());  // inside the headers
    EXPECT_FALSE(parse_family_id(std::span{FAMILY_REPLY}.first(40)).has_value());  // nlmsg_len past the end
    std::array<uint8_t, 36> refusal{0x24, 0x00, 0x00, 0x00, 0x02, 0x00};           // an NLMSG_ERROR
    EXPECT_FALSE(parse_family_id(refusal).has_value());
    EXPECT_FALSE(parse_dev(refusal, NETDEV_ID).has_value());
    EXPECT_FALSE(parse_family_id(DEV_REPLY).has_value());
    EXPECT_FALSE(parse_dev(FAMILY_REPLY, NETDEV_ID).has_value());
    EXPECT_FALSE(parse_dev(DEV_REPLY, NETDEV_ID + 1).has_value());
    auto other_command = DEV_REPLY;
    other_command[16] = 0x02;  // NETDEV_CMD_DEV_ADD_NTF
    EXPECT_FALSE(parse_dev(other_command, NETDEV_ID).has_value());
}

TEST(netdev_features, every_dev_attribute_is_read_and_the_launch_time_bit_reported)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto const device = parse_dev(DEV_REPLY, NETDEV_ID);
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->ifindex == 3);
    EXPECT_TRUE(device && device->xdp_features == 0x7f && device->xdp_rx_metadata == 3);
    EXPECT_TRUE(device && device->xsk.flags == 7);
    EXPECT_TRUE(device && device->xsk.tx_timestamp() && device->xsk.tx_checksum() && device->xsk.launch_time());
}

TEST(netdev_features, a_kernel_without_xsk_features_reports_none)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto reply = DEV_REPLY;
    reply[0] = XSK_ATTRIBUTE_AT;  // the reply ends before xsk-features, as a kernel before 6.8 writes it
    auto const device = parse_dev(std::span{reply}.first(XSK_ATTRIBUTE_AT), NETDEV_ID);
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->ifindex == 3 && device->xdp_features == 0x7f);
    EXPECT_TRUE(device && device->xsk.flags == 0 && !device->xsk.launch_time());
    auto bare = DEV_REPLY;
    bare[0] = 28;  // ifindex alone, as a kernel of 6.3 might
    auto const minimal = parse_dev(std::span{bare}.first(28), NETDEV_ID);
    EXPECT_TRUE(minimal && *minimal == DeviceFeatures{.ifindex = 3});
}

TEST(netdev_features, a_renamed_or_missized_attribute_is_told_apart)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto as_rx_metadata = DEV_REPLY;
    as_rx_metadata[XSK_ATTRIBUTE_AT + 2] = 0x05;  // the xsk-features attribute is now a second rx-metadata one
    auto const device = parse_dev(as_rx_metadata, NETDEV_ID);
    EXPECT_TRUE(device && device->xsk.flags == 0 && device->xdp_rx_metadata == 7);
    auto overrun = DEV_REPLY;
    overrun[XSK_ATTRIBUTE_AT] = 0x10;  // xsk-features claims more than is left
    EXPECT_FALSE(parse_dev(overrun, NETDEV_ID).has_value());
    auto narrow = DEV_REPLY;
    narrow[XSK_ATTRIBUTE_AT] = 0x08;  // a 4-octet u64
    EXPECT_FALSE(parse_dev(narrow, NETDEV_ID).has_value());
    auto no_ifindex = DEV_REPLY;
    no_ifindex[22] = 0x07;  // NETDEV_A_DEV_IFINDEX becomes an attribute nobody asked about
    auto const nameless = parse_dev(no_ifindex, NETDEV_ID);
    EXPECT_TRUE(!nameless && nameless.error() == std::errc::bad_message);
    EXPECT_FALSE(parse_dev(std::span{DEV_REPLY}.first(68), NETDEV_ID).has_value());  // nlmsg_len past the end
}

TEST(netdev_features, the_xsk_feature_bits)
{
    EXPECT_FALSE(XskFeatures{}.launch_time());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_LAUNCH_TIME_FIFO}.launch_time());
    EXPECT_FALSE(XskFeatures{.flags = XSK_TX_LAUNCH_TIME_FIFO}.tx_timestamp());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_TIMESTAMP}.tx_timestamp());
    EXPECT_TRUE(XskFeatures{.flags = XSK_TX_CHECKSUM}.tx_checksum());
    EXPECT_FALSE(XskFeatures{.flags = XSK_TX_TIMESTAMP | XSK_TX_CHECKSUM}.launch_time());
}

#if defined(__linux__)

TEST(netdev_client, the_loopback_interface_has_no_launch_time)
{
    NetdevClient client;
    auto const opened = client.open();
    if (!opened) {
        if (opened.error() == std::errc::no_such_file_or_directory) {
            SKIP("this kernel has no netdev family (before 6.3)");
        }
        SKIP("no generic netlink socket here");
    }
    EXPECT_TRUE(client.is_open());
    EXPECT_NE(client.family_id(), uint16_t{0});
    auto const device = client.features(1);
    if (!device && device.error() == std::errc::timed_out) {
        SKIP("the socket opens but nothing answers (a sandbox)");
    }
    EXPECT_TRUE(device.has_value());
    EXPECT_TRUE(device && device->ifindex == 1);
    EXPECT_TRUE(device && !device->xsk.launch_time());
    auto const missing = client.features(0x7fff'fff0);
    EXPECT_TRUE(!missing && missing.error() == std::errc::no_such_device);
    client.close();
    EXPECT_FALSE(client.is_open());
    auto const once = launch_time_supported(1);
    EXPECT_TRUE(once.has_value() && !*once);
    auto const xsk = query_xsk_features(1);
    EXPECT_TRUE(xsk.has_value() && xsk->flags == 0);
    EXPECT_FALSE(launch_time_supported(0x7fff'fff0).has_value());
}

TEST(netdev_client, a_closed_client_answers_nothing)
{
    NetdevClient client;
    EXPECT_FALSE(client.is_open());
    EXPECT_EQ(client.family_id(), uint16_t{0});
    auto const refused = client.features(1);
    EXPECT_TRUE(!refused && refused.error() == std::errc::bad_file_descriptor);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netdev_features_test)
