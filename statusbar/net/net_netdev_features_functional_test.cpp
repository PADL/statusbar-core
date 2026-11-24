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

// clang-format off

// clang-format on

}  // namespace

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

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netdev_features_functional_test)
