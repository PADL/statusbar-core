// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the interface-facts queries.
///
/// Every test here runs unprivileged and against `lo`, which is what CI
/// has. `lo` is a good subject precisely because it answers some of these
/// questions and not others: it has an index, an MTU and a TX queue, but
/// no ethtool operations at all, so it exercises both the success and the
/// clean-failure path without a real NIC.

#include "statusbar/net/net_interface_info.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>
#include <string>
#include <string_view>

#if defined(__linux__)
#    include <dirent.h>

#    include <net/if.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

#if defined(__linux__)

namespace {

/// Count an interface's tx-N queue directories, independently of the
/// implementation under test, so the expected number is derived rather
/// than asserted loosely.
auto expected_tx_queues(std::string_view interface_name) -> std::size_t
{
    std::string const path = std::string{"/sys/class/net/"} + std::string{interface_name} + "/queues";
    DIR* dir = ::opendir(path.c_str());
    if (dir == nullptr) {
        return 0;
    }
    std::size_t count = 0;
    while (dirent const* entry = ::readdir(dir)) {
        if (std::string_view{entry->d_name}.starts_with("tx-")) {
            ++count;
        }
    }
    ::closedir(dir);
    return count;
}

}  // namespace

TEST(interface_info, tx_queue_count_of_lo_is_at_least_one)
{
    // Counted from /sys/class/net/<if>/queues/tx-*, which needs no ioctl.
    // ETHTOOL_GCHANNELS reports configured channels, which is a subtly
    // different number and the wrong source for an mqprio map.
    auto const queues = tx_queue_count("lo");
    EXPECT_TRUE(queues.has_value());
    if (queues) {
        EXPECT_TRUE(*queues >= 1);
        EXPECT_EQ(*queues, expected_tx_queues("lo"));
    }
}

TEST(interface_info, lo_has_no_link_speed_and_reports_it_as_unknown_not_zero)
{
    // The criterion that matters most. A link with no speed to report must
    // be distinguishable from a broken NIC, because a daemon that starts
    // before the link comes up hits this every time — and must not be
    // handed 0, which would make a CBS idle-slope calculation silently
    // reserve nothing.
    auto const speed = link_speed_mbps("lo");
    EXPECT_FALSE(speed.has_value());
    if (!speed) {
        EXPECT_EQ(speed.error(), make_unknown_link_speed());
        EXPECT_NE(speed.error(), std::make_error_code(std::errc::no_such_device));
    }
}

TEST(interface_info, unknown_link_speed_is_network_down)
{
    // Pinned so the sentinel cannot drift: callers compare against
    // std::errc::network_down, which is what a shaper written elsewhere
    // tests for.
    EXPECT_EQ(make_unknown_link_speed(), std::make_error_code(std::errc::network_down));
}

TEST(interface_info, an_oversized_name_is_refused_before_any_syscall)
{
    // ENAMETOOLONG rather than ENODEV, and the distinction is the test:
    // no kernel interface query returns ENAMETOOLONG, so seeing it proves
    // the length check ran first. Without it the name would be truncated
    // into a 16-byte ifr_name and we would query some *other* interface.
    std::string const too_long(IFNAMSIZ, 'x');
    auto const expected = std::make_error_code(std::errc::filename_too_long);

    auto const index = interface_index(too_long);
    EXPECT_FALSE(index.has_value());
    if (!index) {
        EXPECT_EQ(index.error(), expected);
    }

    auto const mtu = interface_mtu(too_long);
    EXPECT_FALSE(mtu.has_value());
    if (!mtu) {
        EXPECT_EQ(mtu.error(), expected);
    }

    auto const driver = driver_name(too_long);
    EXPECT_FALSE(driver.has_value());
    if (!driver) {
        EXPECT_EQ(driver.error(), expected);
    }

    auto const queues = tx_queue_count(too_long);
    EXPECT_FALSE(queues.has_value());
    if (!queues) {
        EXPECT_EQ(queues.error(), expected);
    }

    auto const speed = link_speed_mbps(too_long);
    EXPECT_FALSE(speed.has_value());
    if (!speed) {
        EXPECT_EQ(speed.error(), expected);
    }
}

TEST(interface_info, a_name_that_is_a_path_is_refused_before_any_path_is_built)
{
    // Short enough to pass the length check, and each would otherwise be
    // pasted into /sys/class/net/<name>/speed or /queues and followed:
    // "../../x/y" walks out of the directory, ".." counts the entries of
    // /sys/class. No interface can have these names, so no_such_device.
    auto const expected = std::make_error_code(std::errc::no_such_device);
    for (std::string_view const name : {"../../x/y", "..", ".", "a/b"}) {
        auto const speed = link_speed_mbps(name);
        EXPECT_FALSE(speed.has_value());
        if (!speed) {
            EXPECT_EQ(speed.error(), expected);
        }
        auto const queues = tx_queue_count(name);
        EXPECT_FALSE(queues.has_value());
        if (!queues) {
            EXPECT_EQ(queues.error(), expected);
        }
    }
}

TEST(interface_info, an_empty_name_names_no_device)
{
    auto const expected = std::make_error_code(std::errc::no_such_device);

    auto const index = interface_index("");
    EXPECT_FALSE(index.has_value());
    if (!index) {
        EXPECT_EQ(index.error(), expected);
    }

    auto const queues = tx_queue_count("");
    EXPECT_FALSE(queues.has_value());
    if (!queues) {
        EXPECT_EQ(queues.error(), expected);
    }

    // The one that needs the guard rather than falling out of the syscall:
    // an empty name builds the path "/sys/class/net//speed", whose open
    // fails — and the "is the interface there?" fallback would then stat
    // /sys/class/net/ itself, find it, and report a *down link* for an
    // interface that was never named.
    auto const speed = link_speed_mbps("");
    EXPECT_FALSE(speed.has_value());
    if (!speed) {
        EXPECT_EQ(speed.error(), expected);
        EXPECT_NE(speed.error(), make_unknown_link_speed());
    }
}

TEST(interface_info, a_driver_answering_every_size_zero_has_no_rings)
{
    EXPECT_FALSE(has_rings(RingParams{}));
    EXPECT_FALSE(has_rings(RingParams{.rx_max = 0, .tx_max = 0, .rx = 0, .tx = 0}));
    EXPECT_TRUE(has_rings(RingParams{.rx_max = 4096, .tx_max = 4096, .rx = 256, .tx = 256}));
    EXPECT_TRUE(has_rings(RingParams{.rx_max = 512, .tx_max = 0, .rx = 512, .tx = 0}));  // RX rings alone are rings
    // Asked for the size it has (zero), a ringless answer would be refused as
    // an argument; reported as no rings, it is never asked.
    auto const refused = rx_ring_change(RingParams{}, 0);
    EXPECT_FALSE(refused.has_value());
}

TEST(interface_info, rx_ring_change_decides_without_a_nic)
{
    RingParams const params{.rx_max = 4096, .tx_max = 4096, .rx = 256, .tx = 256};
    auto const same = rx_ring_change(params, 256);
    EXPECT_TRUE(same.has_value() && !*same);
    auto const bigger = rx_ring_change(params, 2048);
    EXPECT_TRUE(bigger.has_value() && *bigger);
    auto const most = rx_ring_change(params, 4096);
    EXPECT_TRUE(most.has_value() && *most);
    for (auto const impossible : {uint32_t{0}, uint32_t{4097}}) {
        auto const refused = rx_ring_change(params, impossible);
        EXPECT_FALSE(refused.has_value());
        if (!refused) {
            EXPECT_EQ(refused.error(), std::make_error_code(std::errc::invalid_argument));
        }
    }
}

TEST(interface_info, parse_link_speed_reads_a_normal_speed)
{
    // sysfs writes the number with a trailing newline.
    auto const gigabit = parse_link_speed("1000\n");
    EXPECT_TRUE(gigabit.has_value());
    if (gigabit) {
        EXPECT_EQ(*gigabit, 1000u);
    }

    auto const fast_ethernet = parse_link_speed("100\n");
    EXPECT_TRUE(fast_ethernet.has_value());
    if (fast_ethernet) {
        // The case the shaper must not guess: ten times less credit than a
        // gigabit link needs for the same stream.
        EXPECT_EQ(*fast_ethernet, 100u);
    }
}

TEST(interface_info, parse_link_speed_treats_speed_unknown_as_no_speed)
{
    // SPEED_UNKNOWN is -1, and sysfs prints it literally. This is the
    // down-link case, reachable here with no NIC at all.
    auto const unknown = parse_link_speed("-1\n");
    EXPECT_FALSE(unknown.has_value());
    if (!unknown) {
        EXPECT_EQ(unknown.error(), make_unknown_link_speed());
    }
}

TEST(interface_info, parse_link_speed_treats_zero_as_no_speed_not_as_a_speed)
{
    // The failure mode this whole function exists to prevent: 0 accepted as
    // a link speed makes an idle-slope calculation reserve nothing, and the
    // talker bursts.
    auto const zero = parse_link_speed("0\n");
    EXPECT_FALSE(zero.has_value());
    if (!zero) {
        EXPECT_EQ(zero.error(), make_unknown_link_speed());
        EXPECT_NE(zero.error(), std::make_error_code(std::errc::bad_message));
    }
}

TEST(interface_info, parse_link_speed_rejects_text_that_is_not_a_number)
{
    // Distinguishable from "no speed": a garbled attribute is a fault,
    // a down link is not.
    for (auto const* text : {"", "unknown\n", "\n", " 1000"}) {
        auto const parsed = parse_link_speed(text);
        EXPECT_FALSE(parsed.has_value());
        if (!parsed) {
            EXPECT_EQ(parsed.error(), std::make_error_code(std::errc::bad_message));
        }
    }
}

TEST(interface_info, parse_link_speed_refuses_a_value_too_large_for_uint32)
{
    // Not a speed any link negotiates, but the cast would silently truncate.
    auto const huge = parse_link_speed("4294967296\n");
    EXPECT_FALSE(huge.has_value());
    if (!huge) {
        EXPECT_EQ(huge.error(), make_unknown_link_speed());
    }

    // And the largest value that does fit is still accepted.
    auto const at_limit = parse_link_speed("4294967295\n");
    EXPECT_TRUE(at_limit.has_value());
    if (at_limit) {
        EXPECT_EQ(*at_limit, 4294967295u);
    }
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_interface_info_test)
