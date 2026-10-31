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

/// Name of some interface that is not `lo`, if the host has one. Used
/// for the queries `lo` cannot answer; without one those tests skip.
auto a_real_interface() -> std::string
{
    DIR* dir = ::opendir("/sys/class/net");
    if (dir == nullptr) {
        return {};
    }
    std::string found;
    while (dirent const* entry = ::readdir(dir)) {
        std::string_view const name{entry->d_name};
        if (name != "." && name != ".." && name != "lo") {
            found = name;
            break;
        }
    }
    ::closedir(dir);
    return found;
}

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

TEST(interface_info, interface_index_of_lo_is_positive)
{
    auto const index = interface_index("lo");
    EXPECT_TRUE(index.has_value());
    if (index) {
        EXPECT_TRUE(*index > 0);
    }
}

TEST(interface_info, interface_index_agrees_with_if_nametoindex)
{
    auto const index = interface_index("lo");
    EXPECT_TRUE(index.has_value());
    if (index) {
        EXPECT_EQ(static_cast<unsigned>(*index), ::if_nametoindex("lo"));
    }
}

TEST(interface_info, interface_mtu_of_lo_is_reported)
{
    // Loopback's MTU is large (65536 on Linux) but the point is only that
    // it is a real, positive number read off the kernel rather than a
    // default we invented.
    auto const mtu = interface_mtu("lo");
    EXPECT_TRUE(mtu.has_value());
    if (mtu) {
        EXPECT_TRUE(*mtu >= 1500);
    }
}

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

TEST(interface_info, lo_has_no_driver_and_says_so_distinguishably)
{
    // `lo` has no ethtool operations, so GDRVINFO fails with EOPNOTSUPP.
    // That must not be confused with "no such interface": a caller
    // deciding whether it is on igb/igc needs to tell "this interface
    // cannot answer" from "this interface does not exist".
    auto const driver = driver_name("lo");
    EXPECT_FALSE(driver.has_value());
    if (!driver) {
        EXPECT_EQ(driver.error(), std::make_error_code(std::errc::operation_not_supported));
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

TEST(interface_info, a_nonexistent_interface_fails_as_no_such_device)
{
    // All five, including the two that read sysfs rather than call an
    // ioctl: a missing sysfs directory reports ENOENT, which must be
    // mapped so a caller sees one answer for "no such interface".
    constexpr std::string_view MISSING = "nosuchif0";
    auto const expected = std::make_error_code(std::errc::no_such_device);

    auto const index = interface_index(MISSING);
    EXPECT_FALSE(index.has_value());
    if (!index) {
        EXPECT_EQ(index.error(), expected);
    }

    auto const mtu = interface_mtu(MISSING);
    EXPECT_FALSE(mtu.has_value());
    if (!mtu) {
        EXPECT_EQ(mtu.error(), expected);
    }

    auto const driver = driver_name(MISSING);
    EXPECT_FALSE(driver.has_value());
    if (!driver) {
        EXPECT_EQ(driver.error(), expected);
    }

    auto const queues = tx_queue_count(MISSING);
    EXPECT_FALSE(queues.has_value());
    if (!queues) {
        EXPECT_EQ(queues.error(), expected);
    }

    auto const speed = link_speed_mbps(MISSING);
    EXPECT_FALSE(speed.has_value());
    if (!speed) {
        EXPECT_EQ(speed.error(), expected);
    }
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

TEST(interface_info, a_name_of_exactly_ifnamsiz_minus_one_is_not_refused_for_length)
{
    // The boundary. IFNAMSIZ-1 characters plus the terminator is exactly
    // what ifr_name holds, so such a name must reach the kernel and come
    // back ENODEV — not ENAMETOOLONG.
    std::string const longest_legal(IFNAMSIZ - 1, 'x');

    auto const index = interface_index(longest_legal);
    EXPECT_FALSE(index.has_value());
    if (!index) {
        EXPECT_EQ(index.error(), std::make_error_code(std::errc::no_such_device));
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

TEST(interface_info, a_real_interface_reports_a_driver_name)
{
    auto const name = a_real_interface();
    if (name.empty()) {
        return;  // a host with only `lo`
    }

    // Not asserting *which* driver: the point is that a non-virtual
    // interface answers with a non-empty name, which is how FEAT-010
    // would find out it is on igb or igc.
    auto const driver = driver_name(name);
    if (driver) {
        EXPECT_FALSE(driver->empty());
    } else {
        // A virtual interface (veth, a bridge) may also lack ethtool ops;
        // that is the same clean failure `lo` gives, not a fault.
        EXPECT_EQ(driver.error(), std::make_error_code(std::errc::operation_not_supported));
    }
}

TEST(interface_info, every_interface_the_host_has_answers_index_mtu_and_queues)
{
    // A sweep rather than a single subject: these three must work for
    // every interface present, virtual ones included, because `lo` is
    // what CI runs on and a veth is what the root tests use.
    DIR* dir = ::opendir("/sys/class/net");
    EXPECT_TRUE(dir != nullptr);
    if (dir == nullptr) {
        return;
    }

    int checked = 0;
    while (dirent const* entry = ::readdir(dir)) {
        std::string_view const name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        EXPECT_TRUE(interface_index(name).has_value());
        EXPECT_TRUE(interface_mtu(name).has_value());

        // Not just "has a value": the count must be the TX queues alone.
        // Every interface also has rx-N directories, plus "." and "..", so
        // a count that forgot its prefix would still look plausible.
        auto const queues = tx_queue_count(name);
        EXPECT_TRUE(queues.has_value());
        if (queues) {
            EXPECT_EQ(*queues, expected_tx_queues(name));
        }
        ++checked;
    }
    ::closedir(dir);
    EXPECT_TRUE(checked > 0);
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
