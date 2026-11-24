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

TEST(interface_info, a_real_interface_reports_a_driver_name)
{
    auto const name = a_real_interface();
    if (name.empty()) {
        return;  // a host with only `lo`
    }

    // Not asserting *which* driver: the point is that a non-virtual
    // interface answers with a non-empty name, which is how a launch-time
    // probe would find out it is on igb or igc.
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

// `lo` has no rings, and says so the way it says it has no driver.
TEST(interface_info, lo_has_no_rings_and_says_so_distinguishably)
{
    auto const rings = ring_params("lo");
    EXPECT_FALSE(rings.has_value());
    if (!rings) {
        EXPECT_EQ(rings.error(), std::make_error_code(std::errc::operation_not_supported));
    }
    auto const set = set_rx_ring("lo", 256);
    EXPECT_FALSE(set.has_value());
    if (!set) {
        EXPECT_EQ(set.error(), std::make_error_code(std::errc::operation_not_supported));
    }
}

/// Some interface with descriptor rings, if the host has one: a real NIC,
/// not a virtual device. Empty when there is none.
/// An interface with an RX ring that is set: one set_rx_ring() can be asked
/// for the size it has.
auto an_interface_with_rings() -> std::string
{
    DIR* dir = ::opendir("/sys/class/net");
    if (dir == nullptr) {
        return {};
    }
    std::string found;
    while (dirent const* entry = ::readdir(dir)) {
        std::string const name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (auto const rings = ring_params(name); rings && rings->rx > 0) {
            found = name;
            break;
        }
    }
    ::closedir(dir);
    return found;
}

TEST(interface_info, every_interface_answers_about_its_rings_or_refuses_cleanly)
{
    DIR* dir = ::opendir("/sys/class/net");
    EXPECT_TRUE(dir != nullptr);
    if (dir == nullptr) {
        return;
    }
    while (dirent const* entry = ::readdir(dir)) {
        std::string const name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        auto const rings = ring_params(name);
        if (!rings) {
            // A virtual interface has no rings, and neither has a driver whose
            // answer is every size zero: the same clean failure lo gives.
            EXPECT_EQ(rings.error(), std::make_error_code(std::errc::operation_not_supported));
            continue;
        }
        // What came back has rings, and the sizes set fit them.
        EXPECT_TRUE(has_rings(*rings));
        EXPECT_TRUE(rings->rx <= rings->rx_max);
        EXPECT_TRUE(rings->tx <= rings->tx_max);
    }
    ::closedir(dir);
}

// Setting the size the ring already has is read and not written, so it needs
// no privilege and costs no reset - which is what lets it be proved here.
TEST(interface_info, setting_the_rx_ring_to_the_size_it_has_writes_nothing)
{
    auto const name = an_interface_with_rings();
    if (name.empty()) {
        SKIP("no interface here has descriptor rings");
    }
    auto const rings = ring_params(name);
    EXPECT_TRUE(rings.has_value());
    if (!rings) {
        return;
    }
    auto const same = set_rx_ring(name, rings->rx);
    EXPECT_TRUE(same.has_value());
    if (same) {
        EXPECT_TRUE(*same == *rings);
    }
    // A size the driver cannot do is refused before anything is written.
    auto const too_many = set_rx_ring(name, rings->rx_max + 1);
    EXPECT_FALSE(too_many.has_value());
    if (!too_many) {
        EXPECT_EQ(too_many.error(), std::make_error_code(std::errc::invalid_argument));
    }
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_interface_info_functional_test)
