// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The PTP hardware clock's pins and periodic outputs: the pure parts
// everywhere, and on Linux the device against whatever clock the host has,
// read-only where that is all the test is allowed.

#include "statusbar/net/net_phc.hpp"
#include "statusbar/test/test.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

#if defined(__linux__)
#    include <dirent.h>
#    include <unistd.h>
#endif

using namespace statusbar;
using namespace statusbar::net::phc;

#if defined(__linux__)

namespace {

/// The device node of some clock the host has, found through its interfaces;
/// empty when there is none.
auto a_clock_node() -> std::string
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
        auto const index = phc_index(name);
        if (index && index->has_value()) {
            found = phc_device_path(**index);
            break;
        }
    }
    ::closedir(dir);
    return found;
}

}  // namespace

TEST(phc, the_loopback_interface_has_no_hardware_clock)
{
    auto const none = phc_index("lo");
    EXPECT_TRUE(none.has_value());
    EXPECT_TRUE(none && !none->has_value());
    EXPECT_FALSE(phc_index("statusbar-nosuch0").has_value());
    EXPECT_EQ(phc_device_path(3), std::string{"/dev/ptp3"});
}

TEST(phc, the_hosts_clock_reports_what_it_can_do)
{
    auto const node = a_clock_node();
    if (node.empty()) {
        SKIP("no interface here has a hardware clock");
    }
    PhcDevice clock;
    auto const opened = clock.open(node);
    if (!opened) {
        SKIP("the clock's device node cannot be opened here");
    }
    EXPECT_TRUE(clock.is_open());
    auto const caps = clock.capabilities();
    EXPECT_TRUE(caps.has_value());
    if (!caps) {
        return;
    }
    EXPECT_TRUE(caps->pins >= 0 && caps->periodic_output_channels >= 0 && caps->external_timestamp_channels >= 0);
    auto const now = clock.time_ns();
    EXPECT_TRUE(now.has_value());
    // Every pin the clock has is described; the one past the last is not.
    for (int32_t index = 0; index < caps->pins; ++index) {
        auto const pin = clock.pin(static_cast<uint32_t>(index));
        EXPECT_TRUE(pin.has_value());
        EXPECT_TRUE(pin && pin->index == static_cast<uint32_t>(index));
    }
    EXPECT_FALSE(clock.pin(static_cast<uint32_t>(caps->pins)).has_value());
    // A request that is wrong is refused before anything is asked of the
    // clock, privilege or none.
    auto const bad = clock.periodic_output(PeriodicOutput{.channel = 0, .period_ns = 1000, .phase_ns = 1000});
    EXPECT_TRUE(!bad && bad.error() == std::make_error_code(std::errc::invalid_argument));
    if (!clock.writable()) {
        auto const set = clock.set_pin(0, PinFunction::none, 0);
        EXPECT_TRUE(!set && set.error() == std::errc::operation_not_permitted);
        auto const output = clock.periodic_output(PeriodicOutput{.channel = 0, .period_ns = 1'000'000'000});
        EXPECT_TRUE(!output && output.error() == std::errc::operation_not_permitted);
        return;
    }
    if (caps->periodic_output_channels == 0) {
        // Writable, and nothing to write to: the clock refuses the channel.
        EXPECT_FALSE(clock.periodic_output(PeriodicOutput{.channel = 0, .period_ns = 1'000'000'000}).has_value());
    }
    clock.close();
    EXPECT_FALSE(clock.is_open());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_phc_functional_test)
