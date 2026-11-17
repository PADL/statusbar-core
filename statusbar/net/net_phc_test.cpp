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

TEST(phc, a_time_splits_into_seconds_and_nanoseconds_that_are_never_negative)
{
    EXPECT_TRUE((clock_time_from_ns(0) == ClockTime{.sec = 0, .nsec = 0}));
    EXPECT_TRUE((clock_time_from_ns(1'500'000'000) == ClockTime{.sec = 1, .nsec = 500'000'000}));
    EXPECT_TRUE((clock_time_from_ns(3'000'000'000) == ClockTime{.sec = 3, .nsec = 0}));
    EXPECT_TRUE((clock_time_from_ns(999'999'999) == ClockTime{.sec = 0, .nsec = 999'999'999}));
    // A negative time borrows a second: the kernel's nsec is unsigned.
    EXPECT_TRUE((clock_time_from_ns(-1) == ClockTime{.sec = -1, .nsec = 999'999'999}));
    EXPECT_TRUE((clock_time_from_ns(-2'000'000'000) == ClockTime{.sec = -2, .nsec = 0}));
}

TEST(phc, a_period_of_zero_turns_the_output_off_and_asks_for_nothing_else)
{
    PeriodicOutput const off{.channel = 1, .period_ns = 0, .phase_ns = 5, .on_ns = 7, .one_shot = true};
    auto const flags = perout_flags(off);
    EXPECT_TRUE(flags.has_value() && *flags == 0);
}

TEST(phc, the_flags_follow_what_the_request_asks_for)
{
    PeriodicOutput const pps{.channel = 0, .period_ns = 1'000'000'000, .start_ns = 10'000'000'000};
    auto const plain = perout_flags(pps);
    EXPECT_TRUE(plain.has_value() && *plain == 0);

    PeriodicOutput const aligned{.channel = 0, .period_ns = 1'000'000'000, .phase_ns = 0};
    auto const phase = perout_flags(aligned);
    EXPECT_TRUE(phase.has_value() && *phase == PEROUT_PHASE);

    PeriodicOutput const shaped{
        .channel = 0, .period_ns = 1'000'000'000, .phase_ns = 250'000'000, .on_ns = 100'000'000, .one_shot = true};
    auto const all = perout_flags(shaped);
    EXPECT_TRUE(all.has_value() && *all == (PEROUT_PHASE | PEROUT_DUTY_CYCLE | PEROUT_ONE_SHOT));
}

TEST(phc, a_request_the_kernel_would_refuse_is_refused_here_first)
{
    auto const refused = [](PeriodicOutput const& output) {
        auto const flags = perout_flags(output);
        return !flags.has_value() && flags.error() == std::make_error_code(std::errc::invalid_argument);
    };
    EXPECT_TRUE(refused(PeriodicOutput{.period_ns = -1}));
    EXPECT_TRUE(refused(PeriodicOutput{.period_ns = 1000, .phase_ns = 1000}));  // not below the period
    EXPECT_TRUE(refused(PeriodicOutput{.period_ns = 1000, .phase_ns = -1}));
    EXPECT_TRUE(refused(PeriodicOutput{.period_ns = 1000, .on_ns = 1000}));
    EXPECT_TRUE(refused(PeriodicOutput{.period_ns = 1000, .on_ns = -5}));
    EXPECT_TRUE(perout_flags(PeriodicOutput{.period_ns = 1000, .phase_ns = 999, .on_ns = 999}).has_value());
}

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

TEST(phc, a_closed_device_answers_bad_file_descriptor)
{
    PhcDevice clock;
    EXPECT_FALSE(clock.is_open());
    EXPECT_FALSE(clock.writable());
    auto const caps = clock.capabilities();
    EXPECT_TRUE(!caps && caps.error() == std::errc::bad_file_descriptor);
    EXPECT_TRUE(!clock.time_ns().has_value());
    EXPECT_TRUE(!clock.pin(0).has_value());
    EXPECT_TRUE(!clock.set_pin(0, PinFunction::none, 0).has_value());
    EXPECT_TRUE(!clock.periodic_output(PeriodicOutput{.period_ns = 1000}).has_value());
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

TEST_MAIN(statusbar_net, net_phc_test)
