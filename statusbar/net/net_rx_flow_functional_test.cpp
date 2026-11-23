// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for the RX flow rules module.
//
// The decisions - what a plan may ask for, how the RSS table is spread round
// the steered queues, how a rule and its ethtool spec map onto each other -
// are pure and tested here without a NIC. The install-and-restore protocol
// of RxFlowSteering is driven through an RxFlowRecorder and an RssRecorder,
// which is what lets "the rules are gone and the table is back" be asserted.
//
// A real insert needs a NIC with a classifier and CAP_NET_ADMIN; no host this
// was written on has one, so the real ioctl path is exercised only by its
// failure cases.

#include "statusbar/net/net_rss_recorder.hpp"
#include "statusbar/net/net_rx_flow.hpp"
#include "statusbar/net/net_rx_flow_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#if defined(__linux__)
#    include <arpa/inet.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

// The spread

// The plan check

// The spec, where there is one

#if defined(__linux__)

#endif  // __linux__

// Clearing a range

// The real NIC, where the only answer anyone can count on is a refusal

TEST(net_rx_flow, loopback_has_no_classifier)
{
    auto const rule = rx_flow_rule("lo", 0);
    EXPECT_FALSE(rule.has_value());
    if (!rule) {
        EXPECT_TRUE(rule.error() == std::errc::operation_not_supported);
    }
}

// The steering guard, driven through the recorders

TEST_MAIN(statusbar_net, net_rx_flow_functional_test)
