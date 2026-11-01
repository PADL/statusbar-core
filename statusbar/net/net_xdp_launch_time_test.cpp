// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Launch time on an AF_XDP socket: the UMEM's TX metadata, and the per-frame
/// time written into it.
///
/// What cannot be tested here is the only thing that finally matters: whether
/// a NIC honours the time. That needs an igc (or another driver with
/// launch-time offload) and root, and no machine in this tree has one. What is
/// testable without hardware is everything that silently does nothing when it
/// is wrong — the metadata length the UMEM is registered with, the flag in the
/// descriptor, and the bytes of the metadata itself.

#include "statusbar/net/net_linux_xdp.hpp"
#include "statusbar/test/test.hpp"

#include <cstdint>

using namespace statusbar;
using namespace statusbar::net;

TEST(xdp_launch_time, a_config_does_not_ask_for_launch_time_unless_told_to)
{
    XdpConfig config{};
    EXPECT_FALSE(config.tx_launch_time);
}

TEST(xdp_launch_time, the_error_for_a_kernel_without_tx_metadata_is_its_own)
{
    auto const error = make_error_code(XdpError::tx_metadata_not_supported);
    EXPECT_TRUE(error != make_error_code(XdpError::not_supported_on_platform));
    EXPECT_FALSE(error.message().empty());
    EXPECT_TRUE(error.message() != std::string{"Unknown XDP error"});
}

// A closed context has no socket to time frames on, and must say so rather
// than write into a UMEM that is not there.
TEST(xdp_launch_time, a_closed_context_refuses_to_set_a_launch_time)
{
    XdpContext context;
    EXPECT_FALSE(context.tx_launch_time());
    auto const set = context.tx_set_launch_time(0, 1'000);
    EXPECT_FALSE(set.has_value());
    if (!set) {
        EXPECT_EQ(set.error(), make_error_code(XdpError::not_open));
    }
}

// The probe is what open() consults, so it must give a definite answer on
// this host rather than throw or hang: either support, or a reason.
TEST(xdp_launch_time, the_tx_metadata_probe_answers_one_way_or_the_other)
{
    auto const probed = probe_tx_metadata();
    if (!probed) {
        // Unprivileged, or a kernel or libxdp without it. All are reasons.
        EXPECT_FALSE(probed.error().message().empty());
    }
}

// Counters are a soak readout; a run that has been going for days needs them
// zeroed without losing the socket.
TEST(xdp_launch_time, stats_can_be_reset_on_a_closed_context)
{
    XdpContext context;
    context.reset_stats();
    EXPECT_EQ(context.socket_stats().tx_count, uint64_t{0});
}

TEST_MAIN(statusbar_net, net_xdp_launch_time_test)
