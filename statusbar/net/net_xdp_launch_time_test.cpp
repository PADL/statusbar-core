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

#if defined(__linux__) && defined(HAVE_XDP)
#    include <net/if.h>
#endif

#include <cerrno>
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

// A closed context has no socket to time frames on, and the checked form
// must say so rather than write into a UMEM that is not there.
TEST(xdp_launch_time, a_closed_context_refuses_to_set_a_launch_time)
{
    XdpContext context;
    EXPECT_FALSE(context.tx_launch_time());
    auto const set = context.try_tx_set_launch_time(0, 1'000);
    EXPECT_FALSE(set.has_value());
    if (!set) {
#if defined(__linux__) && defined(HAVE_XDP)
        EXPECT_EQ(set.error(), make_error_code(XdpError::not_open));
#else
        // The stub has no socket to be closed; it says so in its own words.
        EXPECT_EQ(set.error(), make_error_code(XdpError::not_supported_on_platform));
#endif
    }
}

// The silent form is a statement on a commit path: it takes the same refusal
// without an answer to drop, and the context is as closed afterwards as before.
TEST(xdp_launch_time, the_silent_form_swallows_the_refusal_of_a_closed_context)
{
    XdpContext context;
    context.tx_set_launch_time(0, 1'000);
    EXPECT_FALSE(context.valid());
    EXPECT_FALSE(context.tx_launch_time());
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

// The kernel reads the metadata length only when XDP_UMEM_TX_METADATA_LEN is
// among the registration flags, and then refuses a length that is not a
// multiple of 8 with EINVAL. A registration without the flag would take this
// length, register no metadata, and drop every launch time after it while
// open() reported success; the probe passes either way, so this is the test
// that sees the flag. Registering a UMEM needs CAP_NET_RAW.
TEST(xdp_launch_time, a_metadata_length_the_kernel_cannot_take_is_refused_at_registration)
{
#if defined(__linux__) && defined(HAVE_XDP_TX_METADATA)
    detail::RingSet rings{};
    detail::UmemRegion umem;
    auto const registered = umem.allocate(2, 2048, 16, 8, 8, rings, 12);
    if (!registered && umem.create_errno() == EPERM) {
        SKIP("registering a UMEM needs CAP_NET_RAW");
    }
    EXPECT_FALSE(registered.has_value());
    EXPECT_EQ(umem.create_errno(), EINVAL);
#else
    SKIP("no AF_XDP TX metadata in this build");
#endif
}

// Counters are a soak readout; a run that has been going for days needs them
// zeroed without losing the socket.
TEST(xdp_launch_time, stats_can_be_reset_on_a_closed_context)
{
    XdpContext context;
    context.reset_stats();
    EXPECT_EQ(context.socket_stats().tx_count, uint64_t{0});
}

// Loopback never times a frame, on any kernel: the probe says so, and says it
// as the launch-time refusal rather than as a transport error. A kernel with
// no netdev family to ask (before 6.6) gives the same answer.
TEST(xdp_launch_time, loopback_has_no_launch_time_and_the_probe_says_so)
{
#if defined(__linux__) && defined(HAVE_XDP)
    auto const lo = ::if_nametoindex("lo");
    EXPECT_TRUE(lo > 0);
    auto const probed = probe_tx_launch_time(lo);
    EXPECT_FALSE(probed.has_value());
    if (!probed) {
        EXPECT_EQ(probed.error(), make_error_code(XdpError::launch_time_not_supported));
    }
#else
    auto const probed = probe_tx_launch_time(1);
    EXPECT_FALSE(probed.has_value());
    if (!probed) {
        EXPECT_EQ(probed.error(), make_error_code(XdpError::not_supported_on_platform));
    }
#endif
}

TEST_MAIN(statusbar_net, net_xdp_launch_time_test)
