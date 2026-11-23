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

TEST_MAIN(statusbar_net, net_xdp_launch_time_functional_test)
