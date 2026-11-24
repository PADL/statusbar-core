// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the PACKET_MMAP backend: the rules it applies before the kernel
/// sees a frame, which need no ring, and the ring behaviour that needs
/// CAP_NET_RAW and skips without it.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_linux_mmap.hpp"
#include "statusbar/test/test.hpp"

#include <cstddef>
#include <string>
#include <system_error>

using namespace statusbar;
using namespace statusbar::net;

//
// The TX length bound. af_packet refuses a send longer than
// mtu + hard_header_len + VLAN_HLEN with EMSGSIZE and leaves the slot
// TP_STATUS_WRONG_FORMAT at the head of the ring, where the kernel stops
// for good; the bound is applied on our side so that never happens.
//

#if defined(__linux__)

TEST(mmap_tx_length, a_frame_past_the_limit_is_refused_and_its_slot_comes_back)
{
    MmapContext port;
    auto const status = port.open({.interface_name = "lo", .ethertype = ieee::protocols::ETHERTYPE_AVTP, .tx_queue_size = 4});
    if (!status.has_value()) {
        SKIP("needs CAP_NET_RAW (AF_PACKET open refused)");
    }
    // Loopback's MTU is far past the slot, so the slot is the limit.
    EXPECT_EQ(port.max_tx_frame_length(), MMAP_MAX_FRAME_LENGTH);

    auto const slot = port.tx_start();
    EXPECT_TRUE(slot.has_value());
    if (!slot.has_value()) {
        return;
    }
    EXPECT_EQ(slot->buffer.size(), port.max_tx_frame_length());

    auto const refused = port.tx_commit(slot->handle, port.max_tx_frame_length() + 1);
    EXPECT_FALSE(refused.has_value());
    if (!refused) {
        EXPECT_EQ(refused.error(), make_error_code(MmapError::frame_too_long));
    }

    // The slot is the next one handed out: no hole in the ring, nothing
    // committed after it held up.
    auto const again = port.tx_start();
    EXPECT_TRUE(again.has_value());
    if (again.has_value()) {
        EXPECT_EQ(again->handle, slot->handle);
        EXPECT_TRUE(port.tx_cancel(again->handle).has_value());
    }
    port.close();
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_linux_mmap_functional_test)
