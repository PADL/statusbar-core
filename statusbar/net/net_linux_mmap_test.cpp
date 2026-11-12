// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the PACKET_MMAP backend: the rules it applies before the kernel
/// sees a frame, which need no ring, and the ring behaviour that needs
/// CAP_NET_RAW and skips without it.

#include "statusbar/net/net_linux_mmap.hpp"

#include "statusbar/ieee/ieee.hpp"
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

TEST(mmap_tx_length, a_1500_mtu_device_takes_one_tag_past_the_mtu)
{
    static_assert(mmap_max_tx_frame_length(1500) == 1518);
    EXPECT_EQ(mmap_max_tx_frame_length(1500), 1518U);
}

TEST(mmap_tx_length, the_slot_is_the_limit_on_a_device_whose_mtu_allows_more)
{
    // 1504 is the first MTU whose kernel limit reaches the QinQ slot.
    static_assert(mmap_max_tx_frame_length(1504) == MMAP_MAX_FRAME_LENGTH);
    static_assert(mmap_max_tx_frame_length(9000) == MMAP_MAX_FRAME_LENGTH);
    EXPECT_EQ(mmap_max_tx_frame_length(65536), MMAP_MAX_FRAME_LENGTH);
}

TEST(mmap_tx_length, a_smaller_mtu_bounds_tighter)
{
    static_assert(mmap_max_tx_frame_length(1280) == 1298);
    EXPECT_EQ(mmap_max_tx_frame_length(576), 594U);
}

TEST(mmap_tx_length, a_context_that_is_not_open_has_the_slot_limit)
{
    MmapContext ctx;
    EXPECT_EQ(ctx.max_tx_frame_length(), MMAP_MAX_FRAME_LENGTH);
}

TEST(mmap_error, frame_too_long_has_a_message_of_its_own)
{
    std::error_code const ec = MmapError::frame_too_long;
    EXPECT_FALSE(ec.message().empty());
    EXPECT_TRUE(ec.message() != std::error_code{MmapError::invalid_index}.message());
    EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
}

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

TEST_MAIN(statusbar_net, net_linux_mmap_test)
