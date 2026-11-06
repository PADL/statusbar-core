// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_xdp_shared_umem.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr size_t FRAME = 4096;
constexpr size_t PER_SHARE = 8;

/// The frames returned to `share`, in order.
auto returns_of(XdpFrameLedger& ledger, size_t const share) -> std::vector<uint64_t>
{
    std::vector<uint64_t> frames;
    ledger.collect_returns(share, [&frames](uint64_t const addr) { frames.push_back(addr); });
    return frames;
}

}  // namespace

// A frame no transmit points into is free as soon as its owner gives it back.
TEST(xdp_frame_ledger, a_frame_never_lent_is_free_when_its_owner_gives_it_back)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    EXPECT_FALSE(ledger.lent(3 * FRAME));
    EXPECT_TRUE(ledger.give_back(3 * FRAME));
    EXPECT_TRUE(ledger.give_back(3 * FRAME + 256));  // reused, received again, released again
}

// A frame lent to transmits goes back on the last of their completions, after its owner gave it back.
TEST(xdp_frame_ledger, a_lent_frame_goes_back_on_its_last_completion)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const frame = 2 * FRAME;
    ledger.lend(frame + 300);  // two packets gathered slices of it
    ledger.lend(frame + 1100);
    EXPECT_TRUE(ledger.lent(frame));
    EXPECT_FALSE(ledger.give_back(frame + 256));  // the ring is done; the transmits are not
    EXPECT_FALSE(ledger.complete(frame + 300, 0));
    EXPECT_TRUE(ledger.complete(frame + 1100, 0));  // the owner's own share: free here
    EXPECT_FALSE(ledger.lent(frame));
    EXPECT_TRUE(returns_of(ledger, 0).empty());
}

// Completions before the owner is done leave the frame to the owner, whatever their order.
TEST(xdp_frame_ledger, completions_before_the_owner_gives_back_leave_it_to_the_owner)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const a = 1 * FRAME;
    uint64_t const b = 5 * FRAME;
    ledger.lend(a);
    ledger.lend(b);
    ledger.lend(a + 64);
    EXPECT_FALSE(ledger.complete(b, 0));  // out of order: b's before a's
    EXPECT_FALSE(ledger.complete(a + 64, 0));
    EXPECT_TRUE(ledger.give_back(b));   // b's transmit is done: free now
    EXPECT_FALSE(ledger.give_back(a));  // a still has one
    EXPECT_TRUE(ledger.complete(a, 0));
}

// A frame lent to another share's socket comes back to its owner through the owner's queue, once.
TEST(xdp_frame_ledger, a_frame_completed_on_another_share_returns_through_its_queue)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const frame = 3 * FRAME;                // share 0's
    uint64_t const other = (PER_SHARE + 2) * FRAME;  // share 1's
    EXPECT_EQ(ledger.share_of(frame), size_t{0});
    EXPECT_EQ(ledger.share_of(other), size_t{1});
    ledger.lend(frame + 512);
    ledger.lend(other + 512);
    EXPECT_FALSE(ledger.give_back(frame));
    EXPECT_FALSE(ledger.give_back(other));
    EXPECT_FALSE(ledger.complete(frame + 512, 1));  // share 1's socket sent it: queued for share 0
    EXPECT_FALSE(ledger.complete(other + 512, 0));
    EXPECT_TRUE(returns_of(ledger, 0) == std::vector<uint64_t>{frame});
    EXPECT_TRUE(returns_of(ledger, 1) == std::vector<uint64_t>{other});
    EXPECT_TRUE(returns_of(ledger, 0).empty());
}

// The queue between two shares holds every frame of a share at once, and in order.
TEST(xdp_frame_ledger, a_shares_every_frame_can_be_queued_at_once)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    std::vector<uint64_t> sent;
    for (size_t i = 0; i < PER_SHARE; ++i) {
        ledger.lend(i * FRAME);
        EXPECT_FALSE(ledger.give_back(i * FRAME));
    }
    for (size_t i = PER_SHARE; i > 0; --i) {  // completed last first
        EXPECT_FALSE(ledger.complete((i - 1) * FRAME, 1));
        sent.push_back((i - 1) * FRAME);
    }
    EXPECT_TRUE(returns_of(ledger, 0) == sent);
}

#if defined(__linux__) && defined(HAVE_XDP)
// A UMEM address is had only for bytes wholly inside one frame of the area: a descriptor never crosses a chunk.
TEST(xdp_shared_umem, addresses_lie_within_one_frame_of_the_area)
{
    auto created = XdpSharedUmem::create(PER_SHARE, 2, FRAME);
    EXPECT_TRUE(created.has_value());
    if (!created) {
        return;
    }
    auto const& umem = **created;
    EXPECT_EQ(umem.size(), PER_SHARE * 2 * FRAME);
    EXPECT_TRUE(umem.address_of(umem.area() + FRAME + 300, 600) == std::optional<uint64_t>{FRAME + 300});
    EXPECT_FALSE(umem.address_of(umem.area() + FRAME - 10, 20).has_value());
    EXPECT_FALSE(umem.address_of(umem.area() + umem.size() - 4, 8).has_value());
    uint8_t const outside = 0;
    EXPECT_FALSE(umem.address_of(&outside, 1).has_value());
    EXPECT_FALSE(XdpSharedUmem::create(PER_SHARE, XdpFrameLedger::MAX_SHARES + 1, FRAME).has_value());
    EXPECT_FALSE(XdpSharedUmem::create(PER_SHARE, 2, 3000).has_value());
}
#endif

TEST_MAIN(statusbar_net, net_xdp_shared_umem_test)
