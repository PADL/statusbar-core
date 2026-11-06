// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_xdp_shared_umem.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
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

/// The frames reopen() frees for `share`, in order.
auto reopened(XdpFrameLedger& ledger, size_t const share) -> std::vector<uint64_t>
{
    std::vector<uint64_t> frames;
    ledger.reopen(share, [&frames](uint64_t const addr) { frames.push_back(addr); });
    return frames;
}

}  // namespace

// A frame no transmit points into is free as soon as its owner gives it back.
TEST(xdp_frame_ledger, a_frame_never_lent_is_free_when_its_owner_gives_it_back)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    ledger.hold(3 * FRAME);
    EXPECT_FALSE(ledger.lent(3 * FRAME));
    EXPECT_TRUE(ledger.give_back(3 * FRAME));
    ledger.hold(3 * FRAME + 256);  // reused, received again
    EXPECT_TRUE(ledger.give_back(3 * FRAME + 256));
}

// A transmit may point into a frame only while its owner has it: a lend after the give back is refused, so a
// sender racing the owner's release never sends from a frame back in the fill ring.
TEST(xdp_frame_ledger, a_lend_is_refused_once_the_owner_gave_the_frame_back)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const frame = 2 * FRAME;
    EXPECT_FALSE(ledger.lend(frame, 1));  // never held: in the kernel or free
    ledger.hold(frame);
    EXPECT_TRUE(ledger.lend(frame + 300, 1));
    EXPECT_FALSE(ledger.give_back(frame));      // the transmit is not done
    EXPECT_FALSE(ledger.lend(frame + 600, 1));  // too late
    EXPECT_EQ(ledger.lent_by(frame, 1), size_t{1});
    EXPECT_FALSE(ledger.complete(frame + 300, 1));  // share 1's socket: queued for share 0
    EXPECT_TRUE(returns_of(ledger, 0) == std::vector<uint64_t>{frame});
}

// A frame lent to transmits goes back on the last of their completions, after its owner gave it back.
TEST(xdp_frame_ledger, a_lent_frame_goes_back_on_its_last_completion)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const frame = 2 * FRAME;
    ledger.hold(frame);
    EXPECT_TRUE(ledger.lend(frame + 300, 0));  // two packets gathered slices of it, on the owner's own socket
    EXPECT_TRUE(ledger.lend(frame + 1100, 0));
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
    ledger.hold(a);
    ledger.hold(b);
    EXPECT_TRUE(ledger.lend(a, 0) && ledger.lend(b, 0) && ledger.lend(a + 64, 0));
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
    ledger.hold(frame);
    ledger.hold(other);
    EXPECT_TRUE(ledger.lend(frame + 512, 1) && ledger.lend(other + 512, 0));
    EXPECT_FALSE(ledger.give_back(frame));
    EXPECT_FALSE(ledger.give_back(other));
    EXPECT_FALSE(ledger.complete(frame + 512, 1));  // share 1's socket sent it: queued for share 0
    EXPECT_FALSE(ledger.complete(other + 512, 0));
    EXPECT_TRUE(returns_of(ledger, 0) == std::vector<uint64_t>{frame});
    EXPECT_TRUE(returns_of(ledger, 1) == std::vector<uint64_t>{other});
    EXPECT_TRUE(returns_of(ledger, 0).empty());
}

// A completion without a loan of the completer's (its own frame sent whole, or a loan a closed socket forgot)
// returns nothing.
TEST(xdp_frame_ledger, a_completion_without_a_loan_is_nothing)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const frame = 4 * FRAME;
    ledger.hold(frame);
    EXPECT_TRUE(ledger.lend(frame, 1));
    EXPECT_FALSE(ledger.complete(frame, 0));  // share 0 has no loan on it
    EXPECT_TRUE(ledger.lent(frame));
    EXPECT_TRUE(ledger.give_back(frame + FRAME));  // not held: nothing
    EXPECT_FALSE(ledger.complete(frame, 1) || ledger.lent(frame));
}

// The queue between two shares holds every frame of a share at once, and in order.
TEST(xdp_frame_ledger, a_shares_every_frame_can_be_queued_at_once)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    std::vector<uint64_t> sent;
    for (size_t i = 0; i < PER_SHARE; ++i) {
        ledger.hold(i * FRAME);
        EXPECT_TRUE(ledger.lend(i * FRAME, 1));
        EXPECT_FALSE(ledger.give_back(i * FRAME));
    }
    for (size_t i = PER_SHARE; i > 0; --i) {  // completed last first
        EXPECT_FALSE(ledger.complete((i - 1) * FRAME, 1));
        sent.push_back((i - 1) * FRAME);
    }
    EXPECT_TRUE(returns_of(ledger, 0) == sent);
}

// A share opened afresh frees what neither the kernel nor a transmit holds, once each: a frame in the kernel
// comes back through its ring, a frame still lent at its completion, and one another share's completion
// freed before the reclaim pass is in its queue, not reclaimed as well.
TEST(xdp_frame_ledger, a_reopened_share_frees_what_nothing_holds_once)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    ledger.to_kernel(0 * FRAME);  // in the fill ring, or sent whole
    ledger.hold(1 * FRAME);       // held, and still lent at the reopen
    EXPECT_TRUE(ledger.lend(1 * FRAME, 1));
    ledger.hold(2 * FRAME);  // lent, given back, completed before the reopen: queued
    EXPECT_TRUE(ledger.lend(2 * FRAME, 1));
    EXPECT_FALSE(ledger.give_back(2 * FRAME));
    EXPECT_FALSE(ledger.complete(2 * FRAME, 1));
    ledger.hold(3 * FRAME);  // held by a sink that forgot it
    auto const freed = reopened(ledger, 0);
    EXPECT_EQ(freed.size(), PER_SHARE - 2);  // all but the kernel's and the lent one
    EXPECT_TRUE(std::ranges::find(freed, uint64_t{0 * FRAME}) == freed.end());
    EXPECT_TRUE(std::ranges::find(freed, uint64_t{1 * FRAME}) == freed.end());
    EXPECT_TRUE(std::ranges::count(freed, uint64_t{2 * FRAME}) == 1);
    EXPECT_TRUE(std::ranges::count(freed, uint64_t{3 * FRAME}) == 1);
    EXPECT_TRUE(returns_of(ledger, 0).empty());
    EXPECT_FALSE(ledger.complete(1 * FRAME, 1));  // the old owner's done: home through the queue
    EXPECT_TRUE(returns_of(ledger, 0) == std::vector<uint64_t>{1 * FRAME});
    ledger.pool_gone(0);  // the socket's queue is gone with it: the kernel holds nothing
    auto const again = reopened(ledger, 0);
    EXPECT_TRUE(again.size() == PER_SHARE && again.front() == 0);  // the kernel's too, and the free list's again
}

// A completion landing after the reclaim pass but before the queues are drained is freed by the drain, once.
TEST(xdp_frame_ledger, a_completion_during_a_reopen_is_freed_once)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    for (size_t i = 1; i < PER_SHARE; ++i) {
        ledger.to_kernel(i * FRAME);  // nothing to reclaim but frame 0
    }
    ledger.hold(5 * FRAME);
    EXPECT_TRUE(ledger.lend(5 * FRAME, 1));
    EXPECT_FALSE(ledger.give_back(5 * FRAME));
    std::vector<uint64_t> freed;
    ledger.reopen(0, [&](uint64_t const addr) {
        freed.push_back(addr);
        if (addr == 0) {
            EXPECT_FALSE(ledger.complete(5 * FRAME, 1));  // lands mid-reopen, after the pass left it lent: queued
        }
    });
    EXPECT_TRUE(freed == std::vector<uint64_t>({0, 5 * FRAME}));  // the drain freed it
    EXPECT_TRUE(returns_of(ledger, 0).empty());
}

// A closing socket's loans are undone as their completions would be: the frames go home.
TEST(xdp_frame_ledger, a_closed_sockets_loans_are_forgotten)
{
    XdpFrameLedger ledger{PER_SHARE, 2, FRAME};
    uint64_t const theirs = 2 * FRAME;                // share 0's, lent to share 1 twice
    uint64_t const own = (PER_SHARE + 1) * FRAME;     // share 1's own, lent to itself
    uint64_t const others = (PER_SHARE + 3) * FRAME;  // share 1's, lent to share 0: not share 1's to forget
    ledger.hold(theirs);
    ledger.hold(own);
    ledger.hold(others);
    EXPECT_TRUE(ledger.lend(theirs, 1) && ledger.lend(theirs + 64, 1) && ledger.lend(own, 1) && ledger.lend(others, 0));
    EXPECT_FALSE(ledger.give_back(theirs));
    EXPECT_FALSE(ledger.give_back(own));
    ledger.forget(1);
    EXPECT_EQ(ledger.lent_by(theirs, 1), size_t{0});
    EXPECT_TRUE(returns_of(ledger, 0) == std::vector<uint64_t>{theirs});
    EXPECT_TRUE(reopened(ledger, 1).size() == PER_SHARE - 1);  // own freed; others still lent to share 0
    EXPECT_TRUE(ledger.lent(others));
}

#if defined(__linux__) && defined(HAVE_XDP)
// A UMEM address is had only for bytes wholly inside one frame of the area: a descriptor never crosses a chunk.
TEST(xdp_shared_umem, addresses_lie_within_one_frame_of_the_area)
{
    auto umem = XdpSharedUmem::create(4, 2, 2048);
    EXPECT_TRUE(umem.has_value());
    if (!umem) {
        return;
    }
    auto const& shared = **umem;
    EXPECT_EQ(shared.size(), size_t{8 * 2048});
    EXPECT_TRUE(shared.registered() == nullptr && shared.anchor() == nullptr);
    uint8_t const* const area = shared.area();
    EXPECT_TRUE(shared.address_of(area + 100, 500) == std::optional<uint64_t>{100});
    EXPECT_TRUE(shared.address_of(area + 2048 * 5 + 10, 2038) == std::optional<uint64_t>{2048 * 5 + 10});
    EXPECT_TRUE(shared.address_of(area + 2000, 100) == std::nullopt);  // across two frames
    EXPECT_TRUE(shared.address_of(area + 2048 * 8 - 10, 20) == std::nullopt);
    EXPECT_TRUE(shared.address_of(area - 1, 10) == std::nullopt);
    EXPECT_TRUE(shared.address_of(area, 0) == std::nullopt);
    EXPECT_FALSE(XdpSharedUmem::create(4, 0).has_value());
    EXPECT_FALSE(XdpSharedUmem::create(4, 5).has_value());
    EXPECT_FALSE(XdpSharedUmem::create(4, 2, 3000).has_value());
}
#endif

TEST_MAIN(statusbar_net, net_xdp_shared_umem_test)
