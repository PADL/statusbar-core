// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// LaunchOrder: launch times kept in commit order on one socket (igc's FIFO), untimed frames at now,
// a backward clock step dropping the floor.

#include "statusbar/net/net_launch_order.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>

using statusbar::net::LaunchOrder;

namespace {

constexpr uint64_t FRAME_NS = 20'833;  // one frame at 48 kHz
constexpr uint64_t TICK_NS = 125'000;
constexpr uint64_t BASE_NS = 1'800'000'000ULL * 1'000'000'000ULL;

}  // namespace

// Two sources on one socket whose departures fall 4 frames apart, committed A then B each tick:
// launch times never decrease, A is never held, B waits at most for A, under a packet (not counted:
// the design's rounding); a hold over a packet is. An untimed frame goes at now, or after the last
// time given.
TEST(net_launch_order, launch_times_never_decrease_across_sources)
{
    LaunchOrder order;
    auto const never = [] { return uint64_t{0}; };
    uint64_t last = 0;
    for (uint64_t k = 0; k < 8; ++k) {
        uint64_t const a = BASE_NS + (k * TICK_NS) + (4 * FRAME_NS);
        uint64_t const b = BASE_NS + (k * TICK_NS);
        uint64_t const given_a = order.next(a, never);
        uint64_t const given_b = order.next(b, never);
        EXPECT_EQ(given_a, a);
        EXPECT_TRUE(given_a >= last && given_b >= given_a);
        EXPECT_TRUE(given_b - b < 6 * FRAME_NS);
        last = given_b;
    }
    EXPECT_EQ(order.clamped(), uint64_t{0});  // under a packet: the design's rounding, not counted
    EXPECT_EQ(order.max_clamp_ns(), uint64_t{0});
    EXPECT_EQ(order.next(BASE_NS + (8 * TICK_NS), never), BASE_NS + (8 * TICK_NS));
    EXPECT_EQ(order.next(BASE_NS + (7 * TICK_NS) - 1, never), BASE_NS + (8 * TICK_NS));  // over a packet: counted
    EXPECT_EQ(order.clamped(), uint64_t{1});
    EXPECT_EQ(order.max_clamp_ns(), TICK_NS + 1);
    uint64_t const later = BASE_NS + (100 * TICK_NS);
    EXPECT_EQ(order.next(0, [&] { return later; }), later);
    EXPECT_EQ(order.next(0, [&] { return later - 1000; }), later);  // now just behind: the last time
    order.reset();
    EXPECT_EQ(order.next(0, [&] { return BASE_NS; }), BASE_NS);
    EXPECT_EQ(order.steps(), uint64_t{0});
}

// A backward PTP step (here 3 s) is not rounding between sources: the floor goes at once, counted, so
// the frames after it are not held into the future in the FIFO.
TEST(net_launch_order, a_backward_clock_step_drops_the_floor)
{
    auto const never = [] { return uint64_t{0}; };
    LaunchOrder order;
    EXPECT_EQ(order.next(BASE_NS, never), BASE_NS);
    EXPECT_EQ(order.next(BASE_NS - LaunchOrder::STEP_NS, never), BASE_NS);  // within the bound: held
    EXPECT_EQ(order.next(BASE_NS - 3'000'000'000ULL, never), BASE_NS - 3'000'000'000ULL);
    EXPECT_EQ(order.next(BASE_NS - 3'000'000'000ULL + TICK_NS, never), BASE_NS - 3'000'000'000ULL + TICK_NS);
    EXPECT_EQ(order.steps(), uint64_t{1});
    EXPECT_EQ(order.clamped(), uint64_t{1});  // the STEP_NS hold, over a packet
}

// A frame committed after its launch time (a tick that overran, the multicore case) is wanted in the
// past: it goes at now instead, counted with the largest lateness, and the order's floor moves to now
// so the frames after it are not held. A frame wanted exactly at now is late too; one a nanosecond
// ahead is not.
TEST(net_launch_order, a_launch_already_past_goes_at_now_and_is_counted)
{
    LaunchOrder order;
    uint64_t now = BASE_NS;
    auto const clock = [&] { return now; };
    EXPECT_EQ(order.next(BASE_NS + TICK_NS, clock), BASE_NS + TICK_NS);
    EXPECT_EQ(order.launched_late(), uint64_t{0});
    now = BASE_NS + (2 * TICK_NS) + 30'000;  // the tick overran: the next frame's time is 30 us past
    EXPECT_EQ(order.next(BASE_NS + (2 * TICK_NS), clock), now);
    EXPECT_EQ(order.next(now, clock), now);  // at now: late by nothing, still sent at now
    EXPECT_EQ(order.next(now + 1, clock), now + 1);
    EXPECT_EQ(order.launched_late(), uint64_t{2});
    EXPECT_EQ(order.max_late_ns(), uint64_t{30'000});
    EXPECT_EQ(order.clamped(), uint64_t{0});
    EXPECT_EQ(order.steps(), uint64_t{0});
    // The floor is now: a later frame on time is not clamped to anything past it.
    EXPECT_EQ(order.next(BASE_NS + (3 * TICK_NS), clock), BASE_NS + (3 * TICK_NS));
    // An untimed frame is now, not late: held to the last time given, under a packet.
    EXPECT_EQ(order.next(0, clock), BASE_NS + (3 * TICK_NS));
    EXPECT_EQ(order.launched_late(), uint64_t{2});
    EXPECT_EQ(order.clamped(), uint64_t{0});
}

// CLOCK_TAI is read without a syscall and moves forward; off Linux there is none.
TEST(net_launch_order, tai_now_moves_forward)
{
    uint64_t const first = statusbar::net::tai_now_ns();
    uint64_t const second = statusbar::net::tai_now_ns();
#if defined(__linux__)
    EXPECT_TRUE(first > 0 && second >= first);
#else
    EXPECT_EQ(first + second, uint64_t{0});
#endif
}

TEST_MAIN(statusbar_net, net_launch_order_test)
