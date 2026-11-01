// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_launch_order.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// A plausible TAI nanosecond count: far enough from zero that subtracting
/// seconds from it cannot underflow, so a test reads as it would in service.
constexpr std::uint64_t T = 1'800'000'000ULL * 1'000'000'000ULL;

/// A `now` that always answers `at`.
[[nodiscard]] auto fixed(std::uint64_t const at)
{
    return [at] { return at; };
}

}  // namespace

// A time that is already in the future of everything handed out goes through
// untouched: the ordinary case costs nothing and reports nothing.
TEST(launch_order, a_time_after_the_last_one_passes_through)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T + 1'000'000, fixed(T)), T + 1'000'000);
    EXPECT_EQ(order.clamped(), std::uint64_t{0});
    EXPECT_EQ(order.steps(), std::uint64_t{0});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{0});
}

// A launch-time queue is a FIFO: a frame committed after another cannot be
// given an earlier time, or the NIC holds the whole queue behind it.
TEST(launch_order, a_time_before_the_last_one_is_held_at_it)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T - 300'000, fixed(T)), T);
    EXPECT_EQ(order.next(T - 1'000, fixed(T)), T);
}

// Zero means the caller has no departure for this frame: it goes at now, and
// now is what the ordering remembers.
TEST(launch_order, a_wanted_time_of_zero_is_sent_at_now)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(0, fixed(T)), T);
    EXPECT_EQ(order.next(T - 500'000, fixed(T)), T);  // held at the now it just used
}

// Two senders committing in the same tick land within a packet of each other,
// which is ordinary and must not look like a late frame. A clamp of more than
// one packet is a frame that missed its slot, and that is worth counting.
TEST(launch_order, a_clamp_under_one_packet_is_not_counted_but_a_longer_one_is)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T - 50'000, fixed(T)), T);
    EXPECT_EQ(order.clamped(), std::uint64_t{0});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{0});
    EXPECT_EQ(order.next(T - 200'000, fixed(T)), T);
    EXPECT_EQ(order.clamped(), std::uint64_t{1});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{200'000});
}

// The largest clamp is kept, not the latest.
TEST(launch_order, the_largest_clamp_is_the_one_remembered)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T - 800'000, fixed(T)), T);
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{800'000});
    EXPECT_EQ(order.next(T - 300'000, fixed(T)), T);
    EXPECT_EQ(order.clamped(), std::uint64_t{2});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{800'000});
}

// A wanted time far behind the last one, with the clock where it was, is a
// stale frame: a talker that stalled and then committed the departures it
// had queued. Those are held like any late frame, or the FIFO would stall
// behind every one of them.
TEST(launch_order, a_stale_frame_a_second_or_more_behind_is_still_held)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T - 1'200'000'000ULL, fixed(T)), T);
    EXPECT_EQ(order.steps(), std::uint64_t{0});
    EXPECT_EQ(order.clamped(), std::uint64_t{1});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{1'200'000'000ULL});
}

// A clock step is the clock itself moving back under the ordering: a PTP
// resync, a domain change, a grandmaster handing over to another with its own
// timebase. Holding every frame at the old time would stall the talker for the
// length of the step, so the ordering follows the clock and says so.
TEST(launch_order, a_backwards_jump_of_the_clock_is_a_step_not_a_clamp)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    std::uint64_t const stepped = T - 3'000'000'000ULL;  // the clock now reads three seconds earlier
    EXPECT_EQ(order.next(stepped, fixed(stepped)), stepped);
    EXPECT_EQ(order.steps(), std::uint64_t{1});
    EXPECT_EQ(order.clamped(), std::uint64_t{0});
    // The new timebase is what the ordering now holds to.
    EXPECT_EQ(order.next(stepped - 100'000, fixed(stepped)), stepped);
}

// The boundary itself: the clock a second behind the last time is a step,
// just under it is not.
TEST(launch_order, the_step_threshold_is_one_second)
{
    LaunchOrder under;
    EXPECT_EQ(under.next(T, fixed(T)), T);
    std::uint64_t const just_under = T - (LaunchOrder::STEP_NS - 1);
    EXPECT_EQ(under.next(just_under, fixed(just_under)), T);
    EXPECT_EQ(under.steps(), std::uint64_t{0});

    LaunchOrder at;
    EXPECT_EQ(at.next(T, fixed(T)), T);
    std::uint64_t const exactly = T - LaunchOrder::STEP_NS;
    EXPECT_EQ(at.next(exactly, fixed(exactly)), exactly);
    EXPECT_EQ(at.steps(), std::uint64_t{1});
}

// An untimed frame is still ordered: now going backwards across a step would
// otherwise hand the NIC a time behind the queue.
TEST(launch_order, an_untimed_frame_whose_now_went_backwards_is_held)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(0, fixed(T - 100'000)), T);
    EXPECT_EQ(order.clamped(), std::uint64_t{0});  // a clamp under a packet
}

// Counters are a soak-test readout, so they must be clearable without
// building a new ordering around a live socket.
TEST(launch_order, reset_clears_the_counters_but_not_the_ordering)
{
    LaunchOrder order;
    EXPECT_EQ(order.next(T, fixed(T)), T);
    EXPECT_EQ(order.next(T - 400'000, fixed(T)), T);
    EXPECT_EQ(order.clamped(), std::uint64_t{1});
    order.reset();
    EXPECT_EQ(order.clamped(), std::uint64_t{0});
    EXPECT_EQ(order.max_clamp_ns(), std::uint64_t{0});
    EXPECT_EQ(order.steps(), std::uint64_t{0});
    EXPECT_EQ(order.next(T - 400'000, fixed(T)), T);  // still ordered behind T
}

// CLOCK_TAI, not CLOCK_REALTIME: a launch time is compared against the clock
// the NIC keeps, and TAI has no leap seconds to step over.
TEST(launch_order, tai_now_is_a_plausible_monotonically_rising_tai_count)
{
    auto const first = tai_now_ns();
    auto const second = tai_now_ns();
    EXPECT_TRUE(second >= first);
    // After 2001 and before 2200, so a wrong clock or wrong units shows up.
    EXPECT_TRUE(first > 1'000'000'000ULL * 1'000'000'000ULL);
    EXPECT_TRUE(first < 7'000'000'000ULL * 1'000'000'000ULL);
}

TEST_MAIN(statusbar_net, net_launch_order_test)
