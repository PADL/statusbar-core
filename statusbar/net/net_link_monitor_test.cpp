// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for net::LinkMonitor — the throttle + transition logic driven by an
// injected link-state reader and a manual clock.

#include "statusbar/net/net_link_monitor.hpp"

#include "statusbar/test/test.hpp"

#include <optional>
#include <vector>

using statusbar::net::LinkMonitor;

namespace {

/// Records (up, now_ns) for each emitted change.
struct Recorder
{
    std::vector<std::pair<bool, int64_t>> changes;
    auto on_change()
    {
        return [this](bool up, int64_t now_ns) { changes.emplace_back(up, now_ns); };
    }
};

constexpr int64_t INTERVAL = 500'000'000;  // 500 ms

}  // namespace

TEST(link_monitor, emits_initial_state_on_first_poll)
{
    Recorder rec;
    std::optional<bool> state = true;
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};

    mon.tick(0);  // first poll happens at now >= 0
    EXPECT_EQ(rec.changes.size(), size_t{1});
    EXPECT_TRUE(rec.changes[0].first);
    EXPECT_EQ(mon.link_up(), std::optional<bool>{true});
}

TEST(link_monitor, throttles_to_poll_interval)
{
    Recorder rec;
    int reads = 0;
    std::optional<bool> state = true;
    LinkMonitor mon{
        [&] {
            ++reads;
            return state;
        },
        rec.on_change(),
        INTERVAL};

    mon.tick(0);             // poll #1 (read)
    mon.tick(1);             // within interval -> no read
    mon.tick(INTERVAL - 1);  // still within interval -> no read
    EXPECT_EQ(reads, 1);
    mon.tick(INTERVAL);  // interval elapsed -> poll #2
    EXPECT_EQ(reads, 2);
}

TEST(link_monitor, emits_only_on_transition)
{
    Recorder rec;
    std::optional<bool> state = true;
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};

    mon.tick(0);         // up (initial) -> emit
    mon.tick(INTERVAL);  // still up -> no emit
    state = false;
    mon.tick(2 * INTERVAL);  // down -> emit
    mon.tick(3 * INTERVAL);  // still down -> no emit
    state = true;
    mon.tick(4 * INTERVAL);  // up -> emit

    EXPECT_EQ(rec.changes.size(), size_t{3});
    EXPECT_TRUE(rec.changes[0].first);               // up
    EXPECT_FALSE(rec.changes[1].first);              // down
    EXPECT_TRUE(rec.changes[2].first);               // up
    EXPECT_EQ(rec.changes[1].second, 2 * INTERVAL);  // carries the reactor clock
}

TEST(link_monitor, unknown_state_emits_nothing_and_keeps_last)
{
    Recorder rec;
    std::optional<bool> state = std::nullopt;  // reader can't determine link state
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};

    mon.tick(0);
    mon.tick(INTERVAL);
    EXPECT_TRUE(rec.changes.empty());
    EXPECT_FALSE(mon.link_up().has_value());

    // Once readable, the first real state is emitted.
    state = true;
    mon.tick(2 * INTERVAL);
    EXPECT_EQ(rec.changes.size(), size_t{1});
    EXPECT_TRUE(rec.changes[0].first);

    // A transient unknown read does NOT spuriously emit a down.
    state = std::nullopt;
    mon.tick(3 * INTERVAL);
    EXPECT_EQ(rec.changes.size(), size_t{1});
    EXPECT_EQ(mon.link_up(), std::optional<bool>{true});  // last-known retained
}

TEST(link_monitor, is_tick_only_pollable)
{
    LinkMonitor mon{[] { return std::optional<bool>{true}; }, [](bool, int64_t) {}, INTERVAL};
    EXPECT_EQ(mon.fd(), -1);
    EXPECT_FALSE(mon.finished());
}

//
// Test Runner
//

// A caller that reset the adapter, resized a ring or attached a program on a
// driver that bounces the link for it knows the carrier may have moved and
// has no message to say so: recheck() reads it now, inside the interval.
TEST(link_monitor, recheck_reads_inside_the_interval_and_reports_a_transition)
{
    Recorder rec;
    int reads = 0;
    std::optional<bool> state = true;
    LinkMonitor mon{
        [&] {
            ++reads;
            return state;
        },
        rec.on_change(),
        INTERVAL};

    mon.tick(0);
    state = false;
    mon.tick(10);  // inside the interval: not read
    EXPECT_EQ(reads, 1);
    mon.recheck(20);
    EXPECT_EQ(reads, 2);
    EXPECT_EQ(rec.changes.size(), size_t{2});
    EXPECT_FALSE(rec.changes[1].first);
    EXPECT_EQ(rec.changes[1].second, int64_t{20});
    EXPECT_EQ(mon.link_up(), std::optional<bool>{false});
    // The scheduled poll is where it was, and finds nothing new.
    mon.tick(INTERVAL);
    EXPECT_EQ(reads, 3);
    EXPECT_EQ(rec.changes.size(), size_t{2});
}

TEST(link_monitor, recheck_with_the_same_state_or_no_answer_emits_nothing)
{
    Recorder rec;
    std::optional<bool> state = true;
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};
    mon.tick(0);
    mon.recheck(1);
    state = std::nullopt;
    mon.recheck(2);
    EXPECT_EQ(rec.changes.size(), size_t{1});
    EXPECT_EQ(mon.link_up(), std::optional<bool>{true});
}

// told() takes the caller's word: a transition is reported at once, and the
// poll that follows, seeing the same state, says nothing more.
TEST(link_monitor, told_reports_a_transition_and_the_poll_after_it_is_quiet)
{
    Recorder rec;
    std::optional<bool> state = true;
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};
    mon.tick(0);
    mon.told(false, 5);
    EXPECT_EQ(rec.changes.size(), size_t{2});
    EXPECT_FALSE(rec.changes[1].first);
    EXPECT_EQ(rec.changes[1].second, int64_t{5});
    EXPECT_EQ(mon.link_up(), std::optional<bool>{false});

    state = false;  // the carrier catches up
    mon.tick(INTERVAL);
    EXPECT_EQ(rec.changes.size(), size_t{2});

    mon.told(false, INTERVAL + 1);  // the same word twice is one transition
    EXPECT_EQ(rec.changes.size(), size_t{2});
    state = true;
    mon.tick(2 * INTERVAL);  // and a further change is still reported
    EXPECT_EQ(rec.changes.size(), size_t{3});
    EXPECT_TRUE(rec.changes[2].first);
}

TEST(link_monitor, told_before_the_first_poll_is_the_first_observed_state)
{
    Recorder rec;
    std::optional<bool> state = true;
    LinkMonitor mon{[&] { return state; }, rec.on_change(), INTERVAL};
    mon.told(true, 0);
    EXPECT_EQ(rec.changes.size(), size_t{1});
    mon.tick(1);  // the first poll agrees, and so says nothing
    EXPECT_EQ(rec.changes.size(), size_t{1});
}

TEST_MAIN(statusbar_net, net_link_monitor_test)
