// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_message_pipe.hpp"

#include "statusbar/test/test.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>

using namespace statusbar::itc;

namespace {

// A small trivially-copyable payload for the value-semantics tests.
struct Sample
{
    float value;
    auto operator==(Sample const&) const -> bool = default;
};

}  // namespace

TEST(sync_message_pipe, latest_returns_nullopt_before_first_publish)
{
    LatestPipe<int> pipe;
    EXPECT_FALSE(pipe.try_consume().has_value());
}

TEST(sync_message_pipe, latest_delivers_published_value)
{
    LatestPipe<Sample> pipe;
    Sample const sent{.value = 0.75F};
    pipe.publish(sent);

    auto out = pipe.try_consume();
    EXPECT_TRUE(out.has_value());
    EXPECT_TRUE(*out == sent);
}

TEST(sync_message_pipe, latest_drops_stale_publishes)
{
    LatestPipe<Sample> pipe;
    pipe.publish(Sample{.value = 0.1F});
    pipe.publish(Sample{.value = 0.5F});
    pipe.publish(Sample{.value = 0.9F});

    auto out = pipe.try_consume();
    EXPECT_TRUE(out.has_value());
    EXPECT_EQ(out->value, 0.9F);  // only the most recent survives
}

TEST(sync_message_pipe, latest_can_publish_is_always_true)
{
    LatestPipe<int> pipe;
    EXPECT_TRUE(pipe.can_publish());
    pipe.publish(1);
    EXPECT_TRUE(pipe.can_publish());
}

TEST(sync_message_pipe, latest_can_consume_tracks_freshness)
{
    LatestPipe<int> pipe;
    EXPECT_FALSE(pipe.can_consume());
    pipe.publish(42);
    EXPECT_TRUE(pipe.can_consume());
    EXPECT_EQ(pipe.consume(), 42);
    EXPECT_FALSE(pipe.can_consume());  // freshness watermark advanced
    pipe.publish(99);
    EXPECT_TRUE(pipe.can_consume());
}

TEST(sync_message_pipe, fifo_preserves_order_and_reports_empty_full)
{
    QueuedPipe<int, 4> pipe;

    EXPECT_TRUE(pipe.empty());
    EXPECT_FALSE(pipe.try_consume().has_value());

    EXPECT_TRUE(pipe.try_publish(10));
    EXPECT_TRUE(pipe.try_publish(20));
    EXPECT_TRUE(pipe.try_publish(30));
    // Capacity 4 holds at most 3 entries (one slot reserved for full-detect).
    EXPECT_FALSE(pipe.try_publish(40));

    auto a = pipe.try_consume();
    EXPECT_TRUE(a.has_value());
    EXPECT_EQ(*a, 10);
    auto b = pipe.try_consume();
    EXPECT_TRUE(b.has_value());
    EXPECT_EQ(*b, 20);
    auto c = pipe.try_consume();
    EXPECT_TRUE(c.has_value());
    EXPECT_EQ(*c, 30);
    EXPECT_FALSE(pipe.try_consume().has_value());
    EXPECT_TRUE(pipe.empty());
}

TEST(sync_message_pipe, fifo_wraps_around_correctly)
{
    QueuedPipe<int, 4> pipe;
    for (int round = 0; round < 8; ++round) {
        EXPECT_TRUE(pipe.try_publish(round));
        auto v = pipe.try_consume();
        EXPECT_TRUE(v.has_value());
        EXPECT_EQ(*v, round);
    }
}

TEST(sync_message_pipe, fifo_can_publish_can_consume_explicit)
{
    QueuedPipe<int, 4> pipe;
    EXPECT_TRUE(pipe.can_publish());
    EXPECT_FALSE(pipe.can_consume());
    pipe.publish(11);
    pipe.publish(22);
    pipe.publish(33);
    EXPECT_FALSE(pipe.can_publish());  // capacity 4 → 3 usable slots
    EXPECT_TRUE(pipe.can_consume());
    EXPECT_EQ(pipe.consume(), 11);
    EXPECT_TRUE(pipe.can_publish());  // one slot freed
}

TEST(sync_message_pipe, fifo_alignment_avoids_false_sharing)
{
    // Sanity check: the struct layout must keep head_ and tail_ in
    // separate cache lines, otherwise producer/consumer cores will
    // bounce the line on every publish/consume.
    static_assert(alignof(QueuedPipe<int, 4>) >= cache_line_bytes);
    EXPECT_TRUE(sizeof(QueuedPipe<int, 4>) >= 2U * cache_line_bytes);
}

TEST(sync_message_pipe, timed_alignment_avoids_false_sharing)
{
    static_assert(alignof(TimedPipe<int, 4>) >= cache_line_bytes);
    EXPECT_TRUE(sizeof(TimedPipe<int, 4>) >= 2U * cache_line_bytes);
}

TEST(sync_message_pipe, timed_holds_back_until_due)
{
    TimedPipe<int, 4> pipe;

    EXPECT_TRUE(pipe.try_publish(/*activate_at_ns=*/1000U, 100));
    EXPECT_TRUE(pipe.try_publish(/*activate_at_ns=*/2000U, 200));

    EXPECT_FALSE(pipe.try_consume_due(/*now_ns=*/500U).has_value());
    auto a = pipe.try_consume_due(/*now_ns=*/1000U);
    EXPECT_TRUE(a.has_value());
    EXPECT_EQ(*a, 100);
    EXPECT_FALSE(pipe.try_consume_due(/*now_ns=*/1500U).has_value());
    auto b = pipe.try_consume_due(/*now_ns=*/9999U);
    EXPECT_TRUE(b.has_value());
    EXPECT_EQ(*b, 200);
    EXPECT_FALSE(pipe.try_consume_due(/*now_ns=*/9999U).has_value());
}

TEST(sync_message_pipe, timed_peek_activation_time)
{
    TimedPipe<int, 4> pipe;
    EXPECT_FALSE(pipe.peek_activation_time().has_value());

    EXPECT_TRUE(pipe.try_publish(/*activate_at_ns=*/12345U, 7));
    auto t = pipe.peek_activation_time();
    EXPECT_TRUE(t.has_value());
    EXPECT_EQ(*t, 12345U);
}

TEST(sync_message_pipe, timed_can_consume_due_separates_emptiness_from_due)
{
    TimedPipe<int, 4> pipe;
    EXPECT_FALSE(pipe.can_consume());
    EXPECT_FALSE(pipe.can_consume_due(0U));

    pipe.publish(/*activate_at_ns=*/1000U, 7);
    EXPECT_TRUE(pipe.can_consume());           // not empty
    EXPECT_FALSE(pipe.can_consume_due(500U));  // not yet due
    EXPECT_TRUE(pipe.can_consume_due(1000U));  // due now

    EXPECT_EQ(pipe.consume(), 7);  // unconditional pop
    EXPECT_FALSE(pipe.can_consume());
}

// ─────────────────────────────────────────────────────────────────────────────
// SPSC concurrent stress tests for the three MessagePipe policies.
//
// These exercise the wait-free contract across two real threads. Each test
// runs ~100k operations, with the producer pushing a monotonically-increasing
// counter and the consumer asserting per-policy invariants. Counts are kept
// modest enough to keep the test suite fast while still being long enough
// that any acquire/release-ordering bug would manifest under TSan or on
// weakly-ordered hardware (AArch64). Run via `make test-asan` for race
// detection coverage.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

constexpr size_t spsc_iterations = 100'000;

// Payload picked so a torn read between the two halves would be obvious:
// .lo and .hi must always be equal in any committed value.
struct SpscMsg
{
    uint64_t lo;
    uint64_t hi;
};

}  // namespace

TEST(sync_message_pipe, latest_concurrent_publish_consume_no_torn_reads)
{
    // LatestPipe contract: each consumed value must be one the producer
    // actually published — no torn reads, no half-state. Consumed values must
    // also be monotonic non-decreasing: latest-wins may SKIP values (the
    // consumer can miss intermediate publishes), but it must never hand back an
    // already-superseded slot. A publish racing with the consumer's exchange
    // can hand the consumer a stale slot; the per-slot publish sequence gate
    // (slot_seq_ / last_delivered_seq_) rejects it, so a backwards snap
    // cannot happen.
    LatestPipe<SpscMsg> pipe;
    std::atomic<uint64_t> max_observed{0};
    std::atomic<bool> torn_read_seen{false};
    std::atomic<bool> backwards_seen{false};
    std::atomic<bool> producer_done{false};

    std::thread producer{[&] {
        for (uint64_t i = 1; i <= spsc_iterations; ++i) {
            pipe.publish(SpscMsg{.lo = i, .hi = i});
        }
        producer_done.store(true, std::memory_order_release);
    }};

    std::thread consumer{[&] {
        uint64_t last = 0;
        while (!producer_done.load(std::memory_order_acquire) || pipe.can_consume()) {
            if (auto m = pipe.try_consume()) {
                if (m->lo != m->hi) {
                    torn_read_seen.store(true, std::memory_order_relaxed);
                }
                if (m->lo < last) {
                    backwards_seen.store(true, std::memory_order_relaxed);
                }
                last = m->lo;
                max_observed.store(last, std::memory_order_relaxed);
            }
        }
    }};

    producer.join();
    consumer.join();

    EXPECT_FALSE(torn_read_seen.load(std::memory_order_relaxed));
    EXPECT_FALSE(backwards_seen.load(std::memory_order_relaxed));
    // The consumer must have observed something (producer publishes far
    // faster than we can plausibly all-miss).
    EXPECT_TRUE(max_observed.load(std::memory_order_relaxed) > 0U);
}

TEST(sync_message_pipe, latest_burst_final_value_never_stranded)
{
    // Regression: consume()/try_consume() recorded the generation watermark
    // AFTER the ready-slot exchange. A publish landing between the two was
    // absorbed into the watermark — can_consume() went false while the fresh
    // value sat in the ready slot, stranded until a later publish bumped the
    // generation. With bursty publishers ("publish, then go quiet") the
    // consumer froze one value behind indefinitely. Publish in bursts and
    // require the final value of every burst to become consumable while the
    // producer is quiet.
    LatestPipe<SpscMsg> pipe;
    std::atomic<uint64_t> acked{0};
    std::atomic<bool> stop{false};
    std::atomic<bool> timed_out{false};

    constexpr uint64_t bursts = 2'000;
    constexpr uint64_t burst_len = 50;

    std::thread consumer{[&] {
        while (!stop.load(std::memory_order_acquire)) {
            if (auto m = pipe.try_consume()) {
                acked.store(m->lo, std::memory_order_release);
            }
        }
    }};

    std::thread producer{[&] {
        for (uint64_t b = 0; b < bursts; ++b) {
            uint64_t const base = b * burst_len;
            for (uint64_t i = 1; i <= burst_len; ++i) {
                pipe.publish(SpscMsg{.lo = base + i, .hi = base + i});
            }
            // The producer is now quiet; the burst's final value must become
            // consumable without any further publish. Generous bound so slow
            // sanitizer runs don't flake — a stranded value never arrives at
            // all, so a genuine regression always exhausts it.
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (acked.load(std::memory_order_acquire) != base + burst_len) {
                if (std::chrono::steady_clock::now() > deadline) {
                    timed_out.store(true, std::memory_order_relaxed);
                    stop.store(true, std::memory_order_release);
                    return;
                }
            }
        }
        stop.store(true, std::memory_order_release);
    }};

    producer.join();
    consumer.join();

    EXPECT_FALSE(timed_out.load(std::memory_order_relaxed));
    EXPECT_EQ(acked.load(std::memory_order_relaxed), bursts * burst_len);
}

TEST(sync_message_pipe, fifo_concurrent_preserves_every_value_in_order)
{
    QueuedPipe<SpscMsg, 64> pipe;
    std::atomic<bool> mismatch_seen{false};
    std::atomic<bool> torn_read_seen{false};

    std::thread producer{[&] {
        for (uint64_t i = 1; i <= spsc_iterations; ++i) {
            // Spin until there's room — FIFO drops nothing.
            while (!pipe.try_publish(SpscMsg{.lo = i, .hi = i})) {
                std::this_thread::yield();
            }
        }
    }};

    std::thread consumer{[&] {
        uint64_t expected = 1;
        while (expected <= spsc_iterations) {
            if (auto m = pipe.try_consume()) {
                if (m->lo != m->hi) {
                    torn_read_seen.store(true, std::memory_order_relaxed);
                }
                if (m->lo != expected) {
                    mismatch_seen.store(true, std::memory_order_relaxed);
                }
                ++expected;
            }
        }
    }};

    producer.join();
    consumer.join();

    EXPECT_FALSE(torn_read_seen.load(std::memory_order_relaxed));
    EXPECT_FALSE(mismatch_seen.load(std::memory_order_relaxed));
}

TEST(sync_message_pipe, timed_concurrent_preserves_every_value_in_order)
{
    TimedPipe<SpscMsg, 64> pipe;
    std::atomic<bool> mismatch_seen{false};
    std::atomic<bool> torn_read_seen{false};

    std::thread producer{[&] {
        for (uint64_t i = 1; i <= spsc_iterations; ++i) {
            while (!pipe.try_publish(/*activate_at_ns=*/i, SpscMsg{.lo = i, .hi = i})) {
                std::this_thread::yield();
            }
        }
    }};

    std::thread consumer{[&] {
        uint64_t expected = 1;
        // Use a "now" that's always >= every entry's activation time
        // so consumption isn't gated on time — this test is about the
        // FIFO+activation-time storage path, not the gating logic
        // (covered in timed_holds_back_until_due).
        uint64_t const now = spsc_iterations + 1;
        while (expected <= spsc_iterations) {
            if (auto m = pipe.try_consume_due(now)) {
                if (m->lo != m->hi) {
                    torn_read_seen.store(true, std::memory_order_relaxed);
                }
                if (m->lo != expected) {
                    mismatch_seen.store(true, std::memory_order_relaxed);
                }
                ++expected;
            }
        }
    }};

    producer.join();
    consumer.join();

    EXPECT_FALSE(torn_read_seen.load(std::memory_order_relaxed));
    EXPECT_FALSE(mismatch_seen.load(std::memory_order_relaxed));
}

TEST_MAIN(statusbar_itc, itc_message_pipe_test)
