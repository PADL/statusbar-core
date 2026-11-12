// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_atomic_triple_buffer_base.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

using statusbar::itc::AtomicTripleBufferBase;

namespace {

[[nodiscard]] auto three_distinct(uint8_t a, uint8_t b, uint8_t c) -> bool
{
    if (a > 2 || b > 2 || c > 2) {
        return false;
    }
    return a != b && a != c && b != c;
}

}  // namespace

TEST(itc_atb_base_init, default_ctor_has_no_fresh_data)
{
    AtomicTripleBufferBase buf;
    EXPECT_FALSE(buf.can_consume());
    EXPECT_EQ(buf.overruns(), uint64_t{0});
}

TEST(itc_atb_base_init, default_ctor_three_indices_distinct)
{
    AtomicTripleBufferBase buf;
    uint8_t const w = buf.writer_slot();
    uint8_t const r = buf.ready_slot();
    uint8_t const f = buf.acquire_read_slot();  // no fresh, returns current front
    EXPECT_TRUE(three_distinct(w, r, f));
}

TEST(itc_atb_base_publish, commit_makes_data_consumable_and_rotates_back)
{
    AtomicTripleBufferBase buf;
    uint8_t const old_back = buf.writer_slot();
    EXPECT_FALSE(buf.can_consume());

    buf.commit_publish();

    EXPECT_TRUE(buf.can_consume());
    uint8_t const new_back = buf.writer_slot();
    EXPECT_NE(new_back, old_back);
    EXPECT_EQ(buf.ready_slot(), old_back);  // what was back is now ready
}

TEST(itc_atb_base_consume, acquire_after_publish_advances_to_ready)
{
    AtomicTripleBufferBase buf;
    uint8_t const old_front = buf.acquire_read_slot();  // no fresh; same slot
    uint8_t const old_back = buf.writer_slot();

    buf.commit_publish();
    EXPECT_TRUE(buf.can_consume());

    uint8_t const new_front = buf.acquire_read_slot();
    EXPECT_FALSE(buf.can_consume());         // dirty bit cleared
    EXPECT_EQ(new_front, old_back);          // consumer now holds what was back
    EXPECT_EQ(buf.ready_slot(), old_front);  // and the old front is the new ready
}

TEST(itc_atb_base_consume, repeated_acquire_without_publish_returns_same_slot)
{
    AtomicTripleBufferBase buf;
    buf.commit_publish();
    uint8_t const f1 = buf.acquire_read_slot();
    uint8_t const f2 = buf.acquire_read_slot();
    uint8_t const f3 = buf.acquire_read_slot();
    EXPECT_EQ(f1, f2);
    EXPECT_EQ(f2, f3);
    EXPECT_FALSE(buf.can_consume());
}

TEST(itc_atb_base_init, initially_dirty_ctor_makes_first_consume_fresh)
{
    AtomicTripleBufferBase buf{AtomicTripleBufferBase::InitiallyDirty{}};
    EXPECT_TRUE(buf.can_consume());
    (void)buf.acquire_read_slot();
    EXPECT_FALSE(buf.can_consume());
}

TEST(itc_atb_base_init, initially_dirty_ctor_preserves_distinct_indices)
{
    AtomicTripleBufferBase buf{AtomicTripleBufferBase::InitiallyDirty{}};
    uint8_t const w = buf.writer_slot();
    uint8_t const r = buf.ready_slot();
    EXPECT_NE(w, r);
}

TEST(itc_atb_base_invariant, three_indices_remain_distinct_across_random_ops)
{
    AtomicTripleBufferBase buf;

    // Deterministic pseudo-random sequence — no <random> needed,
    // just a small LCG seeded so the test is reproducible.
    uint32_t lcg = 0x12345678U;
    auto next_bool = [&]() noexcept -> bool {
        lcg = (lcg * 1664525U) + 1013904223U;
        return ((lcg >> 16) & 1U) != 0;
    };

    for (int i = 0; i < 1000; ++i) {
        if (next_bool()) {
            buf.commit_publish();
        } else {
            (void)buf.acquire_read_slot();
        }
        uint8_t const w = buf.writer_slot();
        uint8_t const r = buf.ready_slot();
        EXPECT_TRUE(w <= 2);
        EXPECT_TRUE(r <= 2);
        EXPECT_NE(w, r);
    }
}

TEST(itc_atb_base_overruns, multiple_publishes_without_consume_count)
{
    AtomicTripleBufferBase buf;
    buf.commit_publish();  // 1st: state was clean, no overrun
    buf.commit_publish();  // 2nd: overwrites unconsumed, +1
    buf.commit_publish();  // 3rd: overwrites unconsumed, +1
    buf.commit_publish();  // 4th: overwrites unconsumed, +1
    buf.commit_publish();  // 5th: overwrites unconsumed, +1
    EXPECT_EQ(buf.overruns(), uint64_t{4});

    (void)buf.acquire_read_slot();
    EXPECT_EQ(buf.overruns(), uint64_t{4});  // consume doesn't change overruns

    (void)buf.acquire_read_slot();
    EXPECT_EQ(buf.overruns(), uint64_t{4});  // still unchanged with no new publish
}

// The handoff both exchanges are acq_rel for: the publisher may write only
// the slot the consumer has given back, never the one it still holds, so a
// consumer that keeps reading its slot across many publishes must see it
// unchanged until its own next acquire. A test cannot prove the memory
// ordering; this one drives the protocol hard enough that a slot-index
// slip or a write into the held slot would show as a changed word.
TEST(itc_atb_base_handoff, a_held_slot_is_never_written_until_it_is_given_back)
{
    AtomicTripleBufferBase buf;
    std::array<std::array<uint64_t, 4>, 3> slots{};
    std::atomic<bool> stop{false};

    std::thread producer{[&]() noexcept {
        uint64_t n = 1;
        while (!stop.load(std::memory_order_relaxed)) {
            auto& slot = slots[buf.writer_slot()];
            slot.fill(n);
            buf.commit_publish();
            ++n;
        }
    }};

    int64_t holds = 0;
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{300};
    while (holds < 20'000 && std::chrono::steady_clock::now() < deadline) {
        if (!buf.can_consume()) {
            continue;
        }
        auto const& held = slots[buf.acquire_read_slot()];
        auto const first = held;
        for (int spin = 0; spin < 50; ++spin) {
            std::atomic_signal_fence(std::memory_order_seq_cst);
        }
        auto const again = held;
        EXPECT_TRUE(first == again);
        EXPECT_TRUE(first[0] == first[1] && first[1] == first[2] && first[2] == first[3]);
        ++holds;
    }

    stop.store(true, std::memory_order_relaxed);
    producer.join();
    EXPECT_TRUE(holds >= int64_t{100});
}

TEST_MAIN(statusbar_itc, itc_atomic_triple_buffer_base_test)
