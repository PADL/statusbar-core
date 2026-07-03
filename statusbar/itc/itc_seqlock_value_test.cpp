// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/itc/itc_seqlock_value.hpp"

#include "statusbar/test/test.hpp"

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

using namespace statusbar;

namespace {

// A two-field payload with a derived invariant (b == derive(a)) so a torn read --
// b from a different store than a -- is detectable with overwhelming probability.
struct Pair
{
    std::uint64_t a;
    std::uint64_t b;
};

[[nodiscard]] constexpr auto derive(std::uint64_t a) noexcept -> std::uint64_t
{
    return (a * 6364136223846793005ULL) + 1442695040888963407ULL;
}

}  // namespace

TEST(seqlock_value, round_trip_and_explicit_initial)
{
    itc::SeqlockValue<Pair> v{Pair{.a = 7, .b = derive(7)}};
    auto p = v.load();
    EXPECT_EQ(p.a, std::uint64_t{7});
    EXPECT_EQ(p.b, derive(7));

    v.store(Pair{.a = 99, .b = derive(99)});
    p = v.load();
    EXPECT_EQ(p.a, std::uint64_t{99});
    EXPECT_EQ(p.b, derive(99));
}

TEST(seqlock_value, default_constructs_to_zero)
{
    itc::SeqlockValue<Pair> v;
    auto const p = v.load();
    EXPECT_EQ(p.a, std::uint64_t{0});
    EXPECT_EQ(p.b, std::uint64_t{0});
}

// One writer, several concurrent readers: every observed snapshot must be a
// consistent whole value (b == derive(a)); a seqlock tear would break the invariant.
TEST(seqlock_value, concurrent_readers_never_tear)
{
    itc::SeqlockValue<Pair> v{Pair{.a = 0, .b = derive(0)}};
    std::atomic<bool> writer_done{false};
    std::atomic<std::uint64_t> torn{0};
    std::atomic<std::uint64_t> reads{0};

    constexpr std::uint64_t k_writes = 500000;
    std::thread writer([&] {
        for (std::uint64_t i = 1; i <= k_writes; ++i) {
            v.store(Pair{.a = i, .b = derive(i)});
        }
        writer_done.store(true, std::memory_order_release);
    });

    std::vector<std::thread> readers;
    readers.reserve(3);
    for (int r = 0; r < 3; ++r) {
        readers.emplace_back([&] {
            while (!writer_done.load(std::memory_order_acquire)) {
                for (int k = 0; k < 1000; ++k) {
                    auto const p = v.load();
                    if (p.b != derive(p.a)) {
                        torn.fetch_add(1, std::memory_order_relaxed);
                    }
                    reads.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    writer.join();
    for (auto& t : readers) {
        t.join();
    }

    EXPECT_EQ(torn.load(), std::uint64_t{0});
    EXPECT_TRUE(reads.load() > 0);
}

TEST_MAIN(statusbar_itc, itc_seqlock_value_test)
