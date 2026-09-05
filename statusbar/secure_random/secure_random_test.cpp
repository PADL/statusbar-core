// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/secure_random/secure_random.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstring>

using namespace statusbar;

TEST(statusbar_secure_random, empty_span_is_noop)
{
    secure_random_bytes({});  // must not crash, must not abort
}

TEST(statusbar_secure_random, fills_requested_length)
{
    std::array<uint8_t, 64> buf{};
    secure_random_bytes(buf);
    // Sanity: at least one byte should be non-zero. False positive
    // probability is 2^-512, well below any practical concern.
    bool any_nonzero = false;
    for (auto b : buf) {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(any_nonzero);
}

TEST(statusbar_secure_random, two_calls_differ)
{
    std::array<uint8_t, 32> a{};
    std::array<uint8_t, 32> b{};
    secure_random_bytes(a);
    secure_random_bytes(b);
    // False positive probability 2^-256.
    EXPECT_NE(std::memcmp(a.data(), b.data(), a.size()), 0);
}

TEST(statusbar_secure_random, small_lengths_work)
{
    // Exercises the loop boundary on Linux (getrandom may return short). A
    // short buffer is legitimately all-zero now and then (1 byte: 1 in 256 —
    // this failed a CI run), so the fill check is on the union of a few draws:
    // 8 draws of 1 byte all zero is 2^-64.
    for (size_t n : {1U, 7U, 15U, 16U, 17U, 31U, 32U, 33U, 257U}) {
        std::vector<uint8_t> buf(n, 0);
        bool any_nonzero = false;
        for (int draw = 0; draw < 8 && !any_nonzero; ++draw) {
            secure_random_bytes(buf);
            for (auto v : buf) {
                if (v != 0) {
                    any_nonzero = true;
                    break;
                }
            }
        }
        EXPECT_TRUE(any_nonzero);
    }
}

TEST_MAIN(statusbar_secure_random, secure_random_test)
