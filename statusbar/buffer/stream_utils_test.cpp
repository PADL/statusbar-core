// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Dedicated coverage for stream_utils.hpp (previously untested) plus the
// empty-span guards in span_utils.hpp: the mem* functions require valid
// pointers even for a zero count, so a default-constructed (null) span
// through span_zero/span_fill/span_copy/span_compare must be a no-op, not
// a nonnull violation under UBSan.

#include "statusbar/buffer/stream_utils.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <sstream>
#include <string>
#include <vector>

using namespace statusbar;

//
// stream_write / stream_read
//

TEST(stream_utils, round_trip_bytes_and_wide_elements)
{
    std::array<uint8_t, 4> const bytes{0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint32_t> const words{0x11223344, 0x55667788};

    std::stringstream ss;
    EXPECT_TRUE(stream_write(ss, bytes));
    EXPECT_TRUE(stream_write(ss, words));

    std::array<uint8_t, 4> bytes_in{};
    std::vector<uint32_t> words_in(2);
    EXPECT_TRUE(stream_read(ss, bytes_in));
    EXPECT_TRUE(stream_read(ss, words_in));

    EXPECT_TRUE(span_compare(make_const_span(bytes), make_const_span(bytes_in)));
    EXPECT_EQ(words_in[0], 0x11223344U);
    EXPECT_EQ(words_in[1], 0x55667788U);
}

TEST(stream_utils, spans_read_and_write_through)
{
    std::array<uint8_t, 3> data{1, 2, 3};
    std::stringstream ss;
    EXPECT_TRUE(stream_write(ss, std::span<uint8_t const>{data}));

    std::array<uint8_t, 3> sink{};
    std::span<uint8_t> sink_span{sink};
    EXPECT_TRUE(stream_read(ss, sink_span));
    EXPECT_EQ(sink[2], 3);
}

TEST(stream_utils, short_read_reports_failure)
{
    std::stringstream ss;
    std::array<uint8_t, 2> const two{0xAA, 0xBB};
    EXPECT_TRUE(stream_write(ss, two));

    std::array<uint8_t, 4> four{};
    // Only 2 of 4 bytes available: the read must report failure and the
    // stream must be failed — the range is only partially overwritten.
    EXPECT_FALSE(stream_read(ss, four));
    EXPECT_FALSE(ss.good());
    EXPECT_EQ(four[0], 0xAA);
    EXPECT_EQ(four[1], 0xBB);
}

TEST(stream_utils, write_to_failed_stream_reports_failure)
{
    std::stringstream ss;
    ss.setstate(std::ios::failbit);
    std::array<uint8_t, 2> const payload{1, 2};
    EXPECT_FALSE(stream_write(ss, payload));
}

//
// Empty-span guards in span_utils — all of these must be safe no-ops on
// default-constructed (null-data) spans.
//

TEST(span_utils_empty, fill_zero_copy_compare_on_null_spans)
{
    std::span<uint8_t> empty_mut{};
    std::span<uint8_t const> empty_const{};

    span_fill(empty_mut, 0x5A);  // no-op, not memset(nullptr, ...)
    span_zero(empty_mut);
    span_copy(empty_mut, empty_const);

    std::span<uint8_t, 0> fixed_mut{empty_mut.data(), 0};
    std::span<uint8_t const, 0> fixed_const{empty_const.data(), 0};
    span_copy(fixed_mut, fixed_const);
    span_copy(fixed_mut, empty_const);  // dynamic source, fixed empty dest

    EXPECT_TRUE(span_compare(fixed_const, fixed_const));  // N == 0: equal
    EXPECT_TRUE(span_compare(empty_const, empty_const));  // both null: equal
    EXPECT_TRUE(span_compare_constant_time(empty_const, empty_const));
    std::array<uint8_t, 1> one{7};
    EXPECT_FALSE(span_compare(empty_const, std::span<uint8_t const>{one}));
}

TEST(span_utils_empty, can_span_copy_on_const_array)
{
    // can_span_copy is a pure predicate — it must accept a const array.
    std::array<uint8_t, 4> const dest{};
    std::array<uint8_t, 4> const src{};
    EXPECT_TRUE(can_span_copy(dest, make_const_span(src)));
    EXPECT_FALSE(can_span_copy(dest, std::span<uint8_t const>{src.data(), 2}));
}

//
// wire_span asserts the same precondition span_store_wire does; a
// well-formed descriptor exercises the guarded path.
//

namespace {
struct SmallWire
{
    uint8_t bytes[4]{9, 8, 7, 6};
    [[nodiscard]] auto wire_size() const noexcept -> size_t { return 2; }
};
}  // namespace

TEST(span_utils_empty, wire_span_respects_declared_size)
{
    SmallWire const desc;
    auto const view = wire_span(desc);
    EXPECT_EQ(view.size(), size_t{2});
    EXPECT_EQ(view[0], 9);
    EXPECT_EQ(view[1], 8);
}

TEST_MAIN(statusbar_buffer, stream_utils_test)
