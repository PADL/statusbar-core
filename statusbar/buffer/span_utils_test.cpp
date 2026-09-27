// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Dedicated coverage for span_utils.hpp — previously the module's largest
// header was tested only incidentally through its consumers. Cases that
// would trip STATUSBAR_ASSERT in a debug build (short sources for the
// zero-fill span_copy overloads, out-of-range octet_range_t) are exercised
// only within their asserted preconditions here; the release-only clamp and
// zero-fill behaviors are documented in the header.

#include "statusbar/buffer/span_utils.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

using namespace statusbar;

//
// octet_range_t
//
TEST(span_utils, octet_range_applies_start_and_length)
{
    std::array<uint8_t, 8> data{0, 1, 2, 3, 4, 5, 6, 7};
    auto const sub = make_const_span(data, octet_range_t{.start = 2, .length = 3});
    EXPECT_EQ(sub.size(), size_t{3});
    EXPECT_EQ(sub[0], 2);
    EXPECT_EQ(sub[2], 4);
}

TEST(span_utils, octet_range_default_length_runs_to_end)
{
    std::array<uint8_t, 8> data{0, 1, 2, 3, 4, 5, 6, 7};
    auto const tail = make_const_span(data, octet_range_t{.start = 5});
    EXPECT_EQ(tail.size(), size_t{3});
    EXPECT_EQ(tail[0], 5);
    auto const whole = make_const_span(data, octet_range_t{});
    EXPECT_EQ(whole.size(), size_t{8});
    // A mutable sub-range writes through to the container.
    auto const mut = make_span(data, octet_range_t{.start = 1, .length = 2});
    mut[0] = 0xAA;
    EXPECT_EQ(data[1], 0xAA);
}

//
// make_span / make_const_span / as_string_view
//
TEST(span_utils, make_span_object_and_containers)
{
    uint32_t value = 0;
    auto const obj_span = make_span(value);
    EXPECT_EQ(obj_span.size(), sizeof(uint32_t));
    obj_span[0] = 0xFF;  // writes through to the object
    EXPECT_TRUE(value != 0);

    std::vector<uint8_t> vec{1, 2, 3};
    EXPECT_EQ(make_const_span(vec).size(), size_t{3});
    statusbar::sg14::inplace_vector<uint8_t, 8> ipv;
    ipv.push_back(9);
    EXPECT_EQ(make_const_span(ipv).size(), size_t{1});
    EXPECT_EQ(make_const_span(ipv)[0], 9);
}

TEST(span_utils, string_view_round_trip)
{
    std::string_view const sv{"wire"};
    auto const bytes = make_const_span(sv);
    EXPECT_EQ(bytes.size(), size_t{4});
    EXPECT_EQ(bytes[0], uint8_t{'w'});
    EXPECT_TRUE(as_string_view(bytes) == sv);
}

//
// span_copy / can_span_copy
//
TEST(span_utils, span_copy_dynamic_copies_min_of_sizes)
{
    std::array<uint8_t, 4> src{1, 2, 3, 4};
    std::array<uint8_t, 2> small{};
    span_copy(std::span<uint8_t>(small), make_const_span(src));  // dest shorter: 2 bytes
    EXPECT_EQ(small[0], 1);
    EXPECT_EQ(small[1], 2);

    std::array<uint8_t, 6> big{};
    span_copy(std::span<uint8_t>(big), make_const_span(src));  // src shorter: 4 bytes
    EXPECT_EQ(big[3], 4);
    EXPECT_EQ(big[4], 0);
}

TEST(span_utils, span_copy_fixed_and_exact_dynamic_source)
{
    std::array<uint8_t, 4> src{5, 6, 7, 8};
    std::array<uint8_t, 4> dst{};
    span_copy(make_span(dst), make_const_span(src));  // fixed N == N
    EXPECT_EQ(dst[3], 8);

    std::array<uint8_t, 4> dst2{};
    // dynamic source of exactly N bytes into a fixed-extent destination
    span_copy(make_span(dst2), std::span<uint8_t const>(src.data(), src.size()));
    EXPECT_EQ(dst2[0], 5);
    EXPECT_TRUE(can_span_copy(make_span(dst2), std::span<uint8_t const>(src.data(), src.size())));
    EXPECT_FALSE(can_span_copy(make_span(dst2), std::span<uint8_t const>(src.data(), 2)));
}

//
// Comparison — plain and constant-time
//
TEST(span_utils, span_compare_equal_and_differing)
{
    std::array<uint8_t, 4> a{1, 2, 3, 4};
    std::array<uint8_t, 4> b{1, 2, 3, 4};
    std::array<uint8_t, 4> c{1, 2, 9, 4};
    EXPECT_TRUE(span_compare(make_const_span(a), make_const_span(b)));
    EXPECT_FALSE(span_compare(make_const_span(a), make_const_span(c)));
    // dynamic-extent overload: length mismatch is unequal
    EXPECT_FALSE(span_compare(std::span<uint8_t const>(a.data(), 3), std::span<uint8_t const>(b.data(), 4)));
}

TEST(span_utils, span_compare_constant_time_matches_plain_semantics)
{
    std::array<uint8_t, 4> a{1, 2, 3, 4};
    std::array<uint8_t, 4> b{1, 2, 3, 4};
    std::array<uint8_t, 4> c{1, 2, 9, 4};
    EXPECT_TRUE(span_compare_constant_time(a, b));
    EXPECT_FALSE(span_compare_constant_time(a, make_const_span(c)));
    // dynamic-extent overload: length mismatch is unequal, no assert
    EXPECT_FALSE(span_compare_constant_time(std::span<uint8_t const>(a.data(), 3), std::span<uint8_t const>(b.data(), 4)));
    // and equal dynamic spans compare equal
    EXPECT_TRUE(span_compare_constant_time(std::span<uint8_t const>(a.data(), 4), std::span<uint8_t const>(b.data(), 4)));
}

//
// span_load / span_store / span_load_padded
//
TEST(span_utils, load_store_round_trip)
{
    uint32_t const original = 0xA1B2C3D4;
    std::array<uint8_t, 8> wire{};
    span_store(wire, original);  // array overload, compile-time N >= sizeof(T)
    uint32_t loaded = 0;
    span_load(loaded, wire);
    EXPECT_EQ(loaded, original);
}

TEST(span_utils, load_padded_zero_fills_missing_tail_and_ignores_extra)
{
    struct WireV2
    {
        uint16_t a;
        uint16_t b;
    };
    WireV2 out{.a = 0xFFFF, .b = 0xFFFF};
    std::array<uint8_t, 2> const short_wire{0x11, 0x22};  // only field a arrives
    span_load_padded(out, make_const_span(short_wire));
    std::array<uint8_t, 2> a_bytes{};
    span_store(a_bytes, out.a);
    EXPECT_EQ(a_bytes[0], 0x11);
    EXPECT_EQ(out.b, uint16_t{0});  // zero-padded, not stale

    std::array<uint8_t, 6> const long_wire{1, 2, 3, 4, 5, 6};  // trailing bytes ignored
    span_load_padded(out, make_const_span(long_wire));
    EXPECT_EQ(std::memcmp(&out, long_wire.data(), sizeof(out)), 0);
}

//
// wire_size-aware helpers
//
namespace {
struct WireDescriptor
{
    uint8_t header[4]{0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t trailer[4]{0x01, 0x02, 0x03, 0x04};
    uint8_t used_trailer_bytes{2};
    [[nodiscard]] auto wire_size() const noexcept -> size_t { return sizeof(header) + used_trailer_bytes; }
};
}  // namespace

TEST(span_utils, wire_span_and_store_wire_use_declared_size)
{
    WireDescriptor const desc;
    auto const view = wire_span(desc);
    EXPECT_EQ(view.size(), size_t{6});
    EXPECT_EQ(view[0], 0xDE);
    EXPECT_EQ(view[5], 0x02);

    std::array<uint8_t, 16> out{};
    span_fill(std::span<uint8_t>(out), 0xEE);
    span_store_wire(std::span<uint8_t>(out), desc);
    EXPECT_EQ(out[5], 0x02);
    EXPECT_EQ(out[6], 0xEE);  // bytes past wire_size untouched
}

//
// Header + payload framing
//
TEST(span_utils, pack_header_payload_frames_and_sizes)
{
    struct Header
    {
        uint8_t type;
        uint8_t flags;
    };
    Header const header{.type = 0x7E, .flags = 0x01};
    std::array<uint8_t, 3> const payload{0xAA, 0xBB, 0xCC};
    std::array<uint8_t, 16> frame{};
    auto const packed = span_pack_header_payload(frame, header, make_const_span(payload));
    EXPECT_EQ(packed.size(), sizeof(Header) + payload.size());
    EXPECT_EQ(packed[0], 0x7E);
    EXPECT_EQ(packed[2], 0xAA);
    EXPECT_EQ(packed[4], 0xCC);
}

//
// Fill / zero
//
TEST(span_utils, fill_and_zero)
{
    std::array<uint8_t, 4> data{};
    span_fill(std::span<uint8_t>(data), 0x5A);
    EXPECT_EQ(data[3], 0x5A);
    span_zero(std::span<uint8_t>(data));
    EXPECT_EQ(data[0], 0);
    EXPECT_EQ(data[3], 0);

    statusbar::sg14::inplace_vector<uint8_t, 4> ipv;
    ipv.push_back(1);
    ipv.push_back(2);
    span_fill(ipv, 0x33);
    EXPECT_EQ(ipv[1], 0x33);
    span_zero(ipv);
    EXPECT_EQ(ipv[0], 0);
}

TEST_MAIN(statusbar_buffer, span_utils_test)
