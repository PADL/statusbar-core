// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

using namespace statusbar;

struct S
{
    int x;
    double y;
};

union U
{
    int x;
    float y;
};

static_assert(PlainType<int>);
static_assert(PlainType<double const>);
static_assert(PlainType<unsigned long long>);
static_assert(PlainType<std::uint64_t>);
#if defined(__SIZEOF_INT128__)
// __int128 / __uint128_t are compiler extensions: std::is_arithmetic_v
// rejects them under a strict -std=c++NN dialect (GCC, and Clang outside
// GNU mode), so PlainElement accepts them explicitly via is_extended_integer_v.
static_assert(PlainType<__uint128_t>);
static_assert(PlainType<__int128_t>);
#endif
static_assert(PlainType<std::array<int, 4>>);
static_assert(PlainLinearCollection<std::array<int, 4>>);
static_assert(PlainType<std::array<double, 2> const>);
static_assert(PlainType<int[4]>);
static_assert(PlainLinearCollection<double[8]>);
static_assert(PlainType<float const[8]>);

static_assert(!PlainType<int*>);
static_assert(!PlainType<float*>);
static_assert(!PlainType<unsigned char*>);
static_assert(!PlainType<std::array<int*, 4>>);
static_assert(!PlainType<S>);
static_assert(!PlainType<U>);
// A span views plain bytes but is not itself plain: its object bytes are a
// pointer and a length, so it must never be serialized in place of what it
// views.
static_assert(PlainStdSpan<std::span<uint8_t>>);
static_assert(PlainStdSpan<std::span<uint8_t, 10>>);
static_assert(!PlainStdSpan<std::span<float*>>);
static_assert(!PlainLinearCollection<std::span<uint8_t>>);
static_assert(!PlainType<std::span<uint8_t>>);
static_assert(!PlainType<std::span<uint8_t const>>);
static_assert(!PlainType<std::span<uint8_t, 10>>);
static_assert(!PlainType<std::span<float*>>);
static_assert(!PlainType<std::span<float*, 10>>);
static_assert(traits::StdSpan<std::span<uint8_t>>);
static_assert(traits::StdSpan<std::span<uint8_t const, 4> const&>);
static_assert(traits::StdSpan<std::span<S>>);
static_assert(!traits::StdSpan<std::array<uint8_t, 4>>);
static_assert(!traits::StdSpan<uint8_t*>);
static_assert(PlainStdVector<std::vector<float>>);
static_assert(!PlainStdVector<std::vector<uint8_t const*>>);
static_assert(!PlainType<std::vector<float>>);
static_assert(!PlainType<std::vector<uint8_t*>>);

static_assert(traits::PlainInplaceVector<statusbar::sg14::inplace_vector<float, 8>>);
static_assert(traits::PlainInplaceVector<statusbar::sg14::inplace_vector<uint32_t, 4>>);
static_assert(!traits::PlainInplaceVector<statusbar::sg14::inplace_vector<uint8_t const*, 4>>);
static_assert(traits::PlainSizedContiguous<std::vector<float>>);
static_assert(traits::PlainSizedContiguous<statusbar::sg14::inplace_vector<float, 8>>);
static_assert(!traits::PlainSizedContiguous<std::array<float, 8>>);

// WireValue: what the builders and compiled serdes move as a unit.
static_assert(traits::WireValue<uint32_t>);
static_assert(traits::WireValue<S>);
static_assert(traits::WireValue<std::array<uint8_t, 6>>);
static_assert(traits::WireValue<uint8_t[4]>);
static_assert(!traits::WireValue<std::span<uint8_t>>);
static_assert(!traits::WireValue<std::span<uint8_t const>>);
static_assert(!traits::WireValue<std::span<uint8_t, 4>>);
static_assert(!traits::WireValue<std::vector<uint8_t>>);
static_assert(!traits::WireValue<std::string>);

// Negative-compile checks. A requires-expression outside a template is
// ill-formed when its body is invalid, so each probe is a concept.
template <typename T>
concept CanMakeSpan = requires(T& v) { make_span(v); };
template <typename T>
concept CanMakeConstSpan = requires(T const& v) { make_const_span(v); };
template <typename T>
concept CanSpanLoad = requires(T& v, std::span<uint8_t const> b) { span_load(v, b); };
template <typename T>
concept CanSpanStore = requires(T const& v, std::span<uint8_t> b) { span_store(b, v); };
template <typename T>
concept CanSpanLoadPadded = requires(T& v, std::span<uint8_t const> b) { span_load_padded(v, b); };
template <typename T>
concept CanProtocolLoad = requires(T* p, std::span<uint8_t const> b) { protocol::load(b, p); };
template <typename T>
concept CanProtocolCanLoad = requires(T* p, std::span<uint8_t const> b) { protocol::can_load(b, p); };
template <typename T>
concept CanProtocolStore = requires(T const& v, std::span<uint8_t> b) { protocol::store(b, v); };
template <typename T>
concept CanSerializedSize = requires(T const& v) { protocol::serialized_size(v); };

// The byte-reinterpreting helpers refuse spans.
static_assert(!CanMakeSpan<std::span<uint8_t>>);
static_assert(!CanMakeConstSpan<std::span<uint8_t const>>);
static_assert(!CanSpanLoad<std::span<uint8_t>>);
static_assert(!CanSpanStore<std::span<uint8_t const>>);
static_assert(!CanSpanLoadPadded<std::span<uint8_t>>);
static_assert(CanMakeSpan<std::array<uint8_t, 4>>);
static_assert(CanMakeConstSpan<uint32_t>);
static_assert(CanSpanLoad<uint32_t>);
static_assert(CanSpanStore<S>);

// protocol::load / store refuse spans — a span is not a PlainType.
static_assert(!CanProtocolLoad<std::span<uint8_t>>);
static_assert(!CanProtocolCanLoad<std::span<uint8_t>>);
static_assert(!CanProtocolStore<std::span<uint8_t const>>);
static_assert(CanProtocolLoad<uint32_t>);
static_assert(CanProtocolLoad<std::array<uint16_t, 3>>);
static_assert(CanProtocolStore<uint32_t>);

// protocol::serialized_size
struct Fixed3
{
    static constexpr size_t LENGTH = 3;
};
template <>
struct statusbar::traits::is_serializable_fixed_struct<Fixed3> : std::true_type
{};
static_assert(protocol::serialized_size(uint32_t{0}) == 4);
static_assert(protocol::serialized_size(std::array<uint8_t, 6>{}) == 6);
static_assert(protocol::serialized_size(Fixed3{}) == 3);
static_assert(!CanSerializedSize<std::span<uint8_t const>>);
static_assert(!CanSerializedSize<std::vector<uint8_t>>);

TEST(traits, general)
{
    static_assert(!PlainType<S>);
    EXPECT_TRUE(true);
}

TEST_MAIN(statusbar_buffer, buffer_traits_test)