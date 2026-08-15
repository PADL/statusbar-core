// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>

using namespace statusbar;
using namespace statusbar::ieee;

//
// IeeeOrderedUInt basic construction and conversion tests
//

TEST(ieee_base, default_constructor)
{
    quadlet_t value;
    EXPECT_EQ(value, 0U);
}

TEST(ieee_base, value_constructor)
{
    quadlet_t value{0x12345678};
    EXPECT_EQ(value, 0x12345678U);
}

TEST(ieee_base, implicit_conversion_from_uint)
{
    quadlet_t value = 0xAABBCCDD;
    EXPECT_EQ(value, 0xAABBCCDDu);
}

TEST(ieee_base, implicit_conversion_to_uint)
{
    quadlet_t value{0x12345678};
    uint32_t host_val = value;
    EXPECT_EQ(host_val, 0x12345678U);
}

TEST(ieee_base, assignment_operator)
{
    quadlet_t value;
    value = 0xDEADBEEF;
    EXPECT_EQ(value, 0xDEADBEEFu);
}

//
// IeeeOrderedUInt explicit get/set tests
//

TEST(ieee_base, explicit_set_and_get_methods)
{
    // Test explicit set() method
    quadlet_t value;
    value.set(0x11223344);
    EXPECT_EQ(value.get(), 0x11223344U);

    // Test multiple set/get operations
    value.set(0xAABBCCDD);
    EXPECT_EQ(value.get(), 0xAABBCCDDu);

    value.set(0xDEADBEEF);
    EXPECT_EQ(value.get(), 0xDEADBEEFu);

    // Test that get() returns the same as implicit conversion
    uint32_t implicit_result = value;
    uint32_t explicit_result = value.get();
    EXPECT_EQ(implicit_result, explicit_result);
}

TEST(ieee_base, set_network_preserves_bytes)
{
    quadlet_t value;
    value.set_network(0x11223344);
    // network_value() should return exactly what was set
    EXPECT_EQ(value.network_value(), 0x11223344U);
}

//
// Byte order conversion tests
//

TEST(ieee_base, network_byte_order_storage)
{
    // On little-endian systems, verify bytes are swapped in storage
    // On big-endian systems, verify bytes are not swapped
    quadlet_t value{0x12345678};

    // Access the internal bytes directly (stored in network/big-endian order)
    auto const bytes = value.span();

    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0x56);
    EXPECT_EQ(bytes[3], 0x78);
}

TEST(ieee_base, round_trip_conversion)
{
    uint32_t const original = 0xCAFEBABE;
    quadlet_t value{original};
    uint32_t const result = value;
    EXPECT_EQ(result, original);
}

//
// All type sizes tests
//

TEST(ieee_base, octet_t_8bit)
{
    octet_t value{0xAB};
    EXPECT_EQ(value, 0xABu);
    EXPECT_EQ(sizeof(value), 1U);
}

TEST(ieee_base, doublet_t_16bit)
{
    doublet_t value{0x1234};
    EXPECT_EQ(value, 0x1234U);
    EXPECT_EQ(sizeof(value), 2U);
}

TEST(ieee_base, quadlet_t_32bit)
{
    quadlet_t value{0x12345678};
    EXPECT_EQ(value, 0x12345678U);
    EXPECT_EQ(sizeof(value), 4U);
}

TEST(ieee_base, octlet_t_64bit)
{
    octlet_t value{0x123456789ABCDEF0};
    EXPECT_EQ(value, 0x123456789ABCDEF0ull);
    EXPECT_EQ(sizeof(value), 8U);
}

//
// Byte data access tests
//

TEST(ieee_base, span_allows_direct_write)
{
    quadlet_t value;
    // Directly write network-ordered bytes
    uint8_t const bytes[4] = {0x11, 0x22, 0x33, 0x44};
    span_copy(value.span(), std::span<uint8_t const, 4>(bytes, 4));

    // Verify the value is stored in network byte order (big-endian)
    EXPECT_EQ(value.get(), 0x11223344U);
}

TEST(ieee_base, memcpy_to_span)
{
    quadlet_t value;
    uint8_t const packet[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    // Simulate reading from network packet
    span_copy(value.span(), std::span<uint8_t const, 4>(packet, 4));

    // Verify bytes are stored correctly (big-endian)
    auto const bytes = value.span();
    EXPECT_EQ(bytes[0], 0xAA);
    EXPECT_EQ(bytes[1], 0xBB);
    EXPECT_EQ(bytes[2], 0xCC);
    EXPECT_EQ(bytes[3], 0xDD);
}

TEST(ieee_base, memcpy_from_span)
{
    quadlet_t value;
    // Set value in host order, which will convert to network order (big-endian)
    value.set(0xAABBCCDD);

    uint8_t packet[4];
    span_copy(std::span<uint8_t, 4>(packet, 4), value.span());

    // Verify bytes copied correctly in big-endian order
    EXPECT_EQ(packet[0], 0xAA);
    EXPECT_EQ(packet[1], 0xBB);
    EXPECT_EQ(packet[2], 0xCC);
    EXPECT_EQ(packet[3], 0xDD);
}

//
// Type traits tests
//

TEST(ieee_base, is_ieee_ordered_uint_trait)
{
    static_assert(is_ieee_ordered_uint<octet_t>::value);
    static_assert(is_ieee_ordered_uint<doublet_t>::value);
    static_assert(is_ieee_ordered_uint<quadlet_t>::value);
    static_assert(is_ieee_ordered_uint<octlet_t>::value);

    static_assert(!is_ieee_ordered_uint<uint8_t>::value);
    static_assert(!is_ieee_ordered_uint<uint16_t>::value);
    static_assert(!is_ieee_ordered_uint<uint32_t>::value);
    static_assert(!is_ieee_ordered_uint<uint64_t>::value);
}

TEST(ieee_base, is_ieee_std_array_trait)
{
    static_assert(is_ieee_std_array<std::array<octet_t, 6>>::value);
    static_assert(is_ieee_std_array<std::array<quadlet_t, 10>>::value);

    static_assert(!is_ieee_std_array<std::array<uint32_t, 10>>::value);
    static_assert(!is_ieee_std_array<quadlet_t>::value);
}

TEST(ieee_base, is_ieee_std_span_trait)
{
    static_assert(is_ieee_std_span<std::span<octet_t, 6>>::value);
    static_assert(is_ieee_std_span<std::span<quadlet_t, 10>>::value);

    static_assert(!is_ieee_std_span<std::span<uint32_t, 10>>::value);
    static_assert(!is_ieee_std_span<quadlet_t>::value);
}

//
// Natural usage pattern tests
//

TEST(ieee_base, natural_arithmetic)
{
    quadlet_t counter = 0;
    counter = counter + 1;
    EXPECT_EQ(counter, 1U);

    counter = counter + 99;
    EXPECT_EQ(counter, 100U);
}

TEST(ieee_base, natural_comparison)
{
    quadlet_t value1 = 100;
    quadlet_t value2 = 200;

    EXPECT_TRUE(value1 < value2);
    EXPECT_TRUE(value2 > value1);
    EXPECT_FALSE(value1 == value2);
}

TEST(ieee_base, array_of_ieee_ordered_values)
{
    std::array<quadlet_t, 3> values = {100, 200, 300};

    EXPECT_EQ(values[0], 100U);
    EXPECT_EQ(values[1], 200U);
    EXPECT_EQ(values[2], 300U);
}

//
// Constexpr tests
//

TEST(ieee_base, constexpr_construction)
{
    constexpr quadlet_t value{0x12345678};
    static_assert(value == 0x12345678U);
}

TEST(ieee_base, constexpr_operations)
{
    constexpr quadlet_t value{100};
    constexpr uint32_t result = value;
    static_assert(result == 100U);
}

// ===========================================================================
// IeeeOrderedUInt<uint8_t> three-way comparison
// ===========================================================================

TEST(ieee_base_octet, spaceship_operator)
{
    octet_t a{10};
    octet_t b{20};
    octet_t c{10};

    EXPECT_TRUE((a <=> c) == std::strong_ordering::equal);
    EXPECT_TRUE((a <=> b) == std::strong_ordering::less);
    EXPECT_TRUE((b <=> a) == std::strong_ordering::greater);
    EXPECT_TRUE(a == c);
    EXPECT_TRUE(a != b);
    EXPECT_TRUE(a < b);
    EXPECT_TRUE(b > a);
}

TEST(ieee_ordered_uint, comparison_no_truncation)
{
    // Regression test for issue 955ee22: comparing doublet_t (uint16_t)
    // with a uint32_t value > 0xFFFF should NOT match due to truncation
    doublet_t d;
    d = 100;
    // 0x10064 truncated to uint16_t is 0x0064 = 100
    // This MUST return false (values are not equal)
    EXPECT_FALSE(d == 0x10064U);

    // Also test <=> doesn't truncate
    EXPECT_TRUE(d < 0x10064U);

    // Same-size comparison should still work
    EXPECT_TRUE(d == 100U);
    EXPECT_TRUE(d == static_cast<uint16_t>(100));

    // quadlet_t with uint64_t
    quadlet_t q;
    q = 42;
    EXPECT_FALSE(q == 0x100000002AUL);
    EXPECT_TRUE(q < 0x100000002AUL);
    EXPECT_TRUE(q == 42U);
}

//
// Test driver main function
//

//
// sextlet_t (48-bit ordered type)
//

TEST(ieee_base, sextlet_default_is_zero)
{
    sextlet_t v;
    EXPECT_EQ(v.get(), 0U);
    EXPECT_EQ(sizeof(v), 6U);
}

TEST(ieee_base, sextlet_network_byte_order_storage)
{
    sextlet_t v{0x0123456789ABULL};
    auto const s = v.span();
    EXPECT_EQ(s[0], 0x01);
    EXPECT_EQ(s[1], 0x23);
    EXPECT_EQ(s[2], 0x45);
    EXPECT_EQ(s[3], 0x67);
    EXPECT_EQ(s[4], 0x89);
    EXPECT_EQ(s[5], 0xAB);
    EXPECT_EQ(v.get(), 0x0123456789ABULL);
}

TEST(ieee_base, sextlet_truncates_to_48_bits)
{
    sextlet_t v{0xFFFF'0123456789ABULL};
    EXPECT_EQ(v.get(), 0x0123456789ABULL);
    EXPECT_EQ(sextlet_t::max_value(), 0x0000FFFFFFFFFFFFULL);
    sextlet_t max{sextlet_t::max_value()};
    EXPECT_EQ(max.get(), 0x0000FFFFFFFFFFFFULL);
}

TEST(ieee_base, sextlet_assignment_and_conversion)
{
    sextlet_t v;
    v = 0x800000000001ULL;
    uint64_t const host = v;
    EXPECT_EQ(host, 0x800000000001ULL);
}

TEST(ieee_base, sextlet_comparisons)
{
    sextlet_t const a{100};
    sextlet_t const b{200};
    EXPECT_TRUE(a < b);
    EXPECT_TRUE(a == 100U);
    EXPECT_TRUE(b > 150);
    EXPECT_TRUE(a != b);
}

TEST(ieee_base, sextlet_span_direct_write)
{
    sextlet_t v;
    auto s = v.span();
    s[0] = 0x00;
    s[1] = 0x00;
    s[2] = 0x00;
    s[3] = 0x00;
    s[4] = 0x01;
    s[5] = 0x02;
    EXPECT_EQ(v.get(), 0x0102U);
}

TEST(ieee_base, sextlet_satisfies_ordered_trait)
{
    EXPECT_TRUE(is_ieee_ordered_uint<sextlet_t>::value);
}

TEST_MAIN(statusbar_ieee, ieee_base_test)