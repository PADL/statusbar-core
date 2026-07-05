// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/fmt/fmt.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>
#include <limits>
#include <string_view>

using namespace statusbar;

// ---- fixed_str ----
TEST(statusbar_fmt, fixed_str_basic)
{
    fmt::fixed_str<8> s{std::string_view{"abc"}};
    EXPECT_EQ(s.size(), size_t{3});
    EXPECT_EQ(s, "abc");
    EXPECT_TRUE(std::string_view{s.c_str()} == "abc");
}

TEST(statusbar_fmt, fixed_str_widening)
{
    fmt::fixed_str<6> small{std::string_view{"0x12"}};
    fmt::fixed_str<8> big = small;  // widening ctor
    EXPECT_EQ(big, "0x12");
}

// ---- decimal ----
TEST(statusbar_fmt, decimal_unsigned)
{
    EXPECT_EQ(fmt::format<"{}">(static_cast<unsigned>(0)), "0");
    EXPECT_EQ(fmt::format<"{}">(static_cast<unsigned>(42)), "42");
    EXPECT_EQ(fmt::format<"{:d}">(static_cast<uint16_t>(1234)), "1234");
}

TEST(statusbar_fmt, decimal_signed_negative)
{
    EXPECT_EQ(fmt::format<"{}">(-5), "-5");
    EXPECT_EQ(fmt::format<"{}">(std::numeric_limits<int32_t>::min()), "-2147483648");
}

TEST(statusbar_fmt, decimal_width_space_pad)
{
    EXPECT_EQ(fmt::format<"{:4}">(static_cast<unsigned>(7)), "   7");
}

// ---- hex ----
TEST(statusbar_fmt, hex_lower_upper_and_zero_pad)
{
    EXPECT_EQ(fmt::format<"{:x}">(static_cast<uint8_t>(0xAB)), "ab");
    EXPECT_EQ(fmt::format<"{:X}">(static_cast<uint8_t>(0xAB)), "AB");
    EXPECT_EQ(fmt::format<"{:02x}">(static_cast<uint8_t>(0x05)), "05");
    EXPECT_EQ(fmt::format<"0x{:04x}">(static_cast<uint16_t>(0x88F7)), "0x88f7");
}

TEST(statusbar_fmt, hex_signed_negative)
{
    // The worst-case bound must leave room for the '-' or the most-negative
    // values silently truncate (regression: INT32_MIN printed "-8000000").
    EXPECT_EQ(fmt::format<"{:x}">(std::numeric_limits<int32_t>::min()), "-80000000");
    EXPECT_EQ(fmt::format<"{:x}">(std::numeric_limits<int8_t>::min()), "-80");
    EXPECT_EQ(fmt::format<"{:X}">(std::numeric_limits<int16_t>::min()), "-8000");
    EXPECT_EQ(fmt::format<"{:x}">(std::numeric_limits<int64_t>::min()), "-8000000000000000");
    EXPECT_EQ(fmt::format<"{:x}">(-5), "-5");
}

// ---- binary ----
TEST(statusbar_fmt, binary_zero_pad)
{
    EXPECT_EQ(fmt::format<"{:08b}">(static_cast<uint8_t>(0x05)), "00000101");
    EXPECT_EQ(fmt::format<"{:b}">(static_cast<uint8_t>(0x05)), "101");
}

TEST(statusbar_fmt, binary_signed_negative)
{
    EXPECT_EQ(fmt::format<"{:b}">(std::numeric_limits<int8_t>::min()), "-10000000");
    EXPECT_EQ(fmt::format<"{:b}">(-5), "-101");
}

// ---- strings / char / literal braces ----
TEST(statusbar_fmt, string_literal_passthrough)
{
    EXPECT_EQ(fmt::format<"{} (0x{:04x})">("PTP", static_cast<uint16_t>(0x88F7)), "PTP (0x88f7)");
}

TEST(statusbar_fmt, char_and_braces)
{
    EXPECT_EQ(fmt::format<"{}{{{}}}">('a', 'b'), "a{b}");
}

TEST(statusbar_fmt, fixed_str_argument)
{
    fmt::fixed_str<8> name{std::string_view{"IPv4"}};
    EXPECT_EQ(fmt::format<"type {}">(name), "type IPv4");
}

// ---- the MAC shape (the motivating case) ----
TEST(statusbar_fmt, mac_six_bytes)
{
    auto s = fmt::format<"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}">(
        static_cast<uint8_t>(0xAA),
        static_cast<uint8_t>(0xBB),
        static_cast<uint8_t>(0xCC),
        static_cast<uint8_t>(0xDD),
        static_cast<uint8_t>(0xEE),
        static_cast<uint8_t>(0xFF));
    EXPECT_EQ(s, "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(decltype(s)::capacity, size_t{17});  // derived, exact
}

// ---- derived-size / constexpr checks ----
TEST(statusbar_fmt, derived_capacity_and_constexpr)
{
    static_assert(decltype(fmt::format<"0x{:04x}">(static_cast<uint16_t>(0)))::capacity == 6);
    static_assert(fmt::format<"0x{:04x}">(static_cast<uint16_t>(0x88F7)).view() == std::string_view{"0x88f7"});
    EXPECT_TRUE(true);
}

// Exact worst-case bounds (the sizing contract).
static_assert(fmt::detail::worst_case<"{}", uint8_t>() == 3);
static_assert(fmt::detail::worst_case<"{}", int32_t>() == 11);  // -2147483648
static_assert(fmt::detail::worst_case<"{:02x}", uint8_t>() == 2);
static_assert(fmt::detail::worst_case<"{:x}", int32_t>() == 9);   // -80000000
static_assert(fmt::detail::worst_case<"{:b}", int8_t>() == 9);    // -10000000
static_assert(fmt::detail::worst_case<"0x{:04x}", uint16_t>() == 6);
static_assert(fmt::detail::worst_case<"{:08b}", uint8_t>() == 8);
static_assert(
    fmt::detail::worst_case<"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>() ==
    17);
// char[4] bound = 3 ("PTP"), " (0x" = 4, {:04x} on uint16_t = 4, ")" = 1 -> 12
static_assert(fmt::detail::worst_case<"{} (0x{:04x})", char[4], uint16_t>() == 12);

TEST(statusbar_fmt, bounds_are_tight)
{
    // Same as the static_asserts but visible as a passing ctest case too.
    EXPECT_EQ((fmt::detail::worst_case<"0x{:04x}", uint16_t>()), size_t{6});
}

// ---------------------------------------------------------------------------
// COMPILE-FAIL HARNESS (manual): each line MUST fail to compile if uncommented.
// Verify by uncommenting one at a time and building; expect the quoted message.
//   fmt::format<"{:f}">(1);                              // float type rejected
//   fmt::format<"{:s}">(42);                             // {:s} on integer
//   fmt::format<"{:x}">("hi");                           // numeric spec on string
//   fmt::format<"{}">(true);                             // bool unsupported
//   { char const* p = "x"; fmt::format<"{}">(p); }       // unbounded const char*
//   { std::string_view sv; fmt::format<"{}">(sv); }      // unbounded string_view
//   fmt::format<"{} {}">(1);                             // more fields than args
//   fmt::format<"{}">(1, 2);                             // more args than fields
//   fmt::format<"{:04">(1);                              // missing '}'
// ---------------------------------------------------------------------------

TEST_MAIN(statusbar_fmt, fmt_test)
