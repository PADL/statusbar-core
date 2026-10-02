// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/checksum/checksum_crc32.hpp"
#include "statusbar/checksum/checksum_ones_complement.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::checksum;

namespace {

// "123456789" — the check string every CRC catalogue quotes.
constexpr std::array<uint8_t, 9> CHECK_STRING{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};

// RFC 1071 arithmetic on the textbook IPv4 header (checksum field zeroed).
constexpr std::array<uint8_t, 20> IPV4_HEADER{
    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
};

// Compile-time proof the tables and the check values agree.
static_assert(crc32_ethernet(std::span<uint8_t const>{CHECK_STRING}) == 0xCBF43926U);
static_assert(crc32_p4(std::span<uint8_t const>{CHECK_STRING}) == 0x1697D06AU);
static_assert(internet_checksum16(std::span<uint8_t const>{IPV4_HEADER}) == 0xB861U);

}  // namespace

TEST(checksum, ones_complement_textbook_ipv4_header)
{
    EXPECT_EQ(internet_checksum16(std::span<uint8_t const>{IPV4_HEADER}), 0xB861U);

    // With the field filled in, the whole header sums to all ones.
    auto with_field = IPV4_HEADER;
    with_field[10] = 0xB8;
    with_field[11] = 0x61;
    EXPECT_TRUE(internet_checksum_ok(std::span<uint8_t const>{with_field}));
    with_field[12] = static_cast<uint8_t>(with_field[12] ^ 0x01U);
    EXPECT_FALSE(internet_checksum_ok(std::span<uint8_t const>{with_field}));
}

TEST(checksum, ones_complement_odd_length_and_fold)
{
    constexpr std::array<uint8_t, 2> two{0x61, 0x62};
    constexpr std::array<uint8_t, 3> three{0x61, 0x62, 0x63};
    EXPECT_EQ(ones_complement_sum16(std::span<uint8_t const>{two}), 0x6162U);
    EXPECT_EQ(ones_complement_sum16(std::span<uint8_t const>{three}), 0xC462U);  // 0x6162 + 0x6300

    // End-around carry: 0xFFFF + 0x0001 folds to 0x0001, never to 0x0000.
    constexpr std::array<uint8_t, 4> carry{0xFF, 0xFF, 0x00, 0x01};
    EXPECT_EQ(ones_complement_sum16(std::span<uint8_t const>{carry}), 0x0001U);
    EXPECT_EQ(ones_complement_sum16(std::span<uint8_t const>{}), 0x0000U);
}

TEST(checksum, ones_complement_piecewise)
{
    auto const all = std::span<uint8_t const>{IPV4_HEADER};
    auto const first = ones_complement_sum16(all.first(8));
    auto const rest = ones_complement_sum16(all.subspan(8), first);
    EXPECT_EQ(rest, ones_complement_sum16(all));
}

TEST(checksum, crc32_ethernet_vectors)
{
    constexpr std::array<uint8_t, 1> a{0x61};
    constexpr std::array<uint8_t, 3> abc{0x61, 0x62, 0x63};
    constexpr std::array<uint8_t, 4> zeros{0x00, 0x00, 0x00, 0x00};
    constexpr std::array<uint8_t, 4> ones{0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{}), 0x00000000U);
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{a}), 0xE8B7BE43U);
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{abc}), 0x352441C2U);
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{zeros}), 0x2144DF1CU);
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{ones}), 0xFFFFFFFFU);
    EXPECT_EQ(crc32_ethernet(std::span<uint8_t const>{CHECK_STRING}), 0xCBF43926U);
}

TEST(checksum, crc32_p4_autosar_vectors)
{
    // Specification of CRC Routines, 7.2.3.2 (32-bit 0xF4ACFB13 polynomial).
    constexpr std::array<uint8_t, 4> v1{0x00, 0x00, 0x00, 0x00};
    constexpr std::array<uint8_t, 3> v2{0xF2, 0x01, 0x83};
    constexpr std::array<uint8_t, 4> v3{0x0F, 0xAA, 0x00, 0x55};
    constexpr std::array<uint8_t, 4> v4{0x00, 0xFF, 0x55, 0x11};
    constexpr std::array<uint8_t, 9> v5{0x33, 0x22, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    constexpr std::array<uint8_t, 3> v6{0x92, 0x6B, 0x55};
    constexpr std::array<uint8_t, 4> v7{0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v1}), 0x6FB32240U);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v2}), 0x4F721A25U);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v3}), 0x20662DF8U);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v4}), 0x9BD7996EU);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v5}), 0xA65A343DU);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v6}), 0xEE688A78U);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{v7}), 0xFFFFFFFFU);
    EXPECT_EQ(crc32_p4(std::span<uint8_t const>{CHECK_STRING}), 0x1697D06AU);
}

TEST(checksum, crc32_piecewise_update)
{
    auto const all = std::span<uint8_t const>{CHECK_STRING};
    auto state = Crc32Ethernet::update(all.first(4));
    state = Crc32Ethernet::update(all.subspan(4, 3), state);
    state = Crc32Ethernet::update(all.subspan(7), state);
    EXPECT_EQ(Crc32Ethernet::finalize(state), 0xCBF43926U);

    auto p4 = Crc32P4::update(all.first(1));
    p4 = Crc32P4::update(all.subspan(1), p4);
    EXPECT_EQ(Crc32P4::finalize(p4), 0x1697D06AU);
}

TEST_MAIN(statusbar_checksum, checksum_test)
