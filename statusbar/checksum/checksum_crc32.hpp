#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Table-driven reflected (LSB-first) CRC-32 with compile-time tables.
/// Two parameter sets are provided ready-made:
///   - Crc32Ethernet: IEEE 802.3 FCS, polynomial 0x04C11DB7 (reflected
///     0xEDB88320), init and xor-out 0xFFFFFFFF; check("123456789") =
///     0xCBF43926. The IEEE 1722-2025 ACF_CRC message's CRC_ETH (9.4.21).
///   - Crc32P4: AUTOSAR "CRC32P4", polynomial 0xF4ACFB13 (reflected
///     0xC8DF352F), init and xor-out 0xFFFFFFFF, reflected in and out;
///     check("123456789") = 0x1697D06A. ACF_CRC's CRC_32P4.
/// Both are constexpr end to end, so a CRC of a constant image can be a
/// static_assert.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::checksum {

namespace detail {

/// The 256-entry byte table for a reflected polynomial.
[[nodiscard]] constexpr auto crc32_reflected_table(uint32_t reflected_poly) noexcept -> std::array<uint32_t, 256>
{
    std::array<uint32_t, 256> table{};
    for (uint32_t n = 0; n < 256U; ++n) {
        uint32_t crc = n;
        for (int k = 0; k < 8; ++k) {
            crc = ((crc & 1U) != 0U) ? (reflected_poly ^ (crc >> 1U)) : (crc >> 1U);
        }
        table[n] = crc;
    }
    return table;
}

}  // namespace detail

/// A reflected CRC-32 parameter set. ReflectedPoly is the bit-reversed
/// polynomial; Init seeds the register; XorOut is applied by finalize().
template <uint32_t ReflectedPoly, uint32_t Init, uint32_t XorOut>
class Crc32Reflected
{
  public:
    static constexpr uint32_t reflected_poly = ReflectedPoly;
    static constexpr uint32_t init = Init;
    static constexpr uint32_t xor_out = XorOut;

    /// Advance the register @p state over @p data (start from init for a
    /// fresh CRC); feed pieces in sequence to CRC a message piecewise.
    [[nodiscard]] static constexpr auto update(std::span<uint8_t const> data, uint32_t state = Init) noexcept -> uint32_t
    {
        for (auto const octet : data) {
            state = TABLE[(state ^ octet) & 0xFFU] ^ (state >> 8U);
        }
        return state;
    }

    /// The CRC value for a register @p state.
    [[nodiscard]] static constexpr auto finalize(uint32_t state) noexcept -> uint32_t { return state ^ XorOut; }

    /// The CRC of @p data in one call.
    [[nodiscard]] static constexpr auto compute(std::span<uint8_t const> data) noexcept -> uint32_t
    {
        return finalize(update(data));
    }

  private:
    static constexpr std::array<uint32_t, 256> TABLE = detail::crc32_reflected_table(ReflectedPoly);
};

/// IEEE 802.3 Frame Check Sequence CRC-32.
using Crc32Ethernet = Crc32Reflected<0xEDB88320U, 0xFFFFFFFFU, 0xFFFFFFFFU>;

/// AUTOSAR CRC32P4 (Specification of CRC Routines 7.2.3.2).
using Crc32P4 = Crc32Reflected<0xC8DF352FU, 0xFFFFFFFFU, 0xFFFFFFFFU>;

/// The Ethernet CRC-32 of @p data.
[[nodiscard]] constexpr auto crc32_ethernet(std::span<uint8_t const> data) noexcept -> uint32_t
{
    return Crc32Ethernet::compute(data);
}

/// The AUTOSAR CRC32P4 of @p data.
[[nodiscard]] constexpr auto crc32_p4(std::span<uint8_t const> data) noexcept -> uint32_t
{
    return Crc32P4::compute(data);
}

}  // namespace statusbar::checksum
