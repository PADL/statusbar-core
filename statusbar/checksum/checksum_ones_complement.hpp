#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Ones-complement 16-bit checksum (the RFC 1071 "Internet checksum") over
/// a byte span: big-endian 16-bit words summed with end-around carry, an
/// odd trailing octet treated as the high octet of a final word whose low
/// octet is zero. The same arithmetic underlies the IPv4, ICMP, IGMP and
/// UDP header checksums and the IEEE 1722-2025 ACF_CHECKSUM message
/// (Clause 9.4.20), which differs from UDP only in that a checksum field
/// of zero is a real value and is validated.

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::checksum {

/// Fold a 32-bit running sum to 16 bits with end-around carry.
[[nodiscard]] constexpr auto ones_complement_fold(uint32_t sum) noexcept -> uint16_t
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<uint16_t>(sum);
}

/// Sum @p data into a ones-complement running total and fold it.
/// @param data     Octets to sum; words are big-endian pairs, an odd
///                 trailing octet is padded with a zero low octet.
/// @param initial  The (folded) sum of preceding pieces, so a message can be
///                 summed piecewise — every piece but the last must have an
///                 even length, or the word alignment shifts.
[[nodiscard]] constexpr auto ones_complement_sum16(std::span<uint8_t const> data, uint32_t initial = 0U) noexcept -> uint16_t
{
    uint32_t sum = initial;
    size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8U) | static_cast<uint32_t>(data[i + 1]);
    }
    if (i < data.size()) {
        sum += static_cast<uint32_t>(data[i]) << 8U;
    }
    return ones_complement_fold(sum);
}

/// The checksum field value for @p data: the ones-complement of its sum.
/// Compute it with the checksum field itself zeroed.
[[nodiscard]] constexpr auto internet_checksum16(std::span<uint8_t const> data) noexcept -> uint16_t
{
    return static_cast<uint16_t>(0xFFFFU ^ ones_complement_sum16(data));
}

/// Verify @p data_with_checksum, which carries its checksum field in place:
/// the sum over everything is 0xFFFF when intact.
[[nodiscard]] constexpr auto internet_checksum_ok(std::span<uint8_t const> data_with_checksum) noexcept -> bool
{
    return ones_complement_sum16(data_with_checksum) == 0xFFFFU;
}

}  // namespace statusbar::checksum
