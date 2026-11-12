#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include <cstdint>

namespace statusbar::pcap {

/// PcapNG block type codes
enum class PcapngBlockType : uint32_t
{
    SectionHeader = 0x0a0d0d0a,         ///< Section Header Block (SHB)
    InterfaceDescription = 0x00000001,  ///< Interface Description Block (IDB)
    Packet = 0x00000002,                ///< Packet Block (obsolete, use EPB)
    SimplePacket = 0x00000003,          ///< Simple Packet Block (SPB)
    NameResolution = 0x00000004,        ///< Name Resolution Block (NRB)
    InterfaceStatistics = 0x00000005,   ///< Interface Statistics Block (ISB)
    EnhancedPacket = 0x00000006,        ///< Enhanced Packet Block (EPB)
    DecryptionSecrets = 0x0000000a,     ///< Decryption Secrets Block (DSB)
    CustomCopyable = 0x00000bad,        ///< Custom Block (copyable)
    CustomNotCopyable = 0x40000bad,     ///< Custom Block (not copyable)
};

/// PcapNG byte order magic number (for endianness detection)
constexpr uint32_t PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;
constexpr uint32_t PCAPNG_BYTE_ORDER_MAGIC_SWAPPED = 0x4d3c2b1a;

/// Link types (same as PCAP, from tcpdump.org)
enum class LinkType : uint16_t
{
    Null = 0,
    Ethernet = 1,
    Ppp = 9,
    PppEther = 51,
    Raw = 101,
    Ieee80211 = 105,
    Linux_sll = 113,
    Linux_sll2 = 276,
};

/// General block header (first 8 bytes of every block)
struct PcapngBlockHeader
{
    uint32_t block_type;    ///< Block type code
    uint32_t block_length;  ///< Total block length including header and trailer
};

/// Section Header Block body (after general header)
struct PcapngSectionHeaderBody
{
    uint32_t byte_order_magic;  ///< 0x1a2b3c4d for native endian
    uint16_t version_major;     ///< Version 1
    uint16_t version_minor;     ///< Version 0
    int64_t section_length;     ///< -1 if unknown
};

/// Interface Description Block body (after general header)
struct PcapngInterfaceDescBody
{
    uint16_t link_type;    ///< Link layer type
    uint16_t reserved;     ///< Must be 0
    uint32_t snap_length;  ///< Maximum packet capture length
};

/// Enhanced Packet Block body (after general header, before packet data)
struct PcapngEnhancedPacketBody
{
    uint32_t interface_id;     ///< Zero-indexed interface ID
    uint32_t timestamp_high;   ///< High 32 bits of timestamp
    uint32_t timestamp_low;    ///< Low 32 bits of timestamp
    uint32_t captured_length;  ///< Captured packet length
    uint32_t original_length;  ///< Original packet length
};

/// Simple Packet Block body (after general header, before packet data)
struct PcapngSimplePacketBody
{
    uint32_t original_length;  ///< Original packet length
};

/// Option header: options follow a block's fixed body as (code, length,
/// value padded to 4) and end with opt_endofopt (code 0, length 0).
struct PcapngOptionHeader
{
    uint16_t code;    ///< Option code (block-type specific above 4)
    uint16_t length;  ///< Value length in octets, before padding
};

/// Interface Description Block option codes read by this module
enum class PcapngIdbOption : uint16_t
{
    end_of_options = 0,  ///< opt_endofopt
    if_tsresol = 9,      ///< one octet: timestamp resolution (see pcapng_units_per_second)
};

/// Timestamp units per second encoded by an if_tsresol option octet: the
/// low seven bits are a negative power of 10 (MSB clear) or of 2 (MSB set).
/// 0 means out of this reader's range: above 10^13 or 2^43 a tick count's
/// conversion to microseconds would overflow, and no capture tool writes
/// such a resolution. Callers keep the microsecond default then.
[[nodiscard]] constexpr auto pcapng_units_per_second(uint8_t if_tsresol) noexcept -> uint64_t
{
    uint8_t const exponent = if_tsresol & 0x7fU;
    if ((if_tsresol & 0x80U) != 0) {
        return exponent <= 43 ? (uint64_t{1} << exponent) : 0;
    }
    if (exponent > 13) {
        return 0;
    }
    uint64_t units = 1;
    for (uint8_t i = 0; i < exponent; ++i) {
        units *= 10;
    }
    return units;
}

/// A tick count at @p units_per_second as microseconds. Whole seconds and
/// the remainder are converted apart, so a nanosecond count since the
/// epoch does not overflow the way (ticks * 10^6) / units would.
[[nodiscard]] constexpr auto pcapng_ticks_to_us(uint64_t ticks, uint64_t units_per_second) noexcept -> uint64_t
{
    constexpr uint64_t us_per_second = 1'000'000;
    if (units_per_second == 0 || units_per_second == us_per_second) {
        return ticks;
    }
    uint64_t const whole_seconds = ticks / units_per_second;
    uint64_t const rest = ticks % units_per_second;
    return (whole_seconds * us_per_second) + ((rest * us_per_second) / units_per_second);
}

/// Swap bytes of a 16-bit value (for endian conversion)
[[nodiscard]] constexpr auto swap_bytes16(uint16_t v) noexcept -> uint16_t
{
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}

/// Swap bytes of a 32-bit value (for endian conversion)
[[nodiscard]] constexpr auto swap_bytes32(uint32_t v) noexcept -> uint32_t
{
    uint32_t r = 0;
    r |= ((v >> 24) & 0x000000ff);
    r |= ((v >> 8) & 0x0000ff00);
    r |= ((v << 8) & 0x00ff0000);
    r |= ((v << 24) & 0xff000000);
    return r;
}

/// Swap bytes of a 64-bit value (for endian conversion)
[[nodiscard]] constexpr auto swap_bytes64(uint64_t v) noexcept -> uint64_t
{
    uint64_t r = 0;
    r |= ((v >> 56) & 0x00000000000000ffULL);
    r |= ((v >> 40) & 0x000000000000ff00ULL);
    r |= ((v >> 24) & 0x0000000000ff0000ULL);
    r |= ((v >> 8) & 0x00000000ff000000ULL);
    r |= ((v << 8) & 0x000000ff00000000ULL);
    r |= ((v << 24) & 0x0000ff0000000000ULL);
    r |= ((v << 40) & 0x00ff000000000000ULL);
    r |= ((v << 56) & 0xff00000000000000ULL);
    return r;
}

/// Round up to 4-byte boundary (pcapng blocks are 32-bit aligned)
[[nodiscard]] constexpr auto align_to_4(uint32_t size) noexcept -> uint32_t
{
    return (size + 3) & ~3U;
}

}  // namespace statusbar::pcap
