#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/ip/ip_ipv4_address.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace statusbar::ip {

using ieee::doublet_t;
using ieee::octet_t;
using ieee::quadlet_t;

/// IPv4 header (20-60 bytes, minimum 20 bytes without options)
/// Network byte order is handled by doublet_t/quadlet_t types
struct IPv4Header
{
    // Protocol numbers
    static constexpr uint8_t PROTOCOL_ICMP = 1;
    static constexpr uint8_t PROTOCOL_IGMP = 2;
    static constexpr uint8_t PROTOCOL_TCP = 6;
    static constexpr uint8_t PROTOCOL_UDP = 17;

    // Minimum header length without options
    static constexpr size_t MIN_LENGTH = 20;
    static constexpr size_t LENGTH = MIN_LENGTH;  // For SerializableFixedStruct trait

    // Fields stored in network byte order where applicable
    octet_t version_ihl;        // Version (4 bits) + IHL (4 bits)
    octet_t dscp_ecn;           // DSCP (6 bits) + ECN (2 bits)
    doublet_t total_length;     // Total packet length
    doublet_t identification;   // Fragment identification
    doublet_t flags_fragment;   // Flags (3 bits) + Fragment offset (13 bits)
    octet_t ttl;                // Time to live
    octet_t protocol;           // Protocol number
    doublet_t header_checksum;  // Header checksum
    IPv4Address src_addr;       // Source address
    IPv4Address dst_addr;       // Destination address

    /// Default constructor
    constexpr IPv4Header() noexcept = default;

    /// Get IP version (should be 4)
    [[nodiscard]] constexpr auto version() const noexcept -> uint8_t { return version_ihl.get_bits<uint8_t>(0xF0, 4); }

    /// Set IP version
    /// @param v IP version number (should be 4)
    constexpr void set_version(uint8_t v) noexcept { version_ihl.set_bits(0xF0, 4, v); }

    /// Get Internet Header Length in 32-bit words
    [[nodiscard]] constexpr auto ihl() const noexcept -> uint8_t { return version_ihl.get_bits<uint8_t>(0x0F, 0); }

    /// Set Internet Header Length in 32-bit words
    /// @param len Header length in 32-bit words (minimum 5)
    constexpr void set_ihl(uint8_t len) noexcept { version_ihl.set_bits(0x0F, 0, len); }

    /// Get header length in bytes
    [[nodiscard]] constexpr auto header_length() const noexcept -> size_t { return static_cast<size_t>(ihl()) * 4; }

    /// Get DSCP value
    [[nodiscard]] constexpr auto dscp() const noexcept -> uint8_t { return dscp_ecn.get_bits<uint8_t>(0xFC, 2); }

    /// Set DSCP value
    /// @param d Differentiated Services Code Point value (6 bits)
    constexpr void set_dscp(uint8_t d) noexcept { dscp_ecn.set_bits(0xFC, 2, d); }

    /// Get ECN value
    [[nodiscard]] constexpr auto ecn() const noexcept -> uint8_t { return dscp_ecn.get_bits<uint8_t>(0x03, 0); }

    /// Set ECN value
    /// @param e Explicit Congestion Notification value (2 bits)
    constexpr void set_ecn(uint8_t e) noexcept { dscp_ecn.set_bits(0x03, 0, e); }

    /// Get flags (3 bits)
    [[nodiscard]] constexpr auto flags() const noexcept -> uint8_t { return flags_fragment.get_bits<uint8_t>(0xE000, 13); }

    /// Set flags
    /// @param f IP flags value (3 bits)
    constexpr void set_flags(uint8_t f) noexcept { flags_fragment.set_bits(0xE000, 13, f); }

    /// Get Don't Fragment flag
    [[nodiscard]] constexpr auto dont_fragment() const noexcept -> bool { return flags_fragment.has_flag(0x4000); }

    /// Get More Fragments flag
    [[nodiscard]] constexpr auto more_fragments() const noexcept -> bool { return flags_fragment.has_flag(0x2000); }

    /// Get fragment offset in 8-byte units
    [[nodiscard]] constexpr auto fragment_offset() const noexcept -> uint16_t
    {
        return flags_fragment.get_bits<uint16_t>(0x1FFF, 0);
    }

    /// Set fragment offset in 8-byte units
    /// @param offset Fragment offset in 8-byte units (13 bits)
    constexpr void set_fragment_offset(uint16_t offset) noexcept { flags_fragment.set_bits(0x1FFF, 0, offset); }

    /// Get payload length (total_length - header_length)
    [[nodiscard]] constexpr auto payload_length() const noexcept -> uint16_t
    {
        // Guard the underflow: a malformed header with total_length < header_length
        // would otherwise wrap to a huge uint16_t (mirrors UdpHeader::payload_length).
        auto const total = total_length.get();
        auto const hlen = header_length();
        return (total >= hlen) ? static_cast<uint16_t>(total - hlen) : uint16_t{0};
    }

    /// Initialize for a typical packet
    /// @param proto IP protocol number (e.g., PROTOCOL_TCP, PROTOCOL_UDP)
    /// @param payload_len Payload length in bytes (excluding header)
    /// @param time_to_live Hop limit (default 64)
    constexpr void init(uint8_t proto, uint16_t payload_len, uint8_t time_to_live = 64) noexcept
    {
        version_ihl = 0x45;  // Version 4, IHL 5 (20 bytes)
        dscp_ecn = 0;
        total_length = static_cast<uint16_t>(MIN_LENGTH + payload_len);
        identification = 0;
        flags_fragment = 0x4000;  // Don't fragment
        ttl = time_to_live;
        protocol = proto;
        header_checksum = 0;
    }

    /// Check if the header has valid field values
    /// Validates version, IHL, and total_length consistency
    [[nodiscard]] constexpr auto is_valid() const noexcept -> bool
    {
        // Version must be 4
        if (version() != 4) {
            return false;
        }
        // IHL must be at least 5 (20 bytes minimum header)
        if (ihl() < 5) {
            return false;
        }
        // Total length must be at least header length
        if (total_length.get() < header_length()) {
            return false;
        }
        return true;
    }

    auto operator<=>(IPv4Header const& rhs) const noexcept -> std::strong_ordering = default;
};

// Compile-time layout verification
static_assert(sizeof(IPv4Header) == 20, "IPv4Header must be exactly 20 bytes");
static_assert(alignof(IPv4Header) <= 2, "IPv4Header alignment must not exceed 2 bytes");
static_assert(offsetof(IPv4Header, version_ihl) == 0, "version_ihl must be at offset 0");
static_assert(offsetof(IPv4Header, dscp_ecn) == 1, "dscp_ecn must be at offset 1");
static_assert(offsetof(IPv4Header, total_length) == 2, "total_length must be at offset 2");
static_assert(offsetof(IPv4Header, identification) == 4, "identification must be at offset 4");
static_assert(offsetof(IPv4Header, flags_fragment) == 6, "flags_fragment must be at offset 6");
static_assert(offsetof(IPv4Header, ttl) == 8, "ttl must be at offset 8");
static_assert(offsetof(IPv4Header, protocol) == 9, "protocol must be at offset 9");
static_assert(offsetof(IPv4Header, header_checksum) == 10, "header_checksum must be at offset 10");
static_assert(offsetof(IPv4Header, src_addr) == 12, "src_addr must be at offset 12");
static_assert(offsetof(IPv4Header, dst_addr) == 16, "dst_addr must be at offset 16");

}  // namespace statusbar::ip

// Serialization traits
// IPv4Header is a packed wire format struct
template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::IPv4Header> : std::true_type
{};

// Export free functions for ADL serialization
// Note: wire_size, can_load, can_store, load, store are provided by
// statusbar::protocol for SerializableFixedStruct types
namespace statusbar::ip {

// Import template functions for wire fixed struct types (IPv4Header)
using protocol::load_unchecked;
using protocol::store_unchecked;

/// Calculate IPv4 header checksum
/// @param header The IPv4 header to calculate checksum for
/// @return The calculated checksum in host byte order
[[nodiscard]] auto calculate_ipv4_checksum(IPv4Header const& header) noexcept -> uint16_t;

/// Update the checksum field in an IPv4 header
/// @param header The IPv4 header to update
void update_ipv4_checksum(IPv4Header& header) noexcept;

/// Verify IPv4 header checksum
/// @param header The IPv4 header to verify
/// @return true if checksum is valid
[[nodiscard]] auto verify_ipv4_checksum(IPv4Header const& header) noexcept -> bool;

}  // namespace statusbar::ip
