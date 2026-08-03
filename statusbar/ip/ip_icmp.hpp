#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>

namespace statusbar::ip {

using ieee::doublet_t;
using ieee::octet_t;

/// ICMP message types
constexpr uint8_t ICMP_TYPE_ECHO_REPLY = 0;
constexpr uint8_t ICMP_TYPE_DEST_UNREACHABLE = 3;
constexpr uint8_t ICMP_TYPE_SOURCE_QUENCH = 4;
constexpr uint8_t ICMP_TYPE_REDIRECT = 5;
constexpr uint8_t ICMP_TYPE_ECHO_REQUEST = 8;
constexpr uint8_t ICMP_TYPE_ROUTER_ADVERTISEMENT = 9;
constexpr uint8_t ICMP_TYPE_ROUTER_SOLICITATION = 10;
constexpr uint8_t ICMP_TYPE_TIME_EXCEEDED = 11;
constexpr uint8_t ICMP_TYPE_PARAMETER_PROBLEM = 12;
constexpr uint8_t ICMP_TYPE_TIMESTAMP_REQUEST = 13;
constexpr uint8_t ICMP_TYPE_TIMESTAMP_REPLY = 14;
constexpr uint8_t ICMP_TYPE_INFO_REQUEST = 15;
constexpr uint8_t ICMP_TYPE_INFO_REPLY = 16;
constexpr uint8_t ICMP_TYPE_ADDRESS_MASK_REQUEST = 17;
constexpr uint8_t ICMP_TYPE_ADDRESS_MASK_REPLY = 18;

/// Destination Unreachable codes
constexpr uint8_t ICMP_CODE_NET_UNREACHABLE = 0;
constexpr uint8_t ICMP_CODE_HOST_UNREACHABLE = 1;
constexpr uint8_t ICMP_CODE_PROTOCOL_UNREACHABLE = 2;
constexpr uint8_t ICMP_CODE_PORT_UNREACHABLE = 3;
constexpr uint8_t ICMP_CODE_FRAGMENTATION_NEEDED = 4;
constexpr uint8_t ICMP_CODE_SOURCE_ROUTE_FAILED = 5;

/// Time Exceeded codes
constexpr uint8_t ICMP_CODE_TTL_EXCEEDED = 0;
constexpr uint8_t ICMP_CODE_FRAGMENT_REASSEMBLY_EXCEEDED = 1;

/// Get human-readable name for ICMP type
/// @param type ICMP message type code
[[nodiscard]] auto icmp_type_name(uint8_t type) noexcept -> std::string_view;

/// ICMP header (8 bytes minimum)
/// Network byte order is handled by doublet_t type
struct IcmpHeader
{
    // Header length is 8 bytes (type + code + checksum + rest of header)
    static constexpr size_t LENGTH = 8;

    octet_t type;          // Message type
    octet_t code;          // Message code
    doublet_t checksum;    // Header checksum
    doublet_t identifier;  // Identifier (for echo request/reply)
    doublet_t sequence;    // Sequence number (for echo request/reply)

    /// Default constructor
    constexpr IcmpHeader() noexcept = default;

    /// Construct with type and code
    /// @param t ICMP message type
    /// @param c ICMP message code
    constexpr IcmpHeader(uint8_t t, uint8_t c) noexcept
        : type(t)
        , code(c)
        , checksum(0)
        , identifier(0)
        , sequence(0)
    {}

    /// Check if this is an echo request
    [[nodiscard]] constexpr auto is_echo_request() const noexcept -> bool { return type == ICMP_TYPE_ECHO_REQUEST; }

    /// Check if this is an echo reply
    [[nodiscard]] constexpr auto is_echo_reply() const noexcept -> bool { return type == ICMP_TYPE_ECHO_REPLY; }

    /// Initialize for an echo request
    /// @param id Echo identifier
    /// @param seq Echo sequence number
    constexpr void init_echo_request(uint16_t id, uint16_t seq) noexcept
    {
        type = ICMP_TYPE_ECHO_REQUEST;
        code = 0;
        checksum = 0;
        identifier = id;
        sequence = seq;
    }

    /// Initialize for an echo reply
    /// @param id Echo identifier
    /// @param seq Echo sequence number
    constexpr void init_echo_reply(uint16_t id, uint16_t seq) noexcept
    {
        type = ICMP_TYPE_ECHO_REPLY;
        code = 0;
        checksum = 0;
        identifier = id;
        sequence = seq;
    }

    auto operator<=>(IcmpHeader const& rhs) const noexcept -> std::strong_ordering = default;
};

// Compile-time layout verification
static_assert(sizeof(IcmpHeader) == 8, "IcmpHeader must be exactly 8 bytes");
static_assert(alignof(IcmpHeader) <= 2, "IcmpHeader alignment must not exceed 2 bytes");
static_assert(offsetof(IcmpHeader, type) == 0, "type must be at offset 0");
static_assert(offsetof(IcmpHeader, code) == 1, "code must be at offset 1");
static_assert(offsetof(IcmpHeader, checksum) == 2, "checksum must be at offset 2");
static_assert(offsetof(IcmpHeader, identifier) == 4, "identifier must be at offset 4");
static_assert(offsetof(IcmpHeader, sequence) == 6, "sequence must be at offset 6");

}  // namespace statusbar::ip

// Serialization traits - IcmpHeader is a packed wire format struct
template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::IcmpHeader> : std::true_type
{};

// Export using declarations for ADL to find the template functions
namespace statusbar::ip {
using protocol::load_unchecked;
using protocol::store_unchecked;
}  // namespace statusbar::ip
