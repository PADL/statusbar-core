#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/ip/ip_ipv6.hpp"
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
using ieee::quadlet_t;

//
// ICMPv6 Message Types (RFC 4443, RFC 4861)
//
/// ICMPv6 Error Messages (Type 0-127)
constexpr uint8_t ICMPV6_TYPE_DEST_UNREACHABLE = 1;
constexpr uint8_t ICMPV6_TYPE_PACKET_TOO_BIG = 2;
constexpr uint8_t ICMPV6_TYPE_TIME_EXCEEDED = 3;
constexpr uint8_t ICMPV6_TYPE_PARAMETER_PROBLEM = 4;

/// ICMPv6 Informational Messages (Type 128-255)
constexpr uint8_t ICMPV6_TYPE_ECHO_REQUEST = 128;
constexpr uint8_t ICMPV6_TYPE_ECHO_REPLY = 129;

/// ICMPv6 Multicast Listener Discovery (MLD) - RFC 2710, RFC 3810
constexpr uint8_t ICMPV6_TYPE_MLD_QUERY = 130;
constexpr uint8_t ICMPV6_TYPE_MLD_REPORT = 131;
constexpr uint8_t ICMPV6_TYPE_MLD_DONE = 132;
constexpr uint8_t ICMPV6_TYPE_MLDV2_REPORT = 143;

/// ICMPv6 Neighbor Discovery Protocol (NDP) - RFC 4861
constexpr uint8_t ICMPV6_TYPE_ROUTER_SOLICITATION = 133;
constexpr uint8_t ICMPV6_TYPE_ROUTER_ADVERTISEMENT = 134;
constexpr uint8_t ICMPV6_TYPE_NEIGHBOR_SOLICITATION = 135;
constexpr uint8_t ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT = 136;
constexpr uint8_t ICMPV6_TYPE_REDIRECT = 137;

//
// ICMPv6 Destination Unreachable Codes (RFC 4443)
//
constexpr uint8_t ICMPV6_CODE_NO_ROUTE = 0;
constexpr uint8_t ICMPV6_CODE_ADMIN_PROHIBITED = 1;
constexpr uint8_t ICMPV6_CODE_BEYOND_SCOPE = 2;
constexpr uint8_t ICMPV6_CODE_ADDRESS_UNREACHABLE = 3;
constexpr uint8_t ICMPV6_CODE_PORT_UNREACHABLE = 4;
constexpr uint8_t ICMPV6_CODE_FAILED_POLICY = 5;
constexpr uint8_t ICMPV6_CODE_REJECT_ROUTE = 6;

//
// ICMPv6 Time Exceeded Codes (RFC 4443)
//
constexpr uint8_t ICMPV6_CODE_HOP_LIMIT_EXCEEDED = 0;
constexpr uint8_t ICMPV6_CODE_FRAGMENT_REASSEMBLY_EXCEEDED = 1;

//
// ICMPv6 Parameter Problem Codes (RFC 4443)
//
constexpr uint8_t ICMPV6_CODE_ERRONEOUS_HEADER = 0;
constexpr uint8_t ICMPV6_CODE_UNRECOGNIZED_NEXT_HEADER = 1;
constexpr uint8_t ICMPV6_CODE_UNRECOGNIZED_OPTION = 2;

//
// NDP Option Types (RFC 4861)
//
constexpr uint8_t NDP_OPTION_SOURCE_LINK_LAYER_ADDR = 1;
constexpr uint8_t NDP_OPTION_TARGET_LINK_LAYER_ADDR = 2;
constexpr uint8_t NDP_OPTION_PREFIX_INFO = 3;
constexpr uint8_t NDP_OPTION_REDIRECTED_HEADER = 4;
constexpr uint8_t NDP_OPTION_MTU = 5;

/// Get human-readable name for ICMPv6 type
/// @param type ICMPv6 message type code
[[nodiscard]] auto icmpv6_type_name(uint8_t type) noexcept -> std::string_view;

//
// ICMPv6 Header (4 bytes base, message-specific data follows)
//
/// ICMPv6 base header (4 bytes)
/// Network byte order is handled by doublet_t type
struct Icmpv6Header
{
    static constexpr size_t LENGTH = 4;

    octet_t type;        // Message type
    octet_t code;        // Message code
    doublet_t checksum;  // Checksum (covers pseudo-header + ICMPv6 message)

    /// Default constructor
    constexpr Icmpv6Header() noexcept = default;

    /// Construct with type and code
    /// @param t ICMPv6 message type
    /// @param c ICMPv6 message code
    constexpr Icmpv6Header(uint8_t t, uint8_t c) noexcept
        : type(t)
        , code(c)
        , checksum(0)
    {}

    /// Check if this is an echo request
    [[nodiscard]] constexpr auto is_echo_request() const noexcept -> bool { return type == ICMPV6_TYPE_ECHO_REQUEST; }

    /// Check if this is an echo reply
    [[nodiscard]] constexpr auto is_echo_reply() const noexcept -> bool { return type == ICMPV6_TYPE_ECHO_REPLY; }

    /// Check if this is a Neighbor Solicitation
    [[nodiscard]] constexpr auto is_neighbor_solicitation() const noexcept -> bool
    {
        return type == ICMPV6_TYPE_NEIGHBOR_SOLICITATION;
    }

    /// Check if this is a Neighbor Advertisement
    [[nodiscard]] constexpr auto is_neighbor_advertisement() const noexcept -> bool
    {
        return type == ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT;
    }

    /// Check if this is a Router Solicitation
    [[nodiscard]] constexpr auto is_router_solicitation() const noexcept -> bool { return type == ICMPV6_TYPE_ROUTER_SOLICITATION; }

    /// Check if this is a Router Advertisement
    [[nodiscard]] constexpr auto is_router_advertisement() const noexcept -> bool
    {
        return type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT;
    }

    /// Check if this is an error message (type 0-127)
    [[nodiscard]] constexpr auto is_error() const noexcept -> bool { return type < 128; }

    /// Check if this is an informational message (type 128-255)
    [[nodiscard]] constexpr auto is_informational() const noexcept -> bool { return type >= 128; }

    auto operator<=>(Icmpv6Header const& rhs) const noexcept -> std::strong_ordering = default;
};

// Compile-time layout verification
static_assert(sizeof(Icmpv6Header) == 4, "Icmpv6Header must be exactly 4 bytes");
static_assert(alignof(Icmpv6Header) <= 2, "Icmpv6Header alignment must not exceed 2 bytes");
static_assert(offsetof(Icmpv6Header, type) == 0, "type must be at offset 0");
static_assert(offsetof(Icmpv6Header, code) == 1, "code must be at offset 1");
static_assert(offsetof(Icmpv6Header, checksum) == 2, "checksum must be at offset 2");

//
// ICMPv6 Echo Request/Reply (8 bytes header)
//
/// ICMPv6 Echo header (used for ping)
struct Icmpv6EchoHeader
{
    static constexpr size_t LENGTH = 8;

    octet_t type;          // ICMPV6_TYPE_ECHO_REQUEST or ICMPV6_TYPE_ECHO_REPLY
    octet_t code;          // Always 0
    doublet_t checksum;    // Checksum
    doublet_t identifier;  // Identifier
    doublet_t sequence;    // Sequence number

    /// Default constructor
    constexpr Icmpv6EchoHeader() noexcept = default;

    /// Initialize for an echo request
    /// @param id Echo identifier
    /// @param seq Echo sequence number
    constexpr void init_echo_request(uint16_t id, uint16_t seq) noexcept
    {
        type = ICMPV6_TYPE_ECHO_REQUEST;
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
        type = ICMPV6_TYPE_ECHO_REPLY;
        code = 0;
        checksum = 0;
        identifier = id;
        sequence = seq;
    }

    auto operator<=>(Icmpv6EchoHeader const& rhs) const noexcept -> std::strong_ordering = default;
};

static_assert(sizeof(Icmpv6EchoHeader) == 8, "Icmpv6EchoHeader must be exactly 8 bytes");

//
// Neighbor Solicitation (24 bytes + options)
//
/// Neighbor Solicitation message (RFC 4861)
struct Icmpv6NeighborSolicitation
{
    static constexpr size_t LENGTH = 24;

    octet_t type;        // ICMPV6_TYPE_NEIGHBOR_SOLICITATION (135)
    octet_t code;        // Always 0
    doublet_t checksum;  // Checksum
    quadlet_t reserved;  // Reserved (must be zero)
    IPv6Address target;  // Target address being queried

    /// Default constructor
    constexpr Icmpv6NeighborSolicitation() noexcept = default;

    auto operator<=>(Icmpv6NeighborSolicitation const& rhs) const noexcept -> std::strong_ordering = default;
};

static_assert(sizeof(Icmpv6NeighborSolicitation) == 24, "Icmpv6NeighborSolicitation must be exactly 24 bytes");

//
// Neighbor Advertisement (24 bytes + options)
//
/// Neighbor Advertisement flags
constexpr uint32_t NA_FLAG_ROUTER = 0x80000000;     // Sender is a router
constexpr uint32_t NA_FLAG_SOLICITED = 0x40000000;  // Response to a solicitation
constexpr uint32_t NA_FLAG_OVERRIDE = 0x20000000;   // Override existing cache entry

/// Neighbor Advertisement message (RFC 4861)
struct Icmpv6NeighborAdvertisement
{
    static constexpr size_t LENGTH = 24;

    octet_t type;        // ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT (136)
    octet_t code;        // Always 0
    doublet_t checksum;  // Checksum
    quadlet_t flags;     // R|S|O flags + reserved
    IPv6Address target;  // Target address

    /// Default constructor
    constexpr Icmpv6NeighborAdvertisement() noexcept = default;

    // Flag accessors using IeeeOrderedUInt methods
    [[nodiscard]] constexpr auto is_router() const noexcept -> bool { return flags.has_flag(NA_FLAG_ROUTER); }
    [[nodiscard]] constexpr auto is_solicited() const noexcept -> bool { return flags.has_flag(NA_FLAG_SOLICITED); }
    [[nodiscard]] constexpr auto is_override() const noexcept -> bool { return flags.has_flag(NA_FLAG_OVERRIDE); }

    /// @param v True to set the router flag
    constexpr void set_router(bool v) noexcept { flags.set_flag(NA_FLAG_ROUTER, v); }
    /// @param v True to set the solicited flag
    constexpr void set_solicited(bool v) noexcept { flags.set_flag(NA_FLAG_SOLICITED, v); }
    /// @param v True to set the override flag
    constexpr void set_override(bool v) noexcept { flags.set_flag(NA_FLAG_OVERRIDE, v); }

    auto operator<=>(Icmpv6NeighborAdvertisement const& rhs) const noexcept -> std::strong_ordering = default;
};

static_assert(sizeof(Icmpv6NeighborAdvertisement) == 24, "Icmpv6NeighborAdvertisement must be exactly 24 bytes");

//
// Router Solicitation (8 bytes + options)
//
/// Router Solicitation message (RFC 4861)
struct Icmpv6RouterSolicitation
{
    static constexpr size_t LENGTH = 8;

    octet_t type;        // ICMPV6_TYPE_ROUTER_SOLICITATION (133)
    octet_t code;        // Always 0
    doublet_t checksum;  // Checksum
    quadlet_t reserved;  // Reserved (must be zero)

    /// Default constructor
    constexpr Icmpv6RouterSolicitation() noexcept = default;

    auto operator<=>(Icmpv6RouterSolicitation const& rhs) const noexcept -> std::strong_ordering = default;
};

static_assert(sizeof(Icmpv6RouterSolicitation) == 8, "Icmpv6RouterSolicitation must be exactly 8 bytes");

}  // namespace statusbar::ip

// Serialization traits - ICMPv6 structs are packed wire format
template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::Icmpv6Header> : std::true_type
{};

template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::Icmpv6EchoHeader> : std::true_type
{};

template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::Icmpv6NeighborSolicitation> : std::true_type
{};

template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::Icmpv6NeighborAdvertisement> : std::true_type
{};

template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::Icmpv6RouterSolicitation> : std::true_type
{};

// Export using declarations for ADL to find the template functions
namespace statusbar::ip {
using protocol::load_unchecked;
using protocol::store_unchecked;
}  // namespace statusbar::ip
