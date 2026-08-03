#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/ip/ip_ipv4_address.hpp"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace statusbar::ip {

using ieee::doublet_t;
using ieee::octet_t;

/// IGMP message types
constexpr uint8_t IGMP_TYPE_MEMBERSHIP_QUERY = 0x11;
constexpr uint8_t IGMP_TYPE_MEMBERSHIP_REPORT_V1 = 0x12;
constexpr uint8_t IGMP_TYPE_MEMBERSHIP_REPORT_V2 = 0x16;
constexpr uint8_t IGMP_TYPE_LEAVE_GROUP = 0x17;
constexpr uint8_t IGMP_TYPE_MEMBERSHIP_REPORT_V3 = 0x22;

/// Get human-readable name for IGMP type
/// @param type IGMP message type code
[[nodiscard]] auto igmp_type_name(uint8_t type) noexcept -> std::string_view;

/// IGMP header (8 bytes for v1/v2)
/// Network byte order is handled by doublet_t type
struct IgmpHeader
{
    // Header length is 8 bytes
    static constexpr size_t LENGTH = 8;

    octet_t type;            // Message type
    octet_t max_resp_time;   // Max response time (in 1/10 seconds)
    doublet_t checksum;      // Header checksum
    IPv4Address group_addr;  // Group address

    /// Default constructor
    constexpr IgmpHeader() noexcept = default;

    /// Construct with type
    /// @param t IGMP message type
    constexpr IgmpHeader(uint8_t t) noexcept
        : type(t)
        , max_resp_time(0)
        , checksum(0)
        , group_addr()
    {}

    /// Check if this is a membership query
    [[nodiscard]] constexpr auto is_membership_query() const noexcept -> bool { return type == IGMP_TYPE_MEMBERSHIP_QUERY; }

    /// Check if this is any membership report
    [[nodiscard]] constexpr auto is_membership_report() const noexcept -> bool
    {
        return type == IGMP_TYPE_MEMBERSHIP_REPORT_V1 || type == IGMP_TYPE_MEMBERSHIP_REPORT_V2 ||
            type == IGMP_TYPE_MEMBERSHIP_REPORT_V3;
    }

    /// Check if this is a leave group message
    [[nodiscard]] constexpr auto is_leave_group() const noexcept -> bool { return type == IGMP_TYPE_LEAVE_GROUP; }

    /// Initialize for a membership query
    /// @param max_resp Maximum response time in 1/10 seconds (default 100)
    constexpr void init_membership_query(uint8_t max_resp = 100) noexcept
    {
        type = IGMP_TYPE_MEMBERSHIP_QUERY;
        max_resp_time = max_resp;
        checksum = 0;
        group_addr = IPv4Address();
    }

    /// Initialize for a membership report (v2)
    /// @param group Multicast group address to report
    constexpr void init_membership_report(IPv4Address const& group) noexcept
    {
        type = IGMP_TYPE_MEMBERSHIP_REPORT_V2;
        max_resp_time = 0;
        checksum = 0;
        group_addr = group;
    }

    /// Initialize for a leave group message
    /// @param group Multicast group address to leave
    constexpr void init_leave_group(IPv4Address const& group) noexcept
    {
        type = IGMP_TYPE_LEAVE_GROUP;
        max_resp_time = 0;
        checksum = 0;
        group_addr = group;
    }

    auto operator<=>(IgmpHeader const& rhs) const noexcept -> std::strong_ordering = default;
};

// Compile-time layout verification
static_assert(sizeof(IgmpHeader) == 8, "IgmpHeader must be exactly 8 bytes");
static_assert(alignof(IgmpHeader) <= 2, "IgmpHeader alignment must not exceed 2 bytes");
static_assert(offsetof(IgmpHeader, type) == 0, "type must be at offset 0");
static_assert(offsetof(IgmpHeader, max_resp_time) == 1, "max_resp_time must be at offset 1");
static_assert(offsetof(IgmpHeader, checksum) == 2, "checksum must be at offset 2");
static_assert(offsetof(IgmpHeader, group_addr) == 4, "group_addr must be at offset 4");

}  // namespace statusbar::ip

// Serialization traits
// IgmpHeader is a packed wire format struct
template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::IgmpHeader> : std::true_type
{};

// Export free functions for ADL serialization
namespace statusbar::ip {

// Import template functions for wire fixed struct types (IgmpHeader)
using protocol::load_unchecked;
using protocol::store_unchecked;

}  // namespace statusbar::ip
