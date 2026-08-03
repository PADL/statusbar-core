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
using ieee::Eui48;

/// ARP hardware types
constexpr uint16_t ARP_HARDWARE_ETHERNET = 1;
constexpr uint16_t ARP_HARDWARE_IEEE802 = 6;

/// ARP protocol types (same as EtherType values)
constexpr uint16_t ARP_PROTOCOL_IPV4 = 0x0800;

/// ARP operation codes
constexpr uint16_t ARP_OP_REQUEST = 1;
constexpr uint16_t ARP_OP_REPLY = 2;
constexpr uint16_t ARP_OP_RARP_REQUEST = 3;
constexpr uint16_t ARP_OP_RARP_REPLY = 4;

/// Get human-readable name for ARP operation
/// @param op ARP operation code
[[nodiscard]] auto arp_op_name(uint16_t op) noexcept -> std::string_view;

/// ARP header for Ethernet/IPv4 (28 bytes)
/// This is the most common ARP format
struct ArpHeader
{
    // Header length for Ethernet/IPv4 ARP
    static constexpr size_t LENGTH = 28;

    doublet_t hardware_type;           // Hardware type (1 = Ethernet)
    doublet_t protocol_type;           // Protocol type (0x0800 = IPv4)
    uint8_t hardware_addr_len{6};      // Hardware address length (6 for Ethernet)
    uint8_t protocol_addr_len{4};      // Protocol address length (4 for IPv4)
    doublet_t operation;               // Operation code
    Eui48 sender_hardware_addr;        // Sender MAC address
    IPv4Address sender_protocol_addr;  // Sender IP address
    Eui48 target_hardware_addr;        // Target MAC address
    IPv4Address target_protocol_addr;  // Target IP address

    /// Default constructor
    constexpr ArpHeader() noexcept
        : hardware_type(ARP_HARDWARE_ETHERNET)
        , protocol_type(ARP_PROTOCOL_IPV4)
        , operation(0)
        , sender_hardware_addr()
        , sender_protocol_addr()
        , target_hardware_addr()
        , target_protocol_addr()
    {}

    /// Check if this is an ARP request
    [[nodiscard]] constexpr auto is_request() const noexcept -> bool { return operation.get() == ARP_OP_REQUEST; }

    /// Check if this is an ARP reply
    [[nodiscard]] constexpr auto is_reply() const noexcept -> bool { return operation.get() == ARP_OP_REPLY; }

    /// Check if this is a RARP request
    [[nodiscard]] constexpr auto is_rarp_request() const noexcept -> bool { return operation.get() == ARP_OP_RARP_REQUEST; }

    /// Check if this is a RARP reply
    [[nodiscard]] constexpr auto is_rarp_reply() const noexcept -> bool { return operation.get() == ARP_OP_RARP_REPLY; }

    /// Check if this is an Ethernet/IPv4 ARP packet
    [[nodiscard]] constexpr auto is_ethernet_ipv4() const noexcept -> bool
    {
        return hardware_type.get() == ARP_HARDWARE_ETHERNET && protocol_type.get() == ARP_PROTOCOL_IPV4 && hardware_addr_len == 6 &&
            protocol_addr_len == 4;
    }

    /// Initialize for an ARP request
    /// @param sender_mac Sender MAC address
    /// @param sender_ip Sender IPv4 address
    /// @param target_ip Target IPv4 address to resolve
    constexpr void init_request(Eui48 const& sender_mac, IPv4Address const& sender_ip, IPv4Address const& target_ip) noexcept
    {
        hardware_type = ARP_HARDWARE_ETHERNET;
        protocol_type = ARP_PROTOCOL_IPV4;
        hardware_addr_len = 6;
        protocol_addr_len = 4;
        operation = ARP_OP_REQUEST;
        sender_hardware_addr = sender_mac;
        sender_protocol_addr = sender_ip;
        target_hardware_addr = Eui48();  // Zero for request
        target_protocol_addr = target_ip;
    }

    /// Initialize for an ARP reply
    /// @param sender_mac Sender MAC address
    /// @param sender_ip Sender IPv4 address
    /// @param target_mac Target MAC address
    /// @param target_ip Target IPv4 address
    constexpr void init_reply(
        Eui48 const& sender_mac, IPv4Address const& sender_ip, Eui48 const& target_mac, IPv4Address const& target_ip) noexcept
    {
        hardware_type = ARP_HARDWARE_ETHERNET;
        protocol_type = ARP_PROTOCOL_IPV4;
        hardware_addr_len = 6;
        protocol_addr_len = 4;
        operation = ARP_OP_REPLY;
        sender_hardware_addr = sender_mac;
        sender_protocol_addr = sender_ip;
        target_hardware_addr = target_mac;
        target_protocol_addr = target_ip;
    }

    auto operator<=>(ArpHeader const& rhs) const noexcept -> std::strong_ordering = default;
};

// Compile-time layout verification
static_assert(sizeof(ArpHeader) == 28, "ArpHeader must be exactly 28 bytes");
static_assert(alignof(ArpHeader) <= 2, "ArpHeader alignment must not exceed 2 bytes");
static_assert(offsetof(ArpHeader, hardware_type) == 0, "hardware_type must be at offset 0");
static_assert(offsetof(ArpHeader, protocol_type) == 2, "protocol_type must be at offset 2");
static_assert(offsetof(ArpHeader, hardware_addr_len) == 4, "hardware_addr_len must be at offset 4");
static_assert(offsetof(ArpHeader, protocol_addr_len) == 5, "protocol_addr_len must be at offset 5");
static_assert(offsetof(ArpHeader, operation) == 6, "operation must be at offset 6");
static_assert(offsetof(ArpHeader, sender_hardware_addr) == 8, "sender_hardware_addr must be at offset 8");
static_assert(offsetof(ArpHeader, sender_protocol_addr) == 14, "sender_protocol_addr must be at offset 14");
static_assert(offsetof(ArpHeader, target_hardware_addr) == 18, "target_hardware_addr must be at offset 18");
static_assert(offsetof(ArpHeader, target_protocol_addr) == 24, "target_protocol_addr must be at offset 24");

}  // namespace statusbar::ip

// Serialization traits
// ArpHeader is a packed wire format struct
template <>
struct statusbar::traits::is_serializable_wire_fixed_struct<statusbar::ip::ArpHeader> : std::true_type
{};

// Export free functions for ADL serialization
namespace statusbar::ip {

// Import template functions for wire fixed struct types (ArpHeader)
using protocol::load_unchecked;
using protocol::store_unchecked;

}  // namespace statusbar::ip
