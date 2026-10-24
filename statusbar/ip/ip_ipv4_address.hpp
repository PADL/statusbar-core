#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <charconv>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace statusbar::ip {

/// IPv4 address (32 bits) using network byte order storage
/// Internally uses ieee::quadlet_t for proper byte ordering
struct IPv4Address
{
    static constexpr size_t LENGTH = 4;

    /// Internal storage in network byte order
    ieee::quadlet_t value;

    /// Default constructor - initializes to 0.0.0.0
    constexpr IPv4Address() noexcept
        : value{}
    {}

    /// Construct from 4 individual octets
    /// @param a First octet (e.g., 192 in 192.168.1.1)
    /// @param b Second octet
    /// @param c Third octet
    /// @param d Fourth octet
    constexpr IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept
        : value{static_cast<uint32_t>(
              (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) | (static_cast<uint32_t>(c) << 8) |
              static_cast<uint32_t>(d))}
    {}

    /// Construct from host byte order uint32
    /// @param addr 32-bit address in host byte order (e.g., 0xC0A80101 for 192.168.1.1)
    constexpr explicit IPv4Address(uint32_t addr) noexcept
        : value{addr}
    {}

    /// Get the size of the IPv4 address in bytes
    [[nodiscard]] static constexpr auto size() noexcept -> size_t { return LENGTH; }

    /// Convert to host byte order uint32
    [[nodiscard]] constexpr auto to_uint32() const noexcept -> uint32_t { return value.get(); }

    /// Get individual octets
    /// @param index Octet index (0-3, where 0 is the most significant)
    [[nodiscard]] constexpr auto octet(size_t const index) const noexcept -> uint8_t
    {
        uint32_t const host_val = to_uint32();
        return static_cast<uint8_t>((host_val >> (24 - (8 * index))) & 0xFF);
    }

    /// Get a span view of the address bytes (in network byte order)
    [[nodiscard]] constexpr auto span() const noexcept { return value.span(); }
    [[nodiscard]] constexpr auto span() noexcept { return value.span(); }

    /// Check if this is the unspecified address (0.0.0.0)
    [[nodiscard]] constexpr auto is_unspecified() const noexcept -> bool { return to_uint32() == 0; }

    /// Check if this is the loopback address (127.x.x.x)
    [[nodiscard]] constexpr auto is_loopback() const noexcept -> bool { return octet(0) == 127; }

    /// Check if this is a multicast address (224.0.0.0 - 239.255.255.255)
    [[nodiscard]] constexpr auto is_multicast() const noexcept -> bool { return (octet(0) & 0xF0) == 0xE0; }

    /// Check if this is a broadcast address (255.255.255.255)
    [[nodiscard]] constexpr auto is_broadcast() const noexcept -> bool { return to_uint32() == 0xFFFFFFFF; }

    /// Check if this is a private address (RFC 1918)
    [[nodiscard]] constexpr auto is_private() const noexcept -> bool
    {
        uint8_t const first = octet(0);
        uint8_t const second = octet(1);

        // 10.0.0.0/8
        if (first == 10) {
            return true;
        }
        // 172.16.0.0/12
        auto is_172_16_block = [](uint8_t f, uint8_t s) constexpr noexcept -> bool { return f == 172 && s >= 16 && s <= 31; };
        if (is_172_16_block(first, second)) {
            return true;
        }
        // 192.168.0.0/16
        if (first == 192 && second == 168) {
            return true;
        }
        return false;
    }

    /// Comparison - compares in host byte order for correct semantics
    [[nodiscard]] constexpr auto operator==(IPv4Address const& rhs) const noexcept -> bool { return value == rhs.value; }
    [[nodiscard]] constexpr auto operator<=>(IPv4Address const& rhs) const noexcept { return value <=> rhs.value; }
};

// Compile-time layout verification
static_assert(sizeof(IPv4Address) == 4, "IPv4Address must be exactly 4 bytes");
static_assert(alignof(IPv4Address) == 1, "IPv4Address must have 1-byte alignment");

/// Parse a dotted-quad IPv4 address ("239.69.1.2"): exactly four decimal
/// octets 0-255, nothing before or after. nullopt otherwise.
/// @param text The text to parse
[[nodiscard]] inline auto parse_ipv4(std::string_view text) noexcept -> std::optional<IPv4Address>
{
    std::array<uint8_t, 4> octets{};
    for (size_t i = 0; i < octets.size(); ++i) {
        auto const dot = text.find('.');
        if ((dot == std::string_view::npos) != (i == octets.size() - 1)) {
            return std::nullopt;
        }
        auto const part = text.substr(0, dot);
        auto const [end, error] = std::from_chars(part.data(), part.data() + part.size(), octets[i]);
        // A leading zero is refused: inet_aton reads "032" as octal, from_chars as decimal.
        if (part.empty() || error != std::errc{} || end != part.data() + part.size() || (part.size() > 1 && part[0] == '0')) {
            return std::nullopt;
        }
        text = dot == std::string_view::npos ? std::string_view{} : text.substr(dot + 1);
    }
    return IPv4Address{octets[0], octets[1], octets[2], octets[3]};
}

}  // namespace statusbar::ip

// Serialization traits
// IPv4Address uses quadlet_t internally which handles network byte order
template <>
struct statusbar::traits::is_serializable_fixed_struct<statusbar::ip::IPv4Address> : std::true_type
{};

// Export free functions for ADL serialization
namespace statusbar::ip {

/// Load an IPv4 address from a buffer without bounds checking
/// @param buf Source buffer containing the address bytes
/// @param item Pointer to IPv4Address to populate
[[nodiscard]] inline auto load_unchecked(std::span<uint8_t const> const buf, IPv4Address* const item) noexcept -> size_t
{
    return ieee::load_unchecked(buf, &item->value);
}

/// Store an IPv4 address to a buffer without bounds checking
/// @param buf Destination buffer to write the address bytes to
/// @param item IPv4Address to store
[[nodiscard]] inline auto store_unchecked(std::span<uint8_t> const buf, IPv4Address const& item) noexcept -> size_t
{
    return ieee::store_unchecked(buf, item.value);
}

}  // namespace statusbar::ip
