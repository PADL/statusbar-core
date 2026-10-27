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

namespace detail {

/// One decimal octet of a dotted quad: one to three digits with a value of
/// 0-255, and no leading zero unless the octet is exactly "0". nullopt for
/// anything else, an empty part and a sign included.
///
/// The leading zero is refused rather than interpreted. inet_aton(3) reads
/// "032" as octal 26 and a decimal parser reads it as 32, so the text has two
/// readings and no way to choose between them; a peer that disagrees with us
/// about what an address means is how an address check passes while the
/// traffic goes elsewhere (CVE-2021-29418 and its relatives). Refusing is the
/// one answer that cannot disagree.
/// @param part The text of a single octet, without the dots
[[nodiscard]] constexpr auto parse_ipv4_octet(std::string_view const part) noexcept -> std::optional<uint8_t>
{
    if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0')) {
        return std::nullopt;
    }
    unsigned value = 0;
    for (char const c : part) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        value = (value * 10) + static_cast<unsigned>(c - '0');
    }
    if (value > 255) {
        return std::nullopt;
    }
    return static_cast<uint8_t>(value);
}

}  // namespace detail

/// Parse a dotted-quad IPv4 address ("239.69.1.2"): exactly four decimal
/// octets of 0-255 separated by three dots, with nothing before, between or
/// after them. nullopt otherwise - no inet_aton(3) shorthand ("10.1",
/// "0x0a000001"), no leading zeros, no surrounding whitespace.
///
/// Strict because the text arrives from the network: SDP session descriptions
/// carried over SAP are written by whoever is announcing, and an address we
/// accept from one must have a single unambiguous reading. See
/// detail::parse_ipv4_octet for why a leading zero is a refusal.
/// @param text The text to parse
[[nodiscard]] constexpr auto parse_ipv4(std::string_view text) noexcept -> std::optional<IPv4Address>
{
    std::array<uint8_t, IPv4Address::LENGTH> octets{};
    for (size_t i = 0; i < octets.size(); ++i) {
        bool const last = (i + 1) == octets.size();
        auto const dot = text.find('.');
        // Three dots, and the fourth octet runs to the end of the text.
        if ((dot == std::string_view::npos) != last) {
            return std::nullopt;
        }
        auto const octet = detail::parse_ipv4_octet(text.substr(0, dot));
        if (!octet.has_value()) {
            return std::nullopt;
        }
        octets[i] = *octet;
        if (!last) {
            text.remove_prefix(dot + 1);
        }
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
