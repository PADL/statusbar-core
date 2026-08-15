#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace statusbar::ieee {

using traits::PlainCArray;
using traits::PlainElement;
using traits::PlainLinearCollection;
using traits::PlainStdArray;
using traits::PlainStdSpan;
using traits::PlainStdVector;
using traits::PlainType;
using traits::UnsignedIntegerType;

///
/// A network byte order (big-endian) unsigned integer wrapper.
///
/// This class provides transparent conversion between host and network byte order
/// for unsigned integers. It stores the value in network byte order internally,
/// making it suitable for use in packed network protocol structures.
///
/// Features:
/// - Implicit conversion to/from host byte order
/// - Comparison operators that work correctly with host values
/// - Bit manipulation helpers (flags, bit fields)
/// - Zero alignment requirement (uses byte array storage)
///
/// \tparam T The underlying unsigned integer type (uint8_t, uint16_t, uint32_t, uint64_t).
///
/// Example:
/// \code
///   doublet_t port = 8080;  // Stored in network byte order
///   uint16_t host_port = port;  // Automatically converted to host order
///   port = 443;  // Assignment from host order
/// \endcode
///
template <UnsignedIntegerType T>
struct IeeeOrderedUInt
{
  private:
    // Store as byte array to eliminate alignment requirements for packed structs
    std::array<uint8_t, sizeof(T)> bytes_;

    // Helper to convert from network byte order to host byte order
    [[nodiscard]] static constexpr auto network_to_host(T network_value) noexcept -> T
    {
        if constexpr (sizeof(T) == 1 || std::endian::native == std::endian::big) {
            // Single byte or big endian host: no conversion needed
            return network_value;
        }
        // Little endian host: byte swap needed
        return std::byteswap(network_value);
    }

    // Helper to convert from host byte order to network byte order
    [[nodiscard]] static constexpr auto host_to_network(T host_value) noexcept -> T
    {
        if constexpr (sizeof(T) == 1 || std::endian::native == std::endian::big) {
            // Single byte or big endian host: no conversion needed
            return host_value;
        }
        // Little endian host: byte swap needed
        return std::byteswap(host_value);
    }

    // Helper to load value from bytes (in network byte order) and convert to host order
    [[nodiscard]] constexpr auto load_bytes() const noexcept -> T
    {
        // Use std::bit_cast for constexpr-compatible byte-to-value conversion
        T const network_value = std::bit_cast<T>(bytes_);
        return network_to_host(network_value);
    }

    // Helper to store value to bytes (convert from host order to network byte order)
    constexpr auto store_bytes(T host_value) noexcept
    {
        T const network_value = host_to_network(host_value);
        // Use std::bit_cast for constexpr-compatible value-to-bytes conversion
        bytes_ = std::bit_cast<std::array<uint8_t, sizeof(T)>>(network_value);
    }

  public:
    /// Default constructor - zero-initializes the value.
    constexpr IeeeOrderedUInt() noexcept
        : bytes_{}
    {}

    /// Construct from a host byte order value.
    /// \param host_value The value in host byte order.
    constexpr IeeeOrderedUInt(T host_value) noexcept
        : bytes_{}
    {
        store_bytes(host_value);
    }

    /// Assignment operator from host byte order value.
    /// \param host_value The value in host byte order.
    /// \return Reference to this object.
    constexpr auto operator=(T host_value) noexcept -> IeeeOrderedUInt&
    {
        store_bytes(host_value);
        return *this;
    }

    /// Implicit conversion to host byte order.
    /// \return The value in host byte order.
    [[nodiscard]] constexpr operator T() const noexcept { return load_bytes(); }

    /// Get the value in host byte order (explicit alternative to implicit conversion).
    /// \return The value in host byte order.
    [[nodiscard]] constexpr auto get() const noexcept -> T { return load_bytes(); }

    /// Set the value from host byte order.
    /// \param host_value The value in host byte order.
    constexpr auto set(T host_value) noexcept { store_bytes(host_value); }

    /// Set the value directly from network-ordered bytes (for deserialization).
    /// \param network_val The value already in network byte order.
    constexpr auto set_network(T network_val) noexcept { bytes_ = std::bit_cast<std::array<uint8_t, sizeof(T)>>(network_val); }

    /// Get the raw network-ordered value (for serialization).
    /// \return The value in network byte order.
    [[nodiscard]] constexpr auto network_value() const noexcept -> T { return std::bit_cast<T>(bytes_); }

    /// Get a mutable span of the underlying bytes.
    /// \return A span of sizeof(T) bytes in network byte order.
    [[nodiscard]] constexpr auto span() noexcept -> std::span<uint8_t, sizeof(T)> { return std::span<uint8_t, sizeof(T)>(bytes_); }

    /// Get a const span of the underlying bytes.
    /// \return A const span of sizeof(T) bytes in network byte order.
    [[nodiscard]] constexpr auto span() const noexcept -> std::span<uint8_t const, sizeof(T)>
    {
        return std::span<uint8_t const, sizeof(T)>(bytes_);
    }

    /// Equality comparison with another IeeeOrderedUInt.
    /// \param other The value to compare with.
    /// \return true if the host-order values are equal.
    [[nodiscard]] constexpr auto operator==(IeeeOrderedUInt const& other) const noexcept -> bool
    {
        return load_bytes() == other.load_bytes();
    }

    /// Three-way comparison with another IeeeOrderedUInt.
    /// \param other The value to compare with.
    /// \return The ordering result based on host-order values.
    [[nodiscard]] constexpr auto operator<=>(IeeeOrderedUInt const& other) const noexcept
    {
        return load_bytes() <=> other.load_bytes();
    }

    /// Equality comparison with any integral type.
    /// Widens to the larger type to avoid silent truncation.
    /// \tparam U An integral type.
    /// \param other The value to compare with.
    /// \return true if the host-order value equals other.
    template <std::integral U>
    [[nodiscard]] constexpr auto operator==(U other) const noexcept -> bool
    {
        using Common = std::common_type_t<T, U>;
        return static_cast<Common>(load_bytes()) == static_cast<Common>(other);
    }

    /// Three-way comparison with any integral type.
    /// Widens to the larger type to avoid silent truncation.
    /// \tparam U An integral type.
    /// \param other The value to compare with.
    /// \return The ordering result.
    template <std::integral U>
    [[nodiscard]] constexpr auto operator<=>(U other) const noexcept
    {
        using Common = std::common_type_t<T, U>;
        return static_cast<Common>(load_bytes()) <=> static_cast<Common>(other);
    }

    //
    // Bit Flag Operations
    //

    /// Check if a flag (or any of multiple flags) is set.
    /// \param flag The flag bitmask to check.
    /// \return true if any of the specified flag bits are set.
    [[nodiscard]] constexpr auto has_flag(T flag) const noexcept -> bool { return (load_bytes() & flag) != 0; }

    /// Check if all specified flags are set.
    /// \param flags The flag bitmask to check.
    /// \return true if all of the specified flag bits are set.
    [[nodiscard]] constexpr auto has_all_flags(T flags) const noexcept -> bool { return (load_bytes() & flags) == flags; }

    /// Set or clear a flag based on a boolean value.
    /// \param flag The flag bitmask to modify.
    /// \param value true to set the flag, false to clear it.
    constexpr auto set_flag(T flag, bool value) noexcept
    {
        if (value) {
            store_bytes(load_bytes() | flag);
        } else {
            store_bytes(load_bytes() & ~flag);
        }
    }

    /// Set a flag (turn it on).
    /// \param flag The flag bitmask to set.
    constexpr auto set_flag(T flag) noexcept { store_bytes(load_bytes() | flag); }

    /// Clear a flag (turn it off).
    /// \param flag The flag bitmask to clear.
    constexpr auto clear_flag(T flag) noexcept { store_bytes(load_bytes() & ~flag); }

    /// Toggle a flag (flip its state).
    /// \param flag The flag bitmask to toggle.
    constexpr auto toggle_flag(T flag) noexcept { store_bytes(load_bytes() ^ flag); }

    /// Extract a bit field value using a mask and shift.
    /// \tparam U The result type (defaults to T).
    /// \param mask The bitmask identifying the field.
    /// \param shift The number of bits to shift right (default 0).
    /// \return The extracted field value.
    template <std::integral U = T>
    [[nodiscard]] constexpr auto get_bits(T mask, unsigned shift = 0) const noexcept -> U
    {
        return static_cast<U>((load_bytes() & mask) >> shift);
    }

    /// Set a bit field value using a mask and shift.
    /// \tparam U The input value type.
    /// \param mask The bitmask identifying the field.
    /// \param shift The number of bits to shift left.
    /// \param value The value to set in the field.
    template <std::integral U>
    constexpr auto set_bits(T mask, unsigned shift, U value) noexcept
    {
        T current = load_bytes();
        current = (current & ~mask) | ((static_cast<T>(value) << shift) & mask);
        store_bytes(current);
    }
};

/// Network byte order 8-bit unsigned integer (1 byte).
using octet_t = IeeeOrderedUInt<std::uint8_t>;

/// Network byte order 16-bit unsigned integer (2 bytes).
using doublet_t = IeeeOrderedUInt<std::uint16_t>;

/// Network byte order 32-bit unsigned integer (4 bytes).
using quadlet_t = IeeeOrderedUInt<std::uint32_t>;

/// Network byte order 64-bit unsigned integer (8 bytes).
using octlet_t = IeeeOrderedUInt<std::uint64_t>;

///
/// A network byte order (big-endian) 48-bit unsigned integer.
///
/// Six bytes of storage with a uint64_t host-order interface — the wire type
/// for IEEE 802.1AS / 1722.1 48-bit fields (PTP seconds, GPTP_TIME control
/// values). Mirrors the IeeeOrderedUInt API; there is no native 48-bit
/// integer, so the byte marshalling lives here instead of std::byteswap.
/// Values are truncated to the low 48 bits on store.
///
struct IeeeOrderedUInt48
{
  private:
    std::array<uint8_t, 6> bytes_;

    static constexpr std::uint64_t VALUE_MASK = 0x0000FFFFFFFFFFFFULL;

    [[nodiscard]] constexpr auto load_bytes() const noexcept -> std::uint64_t
    {
        return (static_cast<std::uint64_t>(bytes_[0]) << 40) | (static_cast<std::uint64_t>(bytes_[1]) << 32) |
            (static_cast<std::uint64_t>(bytes_[2]) << 24) | (static_cast<std::uint64_t>(bytes_[3]) << 16) |
            (static_cast<std::uint64_t>(bytes_[4]) << 8) | static_cast<std::uint64_t>(bytes_[5]);
    }

    constexpr auto store_bytes(std::uint64_t host_value) noexcept
    {
        bytes_[0] = static_cast<uint8_t>((host_value >> 40) & 0xFFU);
        bytes_[1] = static_cast<uint8_t>((host_value >> 32) & 0xFFU);
        bytes_[2] = static_cast<uint8_t>((host_value >> 24) & 0xFFU);
        bytes_[3] = static_cast<uint8_t>((host_value >> 16) & 0xFFU);
        bytes_[4] = static_cast<uint8_t>((host_value >> 8) & 0xFFU);
        bytes_[5] = static_cast<uint8_t>(host_value & 0xFFU);
    }

  public:
    /// Default constructor - zero-initializes the value.
    constexpr IeeeOrderedUInt48() noexcept
        : bytes_{}
    {}

    /// Construct from a host byte order value (truncated to 48 bits).
    constexpr IeeeOrderedUInt48(std::uint64_t host_value) noexcept
        : bytes_{}
    {
        store_bytes(host_value);
    }

    /// Assignment from a host byte order value (truncated to 48 bits).
    constexpr auto operator=(std::uint64_t host_value) noexcept -> IeeeOrderedUInt48&
    {
        store_bytes(host_value);
        return *this;
    }

    /// Implicit conversion to host byte order.
    [[nodiscard]] constexpr operator std::uint64_t() const noexcept { return load_bytes(); }

    /// Get the value in host byte order (explicit alternative to implicit conversion).
    [[nodiscard]] constexpr auto get() const noexcept -> std::uint64_t { return load_bytes(); }

    /// Set the value from host byte order (truncated to 48 bits).
    constexpr auto set(std::uint64_t host_value) noexcept { store_bytes(host_value); }

    /// Get a mutable span of the underlying bytes (network byte order).
    [[nodiscard]] constexpr auto span() noexcept -> std::span<uint8_t, 6> { return std::span<uint8_t, 6>(bytes_); }

    /// Get a const span of the underlying bytes (network byte order).
    [[nodiscard]] constexpr auto span() const noexcept -> std::span<uint8_t const, 6>
    {
        return std::span<uint8_t const, 6>(bytes_);
    }

    /// Equality comparison with another IeeeOrderedUInt48.
    [[nodiscard]] constexpr auto operator==(IeeeOrderedUInt48 const& other) const noexcept -> bool
    {
        return bytes_ == other.bytes_;
    }

    /// Three-way comparison with another IeeeOrderedUInt48.
    [[nodiscard]] constexpr auto operator<=>(IeeeOrderedUInt48 const& other) const noexcept
    {
        return load_bytes() <=> other.load_bytes();
    }

    /// Equality comparison with any integral type.
    template <std::integral U>
    [[nodiscard]] constexpr auto operator==(U other) const noexcept -> bool
    {
        using Common = std::common_type_t<std::uint64_t, U>;
        return static_cast<Common>(load_bytes()) == static_cast<Common>(other);
    }

    /// Three-way comparison with any integral type.
    template <std::integral U>
    [[nodiscard]] constexpr auto operator<=>(U other) const noexcept
    {
        using Common = std::common_type_t<std::uint64_t, U>;
        return static_cast<Common>(load_bytes()) <=> static_cast<Common>(other);
    }

    /// The largest value representable in 48 bits.
    [[nodiscard]] static constexpr auto max_value() noexcept -> std::uint64_t { return VALUE_MASK; }
};

static_assert(sizeof(IeeeOrderedUInt48) == 6);
static_assert(alignof(IeeeOrderedUInt48) == 1);

/// Network byte order 48-bit unsigned integer (6 bytes).
using sextlet_t = IeeeOrderedUInt48;

/// Type trait to check if a type is an IeeeOrderedUInt.
template <typename T>
struct is_ieee_ordered_uint : std::false_type
{};

/// Specialization for IeeeOrderedUInt types.
template <UnsignedIntegerType U>
struct is_ieee_ordered_uint<IeeeOrderedUInt<U>> : std::true_type
{};

/// Specialization for the 48-bit ordered type (same span()-based interface).
template <>
struct is_ieee_ordered_uint<IeeeOrderedUInt48> : std::true_type
{};

/// Type trait to check if a type is an std::array of IeeeOrderedUInt.
template <typename T>
struct is_ieee_std_array : std::false_type
{};

/// Specialization for std::array of IeeeOrderedUInt.
template <UnsignedIntegerType U, std::size_t N>
struct is_ieee_std_array<std::array<IeeeOrderedUInt<U>, N>> : std::true_type
{};

/// Type trait to check if a type is an std::span of IeeeOrderedUInt.
template <typename T>
struct is_ieee_std_span : std::false_type
{};

/// Specialization for std::span of IeeeOrderedUInt.
template <UnsignedIntegerType U, std::size_t N>
struct is_ieee_std_span<std::span<IeeeOrderedUInt<U>, N>> : std::true_type
{};

//
// ADL Serialization Functions for IeeeOrderedUInt
//

///
/// Store an IeeeOrderedUInt to a buffer without bounds checking.
/// The value is stored in network byte order.
///
/// \tparam T The underlying unsigned integer type.
/// \param buf The destination buffer (must be at least sizeof(T) bytes).
/// \param value The value to store.
/// \return The number of bytes written.
///
template <UnsignedIntegerType T>
[[nodiscard]] auto store_unchecked(std::span<uint8_t> const buf, IeeeOrderedUInt<T> const& value) noexcept -> size_t
{
    // IeeeOrderedUInt stores value in network byte order internally as a byte array
    span_copy(buf.subspan(0, sizeof(T)), value.span());
    return sizeof(T);
}

///
/// Load an IeeeOrderedUInt from a buffer without bounds checking.
/// The buffer is expected to contain the value in network byte order.
///
/// \tparam T The underlying unsigned integer type.
/// \param buf The source buffer (must be at least sizeof(T) bytes).
/// \param value Pointer to store the loaded value.
/// \return The number of bytes read.
///
template <UnsignedIntegerType T>
[[nodiscard]] auto load_unchecked(std::span<uint8_t const> const buf, IeeeOrderedUInt<T>* const value) noexcept -> size_t
{
    // Load network-ordered bytes directly into the internal byte array
    span_copy(value->span(), buf.subspan(0, sizeof(T)));
    return sizeof(T);
}

}  // namespace statusbar::ieee
