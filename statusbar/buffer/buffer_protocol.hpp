#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer_base.hpp"
#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_traits.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <system_error>

namespace statusbar {

using traits::SerializableFixedStruct;
using traits::SerializableWireFixedStruct;

namespace protocol {

//
// Plain Type Serialization
// These functions handle loading and storing of plain (trivially copyable) types.
//
///
/// Check if a plain type can be loaded from a buffer.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The source buffer.
/// \param result Pointer to the destination (used for size calculation).
/// \return The required size on success, or an error if buffer is too small.
///
template <PlainType T>
[[nodiscard]] constexpr auto can_load(std::span<uint8_t const> const buf, T* const result) noexcept -> StatusValue<size_t>
{
    auto constexpr required_len = sizeof(*result);
    if (buf.size() < required_len) {
        return failure(BufferError::insufficient_data);
    }
    return success(required_len);
}

///
/// Load a plain type from a buffer with bounds checking.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The source buffer.
/// \param result Pointer to store the loaded value.
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <PlainType T>
[[nodiscard]] constexpr auto load(std::span<uint8_t const> const buf, T* const result) noexcept -> StatusValue<size_t>
{
    if (auto const status = can_load(buf, result); !status) {
        return status;
    }
    auto constexpr required_len = sizeof(*result);
    span_load(*result, buf);
    return success(required_len);
}

///
/// Load a plain type from a buffer without bounds checking.
/// The caller must ensure the buffer has sufficient data.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The source buffer (must be at least sizeof(T) bytes).
/// \param result Pointer to store the loaded value.
/// \return The number of bytes read.
///
template <PlainType T>
[[nodiscard]] constexpr auto load_unchecked(std::span<uint8_t const> const buf, T* const result) noexcept -> size_t
{
    auto constexpr required_len = sizeof(*result);
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= required_len && "load_unchecked: insufficient buffer size");
    span_load(*result, buf);
    return required_len;
}

//
// Array Serialization
//
///
/// Check if an array of plain types can be loaded from a buffer.
///
/// \tparam T A plain (trivially copyable) element type.
/// \tparam N The array size.
/// \param buf The source buffer.
/// \param result Pointer to the destination array.
/// \return The required size on success, or an error if buffer is too small.
///
template <PlainType T, size_t N>
[[nodiscard]] constexpr auto can_load(std::span<uint8_t const> const buf, std::array<T, N>* const result) noexcept
    -> StatusValue<size_t>
{
    auto constexpr required_len = sizeof(T) * N;
    if (buf.size() < required_len) {
        return failure(BufferError::insufficient_data);
    }
    return success(required_len);
}

///
/// Load an array of plain types from a buffer without bounds checking.
///
/// \tparam T A plain (trivially copyable) element type.
/// \tparam N The array size.
/// \param buf The source buffer (must have at least sizeof(T) * N bytes).
/// \param result Pointer to the destination array.
/// \return The number of bytes read.
///
template <PlainType T, size_t N>
[[nodiscard]] constexpr auto load_unchecked(std::span<uint8_t const> const buf, std::array<T, N>* const result) noexcept -> size_t
{
    auto constexpr required_len = sizeof(T) * N;
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= required_len && "load_unchecked: insufficient buffer size for array");
    // A std::array of plain elements is itself a plain object whose bytes are
    // exactly its elements, so the whole array is one span_load. (N == 0 is
    // the one exception: sizeof(std::array<T, 0>) is 1, not 0.)
    if constexpr (N > 0) {
        static_assert(sizeof(std::array<T, N>) == required_len);
        span_load(*result, buf);
    }
    return required_len;
}

///
/// Load an array of plain types from a buffer with bounds checking.
///
/// \tparam T A plain (trivially copyable) element type.
/// \tparam N The array size.
/// \param buf The source buffer.
/// \param result Pointer to the destination array.
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <PlainType T, size_t N>
[[nodiscard]] constexpr auto load(std::span<uint8_t const> const buf, std::array<T, N>* const result) noexcept
    -> StatusValue<size_t>
{
    if (auto const status = can_load(buf, result); !status) {
        return status;
    }
    return load_unchecked(buf, result);
}

//
// Sized Contiguous Container Serialization (std::vector, statusbar::sg14::inplace_vector)
//
///
/// Check if a pre-sized contiguous container of plain types can be loaded from a buffer.
/// The container must already be sized to the expected number of elements.
///
/// \tparam ContainerT A PlainSizedContiguous container (std::vector<T> or statusbar::sg14::inplace_vector<T, N>).
/// \param buf The source buffer.
/// \param result Pointer to the destination container (must be pre-sized).
/// \return The required size on success, or an error if buffer is too small.
///
template <traits::PlainSizedContiguous ContainerT>
[[nodiscard]] constexpr auto can_load(std::span<uint8_t const> const buf, ContainerT* const result) noexcept -> StatusValue<size_t>
{
    auto const count = result->size();
    auto const required_len = sizeof(typename ContainerT::value_type) * count;
    if (buf.size() < required_len) {
        return failure(BufferError::insufficient_data);
    }
    return success(required_len);
}

///
/// Load a pre-sized contiguous container of plain types from a buffer without bounds checking.
/// The container must already be sized to the expected number of elements.
///
/// \tparam ContainerT A PlainSizedContiguous container (std::vector<T> or statusbar::sg14::inplace_vector<T, N>).
/// \param buf The source buffer.
/// \param result Pointer to the destination container (must be pre-sized).
/// \return The number of bytes read.
///
template <traits::PlainSizedContiguous ContainerT>
[[nodiscard]] constexpr auto load_unchecked(std::span<uint8_t const> const buf, ContainerT* const result) noexcept -> size_t
{
    auto const count = result->size();
    auto const required_len = sizeof(typename ContainerT::value_type) * count;
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= required_len && "load_unchecked: insufficient buffer size for container");
    // The elements are contiguous plain objects, so the whole range is one
    // byte copy into the container's storage.
    if (count > 0) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const dest = std::span<uint8_t>(reinterpret_cast<uint8_t*>(result->data()), required_len);
        span_copy(dest, buf.first(required_len));
    }
    return required_len;
}

///
/// Load a pre-sized contiguous container of plain types from a buffer with bounds checking.
/// The container must already be sized to the expected number of elements.
///
/// \tparam ContainerT A PlainSizedContiguous container (std::vector<T> or statusbar::sg14::inplace_vector<T, N>).
/// \param buf The source buffer.
/// \param result Pointer to the destination container (must be pre-sized).
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <traits::PlainSizedContiguous ContainerT>
[[nodiscard]] constexpr auto load(std::span<uint8_t const> const buf, ContainerT* const result) noexcept -> StatusValue<size_t>
{
    if (auto const status = can_load(buf, result); !status) {
        return status;
    }
    return load_unchecked(buf, result);
}

//
// Plain Type Store Operations
//
///
/// Check if a plain type can be stored to a buffer.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The destination buffer.
/// \param value The value to check for storing.
/// \return The required size on success, or an error if buffer is too small.
///
template <PlainType T>
[[nodiscard]] constexpr auto can_store(std::span<uint8_t> const buf, T const& value) noexcept -> StatusValue<size_t>
{
    auto constexpr required_len = sizeof(value);
    if (buf.size() < required_len) {
        return failure(BufferError::insufficient_space);
    }
    return success(required_len);
}

///
/// Store a plain type to a buffer with bounds checking.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The destination buffer.
/// \param value The value to store.
/// \return The number of bytes written on success, or an error if buffer is too small.
///
template <PlainType T>
[[nodiscard]] constexpr auto store(std::span<uint8_t> const buf, T const& value) noexcept -> StatusValue<size_t>
{
    auto constexpr required_len = sizeof(value);
    if (buf.size() < required_len) {
        return failure(BufferError::insufficient_space);
    }
    span_store(buf, value);
    return success(required_len);
}

///
/// Store a plain type to a buffer without bounds checking.
/// The caller must ensure the buffer has sufficient space.
///
/// \tparam T A plain (trivially copyable) type.
/// \param buf The destination buffer (must be at least sizeof(T) bytes).
/// \param value The value to store.
/// \return The number of bytes written.
///
template <PlainType T>
[[nodiscard]] constexpr auto store_unchecked(std::span<uint8_t> const buf, T const& value) noexcept -> size_t
{
    auto constexpr required_len = sizeof(value);
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= required_len && "store_unchecked: insufficient buffer size");
    span_store(buf, value);
    return required_len;
}

//
// Buffer Slicing
//
///
/// Get a slice of a buffer starting at an offset.
/// Returns an empty span if offset is out of bounds.
///
/// \param buf The source buffer.
/// \param offset The starting offset.
/// \return A subspan starting at offset, or empty span if out of bounds.
///
[[nodiscard]] constexpr auto get_slice(std::span<uint8_t const> const buf, std::size_t const offset) noexcept
    -> std::span<uint8_t const>
{
    if (offset >= buf.size()) {
        return std::span<uint8_t const>{};
    }
    return buf.subspan(offset);
}

///
/// Get a slice of a buffer with specified offset and length.
/// Returns an empty span if the requested range is out of bounds.
///
/// \param buf The source buffer.
/// \param offset The starting offset.
/// \param required_len The required length of the slice.
/// \return A subspan of the requested range, or empty span if out of bounds.
///
[[nodiscard]] constexpr auto get_slice(
    std::span<uint8_t const> const buf, std::size_t const offset, std::size_t const required_len) noexcept
    -> std::span<uint8_t const>
{
    // Check for integer overflow before comparing
    if (required_len > buf.size() || offset > buf.size() - required_len) {
        return std::span<uint8_t const>{};
    }
    return buf.subspan(offset, required_len);
}

//
// Serializable Fixed Struct Operations
// These structs have a static LENGTH member and custom load_unchecked/store_unchecked.
//
///
/// Get the wire size of a serializable fixed struct.
///
/// \tparam T A type with a static LENGTH member.
/// \param header The struct (only used for type deduction).
/// \return The wire size in bytes.
///
template <SerializableFixedStruct T>
[[nodiscard]] constexpr auto wire_size(T const& header) noexcept -> size_t
{
    return header.LENGTH;
}

///
/// Check if a serializable fixed struct can be loaded from a buffer.
///
/// \tparam T A serializable fixed struct type.
/// \param buf The source buffer.
/// \param item Pointer to the destination.
/// \return The required size on success, or an error if buffer is too small.
///
template <SerializableFixedStruct T>
[[nodiscard]] constexpr auto can_load(std::span<uint8_t const> const buf, T const* item) noexcept -> StatusValue<size_t>
{
    auto const required = wire_size(*item);
    if (buf.size() < required) {
        return failure(BufferError::insufficient_data);
    }
    return success(required);
}

///
/// Check if a serializable fixed struct can be stored to a buffer.
///
/// \tparam T A serializable fixed struct type.
/// \param buf The destination buffer.
/// \param item The struct to check for storing.
/// \return The required size on success, or an error if buffer is too small.
///
template <SerializableFixedStruct T>
[[nodiscard]] constexpr auto can_store(std::span<uint8_t> const buf, T const& item) noexcept -> StatusValue<size_t>
{
    auto const required = wire_size(item);
    if (buf.size() < required) {
        return failure(BufferError::insufficient_space);
    }
    return success(required);
}

///
/// Load a serializable fixed struct from a buffer with bounds checking.
///
/// \tparam T A serializable fixed struct type.
/// \param buf The source buffer.
/// \param item Pointer to the destination.
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <SerializableFixedStruct T>
[[nodiscard]] auto load(std::span<uint8_t const> const buf, T* const item) noexcept -> StatusValue<size_t>
{
    if (auto status = can_load(buf, item); !status) {
        return status;
    }
    return success(load_unchecked(buf, item));
}

///
/// Store a serializable fixed struct to a buffer with bounds checking.
///
/// \tparam T A serializable fixed struct type.
/// \param buf The destination buffer.
/// \param item The struct to store.
/// \return The number of bytes written on success, or an error if buffer is too small.
///
template <SerializableFixedStruct T>
[[nodiscard]] auto store(std::span<uint8_t> const buf, T const& item) noexcept -> StatusValue<size_t>
{
    if (auto status = can_store(buf, item); !status) {
        return status;
    }
    return success(store_unchecked(buf, item));
}

//
// Serializable Variable Struct Operations
// These structs have variable length determined at runtime.
//
///
/// Load a serializable variable struct from a buffer with bounds checking.
///
/// \tparam T A serializable variable struct type.
/// \param buf The source buffer.
/// \param item Pointer to the destination.
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <traits::SerializableVariableStruct T>
[[nodiscard]] auto load(std::span<uint8_t const> const buf, T* const item) noexcept -> StatusValue<size_t>
{
    if (auto status = can_load(buf, item); !status) {
        return status;
    }
    return success(load_unchecked(buf, item));
}

///
/// Store a serializable variable struct to a buffer with bounds checking.
///
/// \tparam T A serializable variable struct type.
/// \param buf The destination buffer.
/// \param item The struct to store.
/// \return The number of bytes written on success, or an error if buffer is too small.
///
template <traits::SerializableVariableStruct T>
[[nodiscard]] auto store(std::span<uint8_t> const buf, T const& item) noexcept -> StatusValue<size_t>
{
    if (auto status = can_store(buf, item); !status) {
        return status;
    }
    return success(store_unchecked(buf, item));
}

//
// Wire Fixed Struct Serialization
// These structs are packed to match wire format exactly, so memcpy works directly.
//
///
/// Get the wire size of a wire-format fixed struct.
///
/// \tparam T A wire-format struct with a static LENGTH member.
/// \return The wire size in bytes.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] constexpr auto wire_size(T const& /* item */) noexcept -> size_t
{
    return T::LENGTH;
}

///
/// Load a wire-format fixed struct from a buffer without bounds checking.
/// Uses direct memcpy since the struct is packed to match wire format.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The source buffer (must be at least T::LENGTH bytes).
/// \param item Pointer to the destination.
/// \return The number of bytes read.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] auto load_unchecked(std::span<uint8_t const> const buf, T* const item) noexcept -> size_t
{
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= T::LENGTH && "load_unchecked: insufficient buffer size for wire struct");
    span_load(*item, buf);
    return T::LENGTH;
}

///
/// Store a wire-format fixed struct to a buffer without bounds checking.
/// Uses direct memcpy since the struct is packed to match wire format.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The destination buffer (must be at least T::LENGTH bytes).
/// \param item The struct to store.
/// \return The number of bytes written.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] auto store_unchecked(std::span<uint8_t> const buf, T const& item) noexcept -> size_t
{
    auto const buf_size = buf.size();
    STATUSBAR_ASSERT(buf_size >= T::LENGTH && "store_unchecked: insufficient buffer size for wire struct");
    span_store(buf, item);
    return T::LENGTH;
}

///
/// Check if a wire-format fixed struct can be loaded from a buffer.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The source buffer.
/// \return The required size on success, or an error if buffer is too small.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] constexpr auto can_load(std::span<uint8_t const> const buf, T const* /* item */) noexcept -> StatusValue<size_t>
{
    if (buf.size() < T::LENGTH) {
        return failure(BufferError::insufficient_data);
    }
    return success(T::LENGTH);
}

///
/// Check if a wire-format fixed struct can be stored to a buffer.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The destination buffer.
/// \return The required size on success, or an error if buffer is too small.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] constexpr auto can_store(std::span<uint8_t> const buf, T const& /* item */) noexcept -> StatusValue<size_t>
{
    if (buf.size() < T::LENGTH) {
        return failure(BufferError::insufficient_space);
    }
    return success(T::LENGTH);
}

///
/// Load a wire-format fixed struct from a buffer with bounds checking.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The source buffer.
/// \param item Pointer to the destination.
/// \return The number of bytes read on success, or an error if buffer is too small.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] auto load(std::span<uint8_t const> const buf, T* const item) noexcept -> StatusValue<size_t>
{
    if (buf.size() < T::LENGTH) {
        return failure(BufferError::insufficient_data);
    }
    return success(load_unchecked(buf, item));
}

///
/// Store a wire-format fixed struct to a buffer with bounds checking.
///
/// \tparam T A wire-format fixed struct type.
/// \param buf The destination buffer.
/// \param item The struct to store.
/// \return The number of bytes written on success, or an error if buffer is too small.
///
template <SerializableWireFixedStruct T>
[[nodiscard]] auto store(std::span<uint8_t> const buf, T const& item) noexcept -> StatusValue<size_t>
{
    if (buf.size() < T::LENGTH) {
        return failure(BufferError::insufficient_space);
    }
    return success(store_unchecked(buf, item));
}

//
// Serialized size of any wire value
//
///
/// Number of bytes `store_unchecked(buf, value)` will write for a value the
/// builders and compiled serdes handle as a unit: `wire_size(value)` for a
/// SerializableStruct (found via ADL for user types), `sizeof(T)` for any
/// other trivially copyable type. std::span is rejected by WireValue.
///
/// \tparam T A traits::WireValue type.
/// \param value The value to size.
/// \return The number of bytes the value occupies on the wire.
///
template <traits::WireValue T>
[[nodiscard]] constexpr auto serialized_size(T const& value) noexcept -> size_t
{
    if constexpr (traits::SerializableStruct<T>) {
        return wire_size(value);
    } else {
        return sizeof(T);
    }
}

}  // namespace protocol

}  // namespace statusbar
