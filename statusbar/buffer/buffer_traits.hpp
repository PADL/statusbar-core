#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/sg14/inplace_vector.h"
#include "statusbar/status/status.hpp"

#include <array>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace statusbar::traits {

//
// Plain Element Type Traits
// These identify types that can be directly serialized as raw bytes.
//

/// True for the compiler-extension 128-bit integer types (__int128 /
/// __uint128_t). GCC and Clang both define __SIZEOF_INT128__ exactly when
/// these are available — the same gate the crypto module uses
/// (STATUSBAR_CRYPTO_HAS_INT128 in crypto/util/crypto_has_int128.hpp).
/// They must be named explicitly because std::is_arithmetic_v does not
/// recognize them under a strict -std=c++NN dialect (only in GNU mode),
/// even though they are plain, trivially-serializable integers.
template <typename T>
inline constexpr bool is_extended_integer_v =
#if defined(__SIZEOF_INT128__)
    std::is_same_v<T, __int128_t> || std::is_same_v<T, __uint128_t>;
#else
    false;
#endif

/// Concept for plain element types that can be directly serialized.
/// A plain element is an arithmetic type (int, float, etc.), an enum, or a
/// compiler-extension 128-bit integer.
template <typename T>
concept PlainElement =
    (std::is_arithmetic_v<std::remove_cv_t<T>> || std::is_enum_v<std::remove_cv_t<T>> ||
     is_extended_integer_v<std::remove_cv_t<T>>);

/// Type trait to check if a type is a std::array of plain elements.
template <typename T>
struct is_plain_std_array : std::false_type
{};

/// Specialization for std::array of plain elements.
template <typename U, std::size_t N>
struct is_plain_std_array<std::array<U, N>> : std::bool_constant<PlainElement<U>>
{};

/// Type trait to check if a type is a std::span of plain elements.
template <typename U, std::size_t N = std::dynamic_extent>
struct is_plain_std_span : std::false_type
{};

/// Specialization for std::span of plain elements.
template <typename U, std::size_t N>
struct is_plain_std_span<std::span<U, N>> : std::bool_constant<PlainElement<U>>
{};

/// Type trait to check if a type is a std::vector of plain elements.
template <typename T>
struct is_plain_std_vector : std::false_type
{};

/// Specialization for std::vector of plain elements.
template <typename U>
struct is_plain_std_vector<std::vector<U>> : std::bool_constant<PlainElement<U>>
{};

/// Concept for unsigned integer types (excluding bool).
/// Used for network byte order wrapper types.
template <typename T>
concept UnsignedIntegerType = std::unsigned_integral<T> && !std::is_same_v<T, bool>;

/// Concept for std::array of plain elements.
template <typename T>
concept PlainStdArray = is_plain_std_array<std::remove_cvref_t<T>>::value;

/// Concept for std::span of plain elements. A view over plain bytes, NOT a
/// plain type itself — see PlainLinearCollection.
template <typename T>
concept PlainStdSpan = is_plain_std_span<std::remove_cvref_t<T>>::value;

/// Concept for C-style arrays of plain elements.
template <typename T>
concept PlainCArray =
    std::is_array_v<std::remove_reference_t<T>> && PlainElement<std::remove_all_extents_t<std::remove_reference_t<T>>>;

/// Concept for std::vector of plain elements.
template <typename T>
concept PlainStdVector = is_plain_std_vector<std::remove_cvref_t<T>>::value;

/// Type trait to check if a type is a statusbar::sg14::inplace_vector of plain elements.
template <typename T>
struct is_plain_inplace_vector : std::false_type
{};

/// Specialization for statusbar::sg14::inplace_vector of plain elements.
template <typename U, size_t N>
struct is_plain_inplace_vector<statusbar::sg14::inplace_vector<U, N>> : std::bool_constant<PlainElement<U>>
{};

/// Concept for statusbar::sg14::inplace_vector of plain elements.
template <typename T>
concept PlainInplaceVector = is_plain_inplace_vector<std::remove_cvref_t<T>>::value;

/// Concept for a pre-sized contiguous container of plain elements (std::vector or statusbar::sg14::inplace_vector).
/// These containers have runtime .size(), contiguous .data(), and element-wise operator[].
template <typename T>
concept PlainSizedContiguous = PlainStdVector<T> || PlainInplaceVector<T>;

/// Concept for any linear collection of plain elements whose object bytes
/// ARE its elements: std::array and C arrays. std::span is deliberately not
/// one — it is trivially copyable, but its bytes are a pointer and a length,
/// so treating it as plain would serialize the view instead of the viewed
/// bytes. Raw pointers are excluded for the same reason (and carry no length).
/// Spans are appended through the dedicated std::span<uint8_t const>
/// overloads on MutableBuffer and BufferSerializerBuilder.
template <typename T>
concept PlainLinearCollection = PlainStdArray<T> || PlainCArray<T>;

/// Concept for any plain type that can be directly serialized.
/// Includes plain elements and linear collections of plain elements.
template <typename T>
concept PlainType = PlainElement<std::remove_reference_t<T>> || PlainLinearCollection<T>;

//
// Serializable Struct Traits
// These identify structs with custom serialization behavior.
//

/// Trait for structs with fixed-size serialization.
/// Types opting into this trait must provide:
/// - `static constexpr size_t LENGTH` - the wire size in bytes
/// - `load_unchecked(span, T*)` - deserialize from buffer
/// - `store_unchecked(span, T const&)` - serialize to buffer
template <typename T>
struct is_serializable_fixed_struct : std::false_type
{};

/// Concept for fixed-size serializable structs.
template <typename T>
concept SerializableFixedStruct = is_serializable_fixed_struct<std::remove_cvref_t<T>>::value;

/// Trait for structs with variable-size serialization.
/// Types opting into this trait must provide:
/// - `wire_size(T const&)` - get the wire size for this instance
/// - `can_load(span, T const*)` - check if buffer has sufficient data (never writes)
/// - `can_store(span, T const&)` - check if buffer has sufficient space
/// - `load_unchecked(span, T*)` - deserialize from buffer
/// - `store_unchecked(span, T const&)` - serialize to buffer
template <typename T>
struct is_serializable_variable_struct : std::false_type
{};

/// Concept for variable-size serializable structs.
template <typename T>
concept SerializableVariableStruct = is_serializable_variable_struct<std::remove_cvref_t<T>>::value;

/// Concept for any serializable struct (fixed or variable).
template <typename T>
concept SerializableStruct =
    is_serializable_fixed_struct<std::remove_cvref_t<T>>::value || is_serializable_variable_struct<std::remove_cvref_t<T>>::value;

/// Concept for a value the builders and compiled serdes can move to or from
/// the wire as a unit: a SerializableStruct (sized by wire_size()) or a
/// trivially copyable object whose bytes are its wire image (sized by
/// sizeof). std::span is excluded explicitly: it is trivially copyable, but
/// its bytes are a pointer and a length, not the elements it views.
template <typename T>
concept WireValue = !StdSpan<T> && (SerializableStruct<T> || std::is_trivially_copyable_v<std::remove_cvref_t<T>>);

/// Trait for fixed-size structs that are packed to match wire format exactly.
/// These structs can be serialized/deserialized with a single memcpy.
///
/// Requirements:
/// - The struct must have a `static constexpr size_t LENGTH` member
/// - sizeof(StructType) must equal LENGTH (verified by static_assert)
/// - The struct's layout must match the wire format exactly
///
/// Opting into this trait automatically provides load_unchecked and store_unchecked
/// implementations via the template functions in buffer_protocol.hpp.
template <typename T>
struct is_serializable_wire_fixed_struct : std::false_type
{};

/// Concept for wire-format packed structs.
template <typename T>
concept SerializableWireFixedStruct = is_serializable_wire_fixed_struct<std::remove_cvref_t<T>>::value;

}  // namespace statusbar::traits
