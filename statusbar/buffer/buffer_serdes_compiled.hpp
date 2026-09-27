#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

///
/// \file buffer_serdes_compiled.hpp
/// \brief Callback-based compiled serializer/deserializer.
///
/// The CompiledDeserializer uses a fold expression to short-circuit on
/// the first parse failure, avoiding rebuilding the parse chain per buffer.
/// Each field is parsed via a BufferDeserializer and its value passed to
/// a user-supplied callback.
///
/// \par Size Types
///
/// This file uses raw `size_t` for field sizes and offsets rather than the
/// `Position` and `Length` strong typedefs from `buffer_deserializer_builder.hpp`.
/// The strong types are designed for runtime seek/length operations in the
/// builder API. Here, all sizes are compile-time constants derived from
/// `sizeof(T)`, so the additional type safety of wrapper structs adds no
/// value and would complicate the template metaprogramming.
///

#include "statusbar/buffer/buffer_base.hpp"
#include "statusbar/buffer/buffer_deserializer_builder.hpp"
#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_mutable_buffer.hpp"
#include "statusbar/buffer/buffer_protocol.hpp"
#include "statusbar/buffer/buffer_traits.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace statusbar {

//
// Callback-based Compiled Deserializer
//

/// \note extract() is noexcept: the callback MUST NOT throw — a throwing
///       callback terminates the process. T must be default-initializable
///       (extract() value-initializes a T to parse into).
template <typename T, typename Fn>
    requires traits::WireValue<T> && std::default_initializable<T>
class FieldExtractor
{
  public:
    using value_type = T;

  private:
    Fn callback_;

  public:
    ///
    /// Construct a FieldExtractor with a callback function.
    ///
    /// \param fn The callback function to invoke with parsed values.
    ///
    constexpr explicit FieldExtractor(Fn fn) noexcept(std::is_nothrow_move_constructible_v<Fn>)
        : callback_(std::move(fn))
    {}

    ///
    /// Extract a value from the deserializer and invoke the callback.
    ///
    /// The callback runs as soon as this field parses; if a later field in
    /// the same CompiledDeserializer fails, callbacks for earlier fields
    /// have already run. Callers stage into locals and commit only on a
    /// successful overall Status.
    ///
    /// \param deserializer The buffer deserializer to read from.
    /// \return Status indicating success or parse error.
    ///
    [[nodiscard]] auto extract(BufferDeserializer& deserializer) const noexcept -> Status
    {
        T value{};
        auto const status = deserializer.parse(&value);
        if (status) {
            callback_(value);
        }
        return status;
    }
};

///
/// Skip extractor that consumes N bytes without storing the value.
/// Used to skip padding, reserved fields, or unwanted data.
///
/// \tparam N The number of bytes to skip.
///
template <size_t N>
class SkipExtractor
{
  public:
    ///
    /// Extract (skip) N bytes from the deserializer without processing.
    ///
    /// \param deserializer The buffer deserializer to read from.
    /// \return Status indicating success or parse error.
    ///
    [[nodiscard]] auto extract(BufferDeserializer& deserializer) const noexcept -> Status { return deserializer.consume(N); }
};

///
/// Compile-time deserializer structure that stores field extractors and can be reused across buffers.
/// Define the deserializer structure once at compile time, then apply it to multiple buffers.
/// This eliminates the need to rebuild the parsing chain for each buffer.
///
/// \tparam Fields The field extractor types.
///
/// Example:
/// \code
/// constexpr auto deserializer = make_deserializer(
///     field<uint8_t>([](uint8_t type) { /* handle type */ }),
///     field<uint16_t>([](uint16_t len) { /* handle length */ })
/// );
/// deserializer.parse(buffer1);  // Reuse for multiple buffers
/// deserializer.parse(buffer2);
/// \endcode
///
template <typename... Fields>
class CompiledDeserializer
{
    std::tuple<Fields...> fields_;

  public:
    ///
    /// Construct a CompiledDeserializer with field extractors.
    /// Extractors are taken BY VALUE and moved into the tuple: the compiled
    /// object always owns its extractors, never references a caller's.
    ///
    /// \param fields The field extractors to apply during parsing.
    ///
    constexpr explicit CompiledDeserializer(Fields... fields) noexcept((std::is_nothrow_move_constructible_v<Fields> && ...))
        : fields_(std::move(fields)...)
    {}

    ///
    /// Parse a buffer using the compiled deserializer structure.
    /// Applies all field extractors in sequence, stopping at the first error.
    ///
    /// \param buffer The buffer to parse.
    /// \return Status indicating success if all fields parsed successfully, or the first error.
    ///
    [[nodiscard]] auto parse(std::span<uint8_t const> const buffer) const noexcept -> Status
    {
        BufferDeserializer deserializer{buffer};
        return parse_impl(deserializer, std::index_sequence_for<Fields...>{});
    }

  private:
    ///
    /// Implementation helper that applies extractors using fold expression.
    ///
    template <size_t... Is>
    [[nodiscard]] auto parse_impl(BufferDeserializer& deserializer, std::index_sequence<Is...>) const noexcept -> Status
    {
        Status result = success();
        // && fold: apply each extractor in order, short-circuiting the
        // whole fold at the first field that fails.
        (void)((result && (result = std::get<Is>(fields_).extract(deserializer))) && ...);
        return result;
    }
};

///
/// Create a field extractor with a typed callback.
/// Helper function for defining deserializer fields with type deduction.
///
/// \tparam T The type of value to extract.
/// \tparam Fn The callback function type (deduced).
/// \param fn The callback function to invoke with parsed values.
/// \return A FieldExtractor that can be used with make_deserializer().
///
/// The callback MUST NOT throw: the extraction path is noexcept, so a
/// throwing callback terminates the process.
///
/// Example:
/// \code
/// auto f = field<uint32_t>([](uint32_t value) {
///     std::println("Parsed: {}", value);
/// });
/// \endcode
///
template <typename T, typename Fn>
[[nodiscard]] constexpr auto field(Fn&& fn) -> FieldExtractor<T, std::decay_t<Fn>>
{
    // decay_t: an lvalue callback is COPIED into the extractor. Deducing Fn
    // as an lvalue reference would make callback_ a reference member that
    // dangles once the caller's callback goes out of scope.
    return FieldExtractor<T, std::decay_t<Fn>>(std::forward<Fn>(fn));
}

///
/// Create a skip extractor that consumes N bytes without processing.
/// Useful for skipping padding, reserved fields, or unwanted data.
///
/// \tparam N The number of bytes to skip.
/// \return A SkipExtractor that consumes N bytes.
///
/// Example:
/// \code
/// auto const deserializer = make_deserializer(
///     field<uint8_t>([](uint8_t v) { /* header */ }),
///     skip<3>(),  // Skip 3 bytes of padding
///     field<uint32_t>([](uint32_t data) { /* payload */ })
/// );
/// \endcode
///
template <size_t N>
[[nodiscard]] constexpr auto skip() noexcept -> SkipExtractor<N>
{
    return SkipExtractor<N>{};
}

///
/// Create a compile-time deserializer from field extractors.
/// The resulting deserializer can be reused across multiple buffers.
///
/// \tparam Fields The field extractor types (deduced).
/// \param fields The field extractors to include in the deserializer.
/// \return A CompiledDeserializer that can parse buffers with the defined structure.
///
/// Example:
/// \code
/// constexpr auto packet_deserializer = make_deserializer(
///     field<uint8_t>([](uint8_t type) { /* handle */ }),
///     field<uint16_t>([](uint16_t len) { /* handle */ }),
///     field<uint32_t>([](uint32_t data) { /* handle */ })
/// );
///
/// // Reuse for multiple buffers
/// packet_deserializer.parse(buffer1);
/// packet_deserializer.parse(buffer2);
/// \endcode
///
template <typename... Fields>
[[nodiscard]] constexpr auto make_deserializer(Fields&&... fields) -> CompiledDeserializer<std::decay_t<Fields>...>
{
    // decay_t (make_tuple semantics, not forward_as_tuple): lvalue
    // extractors are copied. Deducing Fields as lvalue references would
    // store a tuple of references that dangles once the caller's
    // extractors go out of scope.
    return CompiledDeserializer<std::decay_t<Fields>...>(std::forward<Fields>(fields)...);
}

//
// CompiledSerializer - Build binary packets with compile-time structure
//

///
/// Field serializer with value supplier for compile-time serializer definitions.
/// Stores a function that provides the value to write to the buffer.
///
/// \tparam T The type of value to serialize (must be trivially copyable).
/// \tparam Fn The value supplier function type (typically a lambda returning T).
///
/// \note serialize() is noexcept: the supplier MUST NOT throw — a throwing
///       supplier terminates the process.
template <typename T, typename Fn>
    requires traits::WireValue<T>
class FieldSerializer
{
  public:
    using value_type = T;

  private:
    Fn supplier_;

  public:
    ///
    /// Construct a FieldSerializer with a value supplier.
    ///
    /// \param fn The function that provides the value to serialize.
    ///
    constexpr explicit FieldSerializer(Fn fn) noexcept(std::is_nothrow_move_constructible_v<Fn>)
        : supplier_(std::move(fn))
    {}

    ///
    /// Serialize a value to the buffer.
    ///
    /// \param buffer The mutable buffer to write to.
    /// \return Status indicating success or write error.
    ///
    [[nodiscard]] auto serialize(MutableBuffer& buffer) const noexcept -> Status
    {
        T const value = supplier_();

        size_t const required_size = protocol::serialized_size(value);

        // Get writable span
        auto const available_span = buffer.span_of_available_space(required_size);
        if (available_span.size() < required_size) {
            return failure(BufferError::insufficient_space);
        }

        // Call protocol function via ADL
        using protocol::store_unchecked;
        auto const bytes_written = store_unchecked(available_span, value);
        (void)buffer.advance_unchecked(bytes_written);

        return success();
    }
};

///
/// Skip serializer that writes N zero bytes.
/// Used for padding or reserved fields in packet structures.
///
/// \tparam N The number of zero bytes to write.
///
template <size_t N>
class SkipSerializer
{
  public:
    ///
    /// Serialize (write) N zero bytes to the buffer.
    ///
    /// \param buffer The mutable buffer to write to.
    /// \return Status indicating success or write error.
    ///
    [[nodiscard]] auto serialize(MutableBuffer& buffer) const noexcept -> Status
    {
        std::array<uint8_t, N> const zeros{};
        return buffer.append(make_const_span(zeros));
    }
};

///
/// Conditional field serializer that only writes if a runtime condition is met.
/// Used for optional fields like VLAN tags or protocol extensions.
///
/// \tparam T The type of value to serialize.
/// \tparam CondFn The condition function type (returns bool).
/// \tparam Fn The value supplier function type.
///
/// \note serialize() is noexcept: neither the condition nor the supplier
///       may throw — a throwing callback terminates the process.
template <typename T, typename CondFn, typename Fn>
    requires traits::WireValue<T>
class ConditionalFieldSerializer
{
  public:
    using value_type = T;

  private:
    CondFn condition_;
    FieldSerializer<T, Fn> field_;  ///< one store path — see serialize()

  public:
    ///
    /// Construct a ConditionalFieldSerializer with condition and value supplier.
    ///
    /// \param cond The condition function to evaluate (must return bool).
    /// \param fn The function that provides the value to serialize.
    ///
    constexpr explicit ConditionalFieldSerializer(CondFn cond, Fn fn) noexcept(
        std::is_nothrow_move_constructible_v<CondFn> && std::is_nothrow_move_constructible_v<Fn>)
        : condition_(std::move(cond))
        , field_(std::move(fn))
    {}

    ///
    /// Serialize a value if condition is true.
    /// If condition is false, no bytes are written.
    ///
    /// Delegates the store to FieldSerializer — one size/check/store/advance
    /// path instead of a duplicated block that could drift.
    ///
    /// \param buffer The mutable buffer to write to.
    /// \return Status indicating success or write error.
    ///
    [[nodiscard]] auto serialize(MutableBuffer& buffer) const noexcept -> Status
    {
        if (condition_()) {
            return field_.serialize(buffer);
        }
        // Condition false - don't write anything
        return success();
    }
};

///
/// Compile-time serializer structure for building binary packets.
/// Define the packet structure once at compile time, then serialize to multiple buffers.
///
/// \tparam Fields The field serializer types.
///
/// Example:
/// \code
/// uint8_t type = 0x01;
/// uint16_t length = 100;
/// uint32_t data = 0x12345678;
///
/// auto const packet_serializer = make_serializer(
///     serialize_field<uint8_t>([&type]() { return type; }),
///     serialize_field<uint16_t>([&length]() { return length; }),
///     serialize_field<uint32_t>([&data]() { return data; })
/// );
///
/// std::array<uint8_t, 256> buffer{};
/// MutableBuffer buf{buffer};
/// packet_serializer.serialize(buf);
/// \endcode
///
template <typename... Fields>
class CompiledSerializer
{
    std::tuple<Fields...> fields_;

  public:
    ///
    /// Construct a CompiledSerializer with field serializers.
    /// Serializers are taken BY VALUE and moved into the tuple: the compiled
    /// object always owns its serializers, never references a caller's.
    ///
    /// \param fields The field serializers to apply during serialization.
    ///
    constexpr explicit CompiledSerializer(Fields... fields) noexcept((std::is_nothrow_move_constructible_v<Fields> && ...))
        : fields_(std::move(fields)...)
    {}

    ///
    /// Serialize to a mutable buffer using the compiled structure.
    /// Applies all field serializers in sequence, stopping at the first error.
    ///
    /// \param buffer The mutable buffer to write to.
    /// \return Status indicating success if all fields serialized successfully, or the first error.
    ///
    [[nodiscard]] auto serialize(MutableBuffer& buffer) const noexcept -> Status
    {
        return serialize_impl(buffer, std::index_sequence_for<Fields...>{});
    }

  private:
    ///
    /// Implementation helper that applies serializers using fold expression.
    ///
    template <size_t... Is>
    [[nodiscard]] auto serialize_impl(MutableBuffer& buffer, std::index_sequence<Is...>) const noexcept -> Status
    {
        Status result = success();
        // && fold: apply each serializer in order, short-circuiting the
        // whole fold at the first field that fails.
        (void)((result && (result = std::get<Is>(fields_).serialize(buffer))) && ...);
        return result;
    }
};

///
/// Create a field serializer with a value supplier.
///
/// \tparam T The type of value to serialize.
/// \tparam Fn The value supplier function type (deduced).
/// \param fn The function that returns the value to serialize.
/// \return A FieldSerializer that can be used with make_serializer().
///
/// The supplier MUST NOT throw: the serialization path is noexcept, so a
/// throwing supplier terminates the process.
template <typename T, typename Fn>
[[nodiscard]] constexpr auto serialize_field(Fn&& fn) -> FieldSerializer<T, std::decay_t<Fn>>
{
    // decay_t: an lvalue supplier is COPIED into the serializer (see field()).
    return FieldSerializer<T, std::decay_t<Fn>>(std::forward<Fn>(fn));
}

///
/// Create a skip serializer that writes N zero bytes.
///
/// \tparam N The number of zero bytes to write.
/// \return A SkipSerializer.
///
template <size_t N>
[[nodiscard]] constexpr auto serialize_skip() noexcept -> SkipSerializer<N>
{
    return SkipSerializer<N>{};
}

///
/// Create a conditional field serializer.
///
/// \tparam T The type of value to serialize.
/// \tparam CondFn The condition function type (deduced).
/// \tparam Fn The value supplier function type (deduced).
/// \param cond The condition function that returns bool.
/// \param fn The function that returns the value to serialize.
/// \return A ConditionalFieldSerializer.
///
/// Neither callback may throw: the serialization path is noexcept, so a
/// throwing condition or supplier terminates the process.
template <typename T, typename CondFn, typename Fn>
[[nodiscard]] constexpr auto serialize_conditional_field(CondFn&& cond, Fn&& fn)
    -> ConditionalFieldSerializer<T, std::decay_t<CondFn>, std::decay_t<Fn>>
{
    // decay_t: lvalue callbacks are COPIED into the serializer (see field()).
    return ConditionalFieldSerializer<T, std::decay_t<CondFn>, std::decay_t<Fn>>(std::forward<CondFn>(cond), std::forward<Fn>(fn));
}

///
/// Create a compile-time serializer from field serializers.
///
/// \tparam Fields The field serializer types (deduced).
/// \param fields The field serializers to include.
/// \return A CompiledSerializer that can serialize to buffers with the defined structure.
///
template <typename... Fields>
[[nodiscard]] constexpr auto make_serializer(Fields&&... fields) -> CompiledSerializer<std::decay_t<Fields>...>
{
    // decay_t (make_tuple semantics): lvalue serializers are copied, never
    // stored as references — see make_deserializer().
    return CompiledSerializer<std::decay_t<Fields>...>(std::forward<Fields>(fields)...);
}

}  // namespace statusbar
