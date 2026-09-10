#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer_base.hpp"
#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_protocol.hpp"
#include "statusbar/buffer/buffer_traits.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace statusbar {

/// Strong typedef for buffer positions (byte offset from start)
/// Provides compile-time safety to prevent accidentally swapping position and length arguments
struct Position
{
    size_t value;
    constexpr explicit Position(size_t v) noexcept
        : value{v}
    {}
};

/// Strong typedef for required lengths (byte count needed)
/// Provides compile-time safety to prevent accidentally swapping position and length arguments
struct Length
{
    size_t value;
    constexpr explicit Length(size_t v) noexcept
        : value{v}
    {}
};

///
/// Sequential buffer deserializer with position tracking.
/// Provides methods for parsing trivially copyable types and SerializableStruct types
/// from a buffer while tracking the current read position.
/// This class is non-copyable and non-movable.
///
class BufferDeserializer
{
    std::span<uint8_t const> buffer_;       // Reference to the buffer being parsed
    std::span<uint8_t const> next_span_{};  // Remaining unparsed bytes (cursor position)

  public:
    ///
    /// Construct a BufferDeserializer for the given buffer.
    /// The deserializer is initialized to the start of the buffer.
    ///
    /// \param buffer The buffer to parse.
    ///
    /// \note The referenced buffer must remain valid for the entire lifetime of this
    ///       deserializer. Do not use temporary Buffer objects or Buffers that may be
    ///       destroyed while the deserializer exists.
    ///
    explicit BufferDeserializer(std::span<uint8_t const> const& buffer) noexcept
        : buffer_{buffer}
        , next_span_{buffer_}
    {}

    // Non-copyable, non-movable
    BufferDeserializer(BufferDeserializer const&) = delete;
    BufferDeserializer(BufferDeserializer&&) = delete;
    auto operator=(BufferDeserializer const&) -> BufferDeserializer& = delete;
    auto operator=(BufferDeserializer&&) -> BufferDeserializer& = delete;
    ~BufferDeserializer() = default;

    ///
    /// Reset the deserializer position.
    ///
    /// \param position The byte offset to reset to (default: 0 for start of buffer).
    /// \return true if reset to a valid position, false if position was out of bounds
    ///         (deserializer is set to EOF in that case).
    ///
    /// `position == size()` is out of bounds (nothing left to parse) for a
    /// non-empty buffer. An empty buffer is the one exception: position 0 is
    /// its only valid position, so reset(0) on it succeeds (at EOF) while any
    /// other position fails.
    ///
    [[nodiscard]] auto reset(size_t const position = 0) noexcept -> bool
    {
        if (position >= buffer_.size() && !buffer_.empty()) {
            next_span_ = {};
            return false;
        }
        if (buffer_.empty()) {
            next_span_ = {};
            return position == 0;
        }
        next_span_ = buffer_.subspan(position);
        return true;
    }

    ///
    /// Check if the deserializer has at least the required number of bytes available.
    ///
    /// \param required_length The number of bytes needed.
    /// \return true if at least required_length bytes are available.
    ///
    [[nodiscard]] auto can_peek(size_t const required_length) const noexcept -> bool
    {
        return next_span_.size() >= required_length;
    }

    ///
    /// Get the number of bytes remaining in the buffer from the current position.
    ///
    /// \return The number of bytes available.
    ///
    [[nodiscard]] auto available() const noexcept -> size_t { return next_span_.size(); }

    ///
    /// Get the current deserializer position in the buffer.
    ///
    /// \return The byte offset from the start of the buffer.
    ///
    [[nodiscard]] auto position() const noexcept -> size_t
    {
        // Calculate current position as: total_size - remaining_size
        return buffer_.size() - next_span_.size();
    }

    ///
    /// Peek at the next bytes without consuming them.
    ///
    /// \param required_length The number of bytes to peek.
    /// \return A span of the requested bytes, or empty span if insufficient data.
    ///
    [[nodiscard]] auto peek(size_t const required_length) const noexcept -> std::span<uint8_t const>
    {
        if (next_span_.size() < required_length) {
            return {};
        }
        return next_span_.subspan(0, required_length);
    }

    ///
    /// Consume (skip) the specified number of bytes, advancing the deserializer position.
    ///
    /// \param required_length The number of bytes to consume.
    /// \return Status indicating success or insufficient data error.
    ///
    [[nodiscard]] auto consume(size_t const required_length) noexcept -> Status
    {
        if (next_span_.size() < required_length) {
            return failure(BufferError::insufficient_data);
        }
        next_span_ = next_span_.subspan(required_length);
        return success();
    }

    ///
    /// Parse a trivially copyable type from the current position and advance.
    /// Performs raw memory copy WITHOUT byte-order conversion.
    ///
    /// \tparam T The type to parse (must be trivially copyable but NOT a SerializableStruct).
    /// \param result Pointer to store the parsed value.
    /// \return Status indicating success or insufficient data error.
    ///
    template <typename T>
        requires std::is_trivially_copyable_v<T> && (!traits::SerializableStruct<T>) && (!traits::StdSpan<T>)
    [[nodiscard]] auto parse(T* const result) noexcept -> Status
    {
        if (next_span_.size() < sizeof(T)) {
            return failure(BufferError::insufficient_data);
        }
        parse_unchecked(result);
        return success();
    }

    ///
    /// Check if a trivially copyable type can be parsed.
    ///
    /// \tparam T The type to check (must be trivially copyable but NOT a SerializableStruct).
    /// \param value Pointer to a value (used for type deduction, not modified).
    /// \return Status indicating if parsing would succeed.
    ///
    template <typename T>
        requires std::is_trivially_copyable_v<T> && (!traits::SerializableStruct<T>) && (!traits::StdSpan<T>)
    [[nodiscard]] auto can_parse([[maybe_unused]] T const* const value) const noexcept -> Status
    {
        if (next_span_.size() < sizeof(T)) {
            return failure(BufferError::insufficient_data);
        }
        return success();
    }

    ///
    /// Parse a trivially copyable type without validation (unchecked).
    ///
    /// WARNING: Caller must ensure sufficient data is available before calling.
    ///
    /// \tparam T The type to parse (must be trivially copyable but NOT a SerializableStruct).
    /// \param result Pointer to store the parsed value.
    ///
    template <typename T>
        requires std::is_trivially_copyable_v<T> && (!traits::SerializableStruct<T>) && (!traits::StdSpan<T>)
    auto parse_unchecked(T* const result) noexcept -> void
    {
        auto const required_length = sizeof(T);
        auto const next_size = next_span_.size();
        STATUSBAR_ASSERT(next_size >= required_length && "parse_unchecked: insufficient data");
        span_load(*result, next_span_);
        next_span_ = next_span_.subspan(required_length);
    }

    ///
    /// Parse a SerializableStruct type from the current position and advance.
    /// Uses protocol free functions via ADL for deserialization.
    ///
    /// \tparam T The type to parse (must satisfy SerializableStruct concept).
    /// \param result Pointer to store the parsed value.
    /// \return Status indicating success or insufficient data error.
    ///
    template <typename T>
        requires traits::SerializableStruct<T>
    [[nodiscard]] auto parse(T* const result) noexcept -> Status
    {
        using protocol::can_load;

        // Check if we have enough data using protocol function
        auto const validation = can_load(next_span_, result);
        if (!validation) {
            return failure(validation.error());
        }

        // Parse using protocol function and advance position
        using protocol::load_unchecked;
        auto const bytes_read = load_unchecked(next_span_, result);
        next_span_ = next_span_.subspan(bytes_read);

        return success();
    }

    ///
    /// Check if a SerializableStruct type can be parsed.
    /// Uses protocol free functions via ADL for validation.
    ///
    /// \tparam T The type to check (must satisfy SerializableStruct concept).
    /// \param value Pointer to a value (used for type deduction, not modified).
    /// \return Status indicating if parsing would succeed.
    ///
    template <typename T>
        requires traits::SerializableStruct<T>
    [[nodiscard]] auto can_parse(T const* const value) const noexcept -> Status
    {
        using protocol::can_load;
        auto const validation = can_load(next_span_, value);
        if (!validation) {
            return failure(validation.error());
        }
        return success();
    }

    ///
    /// Parse a SerializableStruct type without validation (unchecked).
    /// Uses protocol free functions via ADL for deserialization.
    ///
    /// WARNING: Caller must ensure sufficient data is available before calling.
    ///
    /// \tparam T The type to parse (must satisfy SerializableStruct concept).
    /// \param result Pointer to store the parsed value.
    ///
    template <typename T>
        requires traits::SerializableStruct<T>
    auto parse_unchecked(T* const result) noexcept -> void
    {
        // Note: load_unchecked has its own assertion for buffer size
        using protocol::load_unchecked;
        auto const bytes_read = load_unchecked(next_span_, result);
        next_span_ = next_span_.subspan(bytes_read);
    }
};

///
/// Builder pattern wrapper for BufferDeserializer with fluent interface.
/// Allows chaining multiple parse and skip operations while capturing the first error.
/// Operations after an error are automatically skipped.
/// This class is non-copyable and non-movable.
///
class BufferDeserializerBuilder
{
    BufferDeserializer deserializer_;  // The underlying deserializer doing the actual work
    std::error_code error_{};          // First error encountered (sticky error state)

  public:
    ///
    /// Construct a BufferDeserializerBuilder wrapping a Buffer.
    /// The deserializer is initialized to the start of the buffer.
    ///
    /// \param buffer The buffer to parse.
    ///
    constexpr explicit BufferDeserializerBuilder(std::span<uint8_t const> buffer) noexcept
        : deserializer_(buffer)
    {}

    // Non-copyable, non-movable
    BufferDeserializerBuilder(BufferDeserializerBuilder const&) = delete;
    BufferDeserializerBuilder(BufferDeserializerBuilder&&) = delete;
    auto operator=(BufferDeserializerBuilder const&) -> BufferDeserializerBuilder& = delete;
    auto operator=(BufferDeserializerBuilder&&) -> BufferDeserializerBuilder& = delete;
    ~BufferDeserializerBuilder() = default;

    ///
    /// Reset the deserializer to the start of the buffer and clear any error state.
    /// This allows the builder to be reused for parsing from the beginning.
    ///
    void reset() noexcept
    {
        (void)deserializer_.reset();
        error_ = {};
    }

    ///
    /// Get the error state of the builder.
    ///
    /// \return The first error that occurred, or empty error_code if all operations succeeded.
    ///
    [[nodiscard]] auto error() const noexcept -> std::error_code const& { return error_; }

    ///
    /// Get the status of the builder operations.
    ///
    /// \return Status indicating success if no errors occurred, or the first error.
    ///
    [[nodiscard]] auto status() const noexcept -> Status { return error_ ? failure(error_) : success(); }

    ///
    /// Check if all operations succeeded.
    ///
    /// \return true if no errors occurred.
    ///
    [[nodiscard]] explicit operator bool() const noexcept { return !error_; }

    ///
    /// Skip (consume) the specified number of bytes if no previous error occurred.
    ///
    /// \param required_length The number of bytes to skip.
    /// \return Reference to this builder for chaining.
    ///
    auto skip(size_t const required_length) noexcept -> BufferDeserializerBuilder&
    {
        // Only attempt to skip if no previous error occurred
        if (!error_) {
            auto const status = deserializer_.consume(required_length);
            if (!status) {
                error_ = status.error();
            }
        }
        return *this;
    }

    ///
    /// Seek to a specific position, with a minimum required length of data at that position.
    ///
    /// \param position - The octet position from the beginning of the buffer.
    /// \param required_length - The required number of bytes needed from that position.
    /// \returns Reference to this builder for chaining.
    ///
    auto seek(Position const position, Length const required_length) noexcept -> BufferDeserializerBuilder&
    {
        if (!error_) {
            if (!deserializer_.reset(position.value) || !deserializer_.can_peek(required_length.value)) {
                error_ = BufferError::insufficient_data;
            }
        }
        return *this;
    }

    ///
    /// Parse a trivially copyable type if no previous error occurred.
    /// Uses direct memcpy without protocol functions.
    ///
    /// \tparam T The type to parse (must be trivially copyable but NOT a SerializableStruct).
    /// \param result Pointer to store the parsed value.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires std::is_trivially_copyable_v<T> && (!traits::SerializableStruct<T>) && (!traits::StdSpan<T>)
    auto parse(T* const result) noexcept -> BufferDeserializerBuilder&
    {
        if (!error_) {
            auto const status = deserializer_.parse(result);
            if (!status) {
                error_ = status.error();
            }
        }
        return *this;
    }

    ///
    /// Parse a SerializableStruct type if no previous error occurred.
    /// Uses protocol free functions via ADL for deserialization.
    /// Works with both fixed-size and variable-size types.
    ///
    /// \tparam T The type to parse (must satisfy SerializableStruct concept).
    /// \param result Pointer to store the parsed value.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires traits::SerializableStruct<T>
    auto parse(T* const result) noexcept -> BufferDeserializerBuilder&
    {
        if (!error_) {
            auto const status = deserializer_.parse(result);
            if (!status) {
                error_ = status.error();
            }
        }
        return *this;
    }

    ///
    /// Check if a type can be parsed without modifying state or error status.
    ///
    /// This delegates to BufferDeserializer::can_parse() which handles both trait-based
    /// and trivially copyable types.
    ///
    /// \tparam T The type to check.
    /// \param value Pointer to a value (used for type deduction, not modified).
    /// \return Status indicating if parsing would succeed.
    ///
    template <typename T>
    [[nodiscard]] auto can_parse(T const* const value) const noexcept -> Status
    {
        return deserializer_.can_parse(value);
    }

    ///
    /// Parse a trivially copyable type without validation (unchecked).
    /// Uses direct memcpy without protocol functions.
    ///
    /// WARNING: Caller must ensure sufficient data is available before calling.
    ///
    /// \tparam T The type to parse (must be trivially copyable but NOT a SerializableStruct).
    /// \param result Pointer to store the parsed value.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires std::is_trivially_copyable_v<T> && (!traits::SerializableStruct<T>) && (!traits::StdSpan<T>)
    auto parse_unchecked(T* const result) noexcept -> BufferDeserializerBuilder&
    {
        if (!error_) {
            deserializer_.parse_unchecked(result);
        }
        return *this;
    }

    ///
    /// Parse a SerializableStruct type without validation (unchecked).
    /// Uses protocol free functions via ADL for deserialization.
    /// Works with both fixed-size and variable-size types.
    ///
    /// WARNING: Caller must ensure sufficient data is available before calling.
    ///
    /// \tparam T The type to parse (must satisfy SerializableStruct concept).
    /// \param result Pointer to store the parsed value.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires traits::SerializableStruct<T>
    auto parse_unchecked(T* const result) noexcept -> BufferDeserializerBuilder&
    {
        if (!error_) {
            deserializer_.parse_unchecked(result);
        }
        return *this;
    }

    ///
    /// Get the current parse position in the buffer.
    ///
    /// \return The byte offset from the start of the buffer.
    ///
    [[nodiscard]] auto position() const noexcept -> size_t { return deserializer_.position(); }
};

}  // namespace statusbar
