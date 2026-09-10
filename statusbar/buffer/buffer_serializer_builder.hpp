#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_mutable_buffer.hpp"
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

///
/// Builder pattern wrapper for MutableBuffer with fluent interface.
/// Allows chaining multiple append operations and captures the first error.
/// Subsequent operations after an error are skipped.
/// This class is non-copyable and non-movable.
///
class BufferSerializerBuilder
{
    MutableBuffer& destination_buffer_;
    std::error_code error_{};

  public:
    ///
    /// Construct a BufferSerializerBuilder wrapping a MutableBuffer.
    ///
    /// \param destination_buffer The buffer to append to.
    ///
    constexpr explicit BufferSerializerBuilder(MutableBuffer& destination_buffer) noexcept
        : destination_buffer_{destination_buffer}
    {}

    // Non-copyable, non-movable
    BufferSerializerBuilder(BufferSerializerBuilder const&) = delete;
    BufferSerializerBuilder(BufferSerializerBuilder&&) = delete;
    auto operator=(BufferSerializerBuilder const&) -> BufferSerializerBuilder& = delete;
    auto operator=(BufferSerializerBuilder&&) -> BufferSerializerBuilder& = delete;
    ~BufferSerializerBuilder() = default;

    ///
    /// Append a value to the buffer using protocol-aware serialization.
    /// If T is a SerializableStruct, uses wire_size() to determine size.
    /// Otherwise uses sizeof(T) for trivially copyable types.
    ///
    /// std::span is not a WireValue: appending one would store the view
    /// (pointer + length), not the bytes it views. Byte spans go through the
    /// non-template `append(std::span<uint8_t const>)` overload below.
    ///
    /// \tparam T The type to append (must be trivially copyable or SerializableStruct).
    /// \param value The value to append.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires traits::WireValue<T>
    auto append(T const& value) noexcept -> BufferSerializerBuilder&
    {
        if (!error_) {
            auto const required_size = protocol::serialized_size(value);

            // Get writable span and call protocol function
            auto const available_span = destination_buffer_.span_of_available_space(required_size);
            if (available_span.size() < required_size) {
                error_ = BufferError::insufficient_space;
            } else {
                using protocol::store_unchecked;
                auto const bytes_written = store_unchecked(available_span, value);
                (void)destination_buffer_.advance_unchecked(bytes_written);
            }
        }
        return *this;
    }

    ///
    /// Append the bytes a span views. Records insufficient_space if the
    /// buffer cannot hold all of them (nothing is written in that case).
    ///
    /// \param bytes The bytes to append.
    /// \return Reference to this builder for chaining.
    ///
    auto append(std::span<uint8_t const> const bytes) noexcept -> BufferSerializerBuilder&
    {
        if (!error_) {
            if (!destination_buffer_.append(bytes)) {
                error_ = BufferError::insufficient_space;
            }
        }
        return *this;
    }

    ///
    /// Append a value without bounds checking (unchecked).
    /// WARNING: Caller must ensure sufficient space is available.
    ///
    /// \tparam T The type to append (must be trivially copyable or SerializableStruct).
    /// \param value The value to append.
    /// \return Reference to this builder for chaining.
    ///
    template <typename T>
        requires traits::WireValue<T>
    auto append_unchecked(T const& value) noexcept -> BufferSerializerBuilder&
    {
        if (!error_) {
            auto const required_size = protocol::serialized_size(value);

            // Caller's contract per the doc comment is to ensure there is room.
            // span_of_available_space() returns an empty span when too small, so
            // we cannot use it here without re-introducing a buffer overflow when
            // the caller violates the precondition. Take the subspan directly
            // and assert.
            auto const space = destination_buffer_.available_space();
            STATUSBAR_ASSERT(required_size <= space && "append_unchecked: insufficient space");
            auto const available_span = destination_buffer_.total_buffer_span().subspan(destination_buffer_.size(), required_size);
            using protocol::store_unchecked;
            auto const bytes_written = store_unchecked(available_span, value);
            (void)destination_buffer_.advance_unchecked(bytes_written);
        }
        return *this;
    }

    ///
    /// Append the bytes a span views without bounds checking.
    /// WARNING: Caller must ensure sufficient space is available.
    ///
    /// \param bytes The bytes to append.
    /// \return Reference to this builder for chaining.
    ///
    auto append_unchecked(std::span<uint8_t const> const bytes) noexcept -> BufferSerializerBuilder&
    {
        if (!error_) {
            destination_buffer_.append_unchecked(bytes);
        }
        return *this;
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
    /// Get the underlying buffer as a span.
    ///
    /// \return The buffer contents as an immutable view.
    ///
    [[nodiscard]] auto get_span() const noexcept -> std::span<uint8_t const> { return destination_buffer_.get_span(); }

    ///
    /// Get a const reference to the underlying MutableBuffer.
    ///
    /// \return Const reference to the wrapped buffer.
    ///
    /// \note Returns a const reference to allow store() operations (writing at specific
    ///       offsets) while preventing append() operations that would bypass the builder's
    ///       error tracking and size management. See MutableBuffer class documentation
    ///       for details on const semantics.
    ///
    [[nodiscard]] auto buffer() const noexcept -> MutableBuffer const& { return destination_buffer_; }

    ///
    /// Get the current write position in the buffer.
    ///
    /// \return The number of bytes written so far.
    ///
    [[nodiscard]] auto position() const noexcept -> size_t { return destination_buffer_.size(); }
};

///
/// Helper base class that holds the MutableBufferWithStorage.
/// This must be inherited BEFORE BufferSerializerBuilder so it's initialized first.
///
template <size_t N>
class BufferSerializerBuilderWithStorageBase
{
  protected:
    MutableBufferWithStorage<N> mutable_buffer_with_storage_{};

    BufferSerializerBuilderWithStorageBase() noexcept = default;
};

///
/// BufferSerializerBuilder with built-in storage.
/// Combines the builder pattern with internal fixed-size array storage.
/// Uses the same "base class initialization helper" pattern as
/// BufferSerializerBuilderWithBuffer so the MutableBuffer the base builder
/// references is fully constructed before the reference is taken.
///
/// \tparam N The size of the internal storage in bytes.
///
template <size_t N>
class BufferSerializerBuilderWithStorage
    : private BufferSerializerBuilderWithStorageBase<N>
    , public BufferSerializerBuilder
{
    using BufferSerializerBuilderWithStorageBase<N>::mutable_buffer_with_storage_;

  public:
    ///
    /// Construct a BufferSerializerBuilderWithStorage with internal storage.
    /// The builder is initialized with N bytes of available space.
    ///
    BufferSerializerBuilderWithStorage() noexcept
        : BufferSerializerBuilderWithStorageBase<N>()            // Initialize helper base first
        , BufferSerializerBuilder(mutable_buffer_with_storage_)  // Pass already-initialized member
    {}

    // Bring base class get_span into overload set (avoids shadowing warning)
    using BufferSerializerBuilder::get_span;

    ///
    /// Get the underlying MutableBuffer.
    ///
    /// \return Reference to the internal mutable buffer.
    ///
    [[nodiscard]] auto get_mutable_buffer() noexcept -> MutableBuffer& { return mutable_buffer_with_storage_; }

    ///
    /// Get the buffer contents as a span.
    ///
    /// \return The buffer contents as an immutable view.
    ///
    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    [[nodiscard]] auto get_span() const noexcept -> std::span<uint8_t const> { return mutable_buffer_with_storage_.get_span(); }
};

///
/// Helper base class that holds the MutableBuffer.
/// This must be inherited BEFORE BufferSerializerBuilder so it's initialized first.
///
class BufferSerializerBuilderWithBufferBase
{
  protected:
    MutableBuffer mutable_buffer_;

    explicit BufferSerializerBuilderWithBufferBase(std::span<uint8_t> const buf) noexcept
        : mutable_buffer_(buf)
    {}
};

///
/// BufferSerializerBuilder that wraps an external buffer provided at construction.
/// Uses the "base class initialization helper" pattern to ensure correct initialization order.
///
/// Initialization order:
/// 1. BufferSerializerBuilderWithBufferBase constructs mutable_buffer_ with the span
/// 2. BufferSerializerBuilder constructs with reference to mutable_buffer_
/// 3. BufferSerializerBuilderWithBuffer constructor body runs (empty)
///
class BufferSerializerBuilderWithBuffer
    : private BufferSerializerBuilderWithBufferBase
    , public BufferSerializerBuilder
{
  public:
    ///
    /// Construct a BufferSerializerBuilderWithBuffer wrapping an external buffer.
    ///
    /// \param buf The external buffer span to use for storage.
    ///
    explicit BufferSerializerBuilderWithBuffer(std::span<uint8_t> const buf) noexcept
        : BufferSerializerBuilderWithBufferBase(buf)  // Initialize helper base first
        , BufferSerializerBuilder(mutable_buffer_)    // Pass already-initialized member to BufferSerializerBuilder
    {}

    // Bring base class get_span into overload set (avoids shadowing warning)
    using BufferSerializerBuilder::get_span;

    ///
    /// Get the underlying MutableBuffer.
    ///
    /// \return Reference to the internal mutable buffer.
    ///
    [[nodiscard]] auto get_mutable_buffer() noexcept -> MutableBuffer& { return mutable_buffer_; }

    ///
    /// Get the buffer contents as a span.
    ///
    /// \return The buffer contents as an immutable view.
    ///
    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    [[nodiscard]] auto get_span() const noexcept -> std::span<uint8_t const> { return mutable_buffer_.get_span(); }
};

}  // namespace statusbar
