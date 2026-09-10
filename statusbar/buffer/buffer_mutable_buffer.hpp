#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_traits.hpp"
#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/status/status.hpp"
#include "statusbar/status/throw_or_abort.hpp"

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

using traits::PlainCArray;
using traits::PlainElement;
using traits::PlainLinearCollection;
using traits::PlainStdArray;
using traits::PlainStdSpan;
using traits::PlainStdVector;
using traits::PlainType;

///
/// Mutable buffer wrapper providing read-write access to a contiguous sequence of bytes.
/// Extends Buffer with write operations, tracking both used and available space.
/// This is a generic buffer that makes NO assumptions about byte order.
/// All store/append operations are raw memory copies without byte-order conversion.
///
/// \par Const Semantics
/// This class uses "physical const" (bitwise const) rather than "logical const" semantics.
/// The store() methods are marked const because they don't modify the span object itself,
/// but they DO modify the memory the span points to. This design allows BufferSerializerBuilder to
/// expose a const MutableBuffer& that permits store() operations (writing at specific offsets)
/// while preventing append() operations (which would bypass the builder's size tracking).
///
class MutableBuffer
{
    std::span<uint8_t const> immutable_span_{};
    std::span<uint8_t> mutable_total_span_{};

  public:
    ///
    /// Construct a MutableBuffer with an empty data span.
    ///
    /// \param total_buffer_span The total buffer space available for writing.
    ///
    explicit MutableBuffer(std::span<uint8_t> const total_buffer_span) noexcept
        : immutable_span_(std::span<uint8_t const>(total_buffer_span.data(), 0))
        , mutable_total_span_{total_buffer_span}
    {}

    ///
    /// Construct a MutableBuffer from a std::array with an empty data span.
    ///
    /// \tparam LEN The size of the array.
    /// \param total_buffer_arr The array to use as buffer storage.
    ///
    template <size_t LEN>
    explicit MutableBuffer(std::array<uint8_t, LEN>& total_buffer_arr) noexcept
        : immutable_span_(std::span<uint8_t const>(total_buffer_arr.data(), 0))
        , mutable_total_span_{total_buffer_arr}
    {}

    ///
    /// Construct a MutableBuffer from a C-style array with an empty data span.
    /// Takes the array by reference so the size template parameter is deduced
    /// from and verified against the actual array — the previous signature
    /// `uint8_t arr[LEN]` decayed to `uint8_t*`, allowing the caller to pass
    /// any pointer and silently get a span claiming LEN bytes of storage.
    ///
    /// \tparam LEN The size of the array.
    /// \param total_buffer_arr The C-style array to use as buffer storage.
    ///
    template <size_t LEN>
    explicit MutableBuffer(uint8_t (&total_buffer_arr)[LEN]) noexcept
        : immutable_span_(std::span<uint8_t const>(&total_buffer_arr[0], 0))
        , mutable_total_span_{std::span<uint8_t, LEN>(&total_buffer_arr[0])}
    {}

    ///
    /// Construct a MutableBuffer with existing data.
    ///
    /// \param total_buffer_span The total buffer space available.
    /// \param data_size The size of existing data in the buffer.
    /// \throws std::system_error If data_size exceeds total_buffer_span size.
    ///
    MutableBuffer(std::span<uint8_t> const total_buffer_span, size_t const data_size)
        : immutable_span_(std::span<uint8_t const>(total_buffer_span.data(), data_size))
        , mutable_total_span_{total_buffer_span}
    {
        if (data_size > total_buffer_span.size()) {
            throw_or_abort(BufferError::invalid_offset);
        }
    }

    ///
    /// Get the underlying span.
    ///
    /// \return The span of bytes.
    ///
    [[nodiscard]] constexpr auto get_span() const noexcept -> std::span<uint8_t const> { return immutable_span_; }

    ///
    /// Set the used-bytes span of this buffer.
    ///
    /// The invariant every other member relies on is that the used span is a
    /// prefix of the total buffer: `available_space()` is
    /// `total.size() - used.size()` and would wrap for a longer span, and
    /// `span_of_available_space()` indexes the total buffer at
    /// `used.size()`. Asserted in debug builds. To discard the contents use
    /// rewind().
    ///
    /// \param new_span The new used span (must start at total_buffer_span().data()
    ///                 and be no longer than the total buffer).
    ///
    constexpr auto set_span(std::span<uint8_t const> const new_span) noexcept -> void
    {
        // Hoisted into locals: STATUSBAR_ASSERT may expand to [[assume]],
        // which ignores expressions with potential side effects.
        auto const* const new_data = new_span.data();
        auto const* const total_data = mutable_total_span_.data();
        auto const new_size = new_span.size();
        auto const total_size = mutable_total_span_.size();
        STATUSBAR_ASSERT(new_data == total_data && "set_span: span must start at the buffer start");
        STATUSBAR_ASSERT(new_size <= total_size && "set_span: span longer than the buffer");
        immutable_span_ = new_span;
    }

    ///
    /// Discard the contents: the used span becomes empty and the whole
    /// buffer is available again. The bytes themselves are not cleared.
    ///
    constexpr auto rewind() noexcept -> void { immutable_span_ = std::span<uint8_t const>(mutable_total_span_.data(), 0); }

    ///
    /// Get the size of the buffer in bytes.
    ///
    /// \return The number of bytes in the buffer.
    ///
    [[nodiscard]] constexpr auto size() const noexcept -> size_t { return immutable_span_.size(); }

    ///
    /// Get the total buffer span including both used and available space.
    ///
    /// \return The total mutable buffer span.
    ///
    [[nodiscard]] constexpr auto total_buffer_span() const noexcept -> std::span<uint8_t> { return mutable_total_span_; }

    ///
    /// Get the number of bytes available for writing.
    ///
    /// \return The number of available bytes.
    ///
    [[nodiscard]] constexpr auto available_space() const noexcept -> size_t
    {
        return mutable_total_span_.size() - immutable_span_.size();
    }

    ///
    /// Get a span of available space with the specified length.
    ///
    /// \param required_length The number of bytes needed.
    /// \return A span of the available space, or empty span if insufficient space.
    ///
    [[nodiscard]] constexpr auto span_of_available_space(size_t const required_length) const noexcept -> std::span<uint8_t>
    {
        if (required_length > available_space()) {
            return std::span<uint8_t>();
        }
        return mutable_total_span_.subspan(immutable_span_.size(), required_length);
    }

    ///
    /// Check if the buffer has enough space to append the specified length.
    ///
    /// \param required_length The number of bytes needed.
    /// \return Status indicating success if space available, or error.
    ///
    [[nodiscard]] auto can_append(size_t const required_length) const noexcept -> Status
    {
        auto const destination_span = span_of_available_space(required_length);
        if (destination_span.size() != required_length) {
            return failure(BufferError::insufficient_space);
        }
        return success();
    }

    ///
    /// Advance the buffer position by the specified count.
    /// This marks additional bytes as used without writing data.
    ///
    /// \param count The number of bytes to advance.
    /// \return The number of bytes advanced on success, or error if insufficient space.
    ///
    [[nodiscard]] auto advance(size_t const count) noexcept -> StatusValue<size_t>
    {
        if (!can_append(count)) {
            return failure(BufferError::insufficient_space);
        }
        auto const required_length = count;
        set_span(total_buffer_span().subspan(0, get_span().size() + required_length));
        return success(count);
    }

    ///
    /// Advance the buffer position by the specified count without bounds checking.
    /// The caller must ensure sufficient space is available.
    ///
    /// \param count The number of bytes to advance.
    /// \return The number of bytes advanced.
    ///
    [[nodiscard]] auto advance_unchecked(size_t const count) noexcept -> size_t
    {
        auto const space = available_space();
        STATUSBAR_ASSERT(count <= space && "advance_unchecked: insufficient space");
        auto const required_length = count;
        set_span(total_buffer_span().subspan(0, get_span().size() + required_length));
        return count;
    }

    ///
    /// Append raw bytes from a span to the buffer.
    ///
    /// \param src The span of bytes to append.
    /// \return Status indicating success or error.
    ///
    [[nodiscard]] auto append(std::span<uint8_t const> const src) noexcept -> Status
    {
        auto const required_length = src.size();
        if (!can_append(required_length)) {
            return failure(BufferError::insufficient_space);
        }
        auto const destination_span = span_of_available_space(required_length);
        span_copy(destination_span, src);
        set_span(total_buffer_span().subspan(0, get_span().size() + required_length));
        return success();
    }

    /// Append raw bytes without bounds checking.
    /// \precondition src.size() <= available_space()
    /// \param src The span of bytes to append.
    auto append_unchecked(std::span<uint8_t const> const src) noexcept -> void
    {
        auto const src_size = src.size();
        auto const space = available_space();
        STATUSBAR_ASSERT(src_size <= space && "append_unchecked: insufficient space");
        auto const required_length = src_size;
        auto const destination_span = span_of_available_space(required_length);
        span_copy(destination_span, src);
        set_span(total_buffer_span().subspan(0, get_span().size() + required_length));
    }

    ///
    /// Check if the buffer can store data at the specified offset and length.
    ///
    /// \param offset The byte offset to store at.
    /// \param required_length The number of bytes to store.
    /// \return Status indicating success if space available, or error.
    ///
    [[nodiscard]] auto can_store(size_t const offset, size_t const required_length) const noexcept -> Status
    {
        // Check for integer overflow before comparing
        if (required_length > get_span().size() || offset > get_span().size() - required_length) {
            return failure(BufferError::insufficient_space);
        }
        return success();
    }

    ///
    /// Store raw bytes from a span at the specified offset.
    ///
    /// \param offset The byte offset to store at.
    /// \param src The span of bytes to store.
    /// \return Status indicating success or error.
    ///
    [[nodiscard]] auto store(size_t const offset, std::span<uint8_t const> const src) const noexcept -> Status
    {
        auto const required_length = src.size();
        // Check for integer overflow before comparing
        if (required_length > get_span().size() || offset > get_span().size() - required_length) {
            return failure(BufferError::insufficient_space);
        }
        auto const destination_span = mutable_total_span_.subspan(offset, required_length);
        span_copy(destination_span, src);
        return success();
    }

    /// Store raw bytes at an offset without bounds checking.
    /// \precondition offset + src.size() <= get_span().size()
    /// \param offset The byte offset to store at.
    /// \param src The span of bytes to store.
    auto store_unchecked(size_t const offset, std::span<uint8_t const> const src) const noexcept -> void
    {
        auto const required_length = src.size();
        auto const span_size = get_span().size();
        STATUSBAR_ASSERT(
            required_length <= span_size && offset <= span_size - required_length &&
            "store_unchecked: offset + length exceeds buffer size");
        auto const destination_span = mutable_total_span_.subspan(offset, required_length);
        span_copy(destination_span, src);
    }
};

/// Private helper base that holds storage before MutableBuffer is initialized.
/// C++ initializes base classes in declaration order, so by inheriting from
/// this before MutableBuffer, the array exists before MutableBuffer's constructor
/// takes a span of it.
template <size_t N>
struct MutableBufferStorage
{
    std::array<std::uint8_t, N> storage_{};
};

///
/// Mutable buffer with built-in storage.
/// Template class that combines MutableBuffer functionality with an internal
/// fixed-size array storage.
///
/// \tparam N The size of the internal storage in bytes.
///
template <size_t N>
class MutableBufferWithStorage
    : private MutableBufferStorage<N>
    , public MutableBuffer
{
  public:
    ///
    /// Construct a MutableBufferWithStorage with internal storage.
    /// The buffer is initialized empty with N bytes of available space.
    ///
    MutableBufferWithStorage() noexcept
        : MutableBufferStorage<N>()
        , MutableBuffer(this->storage_)
    {}
};

}  // namespace statusbar
