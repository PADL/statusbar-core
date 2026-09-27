#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// iostream <-> byte-span interop helpers.
//
// std::ostream::write and std::istream::read take `char*` arguments, but
// byte-oriented code in this codebase works in typed containers (std::span,
// std::vector, std::array) of trivially-copyable element types. These
// wrappers encapsulate the unavoidable char <-> element-type pointer
// crossing so that call sites stay clean and the reinterpret_cast is
// confined to one place.

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <istream>
#include <ostream>
#include <span>
#include <type_traits>

namespace statusbar {

// Concept: any contiguous const range of trivially-copyable elements
// (matches std::span<T const>, std::vector<T> const&, std::array<T, N> const&,
// etc. where T is trivially copyable).
template <typename C>
concept TriviallyCopyableConstRange = requires(C const& c) {
    { c.data() } -> std::convertible_to<typename C::value_type const*>;
    { c.size() } -> std::convertible_to<std::size_t>;
    requires std::is_trivially_copyable_v<typename C::value_type>;
};

// Concept: any contiguous mutable range of trivially-copyable elements.
template <typename C>
concept TriviallyCopyableRange = requires(C& c) {
    { c.data() } -> std::convertible_to<typename C::value_type*>;
    { c.size() } -> std::convertible_to<std::size_t>;
    requires std::is_trivially_copyable_v<typename C::value_type>;
};

/// Write a range of trivially-copyable elements to an output stream.
/// Equivalent to
///   `os.write(reinterpret_cast<char const*>(c.data()), c.size() * sizeof(T))`
/// but hides the pointer-type crossing. The total byte count written is
/// `c.size() * sizeof(element_type)` (unchecked multiply — callers with
/// attacker-controlled sizes must bound them first).
///
/// \return true when the stream is still good after the write. Failures
///         land in the stream state as usual; the return is a convenience
///         so call sites can gate without a separate `os.good()`.
template <TriviallyCopyableConstRange C>
inline auto stream_write(std::ostream& os, C const& c) -> bool
{
    using T = typename C::value_type;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    os.write(reinterpret_cast<char const*>(c.data()), static_cast<std::streamsize>(c.size() * sizeof(T)));
    return bool(os);
}

/// Read a range of trivially-copyable elements from an input stream.
/// The range size is fixed at the call site (typically pre-sized before
/// the call). The total byte count read is `c.size() * sizeof(element_type)`.
///
/// \return true when the full range was read (stream still good). On a
///         short read the range is PARTIALLY overwritten and the stream
///         is failed — check this return (or the stream) before using
///         the contents.
template <TriviallyCopyableRange C>
inline auto stream_read(std::istream& is, C& c) -> bool
{
    using T = typename C::value_type;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    is.read(reinterpret_cast<char*>(c.data()), static_cast<std::streamsize>(c.size() * sizeof(T)));
    return bool(is);
}

}  // namespace statusbar
