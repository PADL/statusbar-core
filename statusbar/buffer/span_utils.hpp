#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Common span utility functions for byte-level operations.
// This header has no dependencies beyond the C++ standard library
// and is shared by the buffer, crypto, and other modules.

#include "statusbar/sg14/inplace_vector.h"
#include "statusbar/status/statusbar_assert.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory_resource>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace statusbar {

namespace traits {

/// Type trait to check if a type is any std::span (any element, any extent).
/// A span is trivially copyable, but its bytes are a pointer and a length,
/// not the elements it views — every byte-reinterpreting helper here and in
/// buffer_traits.hpp refuses it so the view is never serialized in place of
/// the viewed bytes.
template <typename T>
struct is_std_span : std::false_type
{};

/// Specialization for std::span.
template <typename U, std::size_t N>
struct is_std_span<std::span<U, N>> : std::true_type
{};

/// Concept for any std::span, whatever it views.
template <typename T>
concept StdSpan = is_std_span<std::remove_cvref_t<T>>::value;

}  // namespace traits

//
// Sub-range descriptor
//

/// Half-open byte sub-range used by the (container, range) overloads of
/// make_span / make_const_span. `length == std::dynamic_extent` (the default)
/// means "from `start` through the end of the container".
struct octet_range_t
{
    size_t start{0};
    size_t length{std::dynamic_extent};

    /// Apply this range to a byte span (any extent, either constness).
    ///
    /// Clamps gracefully so the result is never out-of-range (no UB), but
    /// asserts in debug builds if the caller asked for more than the source
    /// actually contains. `length == std::dynamic_extent` is interpreted as
    /// "from `start` to the end of `base`" and never trips the assert.
    ///
    /// Templated on Byte and Extent so that fixed-extent inputs (returned
    /// by make_span / make_const_span on std::array) match without an
    /// ambiguous implicit conversion to both std::span<uint8_t> and
    /// std::span<uint8_t const>. The result is always dynamic-extent because
    /// `start` and `length` are runtime values.
    template <typename Byte, size_t Extent>
        requires(std::is_same_v<std::remove_const_t<Byte>, uint8_t>)
    [[nodiscard]] auto apply(std::span<Byte, Extent> const base) const noexcept -> std::span<Byte>
    {
        auto const base_size = base.size();
        STATUSBAR_ASSERT(start <= base_size && "octet_range_t.start past end of buffer");
        auto const safe_start = std::min(start, base_size);
        auto const remaining = base_size - safe_start;
        STATUSBAR_ASSERT((length == std::dynamic_extent || length <= remaining) && "octet_range_t.length exceeds available bytes");
        auto const safe_length = (length == std::dynamic_extent) ? remaining : std::min(length, remaining);
        return base.subspan(safe_start, safe_length);
    }
};

//
// Type reinterpretation — whole-container make_*_span overloads
//

/// Reinterpret a trivially-copyable object as a read-only byte span.
/// std::span is refused: viewing a span's own bytes (pointer + length) is
/// never what a caller means — pass the span itself.
/// @tparam T The type to reinterpret (must be trivially copyable).
/// @param obj The object to view as bytes.
/// @return A fixed-extent span of sizeof(T) const bytes.
template <typename T>
    requires std::is_trivially_copyable_v<T> && (!traits::StdSpan<T>)
inline auto make_const_span(T const& obj) -> std::span<uint8_t const, sizeof(T)>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t const, sizeof(T)>(reinterpret_cast<uint8_t const*>(&obj), sizeof(T));
}

/// Reinterpret a trivially-copyable object as a mutable byte span.
/// std::span is refused for the same reason as make_const_span.
/// @tparam T The type to reinterpret (must be trivially copyable).
/// @param obj The object to view as bytes.
/// @return A fixed-extent span of sizeof(T) mutable bytes.
template <typename T>
    requires std::is_trivially_copyable_v<T> && (!traits::StdSpan<T>)
inline auto make_span(T& obj) -> std::span<uint8_t, sizeof(T)>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t, sizeof(T)>(reinterpret_cast<uint8_t*>(&obj), sizeof(T));
}

/// Overload for std::array<uint8_t, N> — direct const span without reinterpret_cast.
template <size_t N>
inline auto make_const_span(std::array<uint8_t, N> const& arr) -> std::span<uint8_t const, N>
{
    return std::span<uint8_t const, N>(arr);
}

/// Overload for std::array<uint8_t, N> — direct mutable span.
template <size_t N>
inline auto make_span(std::array<uint8_t, N>& arr) -> std::span<uint8_t, N>
{
    return std::span<uint8_t, N>(arr);
}

/// Overload for statusbar::sg14::inplace_vector<uint8_t, N> — dynamic-extent const span over current contents.
template <size_t N>
inline auto make_const_span(statusbar::sg14::inplace_vector<uint8_t, N> const& vec) -> std::span<uint8_t const>
{
    return std::span<uint8_t const>(vec.data(), vec.size());
}

/// Overload for statusbar::sg14::inplace_vector<uint8_t, N> — dynamic-extent mutable span over current contents.
template <size_t N>
inline auto make_span(statusbar::sg14::inplace_vector<uint8_t, N>& vec) -> std::span<uint8_t>
{
    return std::span<uint8_t>(vec.data(), vec.size());
}

/// Overload for std::vector<uint8_t> — dynamic-extent const span over current contents.
inline auto make_const_span(std::vector<uint8_t> const& vec) noexcept -> std::span<uint8_t const>
{
    return std::span<uint8_t const>(vec.data(), vec.size());
}

/// Overload for std::vector<uint8_t> — dynamic-extent mutable span over current contents.
inline auto make_span(std::vector<uint8_t>& vec) noexcept -> std::span<uint8_t>
{
    return std::span<uint8_t>(vec.data(), vec.size());
}

/// Overload for std::pmr::vector<uint8_t> — dynamic-extent const span over current contents.
inline auto make_const_span(std::pmr::vector<uint8_t> const& vec) noexcept -> std::span<uint8_t const>
{
    return std::span<uint8_t const>(vec.data(), vec.size());
}

/// Overload for std::pmr::vector<uint8_t> — dynamic-extent mutable span over current contents.
inline auto make_span(std::pmr::vector<uint8_t>& vec) noexcept -> std::span<uint8_t>
{
    return std::span<uint8_t>(vec.data(), vec.size());
}

/// Overload for std::string_view — dynamic-extent const byte span over the
/// string's chars. The returned span must not outlive the referenced string.
inline auto make_const_span(std::string_view sv) noexcept -> std::span<uint8_t const>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t const>(reinterpret_cast<uint8_t const*>(sv.data()), sv.size());
}

/// Inverse of make_const_span(std::string_view) — view a byte span as a
/// std::string_view by crossing the uint8_t / char pointer barrier. The
/// returned view must not outlive the referenced bytes. No validation
/// is performed on the contents.
inline auto as_string_view(std::span<uint8_t const> bytes) noexcept -> std::string_view
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

//
// Sub-range overloads (container, octet_range_t)
//
// Generic forwarders that pick up any container for which a whole-container
// make_span / make_const_span overload exists. Adding a new container type
// means adding one whole-container overload above; the sub-range form
// automatically follows via the `requires` clause.
//

/// Sub-range mutable view of any container with a make_span overload.
template <typename C>
    requires requires(C& c) { make_span(c); }
[[nodiscard]] inline auto make_span(C& c, octet_range_t const range) noexcept -> std::span<uint8_t>
{
    return range.apply(make_span(c));
}

/// Sub-range const view of any container with a make_const_span overload.
template <typename C>
    requires requires(C const& c) { make_const_span(c); }
[[nodiscard]] inline auto make_const_span(C const& c, octet_range_t const range) noexcept -> std::span<uint8_t const>
{
    return range.apply(make_const_span(c));
}

//
// Byte copying
//

/// Copy bytes from src span to dest span (dynamic extent).
/// Copies min(dest.size(), src.size()) bytes to prevent buffer overflow.
/// @param dest Destination span.
/// @param src Source span.
inline auto span_copy(std::span<uint8_t> const dest, std::span<uint8_t const> const src) noexcept -> void
{
    size_t const n = std::min(dest.size(), src.size());
    if (n > 0) {
        std::memcpy(dest.data(), src.data(), n);
    }
}

/// Copy N bytes between fixed-extent byte spans.
template <size_t N>
inline void span_copy(std::span<uint8_t, N> dest, std::span<uint8_t const, N> src)
{
    std::memcpy(dest.data(), src.data(), N);
}

/// Copy a dynamically-sized source span into a fixed-extent destination.
/// Asserts in debug that src is at least N bytes. In release, when src is
/// shorter than N, copies what is available and zero-fills the remainder so
/// the destination is fully defined and no out-of-bounds read of src occurs.
template <size_t N>
inline void span_copy(std::span<uint8_t, N> dest, std::span<uint8_t const> src)
{
    auto const src_size = src.size();
    STATUSBAR_ASSERT(src_size >= N && "span_copy: source span too small for fixed-extent destination");
    auto const n = std::min(src_size, N);
    std::memcpy(dest.data(), src.data(), n);
    if (n < N) {
        std::memset(dest.data() + n, 0, N - n);
    }
}

/// Copy from an inplace_vector into a dynamic-extent span (copies min of both sizes).
/// Needed because statusbar::sg14::inplace_vector does not implicitly convert to std::span.
template <size_t N>
inline void span_copy(std::span<uint8_t> dest, statusbar::sg14::inplace_vector<uint8_t, N> const& src)
{
    span_copy(dest, make_const_span(src));
}

/// Copy from a dynamic-extent span into an inplace_vector (copies vec.size() bytes).
/// Needed because statusbar::sg14::inplace_vector does not implicitly convert to std::span.
/// Asserts in debug that src is at least dest.size() bytes. In release, when src is
/// shorter, copies what is available and zero-fills the rest of the destination range
/// to avoid reading out-of-bounds.
template <size_t N>
inline void span_copy(statusbar::sg14::inplace_vector<uint8_t, N>& dest, std::span<uint8_t const> src)
{
    auto const src_size = src.size();
    auto const dest_size = dest.size();
    STATUSBAR_ASSERT(src_size >= dest_size && "span_copy: source span too small for inplace_vector destination");
    auto const n = std::min(src_size, dest_size);
    std::memcpy(dest.data(), src.data(), n);
    if (n < dest_size) {
        std::memset(dest.data() + n, 0, dest_size - n);
    }
}

//
// Size validation
//

/// Check if a dynamically-sized source span can be copied into a fixed-extent destination.
template <size_t N>
inline auto can_span_copy([[maybe_unused]] std::span<uint8_t, N> dest, std::span<uint8_t const> src) -> bool
{
    return src.size() == N;
}

/// Check if a dynamically-sized source span can be copied into a fixed-size array.
template <size_t N>
inline auto can_span_copy([[maybe_unused]] std::array<uint8_t, N>& dest, std::span<uint8_t const> src) -> bool
{
    return src.size() == N;
}

/// Check if a dynamically-sized source span can be copied into an inplace_vector.
template <size_t N>
inline auto can_span_copy(statusbar::sg14::inplace_vector<uint8_t, N> const& dest, std::span<uint8_t const> src) -> bool
{
    return src.size() == dest.size();
}

//
// Comparison
//

/// Compare two fixed-extent byte spans for equality.
///
/// **Not** constant-time — `memcmp` short-circuits on the first
/// differing byte, so do not use this to compare MACs, HMACs, tags,
/// session tokens, or any other secret. Use `span_compare_constant_time`
/// for those.
template <size_t N>
inline auto span_compare(std::span<uint8_t const, N> a, std::span<uint8_t const, N> b) -> bool
{
    return std::memcmp(a.data(), b.data(), N) == 0;
}

/// Compare two dynamic-extent byte spans for equality.
///
/// **Not** constant-time (see fixed-extent overload above). For secret
/// comparison call `span_compare_constant_time` instead — the
/// dynamic-extent overload of that returns false in `O(b.size())` when
/// the lengths mismatch, so an attacker still cannot probe the secret
/// byte-by-byte.
inline auto span_compare(std::span<uint8_t const> a, std::span<uint8_t const> b) -> bool
{
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}

/// Constant-time N-byte comparison.
/// ORs all byte differences together to prevent timing side-channels.
template <size_t N>
inline auto span_compare_constant_time(std::span<uint8_t const, N> a, std::span<uint8_t const, N> b) -> bool
{
    uint8_t diff = 0;
    for (size_t i = 0; i < N; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/// Constant-time comparison between a std::array and a fixed-extent span.
/// Needed because template argument deduction cannot bridge the
/// std::array → std::span conversion (it runs before implicit conversions).
template <size_t N>
inline auto span_compare_constant_time(std::array<uint8_t, N> const& a, std::span<uint8_t const, N> b) -> bool
{
    return span_compare_constant_time(make_const_span(a), b);
}

/// Constant-time comparison between two std::arrays. Forwards to the
/// fixed-extent span overload.
template <size_t N>
inline auto span_compare_constant_time(std::array<uint8_t, N> const& a, std::array<uint8_t, N> const& b) -> bool
{
    return span_compare_constant_time(make_const_span(a), make_const_span(b));
}

/// Constant-time comparison between two dynamic-extent byte spans.
///
/// Length mismatch returns false but still walks `b.size()` bytes of `a`
/// — saturated at `a.size()` — to avoid leaking which side is shorter
/// via wall time. The length-comparison branch itself is observable
/// (callers usually already know the expected length); for protocols
/// where the length is itself secret, hash first and compare the digests.
inline auto span_compare_constant_time(std::span<uint8_t const> a, std::span<uint8_t const> b) -> bool
{
    uint8_t diff = a.size() == b.size() ? 0 : 1;
    size_t const n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

//
// Load / Store trivially-copyable types
//

/// Load a trivially copyable type from a byte span.
/// @param dest Reference to destination object.
/// @param src Source span (must be at least sizeof(T) bytes).
///
/// Precondition is checked with `assert`: callers that take a frame from
/// the network must validate the size first (e.g. via `can_load`). The
/// assert turns the "footgun" into an immediate, debuggable abort under
/// a debug build instead of a silent read past the span.
///
/// std::span destinations are refused: loading INTO a span would overwrite
/// its pointer and length with wire bytes. Use span_copy to fill the bytes
/// a span views.
template <typename T>
    requires std::is_trivially_copyable_v<T> && (!traits::StdSpan<T>)
auto span_load(T& dest, std::span<uint8_t const> const src) noexcept -> void
{
    auto const src_size = src.size();
    STATUSBAR_ASSERT(src_size >= sizeof(T));
    std::memcpy(&dest, src.data(), sizeof(T));
}

/// Store a trivially copyable type to a byte span.
/// std::span sources are refused (that would store the view, not the viewed
/// bytes) — use span_copy.
/// @param dest Destination span (must be at least sizeof(T) bytes).
/// @param src Source object to copy from.
template <typename T>
    requires std::is_trivially_copyable_v<T> && (!traits::StdSpan<T>)
auto span_store(std::span<uint8_t> const dest, T const& src) noexcept -> void
{
    auto const dest_size = dest.size();
    STATUSBAR_ASSERT(dest_size >= sizeof(T));
    std::memcpy(dest.data(), &src, sizeof(T));
}

/// Store a trivially copyable type into the beginning of a byte array.
/// The `requires (N >= sizeof(T))` clause enforces the bounds check at
/// compile time; the body forwards to the dynamic-span overload.
template <size_t N, typename T>
    requires std::is_trivially_copyable_v<T> && (N >= sizeof(T))
auto span_store(std::array<uint8_t, N>& dest, T const& src) noexcept -> void
{
    span_store(make_span(dest), src);
}

/// Load a trivially copyable type from a byte array.
/// The `requires (N >= sizeof(T))` clause enforces the bounds check at
/// compile time; the body forwards to the dynamic-span overload.
template <size_t N, typename T>
    requires std::is_trivially_copyable_v<T> && (N >= sizeof(T))
auto span_load(T& dest, std::array<uint8_t, N> const& src) noexcept -> void
{
    span_load(dest, make_const_span(src));
}

//
// Fill / Zero
//

/// Fill a span with a byte value.
/// @param dest Destination span.
/// @param value Byte value to fill with.
inline auto span_fill(std::span<uint8_t> const dest, uint8_t const value) noexcept -> void
{
    std::memset(dest.data(), value, dest.size());
}

/// Fill an inplace_vector's current contents with a byte value.
/// Needed because statusbar::sg14::inplace_vector does not implicitly convert to std::span.
template <size_t N>
inline void span_fill(statusbar::sg14::inplace_vector<uint8_t, N>& vec, uint8_t value)
{
    span_fill(make_span(vec), value);
}

/// Fill a span with zeros.
/// @param dest Destination span.
inline auto span_zero(std::span<uint8_t> dest) noexcept -> void
{
    std::memset(dest.data(), 0, dest.size());
}

/// Zero an inplace_vector's current contents.
/// Needed because statusbar::sg14::inplace_vector does not implicitly convert to std::span.
template <size_t N>
inline void span_zero(statusbar::sg14::inplace_vector<uint8_t, N>& vec) noexcept
{
    span_zero(make_span(vec));
}

//
// Padded load — for forward/backward-compatible wire formats
//

/// Load a trivially-copyable T from `src`, zero-padding any tail bytes
/// the source doesn't provide.
///
/// Use this when a wire format may be SHORTER than the C++ struct because
/// a later revision of the protocol added fields at the end. Bytes 0..n-1
/// (where n = min(src.size(), sizeof(T))) come from the source; bytes
/// n..sizeof(T)-1 are zeroed. If src is longer than sizeof(T), the
/// trailing bytes are ignored.
template <typename T>
    requires std::is_trivially_copyable_v<T> && (!traits::StdSpan<T>)
auto span_load_padded(T& dest, std::span<uint8_t const> const src) noexcept -> void
{
    auto const dest_span = make_span(dest);
    auto const n = std::min(src.size(), sizeof(T));
    span_copy(dest_span.first(n), src.first(n));
    span_zero(dest_span.subspan(n));
}

//
// Wire-size-aware store / span — for types that carry their own
// on-wire length via a `wire_size()` member function.
//
// These are the correct primitives for emitting protocol structures whose
// C++ representation may be larger than the bytes that actually travel
// on the wire (for example, AEM descriptors with a fixed header plus a
// variable-length trailer). `span_store_wire` and `wire_span` both use
// `src.wire_size()` — the caller has already populated the descriptor,
// so its declared wire size is known and authoritative.
//
// For LOADING (incoming wire data into a C++ struct), use
// `span_load_padded` instead. The source buffer's `.size()` is the
// authoritative payload length on the way in — you can't call
// `dest.wire_size()` before loading because the fields that determine
// the size haven't been populated yet.
//
// The `HasWireSize` concept constrains these helpers to types that opt
// into the pattern. Plain POD structs still go through the existing
// `span_load` / `span_store` path, which operate on `sizeof(T)`.
//

/// A type with a `wire_size()` member returning its actual on-wire byte count.
/// The call may be `static constexpr` for fixed-layout descriptors or
/// instance-dependent for descriptors with variable trailers.
template <typename T>
concept HasWireSize = requires(T const& t) {
    { t.wire_size() } noexcept -> std::convertible_to<size_t>;
};

/// Store a trivially-copyable T into `dest`, writing exactly
/// `src.wire_size()` bytes. Bytes beyond `src.wire_size()` within T are
/// not written.
///
/// Preconditions:
///   - `dest.size() >= src.wire_size()`
///   - `src.wire_size() <= sizeof(T)`
///
/// Use this whenever a descriptor is serialized to the wire and the
/// destination buffer is sized for the maximum (e.g. MAX_AEM_DESCRIPTOR_SIZE).
template <typename T>
    requires std::is_trivially_copyable_v<T> && HasWireSize<T>
auto span_store_wire(std::span<uint8_t> const dest, T const& src) noexcept -> void
{
    size_t const wsize = src.wire_size();
    size_t const dsize = dest.size();
    STATUSBAR_ASSERT(wsize <= dsize && "span_store_wire: wire_size exceeds destination");
    STATUSBAR_ASSERT(wsize <= sizeof(T) && "span_store_wire: wire_size exceeds source object");
    std::memcpy(dest.data(), &src, wsize);
}

/// Return a read-only byte view over a descriptor's on-wire bytes —
/// the first `desc.wire_size()` bytes of the object. The returned span
/// aliases `desc` and must not outlive it.
///
/// Use this when passing a descriptor payload to a buffer-oriented API:
///   `span_copy(dest, wire_span(desc));`
/// is equivalent to `span_store_wire(dest, desc)` but composes with APIs
/// that take `std::span<uint8_t const>`. Builds on the existing
/// `make_const_span(T const&)` overload so the reinterpret_cast stays
/// contained to one place in this file.
template <typename T>
    requires std::is_trivially_copyable_v<T> && HasWireSize<T>
[[nodiscard]] inline auto wire_span(T const& desc) noexcept -> std::span<uint8_t const>
{
    return make_const_span(desc).first(desc.wire_size());
}

//
// Header + payload framing
//

/// Pack a typed header followed by a payload into a byte buffer.
///
/// Writes `header` (sizeof(Header) bytes) at offset 0 of `frame`, then copies
/// `payload` immediately after, at offset sizeof(Header). Returns a const view
/// over the populated bytes (`sizeof(Header) + payload.size()`). The returned
/// span aliases `frame`, so it must not outlive it.
///
/// Callers using protocol PDU types must ensure `sizeof(Header)` equals the
/// wire-format header length — typically enforced via static_assert at the
/// PDU type definition (e.g. `static_assert(sizeof(Am824Pdu) == 32)`).
template <typename Header>
    requires std::is_trivially_copyable_v<Header> && (!traits::StdSpan<Header>)
[[nodiscard]] inline auto span_pack_header_payload(
    std::span<uint8_t> frame, Header const& header, std::span<uint8_t const> payload) noexcept -> std::span<uint8_t const>
{
    // frame must hold the header + payload: otherwise subspan(sizeof(Header)) or
    // first(...) below is UB on an undersized frame in libc++.
    size_t const frame_size = frame.size();
    size_t const need = sizeof(Header) + payload.size();
    STATUSBAR_ASSERT(frame_size >= need && "span_pack_header_payload: frame too small");
    span_store(frame, header);
    span_copy(frame.subspan(sizeof(Header)), payload);
    return frame.first(sizeof(Header) + payload.size());
}

/// Overload for any byte container with a make_span overload (std::array,
/// std::vector, statusbar::sg14::inplace_vector, …) — no make_span needed at
/// the call site.
template <typename Header, typename C>
    requires std::is_trivially_copyable_v<Header> && (!traits::StdSpan<Header>) && (!traits::StdSpan<C>) &&
    requires(C& c) { make_span(c); }
[[nodiscard]] inline auto span_pack_header_payload(C& frame, Header const& header, std::span<uint8_t const> payload) noexcept
    -> std::span<uint8_t const>
{
    return span_pack_header_payload(make_span(frame), header, payload);
}

}  // namespace statusbar
