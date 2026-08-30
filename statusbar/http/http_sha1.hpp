#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Handshake-only SHA-1 + base64 (docs/HTTP_PLAN.md §6.1).
///
/// SHA-1 exists here for exactly one purpose: the RFC 6455 WebSocket
/// accept transform, base64(SHA1(key + GUID)) — a nonce transformation
/// with no security role. It must never grow into a general hashing
/// facility; real cryptography lives in the crypto repo, which core
/// deliberately does not depend on.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace statusbar::http {

/// RFC 3174 SHA-1 of @p input into @p digest.
void sha1(std::span<uint8_t const> input, std::span<uint8_t, 20> digest) noexcept;

/// Standard base64 (with padding). @p out needs 4 * ((n + 2) / 3) bytes;
/// returns the encoded length, 0 when @p out is too small.
auto base64_encode(std::span<uint8_t const> input, std::span<char> out) noexcept -> size_t;

/// The Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key:
/// base64(SHA1(key + RFC 6455 GUID)) — always 28 characters.
struct WsAcceptKey
{
    std::array<char, 28> chars;

    [[nodiscard]] auto view() const noexcept -> std::string_view { return {chars.data(), chars.size()}; }
};

[[nodiscard]] auto ws_accept_key(std::string_view client_key) noexcept -> WsAcceptKey;

}  // namespace statusbar::http
