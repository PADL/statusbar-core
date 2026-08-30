// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_sha1.hpp"

#include <bit>
#include <cstring>

namespace statusbar::http {

namespace {

constexpr std::string_view WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void sha1_block(uint32_t state[5], uint8_t const block[64]) noexcept
{
    uint32_t w[80];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[(i * 4) + 1]) << 16) | (uint32_t(block[(i * 4) + 2]) << 8) |
            uint32_t(block[(i * 4) + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f = 0;
        uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t const temp = std::rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = std::rotl(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

}  // namespace

void sha1(std::span<uint8_t const> input, std::span<uint8_t, 20> digest) noexcept
{
    uint32_t state[5] = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U};

    size_t at = 0;
    for (; at + 64 <= input.size(); at += 64) {
        sha1_block(state, input.data() + at);
    }

    // Final block(s): remainder + 0x80 pad + zero fill + 64-bit bit length.
    uint8_t tail[128] = {};
    size_t const remainder = input.size() - at;
    std::memcpy(tail, input.data() + at, remainder);
    tail[remainder] = 0x80;
    size_t const tail_len = remainder + 1 + 8 <= 64 ? 64 : 128;
    uint64_t const bits = uint64_t(input.size()) * 8;
    for (int i = 0; i < 8; ++i) {
        tail[tail_len - 8 + i] = uint8_t(bits >> (56 - (8 * i)));
    }
    sha1_block(state, tail);
    if (tail_len == 128) {
        sha1_block(state, tail + 64);
    }

    for (int i = 0; i < 5; ++i) {
        digest[size_t(i) * 4] = uint8_t(state[i] >> 24);
        digest[(size_t(i) * 4) + 1] = uint8_t(state[i] >> 16);
        digest[(size_t(i) * 4) + 2] = uint8_t(state[i] >> 8);
        digest[(size_t(i) * 4) + 3] = uint8_t(state[i]);
    }
}

auto base64_encode(std::span<uint8_t const> input, std::span<char> out) noexcept -> size_t
{
    static constexpr char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t const encoded = 4 * ((input.size() + 2) / 3);
    if (out.size() < encoded) {
        return 0;
    }
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= input.size(); i += 3) {
        uint32_t const v = (uint32_t(input[i]) << 16) | (uint32_t(input[i + 1]) << 8) | uint32_t(input[i + 2]);
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
        out[o++] = ALPHABET[v & 63];
    }
    if (i + 1 == input.size()) {
        uint32_t const v = uint32_t(input[i]) << 16;
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (i + 2 == input.size()) {
        uint32_t const v = (uint32_t(input[i]) << 16) | (uint32_t(input[i + 1]) << 8);
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
        out[o++] = '=';
    }
    return o;
}

auto ws_accept_key(std::string_view client_key) noexcept -> WsAcceptKey
{
    uint8_t material[128];
    size_t const n = std::min(client_key.size(), sizeof material - WS_GUID.size());
    std::memcpy(material, client_key.data(), n);
    std::memcpy(material + n, WS_GUID.data(), WS_GUID.size());

    uint8_t digest[20];
    sha1(std::span<uint8_t const>{material, n + WS_GUID.size()}, digest);

    WsAcceptKey key{};
    (void)base64_encode(digest, key.chars);
    return key;
}

}  // namespace statusbar::http
