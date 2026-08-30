#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// RFC 6455 WebSocket frame codec (docs/HTTP_PLAN.md §6) — pure functions
/// over byte spans, no I/O and no allocation, mirroring the HTTP parser's
/// testability. The server side of the protocol: inbound frames MUST be
/// masked (1002 otherwise), outbound frames are never masked; control
/// frames (close/ping/pong) carry at most 125 payload bytes and are never
/// fragmented. Fragment reassembly policy lives in the engine — the codec
/// only frames bytes.
///
/// The WsEndpoint interface is the WebSocket counterpart of HttpHandler:
/// register with HttpServer::add_ws_route(); a valid GET upgrade on the
/// path answers 101 and flips the slot permanently to WebSocket mode.
/// ws_send()/ws_send_external() are refusal-based — when the connection
/// is still draining the previous frame they return false rather than
/// queue (per-endpoint policy decides drop-stale vs close; there is no
/// hidden unbounded buffer).

#include "statusbar/http/http_parser.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::http {

enum class WsOpcode : uint8_t
{
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

[[nodiscard]] constexpr auto ws_is_control(WsOpcode opcode) noexcept -> bool
{
    return uint8_t(opcode) >= 0x8;
}

struct WsFrameHeader
{
    bool fin{false};
    WsOpcode opcode{WsOpcode::continuation};
    bool masked{false};
    uint64_t payload_len{0};
    std::array<uint8_t, 4> mask{};
    size_t header_len{0};  ///< bytes the header itself occupies
};

enum class WsParse : uint8_t
{
    need_more,
    ok,
    protocol_error,  ///< reserved bits, bad opcode, or a bad control frame
};

/// Parses one frame header from the start of @p bytes.
[[nodiscard]] auto ws_parse_frame_header(std::span<uint8_t const> bytes, WsFrameHeader& out) noexcept -> WsParse;

/// XOR-unmasks @p payload in place (@p offset is the payload position of
/// payload[0], for unmasking in pieces).
void ws_unmask(std::span<uint8_t> payload, std::array<uint8_t, 4> const& mask, uint64_t offset = 0) noexcept;

/// Writes a server (unmasked) frame header; returns its length, 0 when
/// @p out cannot hold it (max 10 bytes).
[[nodiscard]] auto ws_write_frame_header(std::span<uint8_t> out, WsOpcode opcode, bool fin, uint64_t payload_len) noexcept
    -> size_t;

/// A WebSocket endpoint bound to a path. Callbacks run on the reactor
/// thread; message payloads point into the slot's reassembly buffer and
/// are valid only during the call.
class WsEndpoint
{
  public:
    virtual ~WsEndpoint() = default;

    /// The upgrade completed; request views are valid during this call.
    virtual void on_ws_open(size_t slot, HttpRequest const& request) { (void)slot, (void)request; }

    virtual void on_ws_message(size_t slot, std::span<uint8_t const> payload, bool is_text) = 0;

    /// The connection is gone (close handshake, drop, or TCP loss).
    virtual void on_ws_closed(size_t slot) { (void)slot; }
};

}  // namespace statusbar::http
