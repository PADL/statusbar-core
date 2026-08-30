#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpLimits — every capacity and timeout of the embedded HTTP server,
/// fixed at init time (docs/HTTP_PLAN.md §2). Storage is sized from these
/// once, at construction; the steady-state request path never allocates.
/// Each limit maps to a specific rejection, listed with the field.

#include <cstddef>
#include <cstdint>

namespace statusbar::http {

struct HttpLimits
{
    /// Concurrent connections (the TcpConnectionPool size); beyond it,
    /// accepts are closed immediately.
    size_t max_connections = 8;

    /// Request line bytes (method + target + version + line end) -> 414.
    size_t max_request_line = 2048;

    /// Total header block bytes after the request line -> 431.
    size_t max_header_block = 8192;

    /// Header field count -> 431.
    size_t max_header_count = 32;

    /// Buffered request body bytes (streaming handlers may accept more,
    /// chunk by chunk) -> 413.
    size_t max_body = size_t{64} * 1024;

    /// Response head + inline error/status bodies (the per-connection tx
    /// buffer). Static and streamed bodies do not pass through it.
    size_t max_response_head = 4096;

    /// Reassembled WebSocket message bytes -> close 1009.
    size_t max_ws_message = size_t{64} * 1024;

    /// Nanoseconds from first request byte to complete headers -> 408.
    int64_t header_read_timeout_ns = int64_t(10) * 1'000'000'000;

    /// Idle keep-alive connection lifetime -> close.
    int64_t keep_alive_idle_ns = int64_t(30) * 1'000'000'000;

    /// WebSocket idle: ping after ws_ping_ns, drop (close 1001) after
    /// ws_drop_ns without any inbound frame.
    int64_t ws_ping_ns = int64_t(30) * 1'000'000'000;
    int64_t ws_drop_ns = int64_t(60) * 1'000'000'000;
};

}  // namespace statusbar::http
