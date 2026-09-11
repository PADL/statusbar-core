#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpHandler — the streaming-first dynamic-route contract
/// (docs/HTTP_PLAN.md §5). Handlers register before start() under
/// (method, exact path) and run on the reactor thread; they must not
/// block.
///
/// Per request:
///
///   on_headers(request, writer)  -> Disposition
///       Decide the request's fate from the head alone: buffer the body
///       (engine assembles up to max_body, then on_complete once),
///       stream it (on_body_chunk per read — bodies larger than
///       max_body are the POINT of this mode), or reject with a status
///       (the engine still consumes the body so keep-alive survives —
///       up to max_body; a larger rejected body is answered and closed).
///       A send from on_headers is refused (the writer returns false).
///       "Expect: 100-continue" is answered here from the disposition:
///       buffer/stream get an interim 100 before the body is read; a
///       reject (or a body nothing wants) gets its final status at once,
///       with close, so the client never sends the body.
///
///   on_body_chunk(request, chunk)
///       Streamed mode only; chunk boundaries are transport artifacts.
///
///   on_complete(request, writer)
///       The body is fully delivered (buffered mode hands it here as one
///       span). Respond via the writer — or return WITHOUT sending to
///       hold the slot for asynchronous completion, and finish later
///       with HttpServer::respond() from the reactor thread (the widget
///       bridge's 1722.1 round trips need exactly this).
///
/// The request's views are valid from on_headers until the response is
/// sent (or the connection closes). ResponseWriter is defined alongside
/// HttpServer; see its notes for inline vs external bodies.

#include "statusbar/http/http_parser.hpp"

#include <cstdint>
#include <span>

namespace statusbar::http {

class ResponseWriter;

/// The verdict from on_headers.
class Disposition
{
  public:
    enum class Kind : uint8_t
    {
        buffer,
        stream,
        reject,
    };

    [[nodiscard]] static auto buffer() noexcept -> Disposition { return Disposition{Kind::buffer, 0}; }
    [[nodiscard]] static auto stream() noexcept -> Disposition { return Disposition{Kind::stream, 0}; }
    [[nodiscard]] static auto reject(uint16_t status) noexcept -> Disposition { return Disposition{Kind::reject, status}; }

    [[nodiscard]] auto kind() const noexcept -> Kind { return kind_; }
    [[nodiscard]] auto status() const noexcept -> uint16_t { return status_; }

  private:
    Disposition(Kind kind, uint16_t status) noexcept
        : kind_{kind}
        , status_{status}
    {}

    Kind kind_;
    uint16_t status_;
};

class HttpHandler
{
  public:
    virtual ~HttpHandler() = default;

    [[nodiscard]] virtual auto on_headers(HttpRequest const& request, ResponseWriter& writer) -> Disposition = 0;
    virtual void on_body_chunk(HttpRequest const& request, std::span<uint8_t const> chunk) { (void)request, (void)chunk; }
    virtual void on_complete(HttpRequest const& request, ResponseWriter& writer) = 0;
};

}  // namespace statusbar::http
