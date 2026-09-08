#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpServer — the connection engine (docs/HTTP_PLAN.md §2, §7):
/// HttpParser wired onto TcpConnectionPool. The server is ONE Pollable in
/// the MessageReactor; per pool slot it keeps a Connection record — fixed
/// rx and tx buffers, a parser, a small state machine — all sized from
/// HttpLimits at construction. Nothing allocates after startup.
///
/// Request routing, in precedence order:
///   1. dynamic handlers registered with add_route() (method + exact
///      path; registered code beats manifest data);
///   2. the static manifest, for GET/HEAD (M2);
///   3. a path registered under other methods answers 405 with Allow;
///   4. the legacy dispatch() seam (default 404).
///
/// Bodies are always consumed before responding — buffered into rx,
/// streamed to the handler, or discarded — so keep-alive framing
/// survives every outcome. Streamed handlers may accept bodies larger
/// than max_body; buffered acceptance and unhandled requests are capped
/// by it (413), and a rejected request whose body exceeds it is answered
/// at once and closed rather than drained. Parse failures answer their
/// status and close.
///
/// Timeouts run on the injected reactor clock: header-read (408 + close)
/// armed by the first request byte, keep-alive idle (silent close)
/// between requests.

#include "statusbar/http/http_handler.hpp"
#include "statusbar/http/http_limits.hpp"
#include "statusbar/http/http_parser.hpp"
#include "statusbar/http/http_static.hpp"
#include "statusbar/http/http_ws.hpp"
#include "statusbar/net/net_tcp_server.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace statusbar::http {

class HttpServer;

/// Builds one response into the connection's fixed tx buffer. Created by
/// the engine around handler callbacks; also obtainable from
/// HttpServer::respond() for asynchronous completion.
///
/// Body forms:
///   send(status, type, body)           inline — copied into the tx
///                                      buffer (must fit beside the head,
///                                      else false and a 500 goes out);
///   send_external(status, type, body)  referenced — the span must stay
///                                      valid until the response finishes
///                                      (per-slot handler storage; served
///                                      zero-copy like an mmap body);
///   send_status(status)                the engine's plain-text status
///                                      body.
///
/// add_header() queues extra response headers (fixed per-connection
/// space; false when full). On HEAD requests the body is suppressed but
/// Content-Length still describes it.
///
/// A send is accepted only from on_complete or an asynchronous
/// respond(); one from on_headers is refused (false) and the request
/// proceeds as its disposition says. A response that cannot be built
/// (head or inline body too large for the tx buffer) becomes a fixed
/// 500 + close; sent() is true afterwards and further sends are refused.
class ResponseWriter
{
  public:
    auto add_header(std::string_view name, std::string_view value) noexcept -> bool;
    auto send(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool;
    auto send_external(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool;
    void send_status(uint16_t status) noexcept;

    [[nodiscard]] auto sent() const noexcept -> bool;

    /// The connection slot this writer answers — the handle an
    /// asynchronous handler stores to complete via HttpServer::respond().
    [[nodiscard]] auto slot() const noexcept -> size_t { return slot_; }

  private:
    friend class HttpServer;
    ResponseWriter(HttpServer& server, size_t slot) noexcept
        : server_{&server}
        , slot_{slot}
    {}

    HttpServer* server_;
    size_t slot_;
};

class HttpServer
    : public net::Pollable
    , private net::TcpConnectionHandler
{
  public:
    /// @param static_manifest Optional manifest served to GET/HEAD after
    ///        dynamic routes; borrowed — must outlive the server.
    HttpServer(
        net::SocketAddress const& bind_addr,
        HttpLimits const& limits,
        StaticManifest const* static_manifest = nullptr,
        net::TcpServerOptions tcp_options = {});

    HttpServer(HttpServer const&) = delete;
    auto operator=(HttpServer const&) -> HttpServer& = delete;

    /// Register a handler for (method, exact path) — before the reactor
    /// runs. False on a duplicate registration or a path not starting
    /// with '/'. The handler is borrowed and must outlive the server.
    [[nodiscard]] auto add_route(HttpMethod method, std::string path, HttpHandler& handler) -> bool;

    /// Register a WebSocket endpoint for @p path — before the reactor
    /// runs (this sizes the per-slot reassembly buffers). A valid GET
    /// upgrade answers 101 and flips the slot to WebSocket mode; a plain
    /// GET on the path answers 426.
    [[nodiscard]] auto add_ws_route(std::string path, WsEndpoint& endpoint) -> bool;

    /// Send one WebSocket message frame. Refusal-based: false when the
    /// slot is not an open WebSocket, is mid-close, is still draining the
    /// previous frame, or (for the copying form) the payload does not fit
    /// the tx buffer. ws_send_external references the span instead —
    /// keep it stable until the frame finishes sending.
    [[nodiscard]] auto ws_send(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool;
    [[nodiscard]] auto ws_send_external(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool;

    /// Begin the close handshake: send a close frame with @p code, then
    /// close the connection once it drains.
    void ws_close(size_t slot, uint16_t code) noexcept;

    /// Complete a held (asynchronous) request: valid only for a slot
    /// whose handler returned from on_complete without sending. Returns
    /// a writer bound to that slot, or nullopt when the slot is not
    /// awaiting (e.g. the connection died meanwhile).
    [[nodiscard]] auto respond(size_t slot) noexcept -> std::optional<ResponseWriter>;

    [[nodiscard]] auto valid() const noexcept -> bool { return pool_.valid(); }
    [[nodiscard]] auto local_addr() const -> StatusValue<net::SocketAddress> { return pool_.local_addr(); }
    [[nodiscard]] auto limits() const noexcept -> HttpLimits const& { return limits_; }
    [[nodiscard]] auto active_connections() const noexcept -> size_t { return pool_.active_count(); }

    // -- Pollable --
    [[nodiscard]] auto fd() const noexcept -> int override { return pool_.fd(); }
    void on_ready(int64_t now_ns) override { pool_.on_ready(now_ns); }
    void tick(int64_t now_ns) override;
    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

  protected:
    /// Legacy M1 fallback for requests no route or manifest entry
    /// claimed: the returned status is served as a plain-text response.
    [[nodiscard]] virtual auto dispatch(size_t slot, HttpRequest const& request) -> uint16_t
    {
        (void)slot, (void)request;
        return 404;
    }

  private:
    friend class ResponseWriter;

    enum class ConnState : uint8_t
    {
        reading_head,
        reading_body,
        awaiting_response,  ///< handler holds the slot for async completion
        sending,
    };

    enum class BodyMode : uint8_t
    {
        discard,   ///< nobody wants it; pending_status answers afterwards
        buffered,  ///< assemble in rx, hand to on_complete as one span
        streamed,  ///< feed on_body_chunk per read
    };

    struct Route
    {
        std::string path;
        HttpMethod method;
        HttpHandler* handler;
    };

    struct WsRoute
    {
        std::string path;
        WsEndpoint* endpoint;
    };

    struct Connection
    {
        std::vector<uint8_t> rx;  ///< head + buffered body + pipelined tail
        std::vector<uint8_t> tx;  ///< response head + inline bodies + pread staging
        std::vector<char> extra;  ///< writer-queued extra response headers
        size_t rx_len{0};
        size_t tx_len{0};
        size_t tx_sent{0};
        size_t extra_len{0};
        size_t leftover_at{0};  ///< start of pipelined bytes once the request is framed
        uint64_t body_remaining{0};
        std::span<uint8_t const> body_map{};  ///< mmap/external response body
        int body_fd{-1};                      ///< pread response body
        uint64_t body_size{0};
        uint64_t body_sent{0};
        HttpHandler* handler{nullptr};
        BodyMode body_mode{BodyMode::discard};
        uint16_t pending_status{0};
        ConnState state{ConnState::reading_head};
        bool close_after_send{false};
        bool suppress_body{false};  ///< HEAD: head only, honest Content-Length
        bool response_staged{false};
        bool head_started{false};
        int64_t head_start_ns{0};
        int64_t idle_since_ns{0};
        int64_t last_event_ns{0};  ///< the reactor's clock at the latest callback: the "now" for sends from handlers

        // -- WebSocket mode --
        std::vector<uint8_t> ws_msg;  ///< fragment reassembly (sized by add_ws_route)
        WsEndpoint* ws_endpoint{nullptr};
        size_t ws_msg_len{0};
        WsOpcode ws_msg_opcode{WsOpcode::text};
        bool ws_mode{false};
        bool ws_fragmented{false};
        bool ws_closing{false};
        bool upgrade_pending{false};
        int64_t ws_last_rx_ns{0};
        int64_t ws_last_ping_ns{0};
    };

    // -- TcpConnectionHandler --
    void on_accept(size_t slot, net::SocketAddress const& peer, int64_t now_ns) override;
    void on_readable(size_t slot, int64_t now_ns) override;
    void on_writable(size_t slot, int64_t now_ns) override;
    void on_closed(size_t slot, int64_t now_ns) override;

    void process(size_t slot, int64_t now_ns);
    void handle_complete_head(size_t slot, int64_t now_ns);
    void body_finished(size_t slot, int64_t now_ns);
    void respond_status(size_t slot, uint16_t status, bool close_after, int64_t now_ns);
    void serve_static(size_t slot, StaticRoute const& route, HttpRequest const& request, int64_t now_ns);
    void pump_tx(size_t slot, int64_t now_ns);
    void next_request(size_t slot, int64_t now_ns);

    /// pool_.read that closes the slot on a hard error (only would-block
    /// leaves it open); nullopt means stop reading for now.
    [[nodiscard]] auto read_some(size_t slot, std::span<uint8_t> out) noexcept -> std::optional<size_t>;
    /// Commits a head snprintf'd into tx (true), or — when it did not fit
    /// — stages a fixed 500 + close instead (false).
    [[nodiscard]] auto stage_head(size_t slot, int head_len, int64_t now_ns) noexcept -> bool;
    void fail_response(size_t slot, int64_t now_ns) noexcept;

    // WebSocket engine.
    void try_upgrade(size_t slot, HttpRequest const& request, WsRoute const& route, int64_t now_ns);
    void enter_ws_mode(size_t slot, int64_t now_ns);
    void ws_process(size_t slot, int64_t now_ns);
    auto ws_stage_frame(size_t slot, WsOpcode opcode, std::span<uint8_t const> payload, bool external, int64_t now_ns) noexcept
        -> bool;
    void ws_fail(size_t slot, uint16_t code, int64_t now_ns);
    [[nodiscard]] auto find_ws_route(std::string_view path) const noexcept -> WsRoute const*;

    // ResponseWriter backends.
    auto writer_add_header(size_t slot, std::string_view name, std::string_view value) noexcept -> bool;
    auto writer_send(
        size_t slot, uint16_t status, std::string_view content_type, std::span<uint8_t const> body, bool external) noexcept -> bool;
    [[nodiscard]] auto writer_sent(size_t slot) const noexcept -> bool;

    [[nodiscard]] auto find_route(HttpMethod method, std::string_view path) const noexcept -> HttpHandler*;
    [[nodiscard]] auto path_registered(std::string_view path) const noexcept -> bool;
    void append_allow_header(size_t slot, std::string_view path) noexcept;

    HttpLimits limits_;
    StaticManifest const* static_{nullptr};
    std::vector<Route> routes_;  ///< registered before start
    std::vector<WsRoute> ws_routes_;
    std::vector<Connection> connections_;
    std::vector<HttpParser> parsers_;
    std::vector<uint8_t> discard_;
    net::TcpConnectionPool pool_;  ///< constructed last: callbacks may fire on members above
};

}  // namespace statusbar::http
