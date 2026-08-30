#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpServer — the M1 connection engine (docs/HTTP_PLAN.md §2, §7):
/// HttpParser wired onto TcpConnectionPool. The server is ONE Pollable in
/// the MessageReactor; per pool slot it keeps a Connection record — fixed
/// rx and tx buffers, a parser, a small state machine — all sized from
/// HttpLimits at construction. Nothing allocates after startup.
///
/// Per-request flow: read into rx → incremental parse → dispatch →
/// response through the tx buffer under the pool's short-write contract →
/// keep-alive reset (pipelined bytes compact to the rx front and parse
/// immediately) or close. Request bodies are consumed before responding —
/// buffered from rx when already received, streamed into a discard
/// scratch otherwise — so keep-alive framing survives requests nobody
/// handled. A parse failure answers with its specific status and closes
/// (framing is no longer trustworthy).
///
/// Timeouts run on the injected reactor clock: header-read (408 + close)
/// from the first request byte, keep-alive idle (silent close) between
/// requests. The pool's own idle sweep stays disabled — the server owns
/// connection lifetime.
///
/// Routing lands in M3. Until then dispatch() is a protected seam
/// returning the status to serve as a plain-text response; the default
/// answers 404 to everything.

#include "statusbar/http/http_limits.hpp"
#include "statusbar/http/http_parser.hpp"
#include "statusbar/http/http_static.hpp"
#include "statusbar/net/net_tcp_server.hpp"

#include <cstdint>
#include <vector>

namespace statusbar::http {

class HttpServer
    : public net::Pollable
    , private net::TcpConnectionHandler
{
  public:
    /// @param static_manifest Optional manifest served to GET/HEAD before
    ///        the dispatch seam; borrowed — must outlive the server.
    HttpServer(
        net::SocketAddress const& bind_addr,
        HttpLimits const& limits,
        StaticManifest const* static_manifest = nullptr,
        net::TcpServerOptions tcp_options = {});

    HttpServer(HttpServer const&) = delete;
    auto operator=(HttpServer const&) -> HttpServer& = delete;

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
    /// M1 routing seam (real handlers land in M3): the returned status is
    /// served as a plain-text response. The request's views are valid for
    /// the duration of the call.
    [[nodiscard]] virtual auto dispatch(size_t slot, HttpRequest const& request) -> uint16_t
    {
        (void)slot, (void)request;
        return 404;
    }

  private:
    enum class ConnState : uint8_t
    {
        reading_head,
        discarding_body,
        sending,
    };

    struct Connection
    {
        std::vector<uint8_t> rx;  ///< head + buffered body + pipelined tail
        std::vector<uint8_t> tx;  ///< response head + inline status bodies
        size_t rx_len{0};
        size_t tx_len{0};
        size_t tx_sent{0};
        size_t leftover_at{0};  ///< start of pipelined bytes once the request is framed
        uint64_t discard_remaining{0};
        std::span<uint8_t const> body_map{};  ///< mmap-backed response body
        int body_fd{-1};                      ///< pread-backed response body
        uint64_t body_size{0};
        uint64_t body_sent{0};
        ConnState state{ConnState::reading_head};
        bool close_after_send{false};
        bool head_started{false};  ///< first request byte seen (arms the 408 clock)
        int64_t head_start_ns{0};
        int64_t idle_since_ns{0};
    };

    // -- TcpConnectionHandler --
    void on_accept(size_t slot, net::SocketAddress const& peer, int64_t now_ns) override;
    void on_readable(size_t slot, int64_t now_ns) override;
    void on_writable(size_t slot, int64_t now_ns) override;
    void on_closed(size_t slot, int64_t now_ns) override;

    void process(size_t slot, int64_t now_ns);
    void handle_complete_head(size_t slot, int64_t now_ns);
    void finish_body_and_respond(size_t slot, int64_t now_ns);
    void respond_status(size_t slot, uint16_t status, bool close_after, int64_t now_ns);
    void serve_static(size_t slot, StaticRoute const& route, HttpRequest const& request, int64_t now_ns);
    void pump_tx(size_t slot, int64_t now_ns);
    void next_request(size_t slot, int64_t now_ns);

    HttpLimits limits_;
    StaticManifest const* static_{nullptr};
    std::vector<Connection> connections_;  ///< sized max_connections at construction
    std::vector<HttpParser> parsers_;      ///< one per slot, sized at construction
    std::vector<uint8_t> discard_;         ///< shared body-discard scratch
    net::TcpConnectionPool pool_;          ///< constructed last: callbacks may fire on members above
};

}  // namespace statusbar::http
