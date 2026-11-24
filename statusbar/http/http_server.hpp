#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpServer — the HTTP engine on real sockets: an HttpEngine
/// (http_engine.hpp, where the logic and its notes live) wired onto a
/// net::TcpConnectionPool. The server is ONE Pollable in the
/// MessageReactor. Routes, WebSocket endpoints and responses are the
/// engine's: everything HttpEngine offers is offered here unchanged.

#include "statusbar/http/http_engine.hpp"
#include "statusbar/net/net_tcp_server.hpp"

#include <cstdint>

namespace statusbar::http {

class HttpServer
    : public net::Pollable
    , public HttpEngine
{
  public:
    /// @param static_manifest Optional manifest served to GET/HEAD after
    ///        dynamic routes; borrowed — must outlive the server.
    HttpServer(
        net::SocketAddress const& bind_addr,
        HttpLimits const& limits,
        StaticManifest const* static_manifest = nullptr,
        net::TcpServerOptions tcp_options = {});

    [[nodiscard]] auto valid() const noexcept -> bool { return pool_.valid(); }
    [[nodiscard]] auto local_addr() const -> StatusValue<net::SocketAddress> { return pool_.local_addr(); }

    // -- Pollable --
    [[nodiscard]] auto fd() const noexcept -> int override { return pool_.fd(); }
    void on_ready(int64_t now_ns) override { pool_.on_ready(now_ns); }
    void tick(int64_t now_ns) override;
    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

  private:
    net::TcpConnectionPool pool_;  ///< constructed after the engine: its events land there
};

}  // namespace statusbar::http
