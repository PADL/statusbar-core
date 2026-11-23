// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_server.hpp"

namespace statusbar::http {

HttpServer::HttpServer(
    net::SocketAddress const& bind_addr,
    HttpLimits const& limits,
    StaticManifest const* static_manifest,
    net::TcpServerOptions tcp_options)
    : HttpEngine{limits, static_manifest}
    , pool_{bind_addr, limits.max_connections, events(), [&] {
                // The engine owns connection lifetime (408 vs silent idle
                // close differ) — the pool's blunt idle sweep stays off.
                tcp_options.idle_timeout_ns = 0;
                return tcp_options;
            }()}
{
    attach(pool_);
}

void HttpServer::tick(int64_t now_ns)
{
    pool_.tick(now_ns);
    HttpEngine::tick(now_ns);
}

}  // namespace statusbar::http
