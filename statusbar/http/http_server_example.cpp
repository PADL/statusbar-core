// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HTTP Server Example (M1: the connection engine; the M2 manifest-driven
/// static site will grow here). Serves plain-text status responses — 200
/// for /health, 404 for everything else — with keep-alive, pipelining,
/// body discard, and the injected-clock timeouts, all allocation-free
/// after startup.
///
/// Usage: statusbar-http-server-example --bind=127.0.0.1 --port=8080

#include "statusbar/http/http_server.hpp"
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_server_config.hpp"

#include <memory>
#include <print>

using namespace statusbar;

namespace {

class ExampleServer : public http::HttpServer
{
  public:
    using HttpServer::HttpServer;

  protected:
    [[nodiscard]] auto dispatch(size_t /*slot*/, http::HttpRequest const& request) -> uint16_t override
    {
        return request.path == "/health" ? 200 : 404;
    }
};

}  // namespace

auto main(int argc, char** argv) -> int
{
    auto& stop = itc::install_stop_signal();
    auto [config, sc] = net::ServerConfig::parse_or_exit(argc, argv, "Embedded HTTP server example (M1 engine)");

    auto addr = sc.socket_address();
    if (!addr) {
        std::println(stderr, "Error: Invalid address '{}:{}'", sc.bind_host, sc.port);
        return 1;
    }

    http::HttpLimits limits;
    limits.max_connections = sc.max_clients;
    auto server = std::make_unique<ExampleServer>(*addr, limits);
    if (!server->valid()) {
        std::println(stderr, "Error: Failed to listen on {}:{}", sc.bind_host, sc.port);
        return 1;
    }
    if (auto local = server->local_addr()) {
        std::println(stderr, "HTTP server listening on {}", local->to_string());
    }
    std::println(stderr, "GET /health -> 200; anything else -> 404. Ctrl+C to stop");

    net::MessageReactor reactor{stop, net::monotonic_ns, 100};
    reactor.add(std::move(server));
    reactor.run();
    return 0;
}
