// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HTTP Server Example (M1 engine + M2 manifest-driven static files).
/// With --manifest=site/manifest.toml it serves the manifest's routes
/// (mmap or pread sources, ETag/304, HEAD); /health answers 200 either
/// way and anything else 404 — with keep-alive, pipelining, body
/// discard, and the injected-clock timeouts, all allocation-free after
/// startup.
///
/// Usage: statusbar-http-server-example --bind=127.0.0.1 --port=8080 \
///            --manifest=site/manifest.toml

#include "statusbar/http/http_server.hpp"
#include "statusbar/http/http_static.hpp"
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_server_config.hpp"

#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

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

    // --manifest is ours; strip it before the standard server-arg parse.
    std::string manifest_path;
    std::vector<char*> args;
    args.reserve(size_t(argc));
    for (int i = 0; i < argc; ++i) {
        std::string_view const arg{argv[i]};
        if (arg.starts_with("--manifest=")) {
            manifest_path = arg.substr(11);
        } else {
            args.push_back(argv[i]);
        }
    }
    auto [config, sc] = net::ServerConfig::parse_or_exit(int(args.size()), args.data(), "Embedded HTTP server example (M1+M2)");

    auto addr = sc.socket_address();
    if (!addr) {
        std::println(stderr, "Error: Invalid address '{}:{}'", sc.bind_host, sc.port);
        return 1;
    }

    http::HttpLimits limits;
    limits.max_connections = sc.max_clients;
    static std::optional<http::StaticManifest> manifest;
    if (!manifest_path.empty()) {
        auto loaded = http::StaticManifest::load(manifest_path);
        if (!loaded) {
            std::println(stderr, "Error: manifest '{}' failed to load", manifest_path);
            return 1;
        }
        manifest.emplace(std::move(*loaded));
        std::println(stderr, "Serving {} static route(s) from {}", manifest->size(), manifest_path);
    }
    auto server = std::make_unique<ExampleServer>(*addr, limits, manifest ? &*manifest : nullptr);
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
