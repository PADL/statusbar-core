// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TCP Echo Server Example
/// Accepts TCP connections and echoes back text with character mirroring:
/// - a-z converted to z-a (a->z, b->y, c->x, ...)
/// - A-Z converted to Z-A (A->Z, B->Y, C->X, ...)
/// - 0-9 converted to 9-0 (0->9, 1->8, 2->7, ...)
///
/// Built on TcpConnectionPool: the pool is ONE Pollable in the
/// MessageReactor whose fd is a readiness multiplexer over the listener
/// and every client, so client I/O is event-driven (no tick-cadence
/// latency), connection slots are fixed at startup, and short writes are
/// completed through on_writable instead of being dropped.
///
/// Usage: statusbar-net-tcp-echo --bind=0.0.0.0 --port=8080
/// Config: statusbar-net-tcp-echo --config-load=echo.toml

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_server_config.hpp"
#include "statusbar/net/net_tcp_server.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <print>
#include <span>
#include <vector>

using namespace statusbar::net;

namespace {

/// Convert a character using the mirror transformation
/// a-z -> z-a, A-Z -> Z-A, 0-9 -> 9-0, others unchanged
[[nodiscard]] constexpr auto mirror_char(uint8_t ch) noexcept -> uint8_t
{
    if (ch >= 'a' && ch <= 'z') {
        return static_cast<uint8_t>('z' - (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'Z') {
        return static_cast<uint8_t>('Z' - (ch - 'A'));
    }
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>('9' - (ch - '0'));
    }
    return ch;
}

/// Echo handler with a fixed per-slot pending buffer: a short write keeps
/// the remainder and finishes from on_writable — nothing is dropped, and
/// nothing allocates after construction.
class MirrorEcho : public TcpConnectionHandler
{
  public:
    explicit MirrorEcho(size_t max_clients)
        : pending_(max_clients)
    {}

    void bind(TcpConnectionPool& pool) { pool_ = &pool; }

    void on_accept(size_t slot, SocketAddress const& peer, int64_t) override
    {
        pending_[slot].len = 0;
        std::println(stderr, "Client {} connected (slot={})", peer.to_string(), slot);
    }

    void on_readable(size_t slot, int64_t) override
    {
        auto& pend = pending_[slot];
        for (;;) {
            if (pend.len > 0) {
                return;  // backpressured: finish the pending echo first
            }
            std::array<uint8_t, 4096> buf{};
            auto n = pool_->read(slot, buf);
            if (!n) {
                return;  // would_block (a dead socket surfaces as EOF/error next event)
            }
            if (*n == 0) {
                pool_->close(slot);
                return;
            }
            for (size_t i = 0; i < *n; ++i) {
                buf[i] = mirror_char(buf[i]);
            }
            auto sent = pool_->write(slot, std::span<uint8_t const>{buf.data(), *n});
            if (!sent) {
                pool_->close(slot);
                return;
            }
            if (*sent < *n) {
                pend.len = *n - *sent;
                std::copy_n(buf.begin() + long(*sent), pend.len, pend.bytes.begin());
                return;  // on_writable continues
            }
        }
    }

    void on_writable(size_t slot, int64_t now_ns) override
    {
        auto& pend = pending_[slot];
        if (pend.len == 0) {
            return;
        }
        auto sent = pool_->write(slot, std::span<uint8_t const>{pend.bytes.data(), pend.len});
        if (!sent) {
            pool_->close(slot);
            return;
        }
        std::copy(pend.bytes.begin() + long(*sent), pend.bytes.begin() + long(pend.len), pend.bytes.begin());
        pend.len -= *sent;
        if (pend.len == 0) {
            on_readable(slot, now_ns);  // resume anything the backpressure paused
        }
    }

    void on_closed(size_t slot, int64_t) override
    {
        std::println(stderr, "Client {} disconnected (slot={})", pool_->peer(slot).to_string(), slot);
    }

    void on_rejected(SocketAddress const& peer, int64_t) override
    {
        std::println(stderr, "Rejected client {} (at capacity)", peer.to_string());
    }

  private:
    struct Pending
    {
        std::array<uint8_t, 4096> bytes{};
        size_t len{0};
    };

    TcpConnectionPool* pool_{nullptr};
    std::vector<Pending> pending_;  ///< sized once, at construction
};

/// Adapts the pool + handler pair into the reactor's ownership model.
class EchoPollable : public Pollable
{
  public:
    EchoPollable(SocketAddress const& bind_addr, size_t max_clients, int dscp)
        : handler_{max_clients}
        , pool_{bind_addr, max_clients, handler_, TcpServerOptions{.dscp = dscp}}
    {
        handler_.bind(pool_);
    }

    [[nodiscard]] auto pool() -> TcpConnectionPool& { return pool_; }
    [[nodiscard]] auto fd() const noexcept -> int override { return pool_.fd(); }
    void on_ready(int64_t now_ns) override { pool_.on_ready(now_ns); }
    void tick(int64_t now_ns) override { pool_.tick(now_ns); }
    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

  private:
    MirrorEcho handler_;
    TcpConnectionPool pool_;
};

}  // namespace

auto main(int argc, char** argv) -> int
{
    auto& stop = statusbar::itc::install_stop_signal();
    auto [config, sc] = ServerConfig::parse_or_exit(argc, argv, "TCP echo server with character mirroring (a<->z, A<->Z, 0<->9)");

    auto addr = sc.socket_address();
    if (!addr) {
        std::println(stderr, "Error: Invalid address '{}:{}'", sc.bind_host, sc.port);
        return 1;
    }

    auto handler = std::make_unique<EchoPollable>(*addr, sc.max_clients, sc.dscp);
    if (!handler->pool().valid()) {
        std::println(stderr, "Error: Failed to create TCP listener on {}:{}", sc.bind_host, sc.port);
        return 1;
    }

    if (auto local = handler->pool().local_addr()) {
        std::println(stderr, "Echo server listening on {}", local->to_string());
    }
    if (sc.dscp >= 0) {
        std::println(stderr, "DSCP: {} (TOS: {:#04X})", sc.dscp, sc.dscp << 2);
    }
    std::println(stderr, "Max clients: {}", sc.max_clients);
    std::println(stderr, "Press Ctrl+C to stop");

    MessageReactor reactor{stop, monotonic_ns, 100};
    reactor.add(std::move(handler));

    reactor.run();

    std::println(stderr, "\nShutting down...");

    return 0;
}
