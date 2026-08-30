// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The M5 allocation gate (docs/HTTP_PLAN.md §7): the module's central
/// promise — no dynamic allocation after startup — enforced, not
/// asserted. This translation unit replaces the global operator new
/// family with a counting forwarder; the test builds a server, runs one
/// warm-up pass of every request shape, ARMS the counter, drives a
/// steady-state mixed workload (static GET from both sources, 304, HEAD,
/// buffered POST echo, streamed PUT, pipelined pairs, WebSocket echo and
/// ping, timeout ticks), DISARMS, and requires the count be ZERO.
///
/// The armed section of the test itself must also be allocation-free:
/// request bytes are prebuilt, responses land in fixed buffers, and
/// verification is memcmp-shaped. EXPECT failures may allocate — that
/// only happens when the gate has already failed.

#include "statusbar/http/http_server.hpp"
#include "statusbar/http/http_static.hpp"
#include "statusbar/http/http_ws.hpp"
#include "statusbar/test/test.hpp"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include <sys/socket.h>

// ---- counting operator new family ------------------------------------------

namespace {
std::atomic<bool> g_alloc_armed{false};
std::atomic<uint64_t> g_alloc_count{0};

void count_allocation() noexcept
{
    if (g_alloc_armed.load(std::memory_order_relaxed)) {
        g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    }
}
}  // namespace

// NOLINTBEGIN(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,readability-inconsistent-declaration-parameter-name)
auto operator new(size_t size) -> void*
{
    count_allocation();
    void* p = std::malloc(size == 0 ? 1 : size);
    if (p == nullptr) {
        throw std::bad_alloc{};
    }
    return p;
}

auto operator new[](size_t size) -> void*
{
    return ::operator new(size);
}

auto operator new(size_t size, std::align_val_t alignment) -> void*
{
    count_allocation();
    void* p = nullptr;
    if (::posix_memalign(&p, size_t(alignment) < sizeof(void*) ? sizeof(void*) : size_t(alignment), size == 0 ? 1 : size) != 0) {
        throw std::bad_alloc{};
    }
    return p;
}

auto operator new[](size_t size, std::align_val_t alignment) -> void*
{
    return ::operator new(size, alignment);
}

void operator delete(void* p) noexcept
{
    std::free(p);
}
void operator delete[](void* p) noexcept
{
    std::free(p);
}
void operator delete(void* p, size_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, size_t) noexcept
{
    std::free(p);
}
void operator delete(void* p, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete(void* p, size_t, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, size_t, std::align_val_t) noexcept
{
    std::free(p);
}
// NOLINTEND(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,readability-inconsistent-declaration-parameter-name)

// ---- the workload -----------------------------------------------------------

using namespace statusbar;
using namespace statusbar::http;

namespace {

struct RawClient
{
    int fd{-1};

    explicit RawClient(net::SocketAddress const& to)
    {
        fd = ::socket(to.family(), SOCK_STREAM, 0);
        if (fd >= 0 && ::connect(fd, to.sockaddr(), to.length()) < 0) {
            ::close(fd);
            fd = -1;
        }
    }
    ~RawClient()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }
    RawClient(RawClient const&) = delete;
    auto operator=(RawClient const&) -> RawClient& = delete;

    void send_bytes(uint8_t const* data, size_t len) const
    {
        auto const n = ::send(fd, data, len, 0);
        (void)n;
    }

    /// Receives until @p expect bytes arrived or the budget lapses; fixed
    /// buffer, no allocation.
    auto recv_into(uint8_t* out, size_t cap, size_t expect, int budget_ms) const -> size_t
    {
        size_t got = 0;
        for (int spent = 0; spent < budget_ms && got < expect && got < cap; spent += 5) {
            struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 5) <= 0) {
                continue;
            }
            auto const n = ::recv(fd, out + got, cap - got, 0);
            if (n <= 0) {
                break;
            }
            got += size_t(n);
        }
        return got;
    }
};

/// Buffered echo into per-slot fixed storage; responds via external span.
class GateEcho : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::buffer(); }

    void on_body_chunk(HttpRequest const&, std::span<uint8_t const> chunk) override
    {
        len = std::min(chunk.size(), sizeof store);
        std::memcpy(store, chunk.data(), len);
    }

    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        (void)writer.send_external(200, "application/octet-stream", std::span<uint8_t const>{store, len});
    }

    uint8_t store[256]{};
    size_t len{0};
};

/// Streamed counter answering from fixed storage.
class GateCount : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override
    {
        total = 0;
        return Disposition::stream();
    }
    void on_body_chunk(HttpRequest const&, std::span<uint8_t const> chunk) override { total += chunk.size(); }
    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        auto const n = snprintf(reply, sizeof reply, "%zu", total);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        (void)writer.send_external(200, "text/plain", {reinterpret_cast<uint8_t const*>(reply), size_t(n)});
    }
    size_t total{0};
    char reply[32]{};
};

class GateWsEcho : public WsEndpoint
{
  public:
    explicit GateWsEcho(HttpServer*& server)
        : server_{server}
    {}
    void on_ws_message(size_t slot, std::span<uint8_t const> payload, bool is_text) override
    {
        (void)server_->ws_send_external(slot, payload, is_text);
    }
    HttpServer*& server_;
};

void pump(HttpServer& server, int rounds, int64_t now0)
{
    for (int i = 0; i < rounds; ++i) {
        struct pollfd pfd{.fd = server.fd(), .events = POLLIN, .revents = 0};
        (void)::poll(&pfd, 1, 2);
        server.on_ready(now0 + i);
        server.tick(now0 + i);
    }
}

/// One request/response over an existing keep-alive connection with
/// zero allocations: send prebuilt bytes, receive into a fixed buffer,
/// verify the expected prefix and suffix appear.
auto exchange(
    HttpServer& server,
    RawClient const& client,
    std::vector<uint8_t> const& request,
    char const* expect_prefix,
    size_t expect_at_least,
    int64_t now0) -> bool
{
    static uint8_t response[16384];
    client.send_bytes(request.data(), request.size());
    pump(server, 30, now0);
    auto const got = client.recv_into(response, sizeof response, expect_at_least, 300);
    return got >= expect_at_least && std::memcmp(response, expect_prefix, strlen(expect_prefix)) == 0;
}

auto req(std::string const& text) -> std::vector<uint8_t>
{
    return {text.begin(), text.end()};
}

auto masked_ws_frame(uint8_t opcode, std::string const& payload) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    out.push_back(uint8_t(0x80U | opcode));
    out.push_back(uint8_t(0x80U | payload.size()));  // payloads <= 125 here
    std::array<uint8_t, 4> const mask{0x11, 0x22, 0x33, 0x44};
    out.insert(out.end(), mask.begin(), mask.end());
    for (size_t i = 0; i < payload.size(); ++i) {
        out.push_back(uint8_t(payload[i]) ^ mask[i % 4]);
    }
    return out;
}

}  // namespace

TEST(http_alloc_gate, steady_state_allocates_nothing)
{
    // ---- startup (allocation is fine here) ------------------------------
    char tmpl[] = "/tmp/http_alloc_gate_XXXXXX";
    std::string const dir = ::mkdtemp(tmpl);
    auto write_file = [&](char const* name, std::string const& content) {
        auto* f = std::fopen((dir + "/" + name).c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        (void)std::fwrite(content.data(), 1, content.size(), f);
        (void)std::fclose(f);
    };
    std::string const asset(2048, 'A');
    write_file("asset.bin", asset);
    write_file(
        "manifest.toml",
        "[[route]]\nuri = \"/asset\"\nfile = \"asset.bin\"\ntype = \"application/octet-stream\"\n"
        "[[route]]\nuri = \"/asset-streamed\"\nfile = \"asset.bin\"\ntype = \"application/octet-stream\"\nstream = true\n");
    auto manifest = StaticManifest::load(dir + "/manifest.toml");
    EXPECT_TRUE(manifest.has_value());

    HttpLimits limits;
    limits.max_connections = 4;
    HttpServer server{net::SocketAddress::ipv4_loopback(0), limits, &*manifest};
    HttpServer* server_ptr = &server;
    GateEcho echo;
    GateCount count;
    GateWsEcho ws_echo{server_ptr};
    EXPECT_TRUE(server.add_route(HttpMethod::post, "/echo", echo));
    EXPECT_TRUE(server.add_route(HttpMethod::put, "/count", count));
    EXPECT_TRUE(server.add_ws_route("/ws", ws_echo));
    auto const addr = *server.local_addr();

    // Prebuilt request bytes (the armed loop only reuses them).
    auto const get_asset = req("GET /asset HTTP/1.1\r\nHost: g\r\n\r\n");
    auto const get_streamed = req("GET /asset-streamed HTTP/1.1\r\nHost: g\r\n\r\n");
    auto const head_asset = req("HEAD /asset HTTP/1.1\r\nHost: g\r\n\r\n");
    auto const get_404 = req("GET /nope HTTP/1.1\r\nHost: g\r\n\r\n");
    auto const post_echo = req("POST /echo HTTP/1.1\r\nHost: g\r\nContent-Length: 9\r\n\r\npayload-9");
    auto const put_count = req("PUT /count HTTP/1.1\r\nHost: g\r\nContent-Length: 40\r\n\r\n" + std::string(40, 'z'));
    auto const pipelined = req("GET /asset HTTP/1.1\r\nHost: g\r\n\r\n"
                               "POST /echo HTTP/1.1\r\nHost: g\r\nContent-Length: 3\r\n\r\nabc");
    auto const conditional = [&] {
        // Learn the ETag during warm-up preparation.
        RawClient probe{addr};
        static uint8_t buf[8192];
        probe.send_bytes(get_asset.data(), get_asset.size());
        pump(server, 30, 1);
        auto const got = probe.recv_into(buf, sizeof buf, 200, 300);
        std::string const response{reinterpret_cast<char const*>(buf), got};  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const at = response.find("ETag: ");
        EXPECT_TRUE(at != std::string::npos);
        auto const etag = response.substr(at + 6, response.find('\r', at) - at - 6);
        return req("GET /asset HTTP/1.1\r\nHost: g\r\nIf-None-Match: " + etag + "\r\n\r\n");
    }();
    auto const ws_upgrade = req("GET /ws HTTP/1.1\r\nHost: g\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    auto const ws_text = masked_ws_frame(0x1, "meter update -36.5");
    auto const ws_ping = masked_ws_frame(0x9, "hb");

    // ---- warm-up: every shape once --------------------------------------
    RawClient http_client{addr};
    RawClient ws_client{addr};
    EXPECT_TRUE(exchange(server, http_client, get_asset, "HTTP/1.1 200 OK", 2048, 100));
    EXPECT_TRUE(exchange(server, http_client, get_streamed, "HTTP/1.1 200 OK", 2048, 200));
    EXPECT_TRUE(exchange(server, http_client, head_asset, "HTTP/1.1 200 OK", 64, 300));
    EXPECT_TRUE(exchange(server, http_client, get_404, "HTTP/1.1 404", 32, 400));
    EXPECT_TRUE(exchange(server, http_client, post_echo, "HTTP/1.1 200 OK", 64, 500));
    EXPECT_TRUE(exchange(server, http_client, put_count, "HTTP/1.1 200 OK", 32, 600));
    EXPECT_TRUE(exchange(server, http_client, conditional, "HTTP/1.1 304", 32, 700));
    EXPECT_TRUE(exchange(server, ws_client, ws_upgrade, "HTTP/1.1 101", 64, 800));
    EXPECT_TRUE(exchange(server, ws_client, ws_text, "\x81", 4, 900));

    // ---- the gate --------------------------------------------------------
    g_alloc_count.store(0);
    g_alloc_armed.store(true);
    bool all_ok = true;
    for (int round = 0; round < 25; ++round) {
        int64_t const now = 10'000 + (int64_t(round) * 1'000);
        all_ok = all_ok && exchange(server, http_client, get_asset, "HTTP/1.1 200 OK", 2048, now);
        all_ok = all_ok && exchange(server, http_client, get_streamed, "HTTP/1.1 200 OK", 2048, now + 100);
        all_ok = all_ok && exchange(server, http_client, head_asset, "HTTP/1.1 200 OK", 64, now + 200);
        all_ok = all_ok && exchange(server, http_client, get_404, "HTTP/1.1 404", 32, now + 300);
        all_ok = all_ok && exchange(server, http_client, post_echo, "HTTP/1.1 200 OK", 64, now + 400);
        all_ok = all_ok && exchange(server, http_client, put_count, "HTTP/1.1 200 OK", 32, now + 500);
        all_ok = all_ok && exchange(server, http_client, conditional, "HTTP/1.1 304", 32, now + 600);
        all_ok = all_ok && exchange(server, http_client, pipelined, "HTTP/1.1 200 OK", 2100, now + 700);
        all_ok = all_ok && exchange(server, ws_client, ws_text, "\x81", 4, now + 800);
        all_ok = all_ok && exchange(server, ws_client, ws_ping, "\x8a", 4, now + 900);
    }
    g_alloc_armed.store(false);

    EXPECT_TRUE(all_ok);
    EXPECT_EQ(g_alloc_count.load(), 0U);
}

TEST_MAIN(statusbar_http, http_alloc_gate_test)
