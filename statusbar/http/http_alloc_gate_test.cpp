// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The M5 allocation gate (docs/HTTP_PLAN.md §7): the module's central
/// promise — no dynamic allocation after startup — enforced, not
/// asserted, on the engine itself: it runs here on a made-up wire, with no
/// socket and nothing that waits. (The same gate over real sockets is the
/// functional test beside this one.) This translation unit replaces the whole
/// replaceable global operator new family (plain, aligned, nothrow and
/// aligned-nothrow, with their deletes) with a counting forwarder; the test
/// builds an engine, runs one
/// warm-up pass of every kind of request, ARMS the counter, drives a
/// steady-state mixed workload (static GET from both sources, 304, HEAD,
/// buffered POST echo, streamed PUT, pipelined pairs, WebSocket echo and
/// ping, timeout ticks), DISARMS, and requires the count be ZERO.
///
/// The armed section of the test itself must also be allocation-free:
/// request bytes are prebuilt, responses land in fixed buffers, and
/// verification is done with memcmp. EXPECT failures may allocate — that
/// only happens when the gate has already failed.
///
/// Every replaceable form has to be here, not just the throwing ones. The
/// aggregate test binary links every package's tests, and anything in it
/// that allocates through the nothrow forms (libc++'s std::stable_sort
/// temporary buffer, for one) would otherwise get its memory from the
/// runtime's operator new and hand it to our malloc-based operator delete:
/// an alloc-dealloc mismatch under ASan.

#include "statusbar/http/http_alloc_gate_counting_new.hpp"
#include "statusbar/http/http_engine.hpp"
#include "statusbar/http/http_static.hpp"
#include "statusbar/http/http_test_support.hpp"
#include "statusbar/http/http_ws.hpp"
#include "statusbar/test/test.hpp"

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

// ---- the workload -----------------------------------------------------------

using namespace statusbar;
using namespace statusbar::http;
using namespace statusbar::http::test_support;

namespace {

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
    explicit GateWsEcho(HttpEngine*& server)
        : server_{server}
    {}
    void on_ws_message(size_t slot, std::span<uint8_t const> payload, bool is_text) override
    {
        (void)server_->ws_send_external(slot, payload, is_text);
    }
    HttpEngine*& server_;
};

/// One request/response over an existing keep-alive connection with
/// zero allocations: put prebuilt bytes on the wire, turn the reactor, and
/// check what the engine wrote where it lies, prefix and length.
auto exchange(
    ToldSite<>& site,
    size_t slot,
    std::vector<uint8_t> const& request,
    char const* expect_prefix,
    size_t expect_at_least,
    int64_t now0) -> bool
{
    bool const sent = site.wire.peer_sends(slot, std::span<uint8_t const>{request});
    (void)site.pump(30, now0);
    auto const response = site.wire.written(slot);
    size_t const prefix_len = strlen(expect_prefix);
    bool const ok = sent && response.size() >= expect_at_least && response.size() >= prefix_len &&
        std::memcmp(response.data(), expect_prefix, prefix_len) == 0;
    site.wire.take_written(slot);
    return ok;
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
    ToldSite<> site{limits, &*manifest};
    HttpEngine& server = site.engine;
    HttpEngine* server_ptr = &server;
    GateEcho echo;
    GateCount count;
    GateWsEcho ws_echo{server_ptr};
    EXPECT_TRUE(server.add_route(HttpMethod::post, "/echo", echo));
    EXPECT_TRUE(server.add_route(HttpMethod::put, "/count", count));
    EXPECT_TRUE(server.add_ws_route("/ws", ws_echo));

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
        ToldClient const probe{site.wire};
        probe.send_all(std::span<uint8_t const>{get_asset});
        (void)site.pump(30, 1);
        std::string const response = probe.received();
        auto const at = response.find("ETag: ");
        EXPECT_TRUE(at != std::string::npos);
        auto const etag = response.substr(at + 6, response.find('\r', at) - at - 6);
        return req("GET /asset HTTP/1.1\r\nHost: g\r\nIf-None-Match: " + etag + "\r\n\r\n");
    }();
    auto const ws_upgrade = req("GET /ws HTTP/1.1\r\nHost: g\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    auto const ws_text = masked_ws_frame(0x1, "meter update -36.5");
    auto const ws_ping = masked_ws_frame(0x9, "hb");

    // ---- warm-up: every kind once ---------------------------------------
    (void)site.pump(2, 50);  // the probe's connection is gone before the two that stay
    ToldClient const http_peer{site.wire, 60};
    ToldClient const ws_peer{site.wire, 60};
    size_t const http_client = http_peer.slot();
    size_t const ws_client = ws_peer.slot();
    EXPECT_TRUE(exchange(site, http_client, get_asset, "HTTP/1.1 200 OK", 2048, 100));
    EXPECT_TRUE(exchange(site, http_client, get_streamed, "HTTP/1.1 200 OK", 2048, 200));
    EXPECT_TRUE(exchange(site, http_client, head_asset, "HTTP/1.1 200 OK", 64, 300));
    EXPECT_TRUE(exchange(site, http_client, get_404, "HTTP/1.1 404", 32, 400));
    EXPECT_TRUE(exchange(site, http_client, post_echo, "HTTP/1.1 200 OK", 64, 500));
    EXPECT_TRUE(exchange(site, http_client, put_count, "HTTP/1.1 200 OK", 32, 600));
    EXPECT_TRUE(exchange(site, http_client, conditional, "HTTP/1.1 304", 32, 700));
    EXPECT_TRUE(exchange(site, ws_client, ws_upgrade, "HTTP/1.1 101", 64, 800));
    EXPECT_TRUE(exchange(site, ws_client, ws_text, "\x81", 4, 900));

    // ---- the gate --------------------------------------------------------
    g_alloc_count.store(0);
    g_alloc_armed.store(true);
    bool all_ok = true;
    for (int round = 0; round < 25; ++round) {
        int64_t const now = 10'000 + (int64_t(round) * 1'000);
        all_ok = all_ok && exchange(site, http_client, get_asset, "HTTP/1.1 200 OK", 2048, now);
        all_ok = all_ok && exchange(site, http_client, get_streamed, "HTTP/1.1 200 OK", 2048, now + 100);
        all_ok = all_ok && exchange(site, http_client, head_asset, "HTTP/1.1 200 OK", 64, now + 200);
        all_ok = all_ok && exchange(site, http_client, get_404, "HTTP/1.1 404", 32, now + 300);
        all_ok = all_ok && exchange(site, http_client, post_echo, "HTTP/1.1 200 OK", 64, now + 400);
        all_ok = all_ok && exchange(site, http_client, put_count, "HTTP/1.1 200 OK", 32, now + 500);
        all_ok = all_ok && exchange(site, http_client, conditional, "HTTP/1.1 304", 32, now + 600);
        all_ok = all_ok && exchange(site, http_client, pipelined, "HTTP/1.1 200 OK", 2100, now + 700);
        all_ok = all_ok && exchange(site, ws_client, ws_text, "\x81", 4, now + 800);
        all_ok = all_ok && exchange(site, ws_client, ws_ping, "\x8a", 4, now + 900);
    }
    g_alloc_armed.store(false);

    EXPECT_TRUE(all_ok);
    EXPECT_EQ(g_alloc_count.load(), 0U);
}

TEST_MAIN(statusbar_http, http_alloc_gate_test)
