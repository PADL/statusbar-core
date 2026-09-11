// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_handler.hpp"

#include "statusbar/http/http_server.hpp"
#include "statusbar/test/test.hpp"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>

using namespace statusbar;
using namespace statusbar::http;

namespace {

struct Client
{
    int fd{-1};

    explicit Client(net::SocketAddress const& to)
    {
        fd = ::socket(to.family(), SOCK_STREAM, 0);
        if (fd >= 0 && ::connect(fd, to.sockaddr(), to.length()) < 0) {
            ::close(fd);
            fd = -1;
        }
    }
    ~Client()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }
    Client(Client const&) = delete;
    auto operator=(Client const&) -> Client& = delete;

    void send_all(std::string_view text) const
    {
        auto const n = ::send(fd, text.data(), text.size(), 0);
        (void)n;
    }

    [[nodiscard]] auto recv_for(int budget_ms) const -> std::string
    {
        std::string out;
        std::array<char, 65536> buf{};
        for (int spent = 0; spent < budget_ms; spent += 10) {
            struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 10) <= 0) {
                continue;
            }
            auto const n = ::recv(fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                break;
            }
            out.append(buf.data(), size_t(n));
        }
        return out;
    }

    [[nodiscard]] auto at_eof() const -> bool
    {
        std::array<char, 16> buf{};
        struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 50) <= 0) {
            return false;
        }
        return ::recv(fd, buf.data(), buf.size(), 0) == 0;
    }
};

void pump(HttpServer& server, int rounds = 20, int64_t now0 = 1)
{
    for (int i = 0; i < rounds; ++i) {
        struct pollfd pfd{.fd = server.fd(), .events = POLLIN, .revents = 0};
        (void)::poll(&pfd, 1, 5);
        server.on_ready(now0 + i);
        server.tick(now0 + i);
    }
}

[[nodiscard]] auto status_line(std::string const& response) -> std::string
{
    return response.substr(0, response.find('\r'));
}

[[nodiscard]] auto header_value(std::string const& response, std::string_view name) -> std::string
{
    auto const at = response.find(std::string(name) + ": ");
    if (at == std::string::npos) {
        return {};
    }
    auto const start = at + name.size() + 2;
    return response.substr(start, response.find('\r', start) - start);
}

[[nodiscard]] auto body_of(std::string const& response) -> std::string
{
    auto const at = response.find("\r\n\r\n");
    return at == std::string::npos ? std::string{} : response.substr(at + 4);
}

/// Buffered echo: replies with the body it received, plus a custom header.
class EchoHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::buffer(); }

    void on_body_chunk(HttpRequest const&, std::span<uint8_t const> chunk) override { body.assign(chunk.begin(), chunk.end()); }

    void on_complete(HttpRequest const& request, ResponseWriter& writer) override
    {
        (void)writer.add_header("X-Echo-Path", request.path);
        (void)writer.send(200, "application/octet-stream", body);
    }

    std::vector<uint8_t> body;
};

/// Streaming counter: accepts any length chunk by chunk, replies with the
/// total from per-slot external storage.
class CountHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override
    {
        total = 0;
        chunks = 0;
        return Disposition::stream();
    }

    void on_body_chunk(HttpRequest const&, std::span<uint8_t const> chunk) override
    {
        total += chunk.size();
        ++chunks;
    }

    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        auto const n = snprintf(reply.data(), reply.size(), "count=%zu", total);
        (void)writer.send_external(
            200,
            "text/plain",
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            std::span<uint8_t const>{reinterpret_cast<uint8_t const*>(reply.data()), size_t(n)});
    }

    size_t total{0};
    size_t chunks{0};
    std::array<char, 32> reply{};  ///< stable until the response finishes
};

/// Teapot: rejects from on_headers; the body must still be consumed.
class RejectHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::reject(418); }
    void on_complete(HttpRequest const&, ResponseWriter&) override {}
};

/// Async: holds the slot in on_complete; the test completes it later.
class AsyncHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::buffer(); }
    void on_complete(HttpRequest const&, ResponseWriter& writer) override { held_slot = long(writer.slot()); }

    long held_slot{-1};
};

/// Eager: tries to answer from on_headers (refused), then answers
/// properly from on_complete.
class EagerHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter& writer) -> Disposition override
    {
        early_sent = writer.send(200, "text/plain", {});
        early_marked = writer.sent();
        return Disposition::buffer();
    }

    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        std::string_view const done{"late"};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        late_sent = writer.send(200, "text/plain", {reinterpret_cast<uint8_t const*>(done.data()), done.size()});
    }

    bool early_sent{true};
    bool early_marked{true};
    bool late_sent{false};
};

/// Overflow: builds a response the tx buffer cannot hold — a head made
/// too long by an extra header, or an inline body that does not fit
/// beside the head — then tries a second send.
class OverflowHandler : public HttpHandler
{
  public:
    explicit OverflowHandler(bool long_header)
        : long_header_{long_header}
    {}

    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::buffer(); }

    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        std::string const header(300, 'h');
        std::vector<uint8_t> const body(long_header_ ? 4 : 300, 'b');
        if (long_header_) {
            header_added = writer.add_header("X-Long", header);
        }
        first_sent = writer.send(200, "text/plain", body);
        marked = writer.sent();
        second_sent = writer.send(200, "text/plain", {});
    }

    bool header_added{false};
    bool first_sent{true};
    bool marked{false};
    bool second_sent{true};

  private:
    bool long_header_;
};

struct Fixture
{
    HttpLimits limits;
    std::unique_ptr<HttpServer> server;
    net::SocketAddress addr{};

    explicit Fixture(size_t max_body = 64, size_t max_response_head = 4096, int64_t keep_alive_idle_ns = 30'000'000'000)
    {
        limits.max_connections = 2;
        limits.max_body = max_body;
        limits.max_response_head = max_response_head;
        limits.keep_alive_idle_ns = keep_alive_idle_ns;
        server = std::make_unique<HttpServer>(net::SocketAddress::ipv4_loopback(0), limits);
        EXPECT_TRUE(server->valid());
        addr = *server->local_addr();
    }
};

}  // namespace

TEST(http_handler, buffered_echo_round_trip)
{
    Fixture fx;
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/echo", echo));

    Client c{fx.addr};
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\nhello world");
    pump(*fx.server);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(header_value(response, "X-Echo-Path") == "/echo");
    EXPECT_TRUE(header_value(response, "Content-Length") == "11");
    EXPECT_TRUE(body_of(response) == "hello world");

    // Keep-alive: a second echo on the same socket, body split mid-write.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\n\r\nabc");
    pump(*fx.server, 5);
    c.send_all("def");
    pump(*fx.server);
    EXPECT_TRUE(body_of(c.recv_for(150)) == "abcdef");
}

TEST(http_handler, streaming_accepts_beyond_max_body)
{
    Fixture fx{64};  // buffered cap is tiny; streaming must not care
    CountHandler counter;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/count", counter));

    std::string const body(50000, 'x');
    Client c{fx.addr};
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    pump(*fx.server, 60);
    auto const response = c.recv_for(200);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "count=50000");
    EXPECT_TRUE(counter.chunks > 1U);  // genuinely chunked, not buffered

    // The same request against a BUFFERED route answers 413 and closes
    // without draining the upload, like every other over-cap refusal.
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/buffered", echo));
    c.send_all("PUT /buffered HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    pump(*fx.server);
    auto const refused = c.recv_for(200);
    EXPECT_TRUE(status_line(refused) == "HTTP/1.1 413 Content Too Large");
    EXPECT_TRUE(header_value(refused, "Connection") == "close");
    EXPECT_TRUE(c.at_eof());
}

TEST(http_handler, reject_consumes_body_and_keeps_alive)
{
    Fixture fx;
    RejectHandler teapot;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/brew", teapot));
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/echo", echo));

    Client c{fx.addr};
    c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\n\r\ncoffee!!");
    pump(*fx.server);
    EXPECT_TRUE(status_line(c.recv_for(150)) == "HTTP/1.1 418 I'm a teapot");

    // Framing survived the rejected body: the next request works.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\nok");
    pump(*fx.server);
    EXPECT_TRUE(body_of(c.recv_for(150)) == "ok");
}

TEST(http_handler, method_mismatch_answers_405_with_allow)
{
    Fixture fx;
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/thing", echo));
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/thing", echo));
    // Duplicate registration is refused.
    EXPECT_FALSE(fx.server->add_route(HttpMethod::post, "/thing", echo));
    EXPECT_FALSE(fx.server->add_route(HttpMethod::get, "no-slash", echo));

    Client c{fx.addr};
    c.send_all("GET /thing HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 405 Method Not Allowed");
    EXPECT_TRUE(header_value(response, "Allow") == "POST, PUT");

    // Unregistered paths still fall through to 404.
    c.send_all("GET /elsewhere HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(status_line(c.recv_for(150)) == "HTTP/1.1 404 Not Found");
}

TEST(http_handler, async_completion_holds_the_slot)
{
    Fixture fx;
    AsyncHandler async;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/later", async));

    Client c{fx.addr};
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(async.held_slot >= 0);
    EXPECT_TRUE(c.recv_for(80).empty());  // held: nothing sent yet

    // Complete from "elsewhere" (still the reactor thread).
    auto writer = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer.has_value());
    std::string_view const done{"finally"};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_TRUE(writer->send(200, "text/plain", {reinterpret_cast<uint8_t const*>(done.data()), done.size()}));
    pump(*fx.server, 5);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "finally");

    // The writer is single-shot and the slot is no longer awaiting.
    EXPECT_FALSE(fx.server->respond(size_t(async.held_slot)).has_value());

    // Keep-alive: the connection still serves.
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(async.held_slot >= 0);
    auto writer2 = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer2.has_value());
    writer2->send_status(204);
    pump(*fx.server, 5);
    EXPECT_TRUE(status_line(c.recv_for(150)) == "HTTP/1.1 204 No Content");
}

TEST(http_handler, handlers_take_precedence_and_head_suppresses_body)
{
    Fixture fx;
    CountHandler counter;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/info", counter));
    EXPECT_TRUE(fx.server->add_route(HttpMethod::head, "/info", counter));

    Client c{fx.addr};
    c.send_all("HEAD /info HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server);
    auto const head = c.recv_for(150);
    EXPECT_TRUE(status_line(head) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(header_value(head, "Content-Length") == "7");  // "count=0"
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));                   // no body bytes
}

TEST(http_handler, reject_of_an_oversize_body_answers_and_closes)
{
    Fixture fx{64};
    RejectHandler teapot;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/brew", teapot));

    // The declared body exceeds max_body and never arrives: the rejection
    // must not wait to drain it (that would be an unbounded read of
    // attacker-sized junk); it answers at once and closes.
    Client c{fx.addr};
    c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
    pump(*fx.server);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 418 I'm a teapot");
    EXPECT_TRUE(header_value(response, "Connection") == "close");
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(fx.server->active_connections(), 0U);
}

TEST(http_handler, handler_responses_keep_the_idle_clock_current)
{
    Fixture fx{64, 4096, 5000};
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/ping", echo));

    // Two requests, well apart on the injected clock. The idle timer must
    // run from the SECOND response — a send that used a stale "now" would
    // leave the connection looking idle since the first.
    Client c{fx.addr};
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server, 3, 100);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server, 3, 3000);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");

    fx.server->tick(7000);  // 4000 since the second response: still alive
    EXPECT_EQ(fx.server->active_connections(), 1U);
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*fx.server, 3, 7001);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");

    fx.server->tick(7001 + 5001);  // and now it really is idle
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(fx.server->active_connections(), 0U);
}

TEST(http_handler, send_from_on_headers_is_refused)
{
    Fixture fx;
    EagerHandler eager;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/eager", eager));

    Client c{fx.addr};
    c.send_all("POST /eager HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc");
    pump(*fx.server);
    EXPECT_FALSE(eager.early_sent);
    EXPECT_FALSE(eager.early_marked);
    EXPECT_TRUE(eager.late_sent);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "late");
    EXPECT_TRUE(response.find("HTTP/1.1", 1) == std::string::npos);  // exactly one response

    // The connection is intact for the next request.
    c.send_all("POST /eager HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(body_of(c.recv_for(150)) == "late");
}

TEST(http_handler, unbuildable_responses_become_a_fixed_500)
{
    for (bool const long_header : {true, false}) {
        Fixture fx{64, 128};  // tx buffer: 128 bytes
        OverflowHandler overflow{long_header};
        EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/big", overflow));

        Client c{fx.addr};
        c.send_all("GET /big HTTP/1.1\r\nHost: t\r\n\r\n");
        pump(*fx.server);
        EXPECT_EQ(overflow.header_added, long_header);  // queued fine; the head is what overflows
        EXPECT_FALSE(overflow.first_sent);
        EXPECT_TRUE(overflow.marked);        // the 500 IS the response
        EXPECT_FALSE(overflow.second_sent);  // single-shot still holds
        auto const response = c.recv_for(150);
        EXPECT_TRUE(status_line(response) == "HTTP/1.1 500 Internal Server Error");
        EXPECT_TRUE(header_value(response, "Content-Length") == "0");
        EXPECT_TRUE(header_value(response, "Connection") == "close");
        EXPECT_TRUE(response.ends_with("\r\n\r\n"));
        EXPECT_TRUE(response.find("X-Long") == std::string::npos);  // nothing of the failed head leaks
        EXPECT_TRUE(c.at_eof());
        EXPECT_EQ(fx.server->active_connections(), 0U);
    }
}

TEST(http_handler, extra_header_space_and_body_chunk_come_from_limits)
{
    HttpLimits limits;
    limits.max_connections = 2;
    limits.max_body = 64;
    limits.max_extra_headers = 256;  // OverflowHandler's X-Long line is 310 bytes
    limits.body_chunk = 1000;
    HttpServer server{net::SocketAddress::ipv4_loopback(0), limits};
    EXPECT_TRUE(server.valid());
    auto const addr = *server.local_addr();

    OverflowHandler overflow{true};
    CountHandler counter;
    EXPECT_TRUE(server.add_route(HttpMethod::get, "/big", overflow));
    EXPECT_TRUE(server.add_route(HttpMethod::put, "/count", counter));

    // The queued header no longer fits; the response itself (4-byte body,
    // default tx buffer) is unaffected.
    Client c{addr};
    c.send_all("GET /big HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(server);
    EXPECT_FALSE(overflow.header_added);
    EXPECT_TRUE(overflow.first_sent);
    auto const response = c.recv_for(150);
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(response.find("X-Long") == std::string::npos);

    // Streamed reads are capped at body_chunk. The first chunk is whatever
    // rode in with the head (at most the rx buffer); everything after it
    // arrives in body_chunk-sized reads.
    size_t const rx_capacity = limits.max_request_line + limits.max_header_block + limits.max_body;
    size_t const min_chunks = 1 + ((50000 - rx_capacity + limits.body_chunk - 1) / limits.body_chunk);
    std::string const body(50000, 'x');
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    pump(server, 80);
    EXPECT_TRUE(body_of(c.recv_for(200)) == "count=50000");
    EXPECT_TRUE(counter.chunks >= min_chunks);
}

TEST(http_handler, expect_continue_gets_an_interim_100_before_the_body)
{
    Fixture fx;
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/echo", echo));
    CountHandler counter;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/count", counter));

    // Buffered: the client holds the body back until the 100 arrives.
    Client c{fx.addr};
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-Continue\r\nContent-Length: 5\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(c.recv_for(100) == "HTTP/1.1 100 Continue\r\n\r\n");
    c.send_all("hello");
    pump(*fx.server);
    auto const echoed = c.recv_for(150);
    EXPECT_TRUE(status_line(echoed) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(echoed) == "hello");

    // Streamed, same connection: the 100 sits alone, then the body.
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 7\r\n\r\n");
    pump(*fx.server);
    EXPECT_TRUE(c.recv_for(100) == "HTTP/1.1 100 Continue\r\n\r\n");
    c.send_all("1234567");
    pump(*fx.server);
    EXPECT_TRUE(body_of(c.recv_for(150)) == "count=7");

    // Body already riding with the head: no interim, the client was not
    // waiting for one.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok");
    pump(*fx.server);
    auto const direct = c.recv_for(150);
    EXPECT_TRUE(status_line(direct) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(direct) == "ok");
    EXPECT_FALSE(c.at_eof());
}

TEST(http_handler, expect_continue_on_a_refused_body_is_the_final_status_and_close)
{
    Fixture fx;
    RejectHandler teapot;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/brew", teapot));
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/echo", echo));

    // Rejected from on_headers: no 100, the status right away, closed.
    {
        Client c{fx.addr};
        c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\n");
        pump(*fx.server);
        auto const resp = c.recv_for(150);
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 418 I'm a teapot");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // Buffered but over max_body: 413 without waiting for the upload.
    {
        Client c{fx.addr};
        c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 65\r\n\r\n");
        pump(*fx.server);
        auto const resp = c.recv_for(150);
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 413 Content Too Large");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // No route: the 404 without draining a body nobody wants.
    {
        Client c{fx.addr};
        c.send_all("POST /nowhere HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\n");
        pump(*fx.server);
        auto const resp = c.recv_for(150);
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 404 Not Found");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // HTTP/1.0 never gets a 1xx: the engine reads the body as usual.
    {
        Client c{fx.addr};
        c.send_all("POST /echo HTTP/1.0\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n");
        pump(*fx.server);
        EXPECT_TRUE(c.recv_for(100).empty());
        c.send_all("ok");
        pump(*fx.server);
        EXPECT_TRUE(body_of(c.recv_for(150)) == "ok");
    }
}

TEST_MAIN(statusbar_http, http_handler_test)
