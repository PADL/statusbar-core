// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_handler.hpp"

#include "statusbar/http/http_engine.hpp"
#include "statusbar/http/http_test_support.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar;
using namespace statusbar::http;
using namespace statusbar::http::test_support;

namespace {

// The engine runs here on a made-up wire (http_test_support.hpp): each test
// says what the peer sends, turns the reactor by hand on a clock it makes up,
// and reads back exactly what the engine wrote. No socket, and nothing waits.

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
    ToldSite<> site;
    HttpEngine* server{&site.engine};

    explicit Fixture(size_t max_body = 64, size_t max_response_head = 4096, int64_t keep_alive_idle_ns = 30'000'000'000)
        : site{limits_for(max_body, max_response_head, keep_alive_idle_ns)}
    {}

    static auto limits_for(size_t max_body, size_t max_response_head, int64_t keep_alive_idle_ns) -> HttpLimits
    {
        HttpLimits limits;
        limits.max_connections = 2;
        limits.max_body = max_body;
        limits.max_response_head = max_response_head;
        limits.keep_alive_idle_ns = keep_alive_idle_ns;
        return limits;
    }

    auto pump(int rounds = 20, int64_t now0 = 1) -> size_t { return site.pump(rounds, now0); }
};

}  // namespace

TEST(http_handler, buffered_echo_round_trip)
{
    Fixture fx;
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/echo", echo));

    ToldClient c{fx.site.wire};
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\nhello world");
    fx.pump();
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(header_value(response, "X-Echo-Path") == "/echo");
    EXPECT_TRUE(header_value(response, "Content-Length") == "11");
    EXPECT_TRUE(body_of(response) == "hello world");

    // Keep-alive: a second echo on the same socket, body split mid-write.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\n\r\nabc");
    fx.pump(5);
    c.send_all("def");
    fx.pump();
    EXPECT_TRUE(body_of(c.received()) == "abcdef");
}

TEST(http_handler, streaming_accepts_beyond_max_body)
{
    Fixture fx{64};  // buffered cap is tiny; streaming must not care
    CountHandler counter;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/count", counter));

    std::string const body(50000, 'x');
    ToldClient c{fx.site.wire};
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    fx.pump(60);
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "count=50000");
    EXPECT_TRUE(counter.chunks > 1U);  // genuinely chunked, not buffered

    // The same request against a BUFFERED route answers 413 and closes
    // without draining the upload, like every other over-cap refusal.
    EchoHandler echo;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::put, "/buffered", echo));
    c.send_all("PUT /buffered HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    fx.pump();
    auto const refused = c.received();
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

    ToldClient c{fx.site.wire};
    c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\n\r\ncoffee!!");
    fx.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 418 I'm a teapot");

    // Framing survived the rejected body: the next request works.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\nok");
    fx.pump();
    EXPECT_TRUE(body_of(c.received()) == "ok");
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

    ToldClient c{fx.site.wire};
    c.send_all("GET /thing HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 405 Method Not Allowed");
    EXPECT_TRUE(header_value(response, "Allow") == "POST, PUT");

    // Unregistered paths still fall through to 404.
    c.send_all("GET /elsewhere HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 404 Not Found");
}

TEST(http_handler, async_completion_holds_the_slot)
{
    Fixture fx;
    AsyncHandler async;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/later", async));

    ToldClient c{fx.site.wire};
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(async.held_slot >= 0);
    EXPECT_TRUE(c.received().empty());  // held: nothing sent yet

    // Complete from "elsewhere" (still the reactor thread).
    auto writer = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer.has_value());
    std::string_view const done{"finally"};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_TRUE(writer->send(200, "text/plain", {reinterpret_cast<uint8_t const*>(done.data()), done.size()}));
    fx.pump(5);
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "finally");

    // The writer is single-shot and the slot is no longer awaiting.
    EXPECT_FALSE(fx.server->respond(size_t(async.held_slot)).has_value());

    // Keep-alive: the connection still serves.
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(async.held_slot >= 0);
    auto writer2 = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer2.has_value());
    writer2->send_status(204);
    fx.pump(5);
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 204 No Content");
}

TEST(http_handler, handlers_take_precedence_and_head_suppresses_body)
{
    Fixture fx;
    CountHandler counter;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/info", counter));
    EXPECT_TRUE(fx.server->add_route(HttpMethod::head, "/info", counter));

    ToldClient c{fx.site.wire};
    c.send_all("HEAD /info HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    auto const head = c.received();
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
    ToldClient c{fx.site.wire};
    c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
    fx.pump();
    auto const response = c.received();
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
    ToldClient c{fx.site.wire};
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump(3, 100);
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump(3, 3000);
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");

    fx.server->tick(7000);  // 4000 since the second response: still alive
    EXPECT_EQ(fx.server->active_connections(), 1U);
    c.send_all("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump(3, 7001);
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");

    fx.server->tick(7001 + 5001);  // and now it really is idle
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(fx.server->active_connections(), 0U);
}

TEST(http_handler, send_from_on_headers_is_refused)
{
    Fixture fx;
    EagerHandler eager;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::post, "/eager", eager));

    ToldClient c{fx.site.wire};
    c.send_all("POST /eager HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc");
    fx.pump();
    EXPECT_FALSE(eager.early_sent);
    EXPECT_FALSE(eager.early_marked);
    EXPECT_TRUE(eager.late_sent);
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(response) == "late");
    EXPECT_TRUE(response.find("HTTP/1.1", 1) == std::string::npos);  // exactly one response

    // The connection is intact for the next request.
    c.send_all("POST /eager HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(body_of(c.received()) == "late");
}

TEST(http_handler, unbuildable_responses_become_a_fixed_500)
{
    for (bool const long_header : {true, false}) {
        Fixture fx{64, 128};  // tx buffer: 128 bytes
        OverflowHandler overflow{long_header};
        EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/big", overflow));

        ToldClient c{fx.site.wire};
        c.send_all("GET /big HTTP/1.1\r\nHost: t\r\n\r\n");
        fx.pump();
        EXPECT_EQ(overflow.header_added, long_header);  // queued fine; the head is what overflows
        EXPECT_FALSE(overflow.first_sent);
        EXPECT_TRUE(overflow.marked);        // the 500 IS the response
        EXPECT_FALSE(overflow.second_sent);  // single-shot still holds
        auto const response = c.received();
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
    ToldSite<> site{limits};

    OverflowHandler overflow{true};
    CountHandler counter;
    EXPECT_TRUE(site.engine.add_route(HttpMethod::get, "/big", overflow));
    EXPECT_TRUE(site.engine.add_route(HttpMethod::put, "/count", counter));

    // The queued header no longer fits; the response itself (4-byte body,
    // default tx buffer) is unaffected.
    ToldClient c{site.wire};
    c.send_all("GET /big HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    EXPECT_FALSE(overflow.header_added);
    EXPECT_TRUE(overflow.first_sent);
    auto const response = c.received();
    EXPECT_TRUE(status_line(response) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(response.find("X-Long") == std::string::npos);

    // Streamed reads are capped at body_chunk. The first chunk is whatever
    // rode in with the head (at most the rx buffer); everything after it
    // arrives in body_chunk-sized reads.
    size_t const rx_capacity = limits.max_request_line + limits.max_header_block + limits.max_body;
    size_t const min_chunks = 1 + ((50000 - rx_capacity + limits.body_chunk - 1) / limits.body_chunk);
    std::string const body(50000, 'x');
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n" + body);
    site.pump(80);
    EXPECT_TRUE(body_of(c.received()) == "count=50000");
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
    ToldClient c{fx.site.wire};
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-Continue\r\nContent-Length: 5\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(c.received() == "HTTP/1.1 100 Continue\r\n\r\n");
    c.send_all("hello");
    fx.pump();
    auto const echoed = c.received();
    EXPECT_TRUE(status_line(echoed) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(body_of(echoed) == "hello");

    // Streamed, same connection: the 100 sits alone, then the body.
    c.send_all("PUT /count HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 7\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(c.received() == "HTTP/1.1 100 Continue\r\n\r\n");
    c.send_all("1234567");
    fx.pump();
    EXPECT_TRUE(body_of(c.received()) == "count=7");

    // Body already riding with the head: no interim, the client was not
    // waiting for one.
    c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok");
    fx.pump();
    auto const direct = c.received();
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
        ToldClient c{fx.site.wire};
        c.send_all("POST /brew HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\n");
        fx.pump();
        auto const resp = c.received();
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 418 I'm a teapot");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // Buffered but over max_body: 413 without waiting for the upload.
    {
        ToldClient c{fx.site.wire};
        c.send_all("POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 65\r\n\r\n");
        fx.pump();
        auto const resp = c.received();
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 413 Content Too Large");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // No route: the 404 without draining a body nobody wants.
    {
        ToldClient c{fx.site.wire};
        c.send_all("POST /nowhere HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\n");
        fx.pump();
        auto const resp = c.received();
        EXPECT_TRUE(status_line(resp) == "HTTP/1.1 404 Not Found");
        EXPECT_TRUE(header_value(resp, "Connection") == "close");
        EXPECT_TRUE(c.at_eof());
    }
    // HTTP/1.0 never gets a 1xx: the engine reads the body as usual.
    {
        ToldClient c{fx.site.wire};
        c.send_all("POST /echo HTTP/1.0\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n");
        fx.pump();
        EXPECT_TRUE(c.received().empty());
        c.send_all("ok");
        fx.pump();
        EXPECT_TRUE(body_of(c.received()) == "ok");
    }
}

TEST(http_handler, bytes_behind_a_held_request_do_not_spin_the_reactor)
{
    Fixture fx;
    AsyncHandler async;
    EXPECT_TRUE(fx.server->add_route(HttpMethod::get, "/later", async));

    ToldClient c{fx.site.wire};
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    fx.pump();
    EXPECT_TRUE(async.held_slot >= 0);

    // A pipelined request lands while the first is held. Its bytes stay on
    // the wire until the response goes out; level-triggered, they are
    // "readable" on every poll unless the engine has turned the slot's
    // read interest off, and the reactor would spin for as long as the
    // handler takes. Thirty turns of the reactor raise nothing at all.
    c.send_all("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
    EXPECT_FALSE(fx.site.wire.read_interest(c.slot()));
    EXPECT_EQ(fx.pump(30, 100), size_t{0});
    EXPECT_EQ(fx.site.wire.unread(c.slot()), std::string_view{"GET /later HTTP/1.1\r\nHost: t\r\n\r\n"}.size());
    EXPECT_TRUE(c.received().empty());  // and nothing was answered early

    // Completing the held request lets the waiting one through to the
    // handler, which holds it in turn (synchronously, as the response
    // drains, so the marker is cleared before the send).
    auto writer = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer.has_value());
    async.held_slot = -1;
    writer->send_status(204);
    fx.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 204 No Content");
    EXPECT_TRUE(async.held_slot >= 0);
    auto writer2 = fx.server->respond(size_t(async.held_slot));
    EXPECT_TRUE(writer2.has_value());
    writer2->send_status(204);
    fx.pump(5);
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 204 No Content");
}

TEST_MAIN(statusbar_http, http_handler_test)
