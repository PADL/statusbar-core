// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

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

/// Test engine exposing the M1 dispatch seam: 200 for /ok, 404 otherwise,
/// and a record of what was dispatched.
class TestEngine : public HttpEngine
{
  public:
    using HttpEngine::HttpEngine;

    std::vector<std::string> paths;
    std::vector<uint64_t> body_lengths;

  protected:
    [[nodiscard]] auto dispatch(size_t /*slot*/, HttpRequest const& request) -> uint16_t override
    {
        paths.emplace_back(request.path);
        body_lengths.push_back(request.has_content_length ? request.content_length : 0);
        return request.path == "/ok" ? 200 : 404;
    }
};

auto small_limits() -> HttpLimits
{
    HttpLimits limits;
    limits.max_connections = 2;
    limits.max_body = 64;
    return limits;
}

using TestSite = ToldSite<TestEngine>;

}  // namespace

TEST(http_server, serves_and_keeps_alive)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    ToldClient c{site.wire};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    auto first = c.received();
    EXPECT_TRUE(status_line(first) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(first.find("Connection: keep-alive") != std::string::npos);
    EXPECT_TRUE(first.find("Content-Length: 7") != std::string::npos);
    EXPECT_TRUE(first.ends_with("200 OK\n"));

    // Same connection serves the next request.
    c.send_all("GET /missing HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    auto second = c.received();
    EXPECT_TRUE(status_line(second) == "HTTP/1.1 404 Not Found");
    EXPECT_EQ(server->paths.size(), 2U);
    EXPECT_TRUE(server->paths[0] == "/ok");
    EXPECT_TRUE(server->paths[1] == "/missing");
    EXPECT_EQ(server->active_connections(), 1U);
}

TEST(http_server, pipelined_requests_answer_in_order)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    ToldClient c{site.wire};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\nGET /two HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    auto const both = c.received();
    auto const first_at = both.find("HTTP/1.1 200 OK");
    auto const second_at = both.find("HTTP/1.1 404 Not Found");
    EXPECT_TRUE(first_at != std::string::npos);
    EXPECT_TRUE(second_at != std::string::npos);
    EXPECT_TRUE(first_at < second_at);
    EXPECT_EQ(server->paths.size(), 2U);
}

TEST(http_server, connection_close_is_honored)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    ToldClient c{site.wire};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    site.pump();
    auto const response = c.received();
    EXPECT_TRUE(response.find("Connection: close") != std::string::npos);
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(server->active_connections(), 0U);
}

TEST(http_server, parse_failures_answer_specific_status_and_close)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    {
        ToldClient c{site.wire};
        c.send_all("BREW /pot HTTP/1.1\r\nHost: t\r\n\r\n");
        site.pump();
        EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 501 Not Implemented");
        EXPECT_TRUE(c.at_eof());
    }
    {
        ToldClient c{site.wire};
        c.send_all("garbage\r\n\r\n");
        site.pump();
        EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 400 Bad Request");
        EXPECT_TRUE(c.at_eof());
    }
    {
        // Oversize request line, no terminator anywhere.
        ToldClient c{site.wire};
        c.send_all("GET /" + std::string(4096, 'a'));
        site.pump();
        EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 414 URI Too Long");
        EXPECT_TRUE(c.at_eof());
    }
    // Dispatch never saw the malformed requests.
    EXPECT_EQ(server->paths.size(), 0U);
}

TEST(http_server, bodies_are_consumed_and_capped)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    ToldClient c{site.wire};
    // Body split across writes; keep-alive must survive the discard.
    c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\n12345");
    site.pump(5);
    c.send_all("67890");
    site.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");
    EXPECT_EQ(server->body_lengths.back(), 10U);

    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");

    // Over the buffered-body cap: 413 and close, dispatch not called.
    auto const before = server->paths.size();
    c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
    site.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 413 Content Too Large");
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(server->paths.size(), before);
}

TEST(http_server, head_error_responses_carry_no_body)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    // A HEAD that misses answers 404 with the body's Content-Length but
    // no body bytes — otherwise the client would read "404 Not Found\n"
    // as the start of the next response on this keep-alive connection.
    ToldClient c{site.wire};
    c.send_all("HEAD /missing HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    auto const head = c.received();
    EXPECT_TRUE(status_line(head) == "HTTP/1.1 404 Not Found");
    EXPECT_TRUE(head.find("Content-Length: 14") != std::string::npos);
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));

    // Framing intact: the next response starts cleanly.
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    auto const next = c.received();
    EXPECT_TRUE(status_line(next) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(next.ends_with("200 OK\n"));
    EXPECT_EQ(server->active_connections(), 1U);
}

TEST(http_server, reset_mid_body_closes_the_slot)
{
    TestSite site{small_limits()};
    TestEngine* const server = &site.engine;

    {
        ToldClient c{site.wire};
        c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\n12345");
        site.pump(5);
        EXPECT_EQ(server->active_connections(), 1U);
        // Abort rather than close: the engine's next read fails hard
        // instead of seeing EOF.
        c.reset();
    }
    site.pump();
    // A hard read error must release the slot (a level-triggered reactor
    // would otherwise keep reporting it readable), and dispatch never
    // saw the half request.
    EXPECT_EQ(server->active_connections(), 0U);
    EXPECT_EQ(server->paths.size(), 0U);

    // The pool is healthy afterwards.
    ToldClient c{site.wire};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    site.pump();
    EXPECT_TRUE(status_line(c.received()) == "HTTP/1.1 200 OK");
}

TEST(http_server, slow_loris_gets_408_and_idle_gets_closed)
{
    auto limits = small_limits();
    limits.header_read_timeout_ns = 1000;
    limits.keep_alive_idle_ns = 5000;
    TestSite site{limits};
    TestEngine* const server = &site.engine;

    // Partial head, then the clock advances past the header timeout.
    ToldClient slow{site.wire};
    slow.send_all("GET /ok HTTP/1.1\r\nHost:");
    site.pump(3, 100);
    server->tick(100 + 5000);
    EXPECT_TRUE(status_line(slow.received()) == "HTTP/1.1 408 Request Timeout");
    EXPECT_TRUE(slow.at_eof());

    // An idle keep-alive connection is closed silently.
    ToldClient idle{site.wire, 200};
    site.pump(3, 200);
    EXPECT_EQ(server->active_connections(), 1U);
    server->tick(200 + 50000);
    EXPECT_TRUE(idle.received().empty());
    EXPECT_TRUE(idle.at_eof());
    EXPECT_EQ(server->active_connections(), 0U);
}

TEST_MAIN(statusbar_http, http_server_test)
