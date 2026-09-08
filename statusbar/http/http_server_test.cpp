// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

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

/// Blocking loopback test client.
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

    /// Reads whatever arrives within ~budget_ms (poll-bounded).
    [[nodiscard]] auto recv_for(int budget_ms) const -> std::string
    {
        std::string out;
        std::array<char, 8192> buf{};
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

/// Test server exposing the M1 dispatch seam: 200 for /ok, 404 otherwise,
/// and a record of what was dispatched.
class TestServer : public HttpServer
{
  public:
    using HttpServer::HttpServer;

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

/// Drive the server like the reactor would, with an injected clock value.
void pump(HttpServer& server, int rounds = 20, int64_t now0 = 1)
{
    for (int i = 0; i < rounds; ++i) {
        struct pollfd pfd{.fd = server.fd(), .events = POLLIN, .revents = 0};
        (void)::poll(&pfd, 1, 5);
        server.on_ready(now0 + i);
        server.tick(now0 + i);
    }
}

auto make(TestServer*& out, HttpLimits const& limits) -> net::SocketAddress
{
    static std::vector<std::unique_ptr<TestServer>> keep;  // outlive each test body
    keep.push_back(std::make_unique<TestServer>(net::SocketAddress::ipv4_loopback(0), limits));
    out = keep.back().get();
    EXPECT_TRUE(out->valid());
    auto addr = out->local_addr();
    EXPECT_TRUE(addr.has_value());
    return *addr;
}

[[nodiscard]] auto status_line(std::string const& response) -> std::string
{
    return response.substr(0, response.find('\r'));
}

}  // namespace

TEST(http_server, serves_and_keeps_alive)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    Client c{addr};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    auto first = c.recv_for(100);
    EXPECT_TRUE(status_line(first) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(first.find("Connection: keep-alive") != std::string::npos);
    EXPECT_TRUE(first.find("Content-Length: 7") != std::string::npos);
    EXPECT_TRUE(first.ends_with("200 OK\n"));

    // Same connection serves the next request.
    c.send_all("GET /missing HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    auto second = c.recv_for(100);
    EXPECT_TRUE(status_line(second) == "HTTP/1.1 404 Not Found");
    EXPECT_EQ(server->paths.size(), 2U);
    EXPECT_TRUE(server->paths[0] == "/ok");
    EXPECT_TRUE(server->paths[1] == "/missing");
    EXPECT_EQ(server->active_connections(), 1U);
}

TEST(http_server, pipelined_requests_answer_in_order)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    Client c{addr};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\nGET /two HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    auto const both = c.recv_for(150);
    auto const first_at = both.find("HTTP/1.1 200 OK");
    auto const second_at = both.find("HTTP/1.1 404 Not Found");
    EXPECT_TRUE(first_at != std::string::npos);
    EXPECT_TRUE(second_at != std::string::npos);
    EXPECT_TRUE(first_at < second_at);
    EXPECT_EQ(server->paths.size(), 2U);
}

TEST(http_server, connection_close_is_honored)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    Client c{addr};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    pump(*server);
    auto const response = c.recv_for(100);
    EXPECT_TRUE(response.find("Connection: close") != std::string::npos);
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(server->active_connections(), 0U);
}

TEST(http_server, parse_failures_answer_specific_status_and_close)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    {
        Client c{addr};
        c.send_all("BREW /pot HTTP/1.1\r\nHost: t\r\n\r\n");
        pump(*server);
        EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 501 Not Implemented");
        EXPECT_TRUE(c.at_eof());
    }
    {
        Client c{addr};
        c.send_all("garbage\r\n\r\n");
        pump(*server);
        EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 400 Bad Request");
        EXPECT_TRUE(c.at_eof());
    }
    {
        // Oversize request line, no terminator anywhere.
        Client c{addr};
        c.send_all("GET /" + std::string(4096, 'a'));
        pump(*server);
        EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 414 URI Too Long");
        EXPECT_TRUE(c.at_eof());
    }
    // Dispatch never saw the malformed requests.
    EXPECT_EQ(server->paths.size(), 0U);
}

TEST(http_server, bodies_are_consumed_and_capped)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    Client c{addr};
    // Body split across writes; keep-alive must survive the discard.
    c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\n12345");
    pump(*server, 5);
    c.send_all("67890");
    pump(*server);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");
    EXPECT_EQ(server->body_lengths.back(), 10U);

    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");

    // Over the buffered-body cap: 413 and close, dispatch not called.
    auto const before = server->paths.size();
    c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
    pump(*server);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 413 Content Too Large");
    EXPECT_TRUE(c.at_eof());
    EXPECT_EQ(server->paths.size(), before);
}

TEST(http_server, head_error_responses_carry_no_body)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    // A HEAD that misses answers 404 with the body's Content-Length but
    // no body bytes — otherwise the client would read "404 Not Found\n"
    // as the start of the next response on this keep-alive connection.
    Client c{addr};
    c.send_all("HEAD /missing HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    auto const head = c.recv_for(100);
    EXPECT_TRUE(status_line(head) == "HTTP/1.1 404 Not Found");
    EXPECT_TRUE(head.find("Content-Length: 14") != std::string::npos);
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));

    // Framing intact: the next response starts cleanly.
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    auto const next = c.recv_for(100);
    EXPECT_TRUE(status_line(next) == "HTTP/1.1 200 OK");
    EXPECT_TRUE(next.ends_with("200 OK\n"));
    EXPECT_EQ(server->active_connections(), 1U);
}

TEST(http_server, reset_mid_body_closes_the_slot)
{
    TestServer* server = nullptr;
    auto const addr = make(server, small_limits());

    {
        Client c{addr};
        c.send_all("POST /ok HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\n12345");
        pump(*server, 5);
        EXPECT_EQ(server->active_connections(), 1U);
        // Abort rather than close: linger 0 makes close() send RST, so the
        // server's next read fails hard instead of seeing EOF.
        struct linger const rst{.l_onoff = 1, .l_linger = 0};
        EXPECT_EQ(::setsockopt(c.fd, SOL_SOCKET, SO_LINGER, &rst, sizeof rst), 0);
    }
    pump(*server);
    // A hard read error must release the slot (a level-triggered reactor
    // would otherwise keep reporting it readable), and dispatch never
    // saw the half request.
    EXPECT_EQ(server->active_connections(), 0U);
    EXPECT_EQ(server->paths.size(), 0U);

    // The pool is healthy afterwards.
    Client c{addr};
    c.send_all("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(*server);
    EXPECT_TRUE(status_line(c.recv_for(100)) == "HTTP/1.1 200 OK");
}

TEST(http_server, slow_loris_gets_408_and_idle_gets_closed)
{
    TestServer* server = nullptr;
    auto limits = small_limits();
    limits.header_read_timeout_ns = 1000;
    limits.keep_alive_idle_ns = 5000;
    auto const addr = make(server, limits);

    // Partial head, then the clock advances past the header timeout.
    Client slow{addr};
    slow.send_all("GET /ok HTTP/1.1\r\nHost:");
    pump(*server, 3, 100);
    server->tick(100 + 5000);
    EXPECT_TRUE(status_line(slow.recv_for(100)) == "HTTP/1.1 408 Request Timeout");
    EXPECT_TRUE(slow.at_eof());

    // An idle keep-alive connection is closed silently.
    Client idle{addr};
    pump(*server, 3, 200);
    EXPECT_EQ(server->active_connections(), 1U);
    server->tick(200 + 50000);
    EXPECT_TRUE(idle.recv_for(50).empty());
    EXPECT_TRUE(idle.at_eof());
    EXPECT_EQ(server->active_connections(), 0U);
}

TEST_MAIN(statusbar_http, http_server_test)
