// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_static.hpp"

#include "statusbar/http/http_server.hpp"
#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>

using namespace statusbar;
using namespace statusbar::http;

namespace {

/// A throwaway site on disk: index, an app.js, a 1 MiB asset (mmap), and
/// the same asset again as a pread-streamed route.
struct Site
{
    std::string dir;
    std::string manifest_path;
    std::vector<uint8_t> big;

    Site()
    {
        char tmpl[] = "/tmp/http_static_test_XXXXXX";
        dir = ::mkdtemp(tmpl);
        write_file("index.html", "<html>hello</html>");
        write_file("app.js", "console.log(1);\n");
        big.resize(size_t{1} * 1024 * 1024);
        for (size_t i = 0; i < big.size(); ++i) {
            big[i] = uint8_t((i * 131) + 17);
        }
        write_file(
            "big.bin",
            std::string_view{
                reinterpret_cast<char const*>(big.data()), big.size()});  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        write_file(
            "manifest.toml",
            "[[route]]\n"
            "uri = \"/\"\n"
            "file = \"index.html\"\n"
            "type = \"text/html; charset=utf-8\"\n"
            "cache = \"max-age=60\"\n"
            "\n"
            "[[route]]\n"
            "uri = \"/app.js\"\n"
            "file = \"app.js\"\n"
            "type = \"application/javascript\"\n"
            "\n"
            "[[route]]\n"
            "uri = \"/big.bin\"\n"
            "file = \"big.bin\"\n"
            "type = \"application/octet-stream\"\n"
            "\n"
            "[[route]]\n"
            "uri = \"/big-streamed.bin\"\n"
            "file = \"big.bin\"\n"
            "type = \"application/octet-stream\"\n"
            "stream = true\n");
        manifest_path = dir + "/manifest.toml";
    }

    void write_file(std::string const& name, std::string_view content) const
    {
        auto* f = std::fopen((dir + "/" + name).c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        (void)std::fwrite(content.data(), 1, content.size(), f);
        (void)std::fclose(f);
    }
};

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

[[nodiscard]] auto header_value(std::string const& response, std::string_view name) -> std::string
{
    auto const at = response.find(std::string(name) + ": ");
    if (at == std::string::npos) {
        return {};
    }
    auto const start = at + name.size() + 2;
    return response.substr(start, response.find('\r', start) - start);
}

}  // namespace

TEST(http_static, manifest_load_and_lookup)
{
    Site site;
    auto manifest = StaticManifest::load(site.manifest_path);
    EXPECT_TRUE(manifest.has_value());
    EXPECT_EQ(manifest->size(), 4U);

    auto const* index = manifest->find("/");
    EXPECT_TRUE(index != nullptr);
    EXPECT_TRUE(index->content_type == "text/html; charset=utf-8");
    EXPECT_TRUE(index->cache_control == "max-age=60");
    EXPECT_EQ(index->size, 18U);
    EXPECT_FALSE(index->data.empty());  // mmap-backed
    EXPECT_FALSE(index->etag.empty());
    EXPECT_TRUE(index->last_modified.ends_with(" GMT"));

    auto const* streamed = manifest->find("/big-streamed.bin");
    EXPECT_TRUE(streamed != nullptr);
    EXPECT_TRUE(streamed->data.empty());  // pread-backed
    EXPECT_TRUE(streamed->fd >= 0);

    EXPECT_TRUE(manifest->find("/nope") == nullptr);
    EXPECT_TRUE(manifest->find("/app.js") != nullptr);
}

TEST(http_static, load_fails_loudly)
{
    Site site;
    // A route pointing at a missing file fails the whole load.
    site.write_file("broken.toml", "[[route]]\nuri = \"/x\"\nfile = \"missing.bin\"\ntype = \"text/plain\"\n");
    EXPECT_FALSE(StaticManifest::load(site.dir + "/broken.toml").has_value());
    // Duplicate URIs fail.
    site.write_file(
        "dup.toml",
        "[[route]]\nuri = \"/x\"\nfile = \"app.js\"\ntype = \"a\"\n"
        "[[route]]\nuri = \"/x\"\nfile = \"app.js\"\ntype = \"a\"\n");
    EXPECT_FALSE(StaticManifest::load(site.dir + "/dup.toml").has_value());
    // Missing keys fail.
    site.write_file("nokey.toml", "[[route]]\nuri = \"/x\"\nfile = \"app.js\"\n");
    EXPECT_FALSE(StaticManifest::load(site.dir + "/nokey.toml").has_value());
    // Garbage TOML fails.
    site.write_file("bad.toml", "[[route\n");
    EXPECT_FALSE(StaticManifest::load(site.dir + "/bad.toml").has_value());
}

TEST(http_static, serves_get_head_and_conditional)
{
    Site site;
    auto manifest = StaticManifest::load(site.manifest_path);
    EXPECT_TRUE(manifest.has_value());
    HttpLimits limits;
    limits.max_connections = 2;
    HttpServer server{net::SocketAddress::ipv4_loopback(0), limits, &*manifest};
    EXPECT_TRUE(server.valid());
    auto const addr = *server.local_addr();

    Client c{addr};
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(server);
    auto const index = c.recv_for(100);
    EXPECT_TRUE(index.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(header_value(index, "Content-Type") == "text/html; charset=utf-8");
    EXPECT_TRUE(header_value(index, "Cache-Control") == "max-age=60");
    EXPECT_TRUE(index.ends_with("<html>hello</html>"));
    auto const etag = header_value(index, "ETag");
    EXPECT_FALSE(etag.empty());

    // Conditional GET with the matching ETag -> 304, no body, keep-alive.
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\nIf-None-Match: " + etag + "\r\n\r\n");
    pump(server);
    auto const not_modified = c.recv_for(100);
    EXPECT_TRUE(not_modified.starts_with("HTTP/1.1 304 Not Modified\r\n"));
    EXPECT_TRUE(not_modified.ends_with("\r\n\r\n"));
    EXPECT_TRUE(header_value(not_modified, "ETag") == etag);

    // A stale ETag serves the full body again.
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\nIf-None-Match: \"stale\"\r\n\r\n");
    pump(server);
    EXPECT_TRUE(c.recv_for(100).ends_with("<html>hello</html>"));

    // HEAD: identical headers, no body, keep-alive framing intact.
    c.send_all("HEAD / HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(server);
    auto const head = c.recv_for(100);
    EXPECT_TRUE(head.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(header_value(head, "Content-Length") == "18");
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));

    // Unmapped path falls through to the dispatch seam (404), same socket.
    c.send_all("GET /nope HTTP/1.1\r\nHost: t\r\n\r\n");
    pump(server);
    EXPECT_TRUE(c.recv_for(100).starts_with("HTTP/1.1 404 Not Found\r\n"));
}

namespace {

void stream_big(std::string_view uri, Site const& site)
{
    auto manifest = StaticManifest::load(site.manifest_path);
    EXPECT_TRUE(manifest.has_value());
    HttpLimits limits;
    limits.max_connections = 1;
    HttpServer server{net::SocketAddress::ipv4_loopback(0), limits, &*manifest};
    auto const addr = *server.local_addr();

    Client c{addr};
    c.send_all(std::string("GET ") + std::string(uri) + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    (void)::fcntl(c.fd, F_SETFL, O_NONBLOCK);

    // Drain slowly while pumping — the body must survive backpressure and
    // arrive byte-exact.
    std::string response;
    std::array<char, 32768> buf{};
    for (int i = 0; i < 20000 && response.size() < site.big.size(); ++i) {
        pump(server, 1, i + 1);
        for (;;) {
            auto const n = ::recv(c.fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                break;
            }
            response.append(buf.data(), size_t(n));
        }
    }
    auto const body_at = response.find("\r\n\r\n");
    EXPECT_TRUE(body_at != std::string::npos);
    auto const body = std::string_view{response}.substr(body_at + 4);
    EXPECT_EQ(body.size(), site.big.size());
    EXPECT_TRUE(std::equal(body.begin(), body.end(), site.big.begin(), [](char a, uint8_t b) { return uint8_t(a) == b; }));
}

}  // namespace

TEST(http_static, one_mib_mmap_body_streams_byte_exact)
{
    Site site;
    stream_big("/big.bin", site);
}

TEST(http_static, one_mib_pread_body_streams_byte_exact)
{
    Site site;
    stream_big("/big-streamed.bin", site);
}

TEST_MAIN(statusbar_http, http_static_test)
