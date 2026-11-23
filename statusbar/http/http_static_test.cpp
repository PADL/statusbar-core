// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_static.hpp"

#include "statusbar/http/http_engine.hpp"
#include "statusbar/http/http_test_support.hpp"
#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar;
using namespace statusbar::http;
using namespace statusbar::http::test_support;

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

// The serving tests run the engine on a made-up wire (http_test_support.hpp):
// the files are real, the connection is not. No socket, and nothing waits.

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
    ToldSite<> web{limits, &*manifest};

    ToldClient c{web.wire};
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    web.pump();
    auto const index = c.received();
    EXPECT_TRUE(index.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(header_value(index, "Content-Type") == "text/html; charset=utf-8");
    EXPECT_TRUE(header_value(index, "Cache-Control") == "max-age=60");
    EXPECT_TRUE(index.ends_with("<html>hello</html>"));
    auto const etag = header_value(index, "ETag");
    EXPECT_FALSE(etag.empty());

    // Conditional GET with the matching ETag -> 304, no body, keep-alive.
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\nIf-None-Match: " + etag + "\r\n\r\n");
    web.pump();
    auto const not_modified = c.received();
    EXPECT_TRUE(not_modified.starts_with("HTTP/1.1 304 Not Modified\r\n"));
    EXPECT_TRUE(not_modified.ends_with("\r\n\r\n"));
    EXPECT_TRUE(header_value(not_modified, "ETag") == etag);

    // A stale ETag serves the full body again.
    c.send_all("GET / HTTP/1.1\r\nHost: t\r\nIf-None-Match: \"stale\"\r\n\r\n");
    web.pump();
    EXPECT_TRUE(c.received().ends_with("<html>hello</html>"));

    // HEAD: identical headers, no body, keep-alive framing intact.
    c.send_all("HEAD / HTTP/1.1\r\nHost: t\r\n\r\n");
    web.pump();
    auto const head = c.received();
    EXPECT_TRUE(head.starts_with("HTTP/1.1 200 OK\r\n"));
    EXPECT_TRUE(header_value(head, "Content-Length") == "18");
    EXPECT_TRUE(head.ends_with("\r\n\r\n"));

    // Unmapped path falls through to the dispatch seam (404), same socket.
    c.send_all("GET /nope HTTP/1.1\r\nHost: t\r\n\r\n");
    web.pump();
    EXPECT_TRUE(c.received().starts_with("HTTP/1.1 404 Not Found\r\n"));
}

namespace {

void stream_big(std::string_view uri, Site const& site)
{
    auto manifest = StaticManifest::load(site.manifest_path);
    EXPECT_TRUE(manifest.has_value());
    HttpLimits limits;
    limits.max_connections = 1;
    ToldSite<> web{limits, &*manifest};

    ToldClient c{web.wire};
    c.send_all(std::string("GET ") + std::string(uri) + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");

    // A peer that reads slowly, a few kilobytes a turn and never the same
    // amount twice running: the body must survive the backpressure and
    // arrive byte-exact.
    std::string response;
    for (int i = 0; i < 20000 && !c.at_eof(); ++i) {
        c.accept_only(size_t{1500} + (size_t(i % 7) * 1777));
        web.pump(1, i + 1);
        response += c.received();
    }
    response += c.received();
    EXPECT_TRUE(c.at_eof());
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
