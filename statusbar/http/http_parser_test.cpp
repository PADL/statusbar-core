// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_parser.hpp"

#include "statusbar/test/test.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar::http;

namespace {

auto bytes(std::string_view s) -> std::span<uint8_t const>
{
    return {reinterpret_cast<uint8_t const*>(s.data()), s.size()};  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}

/// Feed the whole request at once.
auto parse_whole(HttpParser& p, std::string_view text) -> ParseState
{
    p.reset();
    return p.parse(bytes(text));
}

/// Feed the request one byte at a time (the buffer grows, the address
/// base stays — mirroring an rx buffer filling up).
auto parse_split(HttpParser& p, std::string_view text) -> ParseState
{
    p.reset();
    auto state = ParseState::need_more;
    for (size_t n = 1; n <= text.size(); ++n) {
        state = p.parse(bytes(text.substr(0, n)));
        if (state != ParseState::need_more) {
            break;
        }
    }
    return state;
}

auto limits() -> HttpLimits
{
    return HttpLimits{};
}

constexpr std::string_view GET_OK = "GET /index.html?x=1 HTTP/1.1\r\nHost: unit\r\nAccept: */*\r\n\r\n";

}  // namespace

TEST(http_parser, parses_a_simple_get)
{
    HttpParser p{limits()};
    EXPECT_TRUE(parse_whole(p, GET_OK) == ParseState::complete);
    auto const& r = p.request();
    EXPECT_TRUE(r.method == HttpMethod::get);
    EXPECT_TRUE(r.target == "/index.html?x=1");
    EXPECT_TRUE(r.path == "/index.html");
    EXPECT_TRUE(r.query == "x=1");
    EXPECT_EQ(r.version_minor, 1);
    EXPECT_TRUE(r.keep_alive);
    EXPECT_FALSE(r.has_content_length);
    EXPECT_EQ(r.headers.size(), 2U);
    EXPECT_TRUE(r.header("HOST") == "unit");
    EXPECT_TRUE(r.header("accept") == "*/*");
    EXPECT_TRUE(r.header("absent").empty());
    EXPECT_EQ(p.consumed(), GET_OK.size());
}

TEST(http_parser, byte_split_matches_whole_feed)
{
    // Byte-at-a-time parsing must agree with whole-buffer parsing on
    // every observable, over a corpus of shapes.
    std::vector<std::string> const corpus{
        std::string{GET_OK},
        "POST /api/set HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
        "PUT /f HTTP/1.1\r\nhost: h\r\ncontent-length: 0\r\n\r\n",
        "HEAD /a/b/c HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        "OPTIONS /x HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
        "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
        "GET /a%20b/c%2ed HTTP/1.1\r\nHost: h\r\n\r\n",
        "GET /a/b/../c/./d//e HTTP/1.1\r\nHost: h\r\n\r\n",
        "\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",  // leading blank line
        "GET / HTTP/1.1\nHost: h\n\n",            // bare-LF terminators
    };
    HttpParser whole{limits()};
    HttpParser split{limits()};
    for (auto const& text : corpus) {
        auto const sw = parse_whole(whole, text);
        auto const ss = parse_split(split, text);
        EXPECT_TRUE(sw == ParseState::complete);
        EXPECT_TRUE(ss == sw);
        auto const& a = whole.request();
        auto const& b = split.request();
        EXPECT_TRUE(a.method == b.method);
        EXPECT_TRUE(a.target == b.target);
        EXPECT_TRUE(a.path == b.path);
        EXPECT_TRUE(a.query == b.query);
        EXPECT_EQ(a.version_minor, b.version_minor);
        EXPECT_TRUE(a.keep_alive == b.keep_alive);
        EXPECT_TRUE(a.has_content_length == b.has_content_length);
        EXPECT_EQ(a.content_length, b.content_length);
        EXPECT_EQ(a.headers.size(), b.headers.size());
        for (size_t i = 0; i < a.headers.size(); ++i) {
            EXPECT_TRUE(a.headers[i].name == b.headers[i].name);
            EXPECT_TRUE(a.headers[i].value == b.headers[i].value);
        }
        EXPECT_EQ(whole.consumed(), split.consumed());
    }
}

TEST(http_parser, path_decoding_and_normalization)
{
    HttpParser p{limits()};
    auto path_of = [&](std::string_view target) {
        auto const text = std::string("GET ") + std::string(target) + " HTTP/1.1\r\nHost: h\r\n\r\n";
        EXPECT_TRUE(parse_whole(p, text) == ParseState::complete);
        return std::string(p.request().path);
    };
    EXPECT_TRUE(path_of("/a/b/../c") == "/a/c");
    EXPECT_TRUE(path_of("/a/./b") == "/a/b");
    EXPECT_TRUE(path_of("//a///b") == "/a/b");
    EXPECT_TRUE(path_of("/a/b/..") == "/a/");
    EXPECT_TRUE(path_of("/a/.") == "/a/");
    EXPECT_TRUE(path_of("/a/") == "/a/");
    EXPECT_TRUE(path_of("/%61%20b") == "/a b");
    EXPECT_TRUE(path_of("/a%2e%2e/../b") == "/b");  // decoded ".." then one pop each
    EXPECT_TRUE(path_of("/+x") == "/+x");           // '+' is not a space in paths
    EXPECT_TRUE(path_of("/") == "/");
    EXPECT_TRUE(path_of("/..a") == "/..a");  // only exact ".." pops
}

TEST(http_parser, rejections_carry_specific_statuses)
{
    HttpParser p{limits()};
    auto status_of = [&](std::string_view text) -> int {
        auto const whole = parse_whole(p, text);
        auto const st = whole == ParseState::failed ? p.error_status() : 0;
        // Failures must be byte-split invariant too.
        auto const split = parse_split(p, text);
        EXPECT_TRUE(split == whole);
        EXPECT_EQ(whole == ParseState::failed ? int(p.error_status()) : 0, int(st));
        return st;
    };

    EXPECT_EQ(status_of("DELETE /x HTTP/1.1\r\nHost: h\r\n\r\n"), 501);
    EXPECT_EQ(status_of("G@T /x HTTP/1.1\r\nHost: h\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET /x HTTP/2.0\r\nHost: h\r\n\r\n"), 505);
    EXPECT_EQ(status_of("GET /x FTP/1.1\r\nHost: h\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET x HTTP/1.1\r\nHost: h\r\n\r\n"), 400);  // not origin-form
    EXPECT_EQ(status_of("GET http://h/x HTTP/1.1\r\nHost: h\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET /x  HTTP/1.1\r\nHost: h\r\n\r\n"), 400);      // double space
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\n\r\n"), 400);                  // 1.1 without Host
    EXPECT_EQ(status_of("GET /%zz HTTP/1.1\r\nHost: h\r\n\r\n"), 400);     // bad percent
    EXPECT_EQ(status_of("GET /%2f HTTP/1.1\r\nHost: h\r\n\r\n"), 400);     // encoded '/'
    EXPECT_EQ(status_of("GET /%00 HTTP/1.1\r\nHost: h\r\n\r\n"), 400);     // encoded NUL
    EXPECT_EQ(status_of("GET /../etc HTTP/1.1\r\nHost: h\r\n\r\n"), 400);  // above root
    EXPECT_EQ(status_of("GET /a/../../b HTTP/1.1\r\nHost: h\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\nHost: h\r\n folded\r\n\r\n"), 400);  // obs-fold
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\nHost: h\r\nBad Name: v\r\n\r\n"), 400);
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\nHost: h\r\nNoColon\r\n\r\n"), 400);
    EXPECT_EQ(status_of("POST /x HTTP/1.1\r\nHost: h\r\n\r\n"), 411);
    EXPECT_EQ(status_of("PUT /x HTTP/1.1\r\nHost: h\r\n\r\n"), 411);
    EXPECT_EQ(status_of("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1x\r\n\r\n"), 400);
    EXPECT_EQ(status_of("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"), 400);
    EXPECT_EQ(status_of("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999999999999\r\n\r\n"), 400);  // overflow
    EXPECT_EQ(status_of("POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"), 501);

    // Field values: controls are refused, obs-text (bytes >= 0x80) is
    // not — and the verdict must not depend on the signedness of char.
    EXPECT_EQ(
        status_of("GET /x HTTP/1.1\r\nHost: h\r\nX-A: a\x01"
                  "b\r\n\r\n"),
        400);
    EXPECT_EQ(
        status_of("GET /x HTTP/1.1\r\nHost: h\r\nX-A: a\x7f"
                  "b\r\n\r\n"),
        400);
    EXPECT_EQ(status_of("GET /x HTTP/1.1\r\nHost: h\r\nX-A: caf\xc3\xa9\r\n\r\n"), 0);
    EXPECT_TRUE(p.request().header("x-a") == "caf\xc3\xa9");
    EXPECT_EQ(status_of("GET /caf\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n"), 400);  // raw non-ASCII in the target
}

TEST(http_parser, limits_are_enforced_even_mid_line)
{
    auto small = limits();
    small.max_request_line = 32;
    small.max_header_block = 64;
    small.max_header_count = 2;
    HttpParser p{small};

    // Request line too long — with no newline in sight yet.
    std::string const long_line(100, 'a');
    EXPECT_TRUE(parse_whole(p, std::string("GET /") + long_line) == ParseState::failed);
    EXPECT_EQ(p.error_status(), 414);

    // Header block too large — an endless header with no terminator.
    std::string const long_header = "GET / HTTP/1.1\r\nX: " + std::string(200, 'v');
    EXPECT_TRUE(parse_whole(p, long_header) == ParseState::failed);
    EXPECT_EQ(p.error_status(), 431);

    // Too many header fields.
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n") == ParseState::failed);
    EXPECT_EQ(p.error_status(), 431);
}

TEST(http_parser, keep_alive_matrix_and_body_boundary)
{
    HttpParser p{limits()};
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.1\r\nHost: h\r\n\r\n") == ParseState::complete);
    EXPECT_TRUE(p.request().keep_alive);
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n") == ParseState::complete);
    EXPECT_FALSE(p.request().keep_alive);
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.0\r\n\r\n") == ParseState::complete);
    EXPECT_FALSE(p.request().keep_alive);
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n") == ParseState::complete);
    EXPECT_TRUE(p.request().keep_alive);
    EXPECT_TRUE(parse_whole(p, "GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade, close\r\n\r\n") == ParseState::complete);
    EXPECT_FALSE(p.request().keep_alive);

    // consumed() marks the body start exactly.
    constexpr std::string_view post = "POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nwxyz";
    EXPECT_TRUE(parse_whole(p, post) == ParseState::complete);
    EXPECT_EQ(p.consumed(), post.size() - 4);
    EXPECT_EQ(p.request().content_length, 4U);
}

TEST(http_parser, reset_reuses_storage_for_the_next_request)
{
    HttpParser p{limits()};
    EXPECT_TRUE(parse_whole(p, GET_OK) == ParseState::complete);
    EXPECT_TRUE(parse_whole(p, "POST /two HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n") == ParseState::complete);
    EXPECT_TRUE(p.request().method == HttpMethod::post);
    EXPECT_TRUE(p.request().path == "/two");
    EXPECT_EQ(p.request().headers.size(), 2U);
}

TEST_MAIN(statusbar_http, http_parser_test)
