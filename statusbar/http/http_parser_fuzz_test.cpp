// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// M5 malformed-input replay (docs/HTTP_PLAN.md §7): a deterministic
/// mutation corpus driven through the pure parser. The parser's purity is
/// what makes this cheap — no sockets, no clock — so every mutant is
/// checked for the full invariant set:
///
///   - the parser terminates in a defined state (need_more / complete /
///     failed) without crashing;
///   - failures carry a status from the documented set;
///   - completion accounting is sane (consumed() within the input,
///     headers within limits, a path that begins with '/');
///   - byte-at-a-time feeding reaches the same state, status, and
///     consumed() as the whole-buffer parse — split invariance under
///     hostile input, not just under the happy path.

#include "statusbar/http/http_parser.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar::http;

namespace {

/// xorshift64* — deterministic across platforms.
struct Rng
{
    uint64_t state;

    explicit Rng(uint64_t seed)
        : state{seed == 0 ? 0x9E3779B97F4A7C15ULL : seed}
    {}

    auto next() -> uint64_t
    {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        return state * 0x2545F4914F6CDD1DULL;
    }

    auto below(uint64_t n) -> uint64_t { return next() % n; }
};

auto seeds() -> std::vector<std::string>
{
    return {
        "GET /index.html?x=1 HTTP/1.1\r\nHost: fuzz\r\nAccept: */*\r\n\r\n",
        "POST /api HTTP/1.1\r\nHost: f\r\nContent-Length: 12\r\n\r\nhello world!",
        "PUT /a/b/../c%20d HTTP/1.1\r\nhost: f\r\ncontent-length: 0\r\nConnection: close\r\n\r\n",
        "HEAD / HTTP/1.0\r\n\r\n",
        "OPTIONS /x HTTP/1.1\r\nHost: f\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n",
        "GET /%41%42/%7e HTTP/1.1\r\nHost: f\r\n\r\n",
        // Hostile shapes as seeds of their own:
        "GET /../../ HTTP/1.1\r\nHost: f\r\n\r\n",
        "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: f\r\n\r\n",
        std::string("GET /") + std::string(300, 'a') + " HTTP/1.1\r\nHost: f\r\n\r\n",
        std::string("\r\n\r\n\r\n") + "GET / HTTP/1.1\r\nHost: f\r\n\r\n",
    };
}

constexpr std::array<uint16_t, 6> ALLOWED_STATUSES{400, 411, 414, 431, 501, 505};

struct Outcome
{
    ParseState state;
    uint16_t status;
    size_t consumed;
};

auto run_whole(HttpParser& parser, std::string const& input) -> Outcome
{
    parser.reset();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const state = parser.parse({reinterpret_cast<uint8_t const*>(input.data()), input.size()});
    return {.state = state, .status = parser.error_status(), .consumed = parser.consumed()};
}

auto run_split(HttpParser& parser, std::string const& input) -> Outcome
{
    parser.reset();
    auto state = ParseState::need_more;
    for (size_t n = 1; n <= input.size() && state == ParseState::need_more; ++n) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        state = parser.parse({reinterpret_cast<uint8_t const*>(input.data()), n});
    }
    return {.state = state, .status = parser.error_status(), .consumed = parser.consumed()};
}

void check_invariants(HttpParser& parser, Outcome const& outcome, std::string const& input)
{
    if (outcome.state == ParseState::failed) {
        bool known = false;
        for (auto const s : ALLOWED_STATUSES) {
            known = known || s == outcome.status;
        }
        EXPECT_TRUE(known);
    } else if (outcome.state == ParseState::complete) {
        EXPECT_TRUE(outcome.consumed <= input.size());
        auto const& request = parser.request();
        EXPECT_TRUE(request.path.starts_with('/'));
        EXPECT_TRUE(request.headers.size() <= HttpLimits{}.max_header_count);
    }
}

}  // namespace

TEST(http_parser_fuzz, mutated_corpus_holds_invariants)
{
    auto const corpus = seeds();
    HttpParser whole{HttpLimits{}};
    HttpParser split{HttpLimits{}};
    Rng rng{20260830};

    int mutants = 0;
    for (int iteration = 0; iteration < 3000; ++iteration) {
        auto input = corpus[rng.below(corpus.size())];
        // 1-4 mutations: flip, insert, delete, duplicate a slice, or
        // truncate.
        auto const mutations = 1 + rng.below(4);
        for (uint64_t m = 0; m < mutations && !input.empty(); ++m) {
            switch (rng.below(5)) {
                case 0:
                    input[rng.below(input.size())] = char(rng.next());
                    break;
                case 1:
                    input.insert(input.begin() + long(rng.below(input.size() + 1)), char(rng.next()));
                    break;
                case 2:
                    input.erase(input.begin() + long(rng.below(input.size())));
                    break;
                case 3: {
                    auto const at = rng.below(input.size());
                    auto const len = 1 + rng.below(16);
                    input.insert(at, input.substr(at, len));
                    break;
                }
                case 4:
                    input.resize(rng.below(input.size() + 1));
                    break;
                default:
                    break;
            }
        }
        if (input.size() > 2048) {
            input.resize(2048);
        }
        ++mutants;

        auto const a = run_whole(whole, input);
        check_invariants(whole, a, input);
        auto const b = run_split(split, input);
        EXPECT_TRUE(a.state == b.state);
        if (a.state != ParseState::need_more) {
            EXPECT_EQ(a.status, b.status);
        }
        if (a.state == ParseState::complete) {
            EXPECT_EQ(a.consumed, b.consumed);
        }
    }
    EXPECT_EQ(mutants, 3000);
}

TEST(http_parser_fuzz, pathological_shapes)
{
    HttpParser parser{HttpLimits{}};
    std::vector<std::string> const nasty{
        std::string(4096, '\xff'),
        std::string(4096, '\0'),
        std::string(4096, '\r'),
        std::string(4096, '\n'),
        std::string("GET ") + std::string(4096, '%'),
        "GET /" + std::string(3000, '%') + "2",
        std::string(100, ' ') + "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\n" + std::string(2000, 'H') + ":",
        "GET / HTTP/1.1\r\nContent-Length: " + std::string(100, '9') + "\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: h\r\n" + std::string("Content-Length: 5\r\n") + std::string(60, 'x'),
    };
    for (auto const& input : nasty) {
        auto const a = run_whole(parser, input);
        check_invariants(parser, a, input);
        auto const b = run_split(parser, input);
        EXPECT_TRUE(a.state == b.state);
    }
}

TEST_MAIN(statusbar_http, http_parser_fuzz_test)
