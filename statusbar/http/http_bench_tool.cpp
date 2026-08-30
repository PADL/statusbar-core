// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
//
// HTTP module benchmark (docs/HTTP_PLAN.md §7): parser microbenchmark
// plus loopback request/response throughput for the three serving paths
// (static mmap GET, buffered POST echo, pipelined GET batches). Client
// and server run in one thread — the client's socket work is included in
// the cost, so the numbers are a floor, not a ceiling.
//
// Build: make build
// Run:   ./build/build-Release/statusbar/statusbar-http-bench
//
// `--check` turns the run into a regression gate: optimized builds
// (NDEBUG) must clear deliberately generous thresholds — an order of
// magnitude below observed numbers, so only a real regression trips —
// and non-optimized builds report SKIP and pass.

#include "statusbar/benchmark/benchmark.hpp"
#include "statusbar/http/http_handler.hpp"
#include "statusbar/http/http_parser.hpp"
#include "statusbar/http/http_server.hpp"
#include "statusbar/http/http_static.hpp"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <print>
#include <span>
#include <string>
#include <string_view>

#include <sys/socket.h>

using namespace statusbar;
using namespace statusbar::http;

namespace {

auto now_ns() -> int64_t
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ---- parser microbenchmark --------------------------------------------------

void bench_parser()
{
    std::println("=== HttpParser (pure, no I/O) ===\n");

    HttpParser parser{HttpLimits{}};
    std::string_view const head = "GET /widgets/panel.html?tab=2 HTTP/1.1\r\n"
                                  "Host: bench.local\r\n"
                                  "Accept: text/html,application/xhtml+xml\r\n"
                                  "Accept-Encoding: gzip, deflate\r\n"
                                  "User-Agent: statusbar-bench/1.0\r\n"
                                  "Connection: keep-alive\r\n"
                                  "\r\n";
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::span<uint8_t const> const bytes{reinterpret_cast<uint8_t const*>(head.data()), head.size()};

    benchmark::BenchmarkConfig const cfg{.warmup_iterations = 500, .measurement_iterations = 5000, .batch_size = 100};
    auto stats = benchmark::run_hw(
        "http_parser/typical_get_head",
        [&](size_t n) {
            for (size_t k = 0; k < n; ++k) {
                parser.reset();
                auto state = parser.parse(bytes);
                benchmark::do_not_optimize(state);
            }
        },
        cfg);
    benchmark::report("http_parser/typical_get_head", stats);
    std::println("");
}

// ---- loopback throughput ----------------------------------------------------

class EchoHandler : public HttpHandler
{
  public:
    auto on_headers(HttpRequest const&, ResponseWriter&) -> Disposition override { return Disposition::buffer(); }

    void on_body_chunk(HttpRequest const&, std::span<uint8_t const> chunk) override
    {
        body_len = std::min(chunk.size(), body.size());
        std::memcpy(body.data(), chunk.data(), body_len);
    }

    void on_complete(HttpRequest const&, ResponseWriter& writer) override
    {
        (void)writer.send_external(200, "application/octet-stream", std::span<uint8_t const>{body.data(), body_len});
    }

  private:
    std::array<uint8_t, 512> body{};
    size_t body_len{0};
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
};

/// One request/response exchange: send, pump the server, drain the reply.
/// Returns bytes received (0 on failure/timeout).
auto exchange(HttpServer& server, int client_fd, std::string_view request, size_t expect) -> size_t
{
    if (::send(client_fd, request.data(), request.size(), 0) != ssize_t(request.size())) {
        return 0;
    }
    static std::array<uint8_t, 65536> sink;
    size_t got = 0;
    for (int spin = 0; spin < 200000 && got < expect; ++spin) {
        server.on_ready(now_ns());
        struct pollfd pfd{.fd = client_fd, .events = POLLIN, .revents = 0};
        while (::poll(&pfd, 1, 0) > 0) {
            auto const n = ::recv(client_fd, sink.data(), sink.size(), 0);
            if (n <= 0) {
                return got;
            }
            got += size_t(n);
        }
    }
    return got;
}

struct Throughput
{
    double requests_per_s;
    double us_per_request;
};

auto bench_exchange(HttpServer& server, int client_fd, std::string_view request, size_t expect, int count) -> Throughput
{
    auto timer = benchmark::Timer::start();
    for (int i = 0; i < count; ++i) {
        if (exchange(server, client_fd, request, expect) != expect) {
            std::println("FAILED: short exchange at iteration {}", i);
            return {.requests_per_s = 0.0, .us_per_request = 0.0};
        }
    }
    auto const seconds = timer.elapsed_s();
    return {
        .requests_per_s = double(count) / seconds,
        .us_per_request = timer.elapsed_us() / double(count),
    };
}

struct Site
{
    std::filesystem::path dir;

    Site()
    {
        std::string tmpl = (std::filesystem::temp_directory_path() / "http-bench-XXXXXX").string();
        dir = ::mkdtemp(tmpl.data());
        std::ofstream asset{dir / "index.html", std::ios::binary};
        std::string const filler(1024, 'x');
        asset << filler;
        std::ofstream manifest{dir / "manifest.toml"};
        manifest << "[[route]]\n"
                    "uri = \"/index.html\"\n"
                    "file = \"index.html\"\n"
                    "type = \"text/html\"\n";
    }
    ~Site() { std::filesystem::remove_all(dir); }
    Site(Site const&) = delete;
    auto operator=(Site const&) -> Site& = delete;
};

constexpr std::string_view GET_REQUEST = "GET /index.html HTTP/1.1\r\nHost: bench\r\n\r\n";
constexpr std::string_view ECHO_REQUEST = "POST /echo HTTP/1.1\r\nHost: bench\r\nContent-Length: 512\r\n\r\n";
constexpr int PIPELINE_DEPTH = 8;

auto bench_throughput(bool check) -> bool
{
    std::println("=== Loopback throughput (single thread: client + server) ===\n");

    Site site;
    auto loaded = StaticManifest::load((site.dir / "manifest.toml").string());
    if (!loaded) {
        std::println("FAILED: manifest load");
        return false;
    }
    StaticManifest const manifest = std::move(*loaded);

    HttpLimits limits;
    EchoHandler echo;
    HttpServer server{net::SocketAddress::ipv4_loopback(0), limits, &manifest};
    if (!server.valid() || !server.add_route(HttpMethod::post, "/echo", echo)) {
        std::println("FAILED: server setup");
        return false;
    }
    auto addr = server.local_addr();
    if (!addr.has_value()) {
        std::println("FAILED: local_addr");
        return false;
    }
    Client client{*addr};
    if (client.fd < 0) {
        std::println("FAILED: connect");
        return false;
    }

    std::string const echo_request = std::string{ECHO_REQUEST} + std::string(512, 'b');

    // Warm-up exchanges double as response-size probes: responses are
    // deterministic, so later exchanges wait for exactly this many bytes.
    auto const get_expect = exchange(server, client.fd, GET_REQUEST, SIZE_MAX);
    auto const echo_expect = exchange(server, client.fd, echo_request, SIZE_MAX);
    if (get_expect == 0 || echo_expect == 0) {
        std::println("FAILED: warm-up probe");
        return false;
    }

    auto const get_stats = bench_exchange(server, client.fd, GET_REQUEST, get_expect, 5000);
    std::println("static GET (1KiB mmap):   {:>10.0f} req/s   {:>8.2f} us/req", get_stats.requests_per_s, get_stats.us_per_request);

    auto const echo_stats = bench_exchange(server, client.fd, echo_request, echo_expect, 5000);
    std::println(
        "buffered POST echo (512B):{:>10.0f} req/s   {:>8.2f} us/req", echo_stats.requests_per_s, echo_stats.us_per_request);

    std::string pipelined;
    for (int i = 0; i < PIPELINE_DEPTH; ++i) {
        pipelined += GET_REQUEST;
    }
    auto const batch_stats = bench_exchange(server, client.fd, pipelined, get_expect * PIPELINE_DEPTH, 5000 / PIPELINE_DEPTH);
    std::println(
        "pipelined GET x{}:         {:>10.0f} req/s   {:>8.2f} us/req",
        PIPELINE_DEPTH,
        batch_stats.requests_per_s * PIPELINE_DEPTH,
        batch_stats.us_per_request / PIPELINE_DEPTH);
    std::println("");

    if (!check) {
        return true;
    }
#ifdef NDEBUG
    // Generous floors — observed numbers are far above these; only a
    // structural regression (accidental blocking, quadratic scan, lost
    // pipelining) should trip them.
    bool ok = true;
    if (get_stats.requests_per_s < 2000.0) {
        std::println("CHECK FAILED: static GET {:.0f} req/s < 2000", get_stats.requests_per_s);
        ok = false;
    }
    if (echo_stats.requests_per_s < 1000.0) {
        std::println("CHECK FAILED: POST echo {:.0f} req/s < 1000", echo_stats.requests_per_s);
        ok = false;
    }
    if (batch_stats.requests_per_s * PIPELINE_DEPTH < 2000.0) {
        std::println("CHECK FAILED: pipelined GET {:.0f} req/s < 2000", batch_stats.requests_per_s * PIPELINE_DEPTH);
        ok = false;
    }
    if (ok) {
        std::println("CHECK PASSED");
    }
    return ok;
#else
    std::println("CHECK SKIPPED (non-optimized build)");
    return true;
#endif
}

}  // namespace

auto main(int argc, char** argv) -> int
{
    bool const check = argc > 1 && std::string_view{argv[1]} == "--check";

    std::println("StatusBar HTTP Benchmarks\n");
    if (!check) {
        bench_parser();
    }
    return bench_throughput(check) ? 0 : 1;
}
