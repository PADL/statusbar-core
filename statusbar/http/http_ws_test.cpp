// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_ws.hpp"

#include "statusbar/http/http_server.hpp"
#include "statusbar/http/http_sha1.hpp"
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

// ---- raw masked-frame test client -----------------------------------------

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

    void send_bytes(std::span<uint8_t const> bytes) const
    {
        auto const n = ::send(fd, bytes.data(), bytes.size(), 0);
        (void)n;
    }

    void send_text(std::string_view text) const
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        send_bytes({reinterpret_cast<uint8_t const*>(text.data()), text.size()});
    }

    [[nodiscard]] auto recv_for(int budget_ms) const -> std::vector<uint8_t>
    {
        std::vector<uint8_t> out;
        std::array<uint8_t, 65536> buf{};
        for (int spent = 0; spent < budget_ms; spent += 10) {
            struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 10) <= 0) {
                continue;
            }
            auto const n = ::recv(fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                break;
            }
            out.insert(out.end(), buf.begin(), buf.begin() + n);
        }
        return out;
    }

    [[nodiscard]] auto at_eof() const -> bool
    {
        std::array<uint8_t, 16> buf{};
        struct pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 50) <= 0) {
            return false;
        }
        return ::recv(fd, buf.data(), buf.size(), 0) == 0;
    }
};

/// Builds one masked client frame.
auto masked_frame(WsOpcode opcode, bool fin, std::string_view payload, uint8_t mask_seed = 0x5A) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    out.push_back(uint8_t((fin ? 0x80U : 0x00U) | uint8_t(opcode)));
    std::array<uint8_t, 4> const mask{mask_seed, uint8_t(mask_seed + 1), uint8_t(mask_seed + 2), uint8_t(mask_seed + 3)};
    if (payload.size() <= 125) {
        out.push_back(uint8_t(0x80U | payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        out.push_back(0x80U | 126U);
        out.push_back(uint8_t(payload.size() >> 8));
        out.push_back(uint8_t(payload.size()));
    } else {
        out.push_back(0x80U | 127U);
        for (int i = 0; i < 8; ++i) {
            out.push_back(uint8_t(uint64_t(payload.size()) >> (56 - (8 * i))));
        }
    }
    out.insert(out.end(), mask.begin(), mask.end());
    for (size_t i = 0; i < payload.size(); ++i) {
        out.push_back(uint8_t(payload[i]) ^ mask[i % 4]);
    }
    return out;
}

/// Parses server (unmasked) frames out of a byte stream.
struct ServerFrame
{
    WsOpcode opcode{};
    bool fin{};
    std::string payload;
};

auto parse_server_frames(std::vector<uint8_t> const& bytes) -> std::vector<ServerFrame>
{
    std::vector<ServerFrame> frames;
    size_t at = 0;
    while (at < bytes.size()) {
        WsFrameHeader header;
        auto const state = ws_parse_frame_header(std::span<uint8_t const>{bytes.data() + at, bytes.size() - at}, header);
        if (state != WsParse::ok || at + header.header_len + header.payload_len > bytes.size()) {
            break;
        }
        EXPECT_FALSE(header.masked);  // server frames are never masked
        ServerFrame frame;
        frame.opcode = header.opcode;
        frame.fin = header.fin;
        frame.payload.assign(
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<char const*>(bytes.data() + at + header.header_len),
            size_t(header.payload_len));
        frames.push_back(std::move(frame));
        at += header.header_len + size_t(header.payload_len);
    }
    return frames;
}

// ---- server fixture --------------------------------------------------------

class EchoEndpoint : public WsEndpoint
{
  public:
    explicit EchoEndpoint(HttpServer*& server)
        : server_{server}
    {}

    void on_ws_open(size_t slot, HttpRequest const& request) override
    {
        opens.push_back(slot);
        open_path = std::string{request.path};
    }

    void on_ws_message(size_t slot, std::span<uint8_t const> payload, bool is_text) override
    {
        last_text = is_text;
        messages.emplace_back(payload.begin(), payload.end());
        (void)server_->ws_send_external(slot, payload, is_text);  // echo from the reassembly buffer
    }

    void on_ws_closed(size_t slot) override { closes.push_back(slot); }

    HttpServer*& server_;
    std::vector<size_t> opens;
    std::vector<size_t> closes;
    std::vector<std::vector<uint8_t>> messages;
    std::string open_path;
    bool last_text{false};
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

struct Fixture
{
    HttpLimits limits;
    std::unique_ptr<HttpServer> server;
    HttpServer* server_raw{nullptr};
    EchoEndpoint echo{server_raw};
    net::SocketAddress addr{};

    Fixture()
    {
        limits.max_connections = 2;
        limits.max_ws_message = 4096;
        server = std::make_unique<HttpServer>(net::SocketAddress::ipv4_loopback(0), limits);
        server_raw = server.get();
        EXPECT_TRUE(server->add_ws_route("/ws", echo));
        addr = *server->local_addr();
    }

    /// Performs the upgrade handshake; returns the raw 101 response text.
    auto upgrade(Client const& c) -> std::string
    {
        c.send_text("GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        pump(*server);
        auto const raw = c.recv_for(100);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::string{reinterpret_cast<char const*>(raw.data()), raw.size()};
    }
};

}  // namespace

// ---- pure-codec and hash tests ---------------------------------------------

TEST(http_ws, sha1_and_base64_vectors)
{
    auto hex = [](std::span<uint8_t const> d) {
        std::string out;
        for (auto const b : d) {
            char pair[3];
            (void)snprintf(pair, sizeof pair, "%02x", b);
            out += pair;
        }
        return out;
    };
    std::array<uint8_t, 20> digest{};
    // RFC 3174 test vectors.
    sha1(
        std::span<uint8_t const>{reinterpret_cast<uint8_t const*>("abc"), 3},
        digest);  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_TRUE(hex(digest) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    sha1({}, digest);
    EXPECT_TRUE(hex(digest) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    std::string const long_input(1000, 'a');
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    sha1(std::span<uint8_t const>{reinterpret_cast<uint8_t const*>(long_input.data()), long_input.size()}, digest);
    EXPECT_TRUE(hex(digest) == "291e9a6c66994949b57ba5e650361e98fc36b1ba");

    // The RFC 6455 §1.3 worked example.
    EXPECT_TRUE(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==").view() == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(http_ws, frame_codec_round_trip_and_validation)
{
    // Header writer forms: 7-bit, 16-bit, 64-bit lengths.
    std::array<uint8_t, 16> buf{};
    EXPECT_EQ(ws_write_frame_header(buf, WsOpcode::text, true, 5), 2U);
    EXPECT_EQ(buf[0], 0x81U);
    EXPECT_EQ(buf[1], 5U);
    EXPECT_EQ(ws_write_frame_header(buf, WsOpcode::binary, true, 300), 4U);
    EXPECT_EQ(buf[1], 126U);
    EXPECT_EQ(ws_write_frame_header(buf, WsOpcode::binary, false, uint64_t{1} << 20), 10U);

    // Parser: masked client frame round-trips.
    auto const frame = masked_frame(WsOpcode::text, true, "hello");
    WsFrameHeader header;
    EXPECT_TRUE(ws_parse_frame_header(frame, header) == WsParse::ok);
    EXPECT_TRUE(header.fin);
    EXPECT_TRUE(header.masked);
    EXPECT_TRUE(header.opcode == WsOpcode::text);
    EXPECT_EQ(header.payload_len, 5U);
    std::vector<uint8_t> payload{frame.begin() + long(header.header_len), frame.end()};
    ws_unmask(payload, header.mask);
    EXPECT_TRUE(std::string(payload.begin(), payload.end()) == "hello");

    // Truncated input asks for more.
    EXPECT_TRUE(ws_parse_frame_header(std::span<uint8_t const>{frame.data(), 1}, header) == WsParse::need_more);
    // Reserved bits, bad opcodes, and long/fragmented control frames fail.
    std::array<uint8_t, 8> bad{0xC1, 0x80, 0, 0, 0, 0, 0, 0};
    EXPECT_TRUE(ws_parse_frame_header(bad, header) == WsParse::protocol_error);
    bad = {0x83, 0x80, 0, 0, 0, 0, 0, 0};  // opcode 3 is reserved
    EXPECT_TRUE(ws_parse_frame_header(bad, header) == WsParse::protocol_error);
    bad = {0x09, 0x80, 0, 0, 0, 0, 0, 0};  // fragmented ping
    EXPECT_TRUE(ws_parse_frame_header(bad, header) == WsParse::protocol_error);
    bad = {0x89, 0xFE, 0x00, 0x80, 0, 0, 0, 0};  // 128-byte ping
    EXPECT_TRUE(ws_parse_frame_header(bad, header) == WsParse::protocol_error);
}

// ---- live server tests -----------------------------------------------------

TEST(http_ws, upgrade_and_text_echo)
{
    Fixture fx;
    Client c{fx.addr};
    auto const response = fx.upgrade(c);
    EXPECT_TRUE(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    EXPECT_TRUE(response.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != std::string::npos);
    EXPECT_EQ(fx.echo.opens.size(), 1U);
    EXPECT_TRUE(fx.echo.open_path == "/ws");

    c.send_bytes(masked_frame(WsOpcode::text, true, "ping pong"));
    pump(*fx.server);
    auto const frames = parse_server_frames(c.recv_for(150));
    EXPECT_EQ(frames.size(), 1U);
    EXPECT_TRUE(frames[0].opcode == WsOpcode::text);
    EXPECT_TRUE(frames[0].payload == "ping pong");
    EXPECT_TRUE(fx.echo.last_text);
}

TEST(http_ws, fragmentation_reassembles_with_interleaved_ping)
{
    Fixture fx;
    Client c{fx.addr};
    (void)fx.upgrade(c);

    // "hello world" in three fragments, a ping wedged between them.
    c.send_bytes(masked_frame(WsOpcode::text, false, "hel"));
    c.send_bytes(masked_frame(WsOpcode::ping, true, "pip"));
    c.send_bytes(masked_frame(WsOpcode::continuation, false, "lo wo"));
    c.send_bytes(masked_frame(WsOpcode::continuation, true, "rld"));
    pump(*fx.server);
    auto const frames = parse_server_frames(c.recv_for(150));
    // The pong answers mid-message; the echo carries the whole message.
    EXPECT_EQ(frames.size(), 2U);
    EXPECT_TRUE(frames[0].opcode == WsOpcode::pong);
    EXPECT_TRUE(frames[0].payload == "pip");
    EXPECT_TRUE(frames[1].opcode == WsOpcode::text);
    EXPECT_TRUE(frames[1].payload == "hello world");
    EXPECT_EQ(fx.echo.messages.size(), 1U);
}

TEST(http_ws, binary_echo_and_server_push)
{
    Fixture fx;
    Client c{fx.addr};
    (void)fx.upgrade(c);

    std::string blob(1000, '\0');
    for (size_t i = 0; i < blob.size(); ++i) {
        blob[i] = char(i * 7);
    }
    c.send_bytes(masked_frame(WsOpcode::binary, true, blob));
    pump(*fx.server);
    auto frames = parse_server_frames(c.recv_for(150));
    EXPECT_EQ(frames.size(), 1U);
    EXPECT_TRUE(frames[0].opcode == WsOpcode::binary);
    EXPECT_TRUE(frames[0].payload == blob);

    // Unsolicited server push (the widget-update path).
    std::string_view const push{"{\"gain\":-3.5}"};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_TRUE(fx.server->ws_send(fx.echo.opens[0], {reinterpret_cast<uint8_t const*>(push.data()), push.size()}, true));
    pump(*fx.server, 5);
    frames = parse_server_frames(c.recv_for(150));
    EXPECT_EQ(frames.size(), 1U);
    EXPECT_TRUE(frames[0].payload == push);
}

TEST(http_ws, close_handshake_and_protocol_errors)
{
    Fixture fx;
    {
        Client c{fx.addr};
        (void)fx.upgrade(c);
        c.send_bytes(masked_frame(WsOpcode::close, true, std::string{"\x03\xe8", 2}));  // 1000
        pump(*fx.server);
        auto const frames = parse_server_frames(c.recv_for(150));
        EXPECT_EQ(frames.size(), 1U);
        EXPECT_TRUE(frames[0].opcode == WsOpcode::close);
        EXPECT_TRUE(frames[0].payload == std::string("\x03\xe8", 2));
        EXPECT_TRUE(c.at_eof());
        EXPECT_EQ(fx.echo.closes.size(), 1U);
    }
    {
        // An unmasked client frame is a protocol error: close 1002.
        Client c{fx.addr};
        (void)fx.upgrade(c);
        std::array<uint8_t, 4> unmasked{0x81, 0x02, 'h', 'i'};
        c.send_bytes(unmasked);
        pump(*fx.server);
        auto const frames = parse_server_frames(c.recv_for(150));
        EXPECT_EQ(frames.size(), 1U);
        EXPECT_TRUE(frames[0].opcode == WsOpcode::close);
        EXPECT_TRUE(frames[0].payload == std::string("\x03\xea", 2));  // 1002
        EXPECT_TRUE(c.at_eof());
    }
    {
        // A message over max_ws_message closes 1009.
        Client c{fx.addr};
        (void)fx.upgrade(c);
        c.send_bytes(masked_frame(WsOpcode::binary, true, std::string(8192, 'x')));
        pump(*fx.server, 40);
        auto const frames = parse_server_frames(c.recv_for(200));
        EXPECT_EQ(frames.size(), 1U);
        EXPECT_TRUE(frames[0].opcode == WsOpcode::close);
        EXPECT_TRUE(frames[0].payload == std::string("\x03\xf1", 2));  // 1009
        EXPECT_TRUE(c.at_eof());
    }
}

TEST(http_ws, plain_get_answers_426_and_idle_policy_pings_then_drops)
{
    Fixture fx;
    {
        Client c{fx.addr};
        c.send_text("GET /ws HTTP/1.1\r\nHost: t\r\n\r\n");
        pump(*fx.server);
        auto const raw = c.recv_for(100);
        std::string const response{raw.begin(), raw.end()};
        EXPECT_TRUE(response.starts_with("HTTP/1.1 426 "));
    }
    {
        Client c{fx.addr};
        (void)fx.upgrade(c);
        // Idle past ws_ping_ns: a ping goes out.
        fx.server->tick(int64_t(40) * 1'000'000'000);
        auto frames = parse_server_frames(c.recv_for(100));
        EXPECT_EQ(frames.size(), 1U);
        EXPECT_TRUE(frames[0].opcode == WsOpcode::ping);
        // No pong ever: past ws_drop_ns the connection is dropped.
        fx.server->tick(int64_t(70) * 1'000'000'000);
        EXPECT_TRUE(c.at_eof());
        EXPECT_EQ(fx.echo.closes.size(), 1U);
    }
}

TEST_MAIN(statusbar_http, http_ws_test)
