// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// Test client: a plain blocking TCP socket connected to the pool.
struct Client
{
    int fd{-1};

    explicit Client(SocketAddress const& to)
    {
        fd = ::socket(to.family(), SOCK_STREAM, 0);
        if (fd >= 0 && ::connect(fd, to.sockaddr(), to.length()) < 0) {
            ::close(fd);
            fd = -1;
        }
#if defined(SO_NOSIGPIPE)
        int const one = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
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

    [[nodiscard]] auto recv_some() const -> std::string
    {
        std::array<char, 4096> buf{};
        auto const n = ::recv(fd, buf.data(), buf.size(), 0);
        return n > 0 ? std::string(buf.data(), size_t(n)) : std::string{};
    }
};

/// Echo handler that also records lifecycle events.
class EchoHandler : public TcpConnectionHandler
{
  public:
    explicit EchoHandler(TcpConnectionPool*& pool)
        : pool_{pool}
    {}

    void on_accept(size_t slot, SocketAddress const&, int64_t) override { accepts.push_back(slot); }

    void on_readable(size_t slot, int64_t) override
    {
        std::array<uint8_t, 1024> buf{};
        for (;;) {
            auto n = pool_->read(slot, buf);
            if (!n) {
                return;  // would_block (or dead — next event handles it)
            }
            if (*n == 0) {
                pool_->close(slot);
                return;
            }
            (void)pool_->write(slot, std::span<uint8_t const>{buf.data(), *n});
        }
    }

    void on_closed(size_t slot, int64_t) override { closes.push_back(slot); }
    void on_rejected(SocketAddress const&, int64_t) override { ++rejects; }

    std::vector<size_t> accepts;
    std::vector<size_t> closes;
    int rejects{0};
    TcpConnectionPool*& pool_;
};

auto loopback() -> SocketAddress
{
    return SocketAddress::ipv4_loopback(0);
}

/// Pump the pool like the reactor would: poll its fd, then on_ready/tick.
void pump(TcpConnectionPool& pool, int rounds = 20, int64_t now0 = 1)
{
    for (int i = 0; i < rounds; ++i) {
        struct pollfd pfd{.fd = pool.fd(), .events = POLLIN, .revents = 0};
        (void)::poll(&pfd, 1, 5);
        pool.on_ready(now0 + i);
        pool.tick(now0 + i);
    }
}

}  // namespace

TEST(net_tcp_server, accept_echo_eof_lifecycle)
{
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{loopback(), 4, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());
    auto addr = pool.local_addr();
    EXPECT_TRUE(addr.has_value());

    Client c{*addr};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    EXPECT_EQ(pool.active_count(), 1U);

    c.send_all("hello pool");
    pump(pool, 5);
    EXPECT_TRUE(c.recv_some() == "hello pool");

    // Orderly client close -> readable -> read()==0 -> handler closes.
    ::shutdown(c.fd, SHUT_WR);
    pump(pool, 10);
    EXPECT_EQ(handler.closes.size(), 1U);
    EXPECT_EQ(pool.active_count(), 0U);
    EXPECT_FALSE(pool.is_open(handler.closes[0]));
}

TEST(net_tcp_server, capacity_reject_and_slot_reuse)
{
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{loopback(), 1, handler};
    pool_ptr = &pool;
    auto addr = pool.local_addr();

    Client first{*addr};
    pump(pool, 5);
    EXPECT_EQ(pool.active_count(), 1U);

    Client second{*addr};
    pump(pool, 5);
    EXPECT_EQ(handler.rejects, 1);
    // The rejected client sees EOF, not silence.
    EXPECT_TRUE(second.recv_some().empty());

    // Freeing the slot lets the next client in, reusing the same slot.
    ::shutdown(first.fd, SHUT_WR);
    pump(pool, 10);
    Client third{*addr};
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 2U);
    EXPECT_EQ(handler.accepts[0], handler.accepts[1]);
    third.send_all("again");
    pump(pool, 5);
    EXPECT_TRUE(third.recv_some() == "again");
}

TEST(net_tcp_server, short_write_backpressure_completes)
{
    // A handler that writes a large payload on accept, keeping the unsent
    // remainder and finishing from on_writable — the short-write contract.
    class Blaster : public TcpConnectionHandler
    {
      public:
        explicit Blaster(TcpConnectionPool*& pool)
            : pool_{pool}
        {
            payload.resize(size_t{4} * 1024 * 1024);
            for (size_t i = 0; i < payload.size(); ++i) {
                payload[i] = uint8_t((i * 31) + 7);
            }
        }
        void on_accept(size_t slot, SocketAddress const&, int64_t) override { push(slot); }
        void on_readable(size_t, int64_t) override {}
        void on_writable(size_t slot, int64_t) override { push(slot); }
        void on_closed(size_t, int64_t) override {}
        void push(size_t slot)
        {
            while (sent < payload.size()) {
                auto n = pool_->write(slot, std::span<uint8_t const>{payload.data() + sent, payload.size() - sent});
                if (!n) {
                    return;
                }
                sent += *n;
                if (*n == 0) {
                    saw_short_write = true;
                    return;  // wait for on_writable
                }
            }
        }
        std::vector<uint8_t> payload;
        size_t sent{0};
        bool saw_short_write{false};
        TcpConnectionPool*& pool_;
    };

    TcpConnectionPool* pool_ptr = nullptr;
    Blaster handler{pool_ptr};
    TcpConnectionPool pool{loopback(), 1, handler};
    pool_ptr = &pool;
    auto addr = pool.local_addr();

    Client c{*addr};
    // Drain on the client side while pumping the pool; verify every byte.
    size_t received = 0;
    std::array<uint8_t, 65536> buf{};
    (void)::fcntl(c.fd, F_SETFL, O_NONBLOCK);
    for (int i = 0; i < 20000 && received < handler.payload.size(); ++i) {
        pump(pool, 1, i + 1);
        for (;;) {
            auto const n = ::recv(c.fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                break;
            }
            for (ssize_t j = 0; j < n; ++j) {
                EXPECT_EQ(buf[size_t(j)], handler.payload[received + size_t(j)]);
            }
            received += size_t(n);
        }
    }
    EXPECT_EQ(received, handler.payload.size());
    EXPECT_EQ(handler.sent, handler.payload.size());
}

TEST(net_tcp_server, idle_timeout_sweeps)
{
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.idle_timeout_ns = 1000;  // the injected clock makes this exact
    TcpConnectionPool pool{loopback(), 2, handler, options};
    pool_ptr = &pool;
    auto addr = pool.local_addr();

    Client c{*addr};
    pump(pool, 3, 100);
    EXPECT_EQ(pool.active_count(), 1U);

    // Advance the clock past the timeout with no traffic.
    pool.tick(100 + 5000);
    EXPECT_EQ(pool.active_count(), 0U);
    EXPECT_EQ(handler.closes.size(), 1U);
    EXPECT_TRUE(c.recv_some().empty());  // server closed the socket
}

TEST_MAIN(statusbar_net, net_tcp_server_test)
