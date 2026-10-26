// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

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

/// A private mkdtemp directory holding one socket path; both are removed
/// on scope exit. Under /tmp so the path stays well inside sun_path.
struct TempSocketDir
{
    std::string dir;

    TempSocketDir()
    {
        std::string tmpl = "/tmp/statusbar_unix_XXXXXX";
        if (::mkdtemp(tmpl.data()) != nullptr) {
            dir = tmpl;
        }
    }
    ~TempSocketDir()
    {
        if (!dir.empty()) {
            (void)::unlink(path().c_str());
            (void)::rmdir(dir.c_str());
        }
    }
    TempSocketDir(TempSocketDir const&) = delete;
    auto operator=(TempSocketDir const&) -> TempSocketDir& = delete;

    [[nodiscard]] auto path() const -> std::string { return dir + "/ctl.sock"; }
};

auto file_exists(std::string const& path) -> bool
{
    struct stat st{};
    return ::lstat(path.c_str(), &st) == 0;
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

TEST(net_tcp_server, unix_accept_echo_eof_lifecycle)
{
    TempSocketDir tmp;
    EXPECT_FALSE(tmp.dir.empty());
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{*bind_addr, 4, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());
    auto addr = pool.local_addr();
    EXPECT_TRUE(addr.has_value());
    EXPECT_EQ(addr->family(), AF_UNIX);
    EXPECT_TRUE(addr->to_string() == tmp.path());
    EXPECT_EQ(addr->port(), 0U);

    Client c{*addr};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    EXPECT_EQ(pool.active_count(), 1U);

    // The client never bound: an unnamed but valid AF_UNIX peer.
    auto const& peer = pool.peer(handler.accepts[0]);
    EXPECT_TRUE(peer.valid());
    EXPECT_EQ(peer.family(), AF_UNIX);
    EXPECT_TRUE(peer.path().empty());
    EXPECT_TRUE(peer.to_string().empty());

    c.send_all("hello unix pool");
    pump(pool, 5);
    EXPECT_TRUE(c.recv_some() == "hello unix pool");

    ::shutdown(c.fd, SHUT_WR);
    pump(pool, 10);
    EXPECT_EQ(handler.closes.size(), 1U);
    EXPECT_EQ(pool.active_count(), 0U);
    EXPECT_FALSE(pool.is_open(handler.closes[0]));
}

TEST(net_tcp_server, unix_seqpacket_keeps_message_boundaries)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{*bind_addr, 4, handler, options};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    int const fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    EXPECT_TRUE(fd >= 0);
    EXPECT_EQ(::connect(fd, bind_addr->sockaddr(), bind_addr->length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    std::array<uint8_t, 3> const first{1, 2, 3};
    std::array<uint8_t, 2> const second{4, 5};
    EXPECT_EQ(pool.write(handler.accepts[0], first).value_or(0), first.size());
    EXPECT_EQ(pool.write(handler.accepts[0], second).value_or(0), second.size());
    std::array<uint8_t, 16> in{};
    EXPECT_EQ(::recv(fd, in.data(), in.size(), 0), ssize_t{3});  // one message per write
    EXPECT_EQ(::recv(fd, in.data(), in.size(), 0), ssize_t{2});
    ::close(fd);
}

TEST(net_tcp_server, unix_stale_socket_replaced)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());

    // Leave a socket file behind, as a crashed previous run would.
    int const stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_TRUE(stale >= 0);
    EXPECT_EQ(::bind(stale, bind_addr->sockaddr(), bind_addr->length()), 0);
    ::close(stale);
    EXPECT_TRUE(file_exists(tmp.path()));

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{*bind_addr, 2, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    Client c{*bind_addr};
    EXPECT_TRUE(c.fd >= 0);
    c.send_all("fresh");
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    EXPECT_TRUE(c.recv_some() == "fresh");
}

TEST(net_tcp_server, unix_refuses_non_socket_path)
{
    TempSocketDir tmp;
    int const file = ::open(tmp.path().c_str(), O_CREAT | O_WRONLY | O_EXCL, 0600);
    EXPECT_TRUE(file >= 0);
    ::close(file);

    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    {
        TcpConnectionPool pool{*bind_addr, 2, handler};
        EXPECT_FALSE(pool.valid());
    }
    // The regular file is untouched, before and after the pool is gone.
    struct stat st{};
    EXPECT_EQ(::lstat(tmp.path().c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
}

TEST(net_tcp_server, unix_live_socket_not_hijacked)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());

    TcpConnectionPool* first_ptr = nullptr;
    EchoHandler first_handler{first_ptr};
    TcpConnectionPool first{*bind_addr, 4, first_handler};
    first_ptr = &first;
    EXPECT_TRUE(first.valid());

    {
        // The path holds a live listener: the second pool must neither
        // unlink it on the way in nor claim it on the way out.
        TcpConnectionPool* second_ptr = nullptr;
        EchoHandler second_handler{second_ptr};
        TcpConnectionPool second{*bind_addr, 4, second_handler};
        EXPECT_FALSE(second.valid());
    }
    EXPECT_TRUE(file_exists(tmp.path()));

    // The first pool still serves (its accept count includes the probe).
    Client c{*bind_addr};
    EXPECT_TRUE(c.fd >= 0);
    c.send_all("still mine");
    pump(first, 5);
    EXPECT_TRUE(c.recv_some() == "still mine");
}

TEST(net_tcp_server, unix_mode_applied)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_mode = 0600;
    TcpConnectionPool pool{*bind_addr, 2, handler, options};
    EXPECT_TRUE(pool.valid());
    struct stat st{};
    EXPECT_EQ(::lstat(tmp.path().c_str(), &st), 0);
    EXPECT_TRUE(S_ISSOCK(st.st_mode));
    EXPECT_EQ(st.st_mode & 07777, mode_t{0600});
    // Staged in a private directory beside it, which is gone again.
    size_t entries = 0;
    for (auto const& entry : std::filesystem::directory_iterator{tmp.dir}) {
        (void)entry;
        ++entries;
    }
    EXPECT_EQ(entries, size_t{1});
    // Connecting by the path reaches it.
    auto addr = pool.local_addr();
    EXPECT_TRUE(addr.has_value());
    Client c{*addr};
    EXPECT_TRUE(c.fd >= 0);
}

#if defined(__linux__)
TEST(net_tcp_server, unix_abstract_peer_renders_with_at)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{*bind_addr, 2, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    // Autobind: binding just the family gives the client a 5-hex-digit
    // abstract name, which the server sees as the peer address.
    int const fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_TRUE(fd >= 0);
    sockaddr_un autobind{};
    autobind.sun_family = AF_UNIX;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    EXPECT_EQ(::bind(fd, reinterpret_cast<sockaddr const*>(&autobind), sizeof(sa_family_t)), 0);
    EXPECT_EQ(::connect(fd, bind_addr->sockaddr(), bind_addr->length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    auto const& peer = pool.peer(handler.accepts[0]);
    EXPECT_TRUE(peer.path().empty());
    auto const text = peer.to_string();
    EXPECT_EQ(text.size(), 6U);
    EXPECT_TRUE(!text.empty() && text[0] == '@');
    ::close(fd);
}
#endif

TEST(net_tcp_server, unix_socket_file_removed_on_destroy)
{
    TempSocketDir tmp;
    auto bind_addr = SocketAddress::local(tmp.path());
    EXPECT_TRUE(bind_addr.has_value());
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    {
        TcpConnectionPool pool{*bind_addr, 2, handler};
        EXPECT_TRUE(pool.valid());
        EXPECT_TRUE(file_exists(tmp.path()));
    }
    EXPECT_FALSE(file_exists(tmp.path()));
}

TEST(net_tcp_server, unix_address_validation)
{
    EXPECT_FALSE(SocketAddress::local("").has_value());
    EXPECT_FALSE(SocketAddress::local("ctl.sock").has_value());
    EXPECT_FALSE(SocketAddress::local("./ctl.sock").has_value());

    constexpr size_t SUN_PATH_SIZE = sizeof(sockaddr_un{}.sun_path);
    EXPECT_FALSE(SocketAddress::local("/" + std::string(SUN_PATH_SIZE - 1, 'a')).has_value());

    // The longest absolute path that still fits with its NUL.
    std::string longest(SUN_PATH_SIZE - 1, 'b');
    longest[0] = '/';
    auto addr = SocketAddress::local(longest);
    EXPECT_TRUE(addr.has_value());
    EXPECT_TRUE(addr->valid());
    EXPECT_EQ(addr->length(), socklen_t(offsetof(sockaddr_un, sun_path) + SUN_PATH_SIZE));
    EXPECT_TRUE(addr->to_string() == longest);
    EXPECT_EQ(addr->port(), 0U);
}

TEST_MAIN(statusbar_net, net_tcp_server_test)
