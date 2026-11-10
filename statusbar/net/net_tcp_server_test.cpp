// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// Test client: a plain blocking socket connected to the pool.
struct Client
{
    int fd{-1};

    explicit Client(SocketAddress const& to, int sock_type = SOCK_STREAM)
    {
        fd = ::socket(to.family(), sock_type, 0);
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

/// Owns a socket path for a test: clears a leftover on the way in, and
/// removes whatever is there on the way out. A failed EXPECT_* leaves a test
/// by return or by exception, so the cleanup has to be a destructor.
class LocalPath
{
  public:
    explicit LocalPath(std::string_view tag)
        : path_{std::string{"/tmp/sb_pool_"} + std::string{tag} + "_" + std::to_string(::getpid()) + ".sock"}
    {
        (void)::unlink(path_.c_str());
    }
    ~LocalPath() { (void)::unlink(path_.c_str()); }
    LocalPath(LocalPath const&) = delete;
    LocalPath(LocalPath&&) = delete;
    auto operator=(LocalPath const&) -> LocalPath& = delete;
    auto operator=(LocalPath&&) -> LocalPath& = delete;

    [[nodiscard]] auto str() const -> std::string const& { return path_; }
    [[nodiscard]] auto addr() const -> SocketAddress
    {
        auto a = SocketAddress::local(path_);
        return a ? *a : SocketAddress{};
    }
    [[nodiscard]] auto exists() const -> bool
    {
        struct stat st{};
        return ::lstat(path_.c_str(), &st) == 0;
    }
    [[nodiscard]] auto is_socket() const -> bool
    {
        struct stat st{};
        return ::lstat(path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
    }
    [[nodiscard]] auto mode_bits() const -> unsigned
    {
        struct stat st{};
        if (::lstat(path_.c_str(), &st) != 0) {
            return 0;
        }
        return static_cast<unsigned>(st.st_mode) & 0777U;
    }

  private:
    std::string path_;
};

/// A bound, listening socket that is not a pool — for the "somebody else is
/// already here" cases, including the wrong-socket-type one.
class RawListener
{
  public:
    RawListener(SocketAddress const& at, int sock_type)
    {
        fd_ = ::socket(AF_UNIX, sock_type, 0);
        if (fd_ >= 0 && ::bind(fd_, at.sockaddr(), at.length()) == 0) {
            bound_ = ::listen(fd_, 4) == 0;
        }
    }
    ~RawListener()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    RawListener(RawListener const&) = delete;
    RawListener(RawListener&&) = delete;
    auto operator=(RawListener const&) -> RawListener& = delete;
    auto operator=(RawListener&&) -> RawListener& = delete;

    [[nodiscard]] auto listening() const -> bool { return bound_; }

  private:
    int fd_{-1};
    bool bound_{false};
};

/// Leave a socket file behind with nobody listening on it, the way a process
/// that died without cleaning up does.
void leave_stale_socket(SocketAddress const& at)
{
    int const fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        (void)::bind(fd, at.sockaddr(), at.length());
        ::close(fd);  // the file stays; nothing is listening on it
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

//
// AF_UNIX local control socket
//

TEST(net_tcp_server_local, a_stream_listener_echoes_a_local_client)
{
    LocalPath const path{"echo"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 4, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());
    EXPECT_TRUE(path.is_socket());

    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    EXPECT_EQ(pool.active_count(), 1U);

    c.send_all("hello socket");
    pump(pool, 5);
    EXPECT_TRUE(c.recv_some() == "hello socket");

    ::shutdown(c.fd, SHUT_WR);
    pump(pool, 10);
    EXPECT_EQ(handler.closes.size(), 1U);
    EXPECT_EQ(pool.active_count(), 0U);
}

TEST(net_tcp_server_local, an_accepted_peer_that_never_bound_is_unnamed)
{
    // A local client has no address of its own unless it bound one, and
    // accept() reports AF_UNIX with nothing after the family. Treating an
    // empty path as failure would reject every ordinary client.
    LocalPath const path{"peer"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    if (handler.accepts.size() == 1) {
        auto const& peer = pool.peer(handler.accepts[0]);
        EXPECT_EQ(peer.family(), AF_UNIX);
        EXPECT_TRUE(peer.path().empty());
        EXPECT_EQ(peer.to_string(), "<unnamed>");
    }
}

TEST(net_tcp_server_local, the_local_address_reports_the_socket_path)
{
    LocalPath const path{"localaddr"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 1, handler};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    auto const bound = pool.local_addr();
    EXPECT_TRUE(bound.has_value());
    if (bound) {
        EXPECT_EQ(bound->family(), AF_UNIX);
        EXPECT_EQ(bound->path(), path.str());
    }
}

TEST(net_tcp_server_local, a_seqpacket_listener_keeps_message_boundaries)
{
#if !defined(__linux__)
    SKIP("AF_UNIX SOCK_SEQPACKET is Linux-only");
#endif
    // Two writes in, two whole messages out. On a stream the two could
    // arrive as one read; seqpacket is the reason this mode exists.
    LocalPath const path{"seq"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());

    Client const c{path.addr(), SOCK_SEQPACKET};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);

    c.send_all("first");
    c.send_all("second");
    pump(pool, 8);

    // Each recv() hands back exactly one message, in order.
    EXPECT_TRUE(c.recv_some() == "first");
    EXPECT_TRUE(c.recv_some() == "second");
}

/// Records accepts and closes; reads nothing, so a test reads the pool itself.
class QuietHandler : public TcpConnectionHandler
{
  public:
    void on_accept(size_t slot, SocketAddress const&, int64_t) override { accepts.push_back(slot); }
    void on_readable(size_t, int64_t) override {}
    void on_closed(size_t slot, int64_t) override { closes.push_back(slot); }

    std::vector<size_t> accepts;
    std::vector<size_t> closes;
};

TEST(net_tcp_server_local, a_seqpacket_message_longer_than_the_buffer_is_refused)
{
#if !defined(__linux__)
    SKIP("AF_UNIX SOCK_SEQPACKET is Linux-only");
#endif
    LocalPath const path{"seqbig"};
    QuietHandler handler;
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    EXPECT_TRUE(pool.valid());
    int const fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    auto const addr = path.addr();
    EXPECT_EQ(::connect(fd, addr.sockaddr(), addr.length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);

    std::array<uint8_t, 8> const big{1, 2, 3, 4, 5, 6, 7, 8};
    std::array<uint8_t, 2> const small{9, 10};
    EXPECT_EQ(::send(fd, big.data(), big.size(), 0), ssize_t{8});
    EXPECT_EQ(::send(fd, small.data(), small.size(), 0), ssize_t{2});
    std::array<uint8_t, 4> in{};
    auto const truncated = pool.read(handler.accepts[0], in);
    EXPECT_TRUE(!truncated && truncated.error() == NetError::buffer_full);
    auto const next = pool.read(handler.accepts[0], in);  // the long one is gone, the next intact
    EXPECT_TRUE(next && *next == 2 && in[0] == 9 && in[1] == 10);
    ::close(fd);
}

TEST(net_tcp_server_local, an_empty_seqpacket_message_is_not_eof)
{
#if !defined(__linux__)
    SKIP("AF_UNIX SOCK_SEQPACKET is Linux-only");
#endif
    LocalPath const path{"seqempty"};
    QuietHandler handler;
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    EXPECT_TRUE(pool.valid());
    int const fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    auto const addr = path.addr();
    EXPECT_EQ(::connect(fd, addr.sockaddr(), addr.length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
    size_t const slot = handler.accepts[0];

    std::array<uint8_t, 16> in{};
    EXPECT_EQ(::send(fd, in.data(), 0, 0), ssize_t{0});
    auto const empty = pool.read(slot, in);  // skipped: nothing else queued yet
    EXPECT_TRUE(!empty && empty.error() == NetError::would_block);
    std::array<uint8_t, 1> const one{7};
    EXPECT_EQ(::send(fd, in.data(), 0, 0), ssize_t{0});
    EXPECT_EQ(::send(fd, one.data(), one.size(), 0), ssize_t{1});
    auto const after = pool.read(slot, in);
    EXPECT_TRUE(after && *after == 1 && in[0] == 7);
    EXPECT_EQ(::send(fd, one.data(), one.size(), 0), ssize_t{1});
    ::close(fd);  // a message queued before the close is still read, then EOF
    auto const last = pool.read(slot, in);
    EXPECT_TRUE(last && *last == 1);
    auto const eof = pool.read(slot, in);
    EXPECT_TRUE(eof && *eof == 0);
}

TEST(net_tcp_server_local, empty_seqpacket_messages_queued_at_close_end_in_eof)
{
#if !defined(__linux__)
    SKIP("AF_UNIX SOCK_SEQPACKET is Linux-only");
#endif
    LocalPath const path{"seqclose"};
    QuietHandler handler;
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    EXPECT_TRUE(pool.valid());
    int const fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    auto const addr = path.addr();
    EXPECT_EQ(::connect(fd, addr.sockaddr(), addr.length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);

    std::array<uint8_t, 4> in{};
    EXPECT_EQ(::send(fd, in.data(), 0, 0), ssize_t{0});
    EXPECT_EQ(::send(fd, in.data(), 0, 0), ssize_t{0});
    ::close(fd);
    auto const eof = pool.read(handler.accepts[0], in);
    EXPECT_TRUE(eof && *eof == 0);
}

TEST(net_tcp_server_local, a_seqpacket_peer_shut_down_for_writing_is_eof)
{
#if !defined(__linux__)
    SKIP("AF_UNIX SOCK_SEQPACKET is Linux-only");
#endif
    LocalPath const path{"seqshut"};
    QuietHandler handler;
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    EXPECT_TRUE(pool.valid());
    int const fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    auto const addr = path.addr();
    EXPECT_EQ(::connect(fd, addr.sockaddr(), addr.length()), 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);

    std::array<uint8_t, 4> in{};
    EXPECT_EQ(::shutdown(fd, SHUT_WR), 0);
    auto const eof = pool.read(handler.accepts[0], in);
    EXPECT_TRUE(eof && *eof == 0);
    ::close(fd);
}

TEST(net_tcp_server_local, a_socket_left_by_a_previous_run_is_replaced)
{
    LocalPath const path{"stale"};
    leave_stale_socket(path.addr());
    EXPECT_TRUE(path.is_socket());

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    // Nobody was listening on it, so it was ours to clear out of the way.
    EXPECT_TRUE(pool.valid());

    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
    pump(pool, 5);
    EXPECT_EQ(handler.accepts.size(), 1U);
}

TEST(net_tcp_server_local, a_live_listener_is_not_hijacked)
{
    // The failure this guards: a second instance unlinks the path, binds its
    // own, and the running daemon keeps a socket nobody can reach.
    LocalPath const path{"live"};
    RawListener const first{path.addr(), SOCK_STREAM};
    EXPECT_TRUE(first.listening());

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool second{path.addr(), 2, handler};
    pool_ptr = &second;
    EXPECT_FALSE(second.valid());

    // The first listener's socket file is untouched, and it still answers.
    EXPECT_TRUE(path.is_socket());
    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
}

TEST(net_tcp_server_local, a_live_socket_of_the_other_type_is_still_not_hijacked)
{
    // A seqpacket connect to a live stream socket fails with EPROTOTYPE, not
    // ECONNREFUSED, and only ECONNREFUSED is read as "nobody is home" -- so
    // a mismatched live socket is refused rather than replaced. (The verdict
    // does not depend on which type the probe used: every answer but
    // ECONNREFUSED means leave it alone. The probe uses the configured type
    // so a matching live peer answers directly.)
    LocalPath const path{"xtype"};
    RawListener const stream_listener{path.addr(), SOCK_STREAM};
    EXPECT_TRUE(stream_listener.listening());

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_seqpacket = true;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());
    EXPECT_TRUE(path.is_socket());

    // And the stream listener is still reachable.
    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
}

TEST(net_tcp_server_local, a_regular_file_at_the_path_is_left_alone)
{
    LocalPath const path{"regular"};
    {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        std::FILE* f = std::fopen(path.str().c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        if (f != nullptr) {
            EXPECT_EQ(std::fwrite("keep", 4, 1, f), size_t{1});
            (void)std::fclose(f);
        }
    }

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());

    // Not a socket, so not ours to delete -- whatever it is, it is still here.
    EXPECT_TRUE(path.exists());
    EXPECT_FALSE(path.is_socket());
}

TEST(net_tcp_server_local, a_symlink_to_a_stale_socket_elsewhere_is_refused)
{
    // The case that tells lstat() from stat(). Through stat() the link reads
    // as a socket nobody is listening on, so the path would be "replaced":
    // unlink() removes the LINK, bind() puts a real socket at our path, and
    // we would have deleted a name we were never given. lstat() reports the
    // link as a link, it is not a socket, and the whole path is refused.
    LocalPath const path{"symlink"};
    LocalPath const elsewhere{"symlink_target"};
    leave_stale_socket(elsewhere.addr());
    EXPECT_TRUE(elsewhere.is_socket());
    EXPECT_EQ(::symlink(elsewhere.str().c_str(), path.str().c_str()), 0);

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());

    // The link is still a link, and the socket it pointed at is still there.
    struct stat st{};
    EXPECT_EQ(::lstat(path.str().c_str(), &st), 0);
    EXPECT_TRUE(S_ISLNK(st.st_mode));
    EXPECT_TRUE(elsewhere.is_socket());
}

TEST(net_tcp_server_local, a_dangling_symlink_at_the_path_is_refused)
{
    LocalPath const path{"dangling"};
    std::string const target = path.str() + ".missing";
    (void)::unlink(target.c_str());
    EXPECT_EQ(::symlink(target.c_str(), path.str().c_str()), 0);

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());

    // Nothing was created where it pointed: bind() does not follow a trailing
    // symlink either, so this one is refused twice over.
    struct stat st{};
    EXPECT_EQ(::lstat(path.str().c_str(), &st), 0);
    EXPECT_TRUE(S_ISLNK(st.st_mode));
    EXPECT_TRUE(::lstat(target.c_str(), &st) != 0);

    (void)::unlink(target.c_str());
}

TEST(net_tcp_server_local, the_requested_mode_is_on_the_socket_file)
{
    LocalPath const path{"mode"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_mode = 0600;  // owner only
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());
    EXPECT_EQ(path.mode_bits(), 0600U);
}

TEST(net_tcp_server_local, a_mode_the_umask_would_narrow_is_set_whole)
{
    LocalPath const path{"narrowed"};
    mode_t const umask_was = ::umask(0077);
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_mode = 0660;
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    pool_ptr = &pool;
    (void)::umask(umask_was);
    EXPECT_TRUE(pool.valid());
    EXPECT_EQ(path.mode_bits(), 0660U);
    auto const bound = pool.local_addr();
    EXPECT_TRUE(bound.has_value() && bound->path() == path.str());
    Client const c{path.addr()};
    EXPECT_TRUE(c.fd >= 0);
}

// A path of 100 octets is bound in place with its mode, as any other.
TEST(net_tcp_server_local, a_long_path_is_bound_with_its_mode)
{
    std::string top = "/tmp/sb_pool_long_XXXXXX";
    EXPECT_TRUE(::mkdtemp(top.data()) != nullptr);
    std::string const dir = top + "/" + std::string(100 - top.size() - 1, 'd');  // 100 octets
    EXPECT_EQ(::mkdir(dir.c_str(), 0700), 0);
    std::string const path = dir + "/s";
    auto const addr = SocketAddress::local(path);
    EXPECT_TRUE(addr.has_value());
    {
        TcpConnectionPool* pool_ptr = nullptr;
        EchoHandler handler{pool_ptr};
        TcpServerOptions options;
        options.unix_mode = 0600;
        TcpConnectionPool pool{*addr, 2, handler, options};
        pool_ptr = &pool;
        EXPECT_TRUE(pool.valid());
        struct stat st{};
        EXPECT_TRUE(::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode) && (st.st_mode & 07777U) == 0600U);
    }
    (void)::rmdir(dir.c_str());
    (void)::rmdir(top.c_str());
}

TEST(net_tcp_server_local, without_a_mode_the_umask_result_stands)
{
    LocalPath const path{"nomode"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};  // unix_mode stays -1
    pool_ptr = &pool;
    EXPECT_TRUE(pool.valid());
    // Nothing asserted about which bits those are -- only that the socket
    // exists and we did not chmod it to something of our own invention.
    EXPECT_TRUE(path.is_socket());
}

TEST(net_tcp_server_local, the_socket_file_goes_away_with_the_pool)
{
    LocalPath const path{"cleanup"};
    {
        TcpConnectionPool* pool_ptr = nullptr;
        EchoHandler handler{pool_ptr};
        TcpConnectionPool pool{path.addr(), 2, handler};
        pool_ptr = &pool;
        EXPECT_TRUE(pool.valid());
        EXPECT_TRUE(path.is_socket());
    }
    EXPECT_FALSE(path.exists());
}

TEST(net_tcp_server_local, a_file_that_replaced_ours_is_left_behind)
{
    // Ownership is by device and inode, not by path. If our socket is gone
    // and something else is at the name by the time we shut down, it is not
    // ours to remove.
    LocalPath const path{"swapped"};
    {
        TcpConnectionPool* pool_ptr = nullptr;
        EchoHandler handler{pool_ptr};
        TcpConnectionPool pool{path.addr(), 2, handler};
        pool_ptr = &pool;
        EXPECT_TRUE(pool.valid());

        // Somebody replaces the name with a file of their own.
        EXPECT_EQ(::unlink(path.str().c_str()), 0);
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        std::FILE* f = std::fopen(path.str().c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        if (f != nullptr) {
            EXPECT_EQ(std::fwrite("theirs", 6, 1, f), size_t{1});
            (void)std::fclose(f);
        }
    }
    EXPECT_TRUE(path.exists());
    EXPECT_FALSE(path.is_socket());
}

TEST(net_tcp_server_local, two_pools_in_a_row_at_the_same_path)
{
    // The ordinary restart: the first pool's destructor removes the file, and
    // the second binds a fresh one. Asserted because it is the path that
    // would break if ownership were tracked by anything other than the
    // filesystem.
    LocalPath const path{"restart"};
    for (int round = 0; round < 2; ++round) {
        TcpConnectionPool* pool_ptr = nullptr;
        EchoHandler handler{pool_ptr};
        TcpConnectionPool pool{path.addr(), 2, handler};
        pool_ptr = &pool;
        EXPECT_TRUE(pool.valid());

        Client const c{path.addr()};
        EXPECT_TRUE(c.fd >= 0);
        pump(pool, 5);
        EXPECT_EQ(handler.accepts.size(), 1U);
    }
}
