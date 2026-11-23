// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for statusbar.net module

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net.hpp"
#include "statusbar/net/net_ring_buffer_base.hpp"
#include "statusbar/net/net_ring_queue_base.hpp"
#include "statusbar/test/test.hpp"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace statusbar;
using namespace statusbar::net;
namespace ieee = statusbar::ieee;

//
// Static Assertions - Compile-time Verification
//

// Verify NetError enum values are distinct and start from 1
static_assert(static_cast<int>(NetError::socket_creation_failed) == 1, "NetError should start at 1");
static_assert(static_cast<int>(NetError::bind_failed) == 2, "bind_failed should be 2");
static_assert(static_cast<int>(NetError::already_connected) == 16, "NetError should have 16 values");

#ifdef __linux__
// Verify MmapError enum values
static_assert(static_cast<int>(MmapError::socket_creation_failed) == 1, "MmapError should start at 1");
static_assert(static_cast<int>(MmapError::not_supported_on_platform) == 15, "MmapError last value should be 15");
#endif

// Verify Ethernet constants are sensible
static_assert(MAX_ETHERNET_FRAME_SIZE == 1514, "Standard Ethernet frame without VLAN");
static_assert(MAX_ETHERNET_FRAME_SIZE_VLAN == 1518, "Ethernet frame with single VLAN tag");
static_assert(MAX_ETHERNET_FRAME_SIZE_QINQ == 1522, "Ethernet frame with QinQ double VLAN");
static_assert(MIN_ETHERNET_FRAME_SIZE == 60, "Minimum Ethernet frame excluding FCS");
static_assert(ETHERNET_HEADER_SIZE == 14, "Ethernet header: 6+6+2 bytes");
static_assert(VLAN_TAG_SIZE == 4, "VLAN tag: TPID + TCI");
static_assert(MAX_ETHERNET_PAYLOAD == 1500, "Standard MTU");
static_assert(MAX_ETHERNET_PAYLOAD_WITH_VLAN == 1504, "MTU + VLAN in payload");

#ifdef __linux__
// Verify MMAP constants
static_assert(MMAP_FRAME_SIZE == 2048, "MMAP frame slot size");
static_assert(MMAP_MAX_FRAME_LENGTH == 1522, "MMAP max frame with QinQ");
static_assert(MMAP_MIN_FRAME_LENGTH == 64, "IEEE 802.3 minimum frame");
#endif

// Verify socket type constants match system values
static_assert(SocketStream == SOCK_STREAM, "SocketStream should equal SOCK_STREAM");
static_assert(SocketDatagram == SOCK_DGRAM, "SocketDatagram should equal SOCK_DGRAM");

// Verify Ethernet constant relationships
static_assert(MAX_ETHERNET_FRAME_SIZE == ETHERNET_HEADER_SIZE + MAX_ETHERNET_PAYLOAD, "Frame = Header + Payload");
static_assert(MAX_ETHERNET_FRAME_SIZE_VLAN == MAX_ETHERNET_FRAME_SIZE + VLAN_TAG_SIZE, "VLAN frame = Frame + Tag");
static_assert(MAX_ETHERNET_FRAME_SIZE_QINQ == MAX_ETHERNET_FRAME_SIZE_VLAN + VLAN_TAG_SIZE, "QinQ = VLAN + Tag");

//
// Error Tests
//

//
// errno_code tests
//

//
// Unicast send and priority tests
//

namespace {

/// The loopback interface's index, 0 when the host has none by either name.
auto loopback_index() -> unsigned int
{
    auto const linux_name = ::if_nametoindex("lo");
    return linux_name != 0 ? linux_name : ::if_nametoindex("lo0");
}

/// An int socket option read back, -1 when the read fails.
auto read_int_option(int const fd, int const level, int const option) -> int
{
    int value = -1;
    socklen_t length = sizeof(value);
    if (::getsockopt(fd, level, option, &value, &length) != 0) {
        return -1;
    }
    return value;
}

}  // namespace

// The hop limit is written as asked and reads back as asked.
TEST(net_unicast_send, the_hop_limit_reads_back)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    EXPECT_TRUE(set_unicast_hops(socket->get(), AF_INET, 7).has_value());
    EXPECT_EQ(read_int_option(socket->get(), IPPROTO_IP, IP_TTL), 7);
    EXPECT_TRUE(set_unicast_hops(socket->get(), AF_INET, 200).has_value());
    EXPECT_EQ(read_int_option(socket->get(), IPPROTO_IP, IP_TTL), 200);
}

// 0 is the host's default, not a TTL of 0: a socket set back to it sends
// again with the stack's own value.
TEST(net_unicast_send, a_hop_limit_of_zero_restores_the_default)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    int const before = read_int_option(socket->get(), IPPROTO_IP, IP_TTL);
    EXPECT_TRUE(before > 0);
    EXPECT_TRUE(set_unicast_hops(socket->get(), AF_INET, 3).has_value());
    EXPECT_TRUE(set_unicast_hops(socket->get(), AF_INET, 0).has_value());
    int const after = read_int_option(socket->get(), IPPROTO_IP, IP_TTL);
    EXPECT_TRUE(after > 0);
    EXPECT_TRUE(after != 3);
}

// The egress interface is pinned to the loopback by index; where the option
// can be read back it names the same index, and 0 lets the route choose again.
TEST(net_unicast_send, the_interface_is_pinned_by_index_and_released_by_zero)
{
    auto const lo = loopback_index();
    if (lo == 0) {
        SKIP("no loopback interface by either name");
    }
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    EXPECT_TRUE(set_unicast_interface(socket->get(), AF_INET, lo).has_value());
#if defined(__linux__)
    EXPECT_EQ(
        static_cast<unsigned int>(ntohl(static_cast<uint32_t>(read_int_option(socket->get(), IPPROTO_IP, IP_UNICAST_IF)))), lo);
#elif defined(IP_BOUND_IF)
    EXPECT_EQ(static_cast<unsigned int>(read_int_option(socket->get(), IPPROTO_IP, IP_BOUND_IF)), lo);
#endif
    EXPECT_TRUE(set_unicast_interface(socket->get(), AF_INET, 0).has_value());
}

// set_unicast_send is the two writes together, both made whatever the values.
TEST(net_unicast_send, the_pair_sets_interface_and_hops_together)
{
    auto const lo = loopback_index();
    if (lo == 0) {
        SKIP("no loopback interface by either name");
    }
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    EXPECT_TRUE(set_unicast_send(socket->get(), AF_INET, lo, 9).has_value());
    EXPECT_EQ(read_int_option(socket->get(), IPPROTO_IP, IP_TTL), 9);
    EXPECT_TRUE(set_unicast_send(socket->get(), AF_INET, 0, 0).has_value());
    EXPECT_TRUE(read_int_option(socket->get(), IPPROTO_IP, IP_TTL) != 9);
}

// SO_PRIORITY is Linux's: there it reads back, and the unprivileged range is
// accepted; elsewhere the call is a successful no-op.
TEST(net_socket_priority, the_priority_reads_back_on_linux_and_is_a_no_op_elsewhere)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    EXPECT_TRUE(set_priority(socket->get(), 6).has_value());
#if defined(__linux__)
    EXPECT_EQ(read_int_option(socket->get(), SOL_SOCKET, SO_PRIORITY), 6);
    EXPECT_FALSE(set_priority(-1, 1).has_value());
#else
    EXPECT_TRUE(set_priority(-1, 1).has_value());
#endif
}

//
// FileDescriptor Tests
//

//
// SocketAddress Tests
//

//
// AF_LOCAL (AF_UNIX) SocketAddress Tests
//

namespace {

#ifdef __linux__
/// A socket path under /tmp, tagged per test and per process so two runs
/// can overlap. Deliberately short: sun_path is the tightest buffer in the
/// sockets API, and these are real files in a real directory.
auto local_test_path(std::string_view tag) -> std::string
{
    std::string path{"/tmp/sb_addr_"};
    path += tag;
    path += '_';
    path += std::to_string(::getpid());
    path += ".sock";
    return path;
}

/// Owns a test socket path: clears a leftover on the way in and removes
/// the socket on the way out. A failed EXPECT_* leaves the test by return
/// or by exception depending on the build, so an unlink written at the
/// bottom of a test runs only while the test passes -- which is exactly
/// when it is not needed.
class LocalSocketPath
{
  public:
    explicit LocalSocketPath(std::string_view tag)
        : path_{local_test_path(tag)}
    {
        ::unlink(path_.c_str());
    }
    ~LocalSocketPath() { ::unlink(path_.c_str()); }
    LocalSocketPath(LocalSocketPath const&) = delete;
    LocalSocketPath(LocalSocketPath&&) = delete;
    auto operator=(LocalSocketPath const&) -> LocalSocketPath& = delete;
    auto operator=(LocalSocketPath&&) -> LocalSocketPath& = delete;

    [[nodiscard]] auto get() const noexcept -> std::string const& { return path_; }

  private:
    std::string path_;
};
#endif  // __linux__

}  // namespace

#ifdef __linux__

TEST(net_addr_local, an_autobound_abstract_name_renders_with_an_at_sign)
{
    // local() will not make an abstract name, so the only source of one is
    // the kernel: binding with nothing but the family asks Linux to
    // autobind, which produces an abstract name of five hex digits after a
    // leading NUL. Rendering what we are handed is still our job.
    int const fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    EXPECT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    sockaddr_un family_only{};
    family_only.sun_family = AF_UNIX;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const* as_sockaddr = reinterpret_cast<struct sockaddr const*>(&family_only);
    EXPECT_EQ(::bind(fd, as_sockaddr, static_cast<socklen_t>(sizeof(sa_family_t))), 0);

    SocketAddress bound;
    bound.reset_length();
    EXPECT_EQ(::getsockname(fd, bound.sockaddr(), bound.length_ptr()), 0);
    ::close(fd);

    EXPECT_TRUE(bound.valid());
    EXPECT_EQ(bound.family(), AF_UNIX);
    // Abstract: no filesystem path to report.
    EXPECT_TRUE(bound.path().empty());
    auto const rendered = bound.to_string();
    EXPECT_EQ(rendered.size(), 6U);
    EXPECT_EQ(rendered.front(), '@');
}

TEST(net_addr_local, an_accepted_unnamed_peer_is_valid_and_pathless)
{
    LocalSocketPath const path{"accept"};
    auto listen_addr = SocketAddress::local(path.get());
    EXPECT_TRUE(listen_addr.has_value());
    if (!listen_addr) {
        return;
    }

    auto listener = create_tcp_listener(*listen_addr, 1);
    EXPECT_TRUE(listener.has_value());
    if (listener) {
        // A client that never binds has no address of its own, and accept()
        // reports exactly that: AF_UNIX with nothing after the family. It is
        // a valid address -- a caller reading an empty path as failure would
        // reject a legitimate connection.
        auto client = create_tcp_socket(*listen_addr, false);
        EXPECT_TRUE(client.has_value());
        if (client) {
            EXPECT_EQ(::connect(client->get(), listen_addr->sockaddr(), listen_addr->length()), 0);

            SocketAddress peer;
            peer.reset_length();
            int const accepted = ::accept(listener->get(), peer.sockaddr(), peer.length_ptr());
            EXPECT_TRUE(accepted >= 0);
            if (accepted >= 0) {
                ::close(accepted);
            }
            EXPECT_TRUE(peer.valid());
            EXPECT_EQ(peer.family(), AF_UNIX);
            EXPECT_TRUE(peer.path().empty());
            EXPECT_EQ(peer.to_string(), "<unnamed>");
        }
    }
}

TEST(net_addr_local, a_datagram_exchange_names_the_sender_by_its_path)
{
    // The shape the linuxptp management socket wants: bind a path of our
    // own, send to theirs, and read the sender's path back off the reply
    // address. Everything here goes through the public API.
    LocalSocketPath const server_path{"srv"};
    LocalSocketPath const client_path{"cli"};

    auto server_addr = SocketAddress::local(server_path.get());
    auto client_addr = SocketAddress::local(client_path.get());
    EXPECT_TRUE(server_addr.has_value());
    EXPECT_TRUE(client_addr.has_value());
    if (server_addr && client_addr) {
        auto server = create_udp_socket(*server_addr, true);
        auto client = create_udp_socket(*client_addr, true);
        EXPECT_TRUE(server.has_value());
        EXPECT_TRUE(client.has_value());
        if (server && client) {
            std::string_view const question{"GET_TIME_STATUS_NP"};
            auto const sent =
                ::sendto(client->get(), question.data(), question.size(), 0, server_addr->sockaddr(), server_addr->length());
            EXPECT_EQ(sent, static_cast<ssize_t>(question.size()));

            std::array<char, 64> buf{};
            SocketAddress from;
            from.reset_length();
            auto const received = ::recvfrom(server->get(), buf.data(), buf.size(), 0, from.sockaddr(), from.length_ptr());
            EXPECT_EQ(received, static_cast<ssize_t>(question.size()));
            EXPECT_EQ(from.family(), AF_UNIX);
            EXPECT_EQ(from.path(), client_path.get());
            // The length the kernel reports for the address we built is the
            // length we built: this is why local() counts the NUL.
            EXPECT_EQ(from.length(), client_addr->length());

            std::string_view const answer{"OK"};
            auto const replied = ::sendto(server->get(), answer.data(), answer.size(), 0, from.sockaddr(), from.length());
            EXPECT_EQ(replied, static_cast<ssize_t>(answer.size()));

            std::array<char, 64> reply{};
            auto const back = ::recv(client->get(), reply.data(), reply.size(), 0);
            EXPECT_EQ(back, static_cast<ssize_t>(answer.size()));
            EXPECT_EQ(std::string_view(reply.data(), answer.size()), answer);
        }
    }
}

TEST(net_addr_local, a_dscp_request_is_skipped_rather_than_failing_a_local_socket)
{
    LocalSocketPath const path{"dscp"};
    auto addr = SocketAddress::local(path.get());
    EXPECT_TRUE(addr.has_value());
    if (addr) {
        // DSCP is an IP header field. Setting it on a unix socket fails,
        // and failing it here would take the whole open down.
        auto sock = create_udp_socket(*addr, true, 46);
        EXPECT_TRUE(sock.has_value());
    }
}

#endif  // __linux__

//
// Socket Utility Tests
//

//
// Integration Tests (create real sockets)
//

TEST(net_socket_create, create_udp_socket)
{
    auto addr = SocketAddress::ipv4_any(0);  // Port 0 = ephemeral
    auto result = create_udp_socket(addr, true);
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_TRUE(result->valid());
    }
}

TEST(net_socket_create, create_tcp_socket)
{
    auto addr = SocketAddress::ipv4_loopback(0);  // Port 0 = ephemeral
    auto result = create_tcp_socket(addr, true);
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_TRUE(result->valid());
    }
}

TEST(net_socket_create, create_tcp_listener)
{
    auto addr = SocketAddress::ipv4_loopback(0);
    auto result = create_tcp_listener(addr);
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_TRUE(result->valid());
    }
}

TEST(net_socket_create, set_nonblocking_valid)
{
    auto addr = SocketAddress::ipv4_any(0);
    auto result = create_udp_socket(addr, true);
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto status = set_nonblocking(result->get());
        EXPECT_TRUE(status);
    }
}

//
// UDP multicast helpers (create real sockets)
//
// The positive path runs over `lo`, which is enough to prove a join, a send
// and a receive. It is not enough to prove the negative: when the egress
// interface is the loopback device, the device returns the frame whatever
// IP_MULTICAST_LOOP says, so a datagram sent with loop = false still arrives
// here. That half of the option is checked by reading the socket option back
// instead, and a true off-host test needs a second machine.
//

namespace {

/// Bind `fd` to an ephemeral port on every address and report the port the
/// kernel chose, or 0 if the bind failed.
[[nodiscard]] auto bind_ephemeral(int fd) noexcept -> uint16_t
{
    sockaddr_in wanted{};
    wanted.sin_family = AF_INET;
    wanted.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(fd, reinterpret_cast<sockaddr const*>(&wanted), sizeof(wanted)) != 0) {
        return 0;
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        return 0;
    }
    return ntohs(bound.sin_port);
}

/// An interface index no host has, for checking that the index argument is
/// really passed to the kernel rather than quietly dropped.
constexpr unsigned int NoSuchInterface = 0x7FFFFFFF;

}  // namespace

TEST(net_multicast, make_udp_socket_is_cloexec_and_nonblocking)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    if (socket) {
        EXPECT_TRUE(socket->valid());

        // Asked of the kernel rather than assumed: a descriptor that leaks
        // across exec into a child is a real fault in a daemon that spawns.
        int const descriptor_flags = ::fcntl(socket->get(), F_GETFD);
        EXPECT_TRUE(descriptor_flags >= 0);
        EXPECT_NE(descriptor_flags & FD_CLOEXEC, 0);

        int const status_flags = ::fcntl(socket->get(), F_GETFL);
        EXPECT_TRUE(status_flags >= 0);
        EXPECT_NE(status_flags & O_NONBLOCK, 0);
    }
}

TEST(net_multicast, join_group_rejects_a_non_multicast_address)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    if (socket) {
        auto const unicast = join_group(socket->get(), statusbar::ip::IPv4Address(10, 0, 0, 1), 0);
        EXPECT_FALSE(unicast.has_value());
        EXPECT_TRUE(unicast.error() == std::make_error_code(std::errc::invalid_argument));

        auto const broadcast = join_group(socket->get(), statusbar::ip::IPv4Address(255, 255, 255, 255), 0);
        EXPECT_FALSE(broadcast.has_value());

        auto const unspecified = join_group(socket->get(), statusbar::ip::IPv4Address(0, 0, 0, 0), 0);
        EXPECT_FALSE(unspecified.has_value());

        // The boundaries of 224.0.0.0/4 are in the group, not out of it.
        EXPECT_TRUE(join_group(socket->get(), statusbar::ip::IPv4Address(224, 0, 0, 1), 0).has_value());
        EXPECT_TRUE(join_group(socket->get(), statusbar::ip::IPv4Address(239, 255, 255, 255), 0).has_value());
    }
}

TEST(net_multicast, join_group_reports_an_unknown_interface)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    if (socket) {
        auto const joined = join_group(socket->get(), statusbar::ip::IPv4Address(239, 69, 1, 2), NoSuchInterface);
        EXPECT_FALSE(joined.has_value());
    }
}

TEST(net_multicast, set_multicast_send_sets_ttl_and_loop)
{
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    if (socket) {
        for (bool const loop : {true, false}) {
            auto const prepared = set_multicast_send(socket->get(), 0, 7, loop);
            EXPECT_TRUE(prepared.has_value());

            int ttl = -1;
            socklen_t ttl_length = sizeof(ttl);
            EXPECT_EQ(::getsockopt(socket->get(), IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &ttl_length), 0);
            EXPECT_EQ(ttl, 7);

            int looped = -1;
            socklen_t loop_length = sizeof(looped);
            EXPECT_EQ(::getsockopt(socket->get(), IPPROTO_IP, IP_MULTICAST_LOOP, &looped, &loop_length), 0);
            EXPECT_EQ(looped, loop ? 1 : 0);
        }
    }
}

TEST(net_multicast, set_multicast_send_reports_an_unknown_interface)
{
#if defined(__linux__)
    auto socket = make_udp_socket();
    EXPECT_TRUE(socket.has_value());
    if (socket) {
        auto const prepared = set_multicast_send(socket->get(), NoSuchInterface, 1, true);
        EXPECT_FALSE(prepared.has_value());
    }
#else
    // Elsewhere the index cannot be expressed, so there is nothing to reject.
    EXPECT_TRUE(true);
#endif
}

TEST(net_multicast, a_datagram_sent_to_a_joined_group_arrives)
{
    statusbar::ip::IPv4Address const group(239, 69, 1, 2);
    auto const loopback_index = ::if_nametoindex("lo");

    auto receiver = make_udp_socket();
    auto sender = make_udp_socket();
    EXPECT_TRUE(receiver.has_value());
    EXPECT_TRUE(sender.has_value());
    if (!receiver || !sender || loopback_index == 0) {
        return;
    }

    EXPECT_TRUE(set_reuse_addr(receiver->get()).has_value());
    auto const port = bind_ephemeral(receiver->get());
    EXPECT_NE(port, 0);
    if (port == 0) {
        return;
    }

    // A host whose loopback is not multicast-capable cannot run the rest; the
    // join is the thing that tells us, so the remainder hangs off it.
    auto const joined = join_group(receiver->get(), group, loopback_index);
    if (!joined) {
        return;
    }
    EXPECT_TRUE(set_multicast_send(sender->get(), loopback_index, 1, true).has_value());

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(group.to_uint32());
    destination.sin_port = htons(port);

    constexpr std::string_view payload{"probe"};
    auto const sent = ::sendto(
        sender->get(), payload.data(), payload.size(), 0, reinterpret_cast<sockaddr const*>(&destination), sizeof(destination));
    EXPECT_EQ(static_cast<size_t>(sent), payload.size());

    // The socket is non-blocking by construction, so wait for it rather than
    // racing the kernel's delivery.
    pollfd waiting{.fd = receiver->get(), .events = POLLIN, .revents = 0};
    EXPECT_EQ(::poll(&waiting, 1, 2000), 1);

    std::array<char, 64> received{};
    auto const got = ::recv(receiver->get(), received.data(), received.size(), 0);
    EXPECT_EQ(static_cast<size_t>(got), payload.size());
    if (got > 0) {
        EXPECT_TRUE(std::string_view(received.data(), static_cast<size_t>(got)) == payload);
    }
}

//
// IPv6 Scope ID Tests
//

//
// NotificationPipe Tests
//

//
// RawnetContext Tests
//

#ifdef __linux__
//
// MmapError Tests
//

//
// MmapContext Tests (stub tests for non-Linux platforms)
//

//
// Error Category Name Tests (mmap)
//

#endif  // __linux__

//
// Error Category Name Tests
//

//
// RawnetContext Move Assignment Test
//

//
// RingQueueBase Tests (non-template base)
//

// Simple struct with clear() for testing RingQueueBase via FixedQueue

//
// RingBufferBase Tests (non-template base)
//

//
// MessageReactor Tests
//

namespace {

/// Mock Pollable for testing the reactor.
/// Uses a pipe internally so poll() can detect readiness.
class MockPollable : public Pollable
{
  public:
    MockPollable()
    {
        int fds[2] = {-1, -1};
        if (::pipe(fds) == 0) {
            read_fd_ = fds[0];
            write_fd_ = fds[1];
            (void)set_nonblocking(read_fd_);
            (void)set_nonblocking(write_fd_);
        }
    }

    ~MockPollable() override
    {
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
        if (write_fd_ >= 0) {
            ::close(write_fd_);
        }
    }

    MockPollable(MockPollable const&) = delete;
    auto operator=(MockPollable const&) -> MockPollable& = delete;
    MockPollable(MockPollable&&) = delete;
    auto operator=(MockPollable&&) -> MockPollable& = delete;

    /// Make the fd readable (triggers on_ready on next poll cycle).
    void make_readable()
    {
        uint8_t byte = 0x42;
        (void)::write(write_fd_, &byte, 1);
    }

    /// Drain pipe so it becomes non-readable again.
    void drain_pipe()
    {
        uint8_t buf[64];
        while (::read(read_fd_, buf, sizeof(buf)) > 0) {
        }
    }

    void set_finished(bool v) { finished_ = v; }
    void set_use_fd(bool v) { use_fd_ = v; }

    [[nodiscard]] auto on_ready_count() const -> int { return on_ready_count_; }
    [[nodiscard]] auto tick_count() const -> int { return tick_count_; }
    [[nodiscard]] auto on_writable_count() const -> int { return on_writable_count_; }
    [[nodiscard]] auto last_now_ns() const -> int64_t { return last_now_ns_; }

    // -- Pollable interface --

    [[nodiscard]] auto fd() const noexcept -> int override { return use_fd_ ? read_fd_ : -1; }

    void on_ready(int64_t now_ns) override
    {
        ++on_ready_count_;
        last_now_ns_ = now_ns;
        drain_pipe();
    }

    void on_writable(int64_t now_ns) override
    {
        ++on_writable_count_;
        last_now_ns_ = now_ns;
    }

    void tick(int64_t now_ns) override
    {
        ++tick_count_;
        last_now_ns_ = now_ns;
    }

    [[nodiscard]] auto finished() const noexcept -> bool override { return finished_; }

  private:
    int read_fd_{-1};
    int write_fd_{-1};
    bool finished_{false};
    bool use_fd_{true};
    int on_ready_count_{0};
    int tick_count_{0};
    int on_writable_count_{0};
    int64_t last_now_ns_{0};
};

}  // namespace

TEST(net_reactor, add_from_on_ready_does_not_invalidate_dispatch)
{
    // dispatch_ready used to hold a reference into ports_ across both
    // callbacks; an add() from on_ready() that reallocated the vector left
    // the reference dangling for the on_writable() call on the same port
    // (use-after-free under ASan). Dispatch now snapshots the raw pointer,
    // which stays stable across vector growth.
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 0; };

    MessageReactor reactor{stop, clock, 0};

    int on_writable_count = 0;

    struct AddingPort : public Pollable
    {
        int sock_a{-1};
        int sock_b{-1};
        MessageReactor& reactor_ref;
        int& on_writable_count_ref;

        AddingPort(MessageReactor& r, int& wc)
            : reactor_ref(r)
            , on_writable_count_ref(wc)
        {
            int fds[2];
            ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
            sock_a = fds[0];
            sock_b = fds[1];
            (void)set_nonblocking(sock_a);
            uint8_t byte = 1;
            (void)::write(sock_b, &byte, 1);  // sock_a: POLLIN and POLLOUT in one cycle
        }
        ~AddingPort() override
        {
            ::close(sock_a);
            ::close(sock_b);
        }
        AddingPort(AddingPort const&) = delete;
        auto operator=(AddingPort const&) -> AddingPort& = delete;
        AddingPort(AddingPort&&) = delete;
        auto operator=(AddingPort&&) -> AddingPort& = delete;

        [[nodiscard]] auto fd() const noexcept -> int override { return sock_a; }
        [[nodiscard]] auto poll_events() const noexcept -> short override { return static_cast<short>(POLLIN | POLLOUT); }
        void on_ready(int64_t /*now_ns*/) override
        {
            uint8_t buf[16];
            while (::read(sock_a, buf, sizeof(buf)) > 0) {
            }
            // Grow ports_ far past any small-capacity threshold so the
            // vector reallocates mid-dispatch.
            for (int i = 0; i < 64; ++i) {
                auto extra = std::make_unique<MockPollable>();
                extra->set_finished(true);  // reaped by remove_finished()
                reactor_ref.add(std::move(extra));
            }
        }
        void on_writable(int64_t /*now_ns*/) override { ++on_writable_count_ref; }
        void tick(int64_t /*now_ns*/) override {}
        [[nodiscard]] auto finished() const noexcept -> bool override { return false; }
    };

    reactor.add(std::make_unique<AddingPort>(reactor, on_writable_count));
    (void)reactor.poll_once(10);

    // on_writable must still be delivered to the (stable) port after the add.
    EXPECT_EQ(on_writable_count, 1);
    // The finished extras were reaped; only the AddingPort remains.
    EXPECT_EQ(reactor.active_count(), size_t{1});
}

//
// Exhaustive error message coverage
//

//
// LoopbackPort Tests
//

#include "statusbar/net/net_loopback_port.hpp"

//
// BpfPortContext Tests (no real hardware — just construction and pool logic)
//

#include "statusbar/net/net_bpf_port.hpp"

//
// RawEthernetPollable Tests
//

#include "statusbar/net/net_raw_ethernet_pollable.hpp"

TEST_MAIN(statusbar_net, net_functional_test)
