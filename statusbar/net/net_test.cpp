// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for statusbar.net module

#include "statusbar/net/net.hpp"

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net_ring_buffer_base.hpp"
#include "statusbar/net/net_ring_queue_base.hpp"
#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

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

TEST(net_error, error_code_from_enum)
{
    std::error_code ec = NetError::socket_creation_failed;
    EXPECT_TRUE(ec.value() == 1);
    EXPECT_TRUE(ec.category().name() != nullptr);
}

TEST(net_error, different_errors_have_different_values)
{
    std::error_code ec1 = NetError::socket_creation_failed;
    std::error_code ec2 = NetError::bind_failed;
    EXPECT_NE(ec1.value(), ec2.value());
}

TEST(net_error, error_message_not_empty)
{
    std::error_code ec = NetError::socket_creation_failed;
    EXPECT_TRUE(!ec.message().empty());
}

//
// FileDescriptor Tests
//

TEST(net_fd, default_invalid)
{
    FileDescriptor fd;
    EXPECT_FALSE(fd.valid());
    EXPECT_EQ(fd.get(), -1);
}

TEST(net_fd, explicit_value)
{
    // Note: We don't actually create a socket here, just test construction
    FileDescriptor fd{-1};
    EXPECT_FALSE(fd.valid());
}

TEST(net_fd, move_construction)
{
    FileDescriptor fd1{-1};
    FileDescriptor fd2{std::move(fd1)};
    EXPECT_FALSE(fd1.valid());
    EXPECT_FALSE(fd2.valid());
}

TEST(net_fd, move_assignment)
{
    FileDescriptor fd1{-1};
    FileDescriptor fd2{-1};
    fd2 = std::move(fd1);
    EXPECT_FALSE(fd1.valid());
    EXPECT_FALSE(fd2.valid());
}

TEST(net_fd, release)
{
    FileDescriptor fd{-1};
    int raw = fd.release();
    EXPECT_EQ(raw, -1);
    EXPECT_FALSE(fd.valid());
}

//
// SocketAddress Tests
//

TEST(net_addr, default_invalid)
{
    SocketAddress addr;
    EXPECT_FALSE(addr.valid());
}

TEST(net_addr, ipv4_any)
{
    auto addr = SocketAddress::ipv4_any(8080);
    EXPECT_TRUE(addr.valid());
    EXPECT_EQ(addr.port(), 8080);
    EXPECT_EQ(addr.family(), AF_INET);
}

TEST(net_addr, ipv4_loopback)
{
    auto addr = SocketAddress::ipv4_loopback(9999);
    EXPECT_TRUE(addr.valid());
    EXPECT_EQ(addr.port(), 9999);
    EXPECT_EQ(addr.family(), AF_INET);
}

TEST(net_addr, ipv4_from_octets)
{
    auto addr = SocketAddress::ipv4(192, 168, 1, 100, 1234);
    EXPECT_TRUE(addr.valid());
    EXPECT_EQ(addr.port(), 1234);
    EXPECT_EQ(addr.family(), AF_INET);
}

TEST(net_addr, ipv6_any)
{
    auto addr = SocketAddress::ipv6_any(8080);
    EXPECT_TRUE(addr.valid());
    EXPECT_EQ(addr.port(), 8080);
    EXPECT_EQ(addr.family(), AF_INET6);
}

TEST(net_addr, ipv6_loopback)
{
    auto addr = SocketAddress::ipv6_loopback(9999);
    EXPECT_TRUE(addr.valid());
    EXPECT_EQ(addr.port(), 9999);
    EXPECT_EQ(addr.family(), AF_INET6);
}

TEST(net_addr, to_string_ipv4)
{
    auto addr = SocketAddress::ipv4_loopback(8080);
    auto str = addr.to_string();
    EXPECT_TRUE(str.find("127.0.0.1") != std::string::npos);
    EXPECT_TRUE(str.find("8080") != std::string::npos);
}

TEST(net_addr, to_string_invalid)
{
    SocketAddress addr;
    auto str = addr.to_string();
    EXPECT_TRUE(str.find("invalid") != std::string::npos);
}

TEST(net_addr, to_string_ipv6_uses_brackets)
{
    auto addr = SocketAddress::ipv6_loopback(9000);
    auto str = addr.to_string();
    // Brackets surround the IPv6 literal: "[::1]:9000"
    EXPECT_TRUE(str.front() == '[');
    EXPECT_TRUE(str.find("]:9000") != std::string::npos);
    EXPECT_TRUE(str.find("::1") != std::string::npos);
}

TEST(net_addr, from_string_ipv4)
{
    auto result = SocketAddress::from_string("127.0.0.1", "8080", SOCK_DGRAM);
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_EQ(result->port(), 8080);
        EXPECT_EQ(result->family(), AF_INET);
    }
}

TEST(net_addr, from_string_ipv6)
{
    auto result = SocketAddress::from_string("::1", "9000", SOCK_STREAM);
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_EQ(result->port(), 9000);
        EXPECT_EQ(result->family(), AF_INET6);
    }
}

TEST(net_addr, from_string_invalid)
{
    auto result = SocketAddress::from_string("not.valid.address.here", "abc", SOCK_DGRAM);
    EXPECT_FALSE(result.has_value());
}

TEST(net_addr, from_string_rejects_oversize_host)
{
    // host_buf is std::array<char, 256>; from_string returns invalid_address
    // when host.size() >= 256 (so the value doesn't fit with a NUL terminator).
    std::string const oversize_host(256, 'a');
    auto result = SocketAddress::from_string(oversize_host, "8080", SOCK_DGRAM);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::invalid_address));
}

TEST(net_addr, from_string_rejects_oversize_port)
{
    // port_buf is std::array<char, 64>; same shape as oversize host.
    std::string const oversize_port(64, '9');
    auto result = SocketAddress::from_string("127.0.0.1", oversize_port, SOCK_DGRAM);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::invalid_address));
}

TEST(net_addr, from_string_invalid_returns_getaddrinfo_failed)
{
    // Once host+port fit the local buffers, the only way for from_string to
    // fail is for getaddrinfo() to reject the input (AI_NUMERICHOST means it
    // won't try DNS).
    auto result = SocketAddress::from_string("not.a.numeric.host", "8080", SOCK_DGRAM);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::getaddrinfo_failed));
}

TEST(net_util, split_host_port_ipv4)
{
    std::string host;
    std::string port;
    EXPECT_TRUE(split_host_port("example.com:3478", host, port));
    EXPECT_EQ(host, "example.com");
    EXPECT_EQ(port, "3478");
}

TEST(net_util, split_host_port_ipv6_brackets)
{
    std::string host;
    std::string port;
    EXPECT_TRUE(split_host_port("[fe80::1]:9999", host, port));
    EXPECT_EQ(host, "fe80::1");
    EXPECT_EQ(port, "9999");
}

TEST(net_util, split_host_port_invalid)
{
    std::string host;
    std::string port;
    EXPECT_FALSE(split_host_port("noport", host, port));
}

TEST(net_util, parse_hex_into)
{
    std::array<uint8_t, 4> out{};
    EXPECT_TRUE(parse_hex_into("0a1b2c3d", std::span<uint8_t>{out}));
    EXPECT_EQ(out[0], 0x0a);
    EXPECT_EQ(out[1], 0x1b);
    EXPECT_EQ(out[2], 0x2c);
    EXPECT_EQ(out[3], 0x3d);
    EXPECT_FALSE(parse_hex_into("zz", std::span<uint8_t>{out}));
}

TEST(net_util, address_to_host_port_ipv4)
{
    auto addr = SocketAddress::ipv4_loopback(8080);
    std::string host;
    uint16_t port = 0;
    EXPECT_TRUE(address_to_host_port(addr, host, port));
    EXPECT_EQ(host, "127.0.0.1");
    EXPECT_EQ(port, 8080);
}

//
// Socket Utility Tests
//

TEST(net_socket, would_block_check)
{
    // These are just function existence tests
    errno = EAGAIN;
    EXPECT_TRUE(would_block());

    errno = EWOULDBLOCK;
    EXPECT_TRUE(would_block());

    errno = 0;
    EXPECT_FALSE(would_block());
}

TEST(net_socket, was_interrupted_check)
{
    errno = EINTR;
    EXPECT_TRUE(was_interrupted());

    errno = 0;
    EXPECT_FALSE(was_interrupted());
}

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
// IPv6 Scope ID Tests
//

TEST(net_scope_id, ipv6_default_scope_id_zero)
{
    std::array<uint8_t, 16> addr{};
    addr[15] = 1;  // ::1
    auto sock_addr = SocketAddress::ipv6(addr, 8080);
    EXPECT_EQ(sock_addr.scope_id(), 0U);
}

TEST(net_scope_id, ipv6_with_scope_id)
{
    std::array<uint8_t, 16> addr{};
    addr[0] = 0xfe;
    addr[1] = 0x80;                                       // fe80:: link-local prefix
    auto sock_addr = SocketAddress::ipv6(addr, 8080, 5);  // scope_id = 5
    EXPECT_EQ(sock_addr.scope_id(), 5U);
    EXPECT_EQ(sock_addr.port(), 8080);
    EXPECT_EQ(sock_addr.family(), AF_INET6);
}

TEST(net_scope_id, ipv6_link_local_factory)
{
    std::array<uint8_t, 16> addr{};
    addr[0] = 0xfe;
    addr[1] = 0x80;
    auto sock_addr = SocketAddress::ipv6_link_local(addr, 8080, 7);
    EXPECT_EQ(sock_addr.scope_id(), 7U);
    EXPECT_EQ(sock_addr.port(), 8080);
    EXPECT_EQ(sock_addr.family(), AF_INET6);
}

TEST(net_scope_id, set_scope_id)
{
    std::array<uint8_t, 16> addr{};
    addr[0] = 0xfe;
    addr[1] = 0x80;
    auto sock_addr = SocketAddress::ipv6(addr, 8080);
    sock_addr.set_scope_id(42);
    EXPECT_EQ(sock_addr.scope_id(), 42U);
}

TEST(net_scope_id, scope_id_ignored_for_ipv4)
{
    auto sock_addr = SocketAddress::ipv4_loopback(8080);
    // IPv4 doesn't have scope_id, should return 0
    EXPECT_EQ(sock_addr.scope_id(), 0U);
}

//
// NotificationPipe Tests
//

TEST(net_notify, default_invalid)
{
    NotificationPipe pipe;
    EXPECT_FALSE(pipe.valid());
    EXPECT_EQ(pipe.read_fd(), -1);
    EXPECT_EQ(pipe.write_fd(), -1);
}

TEST(net_notify, create_valid)
{
    auto pipe = NotificationPipe::create();
    EXPECT_TRUE(pipe.valid());
    EXPECT_TRUE(pipe.read_fd() >= 0);
    EXPECT_TRUE(pipe.write_fd() >= 0);
}

TEST(net_notify, send_and_receive)
{
    auto pipe = NotificationPipe::create();
    EXPECT_TRUE(pipe.valid());

    EXPECT_TRUE(pipe.notify(42));

    uint8_t code{};
    EXPECT_TRUE(pipe.read_one(code));
    EXPECT_EQ(code, 42);
}

TEST(net_notify, multiple_notifications)
{
    auto pipe = NotificationPipe::create();
    EXPECT_TRUE(pipe.valid());

    // Send multiple notifications
    for (uint8_t i = 0; i < 5; ++i) {
        EXPECT_TRUE(pipe.notify(i));
    }

    // Read all notifications in order
    for (uint8_t i = 0; i < 5; ++i) {
        uint8_t code{};
        EXPECT_TRUE(pipe.read_one(code));
        EXPECT_EQ(code, i);
    }

    // No more notifications
    uint8_t code{};
    EXPECT_FALSE(pipe.read_one(code));
}

TEST(net_notify, drain_with_callback)
{
    auto pipe = NotificationPipe::create();
    EXPECT_TRUE(pipe.valid());

    EXPECT_TRUE(pipe.notify(10));
    EXPECT_TRUE(pipe.notify(20));
    EXPECT_TRUE(pipe.notify(30));

    std::vector<uint8_t> received;
    pipe.drain([&](uint8_t code) { received.push_back(code); });
    EXPECT_EQ(received.size(), 3U);
    EXPECT_EQ(received[0], 10);
    EXPECT_EQ(received[1], 20);
    EXPECT_EQ(received[2], 30);
}

TEST(net_notify, move_construction)
{
    auto pipe1 = NotificationPipe::create();
    EXPECT_TRUE(pipe1.valid());

    int read_fd = pipe1.read_fd();
    int write_fd = pipe1.write_fd();

    NotificationPipe pipe2{std::move(pipe1)};
    EXPECT_FALSE(pipe1.valid());
    EXPECT_TRUE(pipe2.valid());
    EXPECT_EQ(pipe2.read_fd(), read_fd);
    EXPECT_EQ(pipe2.write_fd(), write_fd);
}

TEST(net_notify, move_assignment)
{
    auto pipe1 = NotificationPipe::create();
    NotificationPipe pipe2;

    int read_fd = pipe1.read_fd();
    int write_fd = pipe1.write_fd();

    pipe2 = std::move(pipe1);
    EXPECT_FALSE(pipe1.valid());
    EXPECT_TRUE(pipe2.valid());
    EXPECT_EQ(pipe2.read_fd(), read_fd);
    EXPECT_EQ(pipe2.write_fd(), write_fd);
}

TEST(net_notify, close_invalidates)
{
    auto pipe = NotificationPipe::create();
    EXPECT_TRUE(pipe.valid());

    pipe.close();
    EXPECT_FALSE(pipe.valid());
    EXPECT_EQ(pipe.read_fd(), -1);
    EXPECT_EQ(pipe.write_fd(), -1);
}

//
// RawnetContext Tests
//

TEST(net_rawnet_ctx, default_invalid)
{
    RawnetContext ctx;
    EXPECT_FALSE(ctx.valid());
    EXPECT_EQ(ctx.fd(), -1);
    EXPECT_EQ(ctx.interface_index(), -1);
}

TEST(net_rawnet_ctx, move_construction)
{
    RawnetContext ctx1;
    // Can't really test open without root, just test move semantics
    RawnetContext ctx2{std::move(ctx1)};
    EXPECT_FALSE(ctx1.valid());
    EXPECT_FALSE(ctx2.valid());  // Neither is valid since we didn't open
}

TEST(net_rawnet_ctx, set_default_dest_mac)
{
    RawnetContext ctx;
    ieee::Eui48 mac{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    ctx.set_default_dest_mac(mac);
    EXPECT_EQ(ctx.default_dest_mac(), mac);
}

#ifdef __linux__
//
// MmapError Tests
//

TEST(net_mmap_error, error_code_from_enum)
{
    std::error_code ec = MmapError::socket_creation_failed;
    EXPECT_EQ(ec.value(), 1);
    EXPECT_TRUE(ec.category().name() != nullptr);
    EXPECT_EQ(std::string_view(ec.category().name()), "statusbar.net.mmap");
}

TEST(net_mmap_error, different_errors_have_messages)
{
    std::error_code ec1 = MmapError::tx_ring_full;
    std::error_code ec2 = MmapError::rx_ring_empty;
    EXPECT_FALSE(ec1.message().empty());
    EXPECT_FALSE(ec2.message().empty());
    EXPECT_NE(ec1.message(), ec2.message());
}

TEST(net_mmap_error, platform_error)
{
    std::error_code ec = MmapError::not_supported_on_platform;
    EXPECT_TRUE(ec.message().find("not supported") != std::string::npos);
}

//
// MmapContext Tests (stub tests for non-Linux platforms)
//

TEST(net_mmap_ctx, default_invalid)
{
    MmapContext ctx;
    EXPECT_FALSE(ctx.valid());
    EXPECT_EQ(ctx.fd(), -1);
    EXPECT_EQ(ctx.interface_index(), 0U);
}

TEST(net_mmap_ctx, move_construction)
{
    MmapContext ctx1;
    MmapContext ctx2{std::move(ctx1)};
    EXPECT_FALSE(ctx1.valid());
    EXPECT_FALSE(ctx2.valid());
}

//
// Error Category Name Tests (mmap)
//

TEST(net_error_category, mmap_name_matches)
{
    EXPECT_EQ(std::string_view(mmap_error_category().name()), "statusbar.net.mmap");
}
#endif  // __linux__

//
// Error Category Name Tests
//

TEST(net_error_category, name_matches)
{
    EXPECT_EQ(std::string_view(net_error_category().name()), "statusbar.net");
}

//
// RawnetContext Move Assignment Test
//

TEST(net_rawnet_ctx_move, move_assignment)
{
    RawnetContext ctx1;
    RawnetContext ctx2;
    ctx1.set_default_dest_mac(ieee::Eui48{0x11, 0x22, 0x33, 0x44, 0x55, 0x66});

    ctx2 = std::move(ctx1);
    EXPECT_FALSE(ctx1.valid());
    EXPECT_FALSE(ctx2.valid());  // Neither valid since not opened
}

//
// RingQueueBase Tests (non-template base)
//

// Simple struct with clear() for testing RingQueueBase via FixedQueue
namespace {
struct TestElement
{
    int value{0};
    bool cleared{false};
    void clear() noexcept
    {
        value = 0;
        cleared = true;
    }
};
}  // namespace

TEST(net_ring_queue_base, initial_empty)
{
    std::array<TestElement, 4> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 4};
    EXPECT_TRUE(base.empty());
    EXPECT_FALSE(base.full());
    EXPECT_EQ(base.count(), 0U);
    EXPECT_TRUE(base.can_push());
    EXPECT_FALSE(base.can_pop());
    EXPECT_TRUE(base.push_slot_ptr() != nullptr);
    EXPECT_TRUE(base.peek_ptr() == nullptr);
}

TEST(net_ring_queue_base, push_and_pop)
{
    std::array<TestElement, 4> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 4};

    // Push one element
    auto* slot = static_cast<TestElement*>(base.push_slot_ptr());
    EXPECT_TRUE(slot != nullptr);
    slot->value = 42;
    base.commit_push();
    EXPECT_EQ(base.count(), 1U);

    // Peek returns the same element
    auto const* peek = static_cast<TestElement const*>(base.peek_ptr());
    EXPECT_TRUE(peek != nullptr);
    EXPECT_EQ(peek->value, 42);

    // Pop advances
    base.pop_advance();
    EXPECT_EQ(base.count(), 0U);
    EXPECT_TRUE(base.empty());
}

TEST(net_ring_queue_base, fill_to_capacity)
{
    std::array<TestElement, 3> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 3};

    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(base.can_push());
        auto* slot = static_cast<TestElement*>(base.push_slot_ptr());
        slot->value = i + 1;
        base.commit_push();
    }

    EXPECT_TRUE(base.full());
    EXPECT_FALSE(base.can_push());
    EXPECT_TRUE(base.push_slot_ptr() == nullptr);
    EXPECT_EQ(base.count(), 3U);
}

TEST(net_ring_queue_base, wrapping)
{
    std::array<TestElement, 3> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 3};

    // Fill, drain 2, push 2 more (forces wrap)
    for (int i = 0; i < 3; ++i) {
        auto* slot = static_cast<TestElement*>(base.push_slot_ptr());
        slot->value = i;
        base.commit_push();
    }
    base.pop_advance();
    base.pop_advance();
    EXPECT_EQ(base.count(), 1U);

    // Push 2 more — write_pos wraps around
    for (int i = 10; i < 12; ++i) {
        auto* slot = static_cast<TestElement*>(base.push_slot_ptr());
        slot->value = i;
        base.commit_push();
    }
    EXPECT_EQ(base.count(), 3U);
    EXPECT_TRUE(base.full());

    // Drain all and verify FIFO order
    auto const* p = static_cast<TestElement const*>(base.peek_ptr());
    EXPECT_EQ(p->value, 2);
    base.pop_advance();
    p = static_cast<TestElement const*>(base.peek_ptr());
    EXPECT_EQ(p->value, 10);
    base.pop_advance();
    p = static_cast<TestElement const*>(base.peek_ptr());
    EXPECT_EQ(p->value, 11);
    base.pop_advance();
    EXPECT_TRUE(base.empty());
}

TEST(net_ring_queue_base, reset)
{
    std::array<TestElement, 4> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 4};

    auto* slot = static_cast<TestElement*>(base.push_slot_ptr());
    slot->value = 1;
    base.commit_push();
    EXPECT_EQ(base.count(), 1U);

    base.reset();
    EXPECT_TRUE(base.empty());
    EXPECT_EQ(base.count(), 0U);
    EXPECT_TRUE(base.can_push());
}

TEST(net_ring_queue_base, pointer_arithmetic)
{
    // Verify that push_slot_ptr returns correct addresses
    std::array<TestElement, 4> storage{};
    RingQueueBase base{make_span(storage).data(), sizeof(TestElement), 4};

    auto* slot0 = static_cast<TestElement*>(base.push_slot_ptr());
    EXPECT_TRUE(slot0 == &storage[0]);
    slot0->value = 0;
    base.commit_push();

    auto* slot1 = static_cast<TestElement*>(base.push_slot_ptr());
    EXPECT_TRUE(slot1 == &storage[1]);
    slot1->value = 1;
    base.commit_push();

    // Peek should return slot0
    auto* peek = static_cast<TestElement*>(base.peek_ptr());
    EXPECT_TRUE(peek == &storage[0]);
    EXPECT_EQ(peek->value, 0);
}

//
// RingBufferBase Tests (non-template base)
//

TEST(net_ring_buffer_base, initial_empty)
{
    std::array<uint8_t, 64> storage{};
    RingBufferBase buf{std::span{storage}};
    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());
    EXPECT_EQ(buf.readable_count(), 0U);
    EXPECT_EQ(buf.writable_count(), 63U);  // capacity - 1
}

TEST(net_ring_buffer_base, write_and_read)
{
    std::array<uint8_t, 64> storage{};
    RingBufferBase buf{std::span{storage}};

    std::array<uint8_t, 4> data = {1, 2, 3, 4};
    size_t written = buf.write(data);
    EXPECT_EQ(written, 4U);
    EXPECT_EQ(buf.readable_count(), 4U);

    std::array<uint8_t, 4> out{};
    size_t read_count = buf.read(out);
    EXPECT_EQ(read_count, 4U);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], 2);
    EXPECT_EQ(out[2], 3);
    EXPECT_EQ(out[3], 4);
    EXPECT_TRUE(buf.empty());
}

TEST(net_ring_buffer_base, clear)
{
    std::array<uint8_t, 64> storage{};
    RingBufferBase buf{std::span{storage}};

    std::array<uint8_t, 10> data{};
    buf.write(data);
    EXPECT_FALSE(buf.empty());

    buf.clear();
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.readable_count(), 0U);
}

TEST(net_ring_buffer_base, wrapping)
{
    std::array<uint8_t, 8> storage{};
    RingBufferBase buf{std::span{storage}};
    // Usable capacity = 7 (one slot reserved)

    // Write 5 bytes, read 5, write 5 more (forces wrap)
    std::array<uint8_t, 5> data1 = {1, 2, 3, 4, 5};
    buf.write(data1);
    std::array<uint8_t, 5> out1{};
    buf.read(out1);
    EXPECT_TRUE(buf.empty());

    // Now read_pos=5, write_pos=5. Write 5 more bytes — wraps around
    std::array<uint8_t, 5> data2 = {10, 20, 30, 40, 50};
    size_t written = buf.write(data2);
    EXPECT_EQ(written, 5U);

    std::array<uint8_t, 5> out2{};
    size_t read_count = buf.read(out2);
    EXPECT_EQ(read_count, 5U);
    EXPECT_EQ(out2[0], 10);
    EXPECT_EQ(out2[1], 20);
    EXPECT_EQ(out2[2], 30);
    EXPECT_EQ(out2[3], 40);
    EXPECT_EQ(out2[4], 50);
}

TEST(net_ring_buffer_base, readable_span_contiguous)
{
    std::array<uint8_t, 16> storage{};
    RingBufferBase buf{std::span{storage}};

    std::array<uint8_t, 4> data = {0xAA, 0xBB, 0xCC, 0xDD};
    buf.write(data);

    auto span = buf.readable_span();
    EXPECT_EQ(span.size(), 4U);
    EXPECT_EQ(span[0], 0xAA);
    EXPECT_EQ(span[3], 0xDD);
}

TEST(net_ring_buffer_base, writable_span_contiguous)
{
    std::array<uint8_t, 16> storage{};
    RingBufferBase buf{std::span{storage}};

    auto span = buf.writable_span();
    EXPECT_TRUE(span.size() > 0);
    // Write directly into the span
    span[0] = 0xFF;
    buf.advance_write(1);
    EXPECT_EQ(buf.readable_count(), 1U);
    EXPECT_EQ(buf.readable_span()[0], 0xFF);
}

TEST(net_ring_buffer_base, overflow_protection)
{
    std::array<uint8_t, 8> storage{};
    RingBufferBase buf{std::span{storage}};
    // Usable capacity = 7

    std::array<uint8_t, 10> data{};
    size_t written = buf.write(data);
    EXPECT_EQ(written, 7U);  // Only 7 bytes fit
    EXPECT_TRUE(buf.full());
}

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

TEST(net_reactor, empty_reactor_returns_false)
{
    itc::StopToken stop{};
    MessageReactor reactor{stop, monotonic_ns, 0};
    // No ports — should_run() is false immediately
    EXPECT_FALSE(reactor.poll_once(0));
}

TEST(net_reactor, single_port_gets_ticked)
{
    itc::StopToken stop{};
    int64_t fake_time = 1'000'000;
    auto clock = [&]() -> int64_t { return fake_time; };

    auto mock = std::make_unique<MockPollable>();
    auto* ptr = mock.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));

    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(ptr->tick_count(), 1);
    EXPECT_EQ(ptr->last_now_ns(), int64_t{1'000'000});

    fake_time = 2'000'000;
    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(ptr->tick_count(), 2);
    EXPECT_EQ(ptr->last_now_ns(), int64_t{2'000'000});
}

TEST(net_reactor, on_ready_called_when_readable)
{
    itc::StopToken stop{};
    int64_t fake_time = 100;
    auto clock = [&]() -> int64_t { return fake_time; };

    auto mock = std::make_unique<MockPollable>();
    auto* ptr = mock.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));

    // No data — on_ready should NOT fire, but tick should
    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(ptr->on_ready_count(), 0);
    EXPECT_EQ(ptr->tick_count(), 1);

    // Make pipe readable — on_ready should fire
    ptr->make_readable();
    fake_time = 200;
    EXPECT_TRUE(reactor.poll_once(10));
    EXPECT_EQ(ptr->on_ready_count(), 1);
    EXPECT_EQ(ptr->tick_count(), 2);
    EXPECT_EQ(ptr->last_now_ns(), int64_t{200});
}

TEST(net_reactor, clock_injection_consistent)
{
    // All ports see the same timestamp in a single cycle
    itc::StopToken stop{};
    int64_t fake_time = 42;
    auto clock = [&]() -> int64_t { return fake_time; };

    auto a = std::make_unique<MockPollable>();
    auto b = std::make_unique<MockPollable>();
    auto* pa = a.get();
    auto* pb = b.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(a));
    reactor.add(std::move(b));

    pa->make_readable();
    pb->make_readable();

    EXPECT_TRUE(reactor.poll_once(10));
    // Both ports should see the same timestamp
    EXPECT_EQ(pa->last_now_ns(), int64_t{42});
    EXPECT_EQ(pb->last_now_ns(), int64_t{42});
}

TEST(net_reactor, finished_port_removed)
{
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 0; };

    auto mock = std::make_unique<MockPollable>();
    auto* ptr = mock.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));
    EXPECT_EQ(reactor.active_count(), size_t{1});

    // Mark finished — should be removed after this cycle
    ptr->set_finished(true);
    // poll_once returns true because should_run() at entry sees the port,
    // but remove_finished() then compacts it away
    (void)reactor.poll_once(0);
    EXPECT_EQ(reactor.active_count(), size_t{0});

    // Next cycle: no ports, returns false
    EXPECT_FALSE(reactor.poll_once(0));
}

TEST(net_reactor, stop_flag_stops_reactor)
{
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 0; };

    auto mock = std::make_unique<MockPollable>();
    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));

    EXPECT_TRUE(reactor.poll_once(0));

    // Set stop flag
    stop.request_stop();
    EXPECT_FALSE(reactor.poll_once(0));
}

TEST(net_reactor, tick_only_port)
{
    // Port with fd() == -1 still gets ticked
    itc::StopToken stop{};
    int64_t fake_time = 500;
    auto clock = [&]() -> int64_t { return fake_time; };

    auto mock = std::make_unique<MockPollable>();
    auto* ptr = mock.get();
    ptr->set_use_fd(false);  // fd() returns -1

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));

    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(ptr->tick_count(), 1);
    EXPECT_EQ(ptr->on_ready_count(), 0);  // Never polled, never ready
    EXPECT_EQ(ptr->last_now_ns(), int64_t{500});
}

TEST(net_reactor, multiple_ports_independent)
{
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 99; };

    auto a = std::make_unique<MockPollable>();
    auto b = std::make_unique<MockPollable>();
    auto c = std::make_unique<MockPollable>();
    auto* pa = a.get();
    auto* pb = b.get();
    auto* pc = c.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(a));
    reactor.add(std::move(b));
    reactor.add(std::move(c));
    EXPECT_EQ(reactor.active_count(), size_t{3});

    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(pa->tick_count(), 1);
    EXPECT_EQ(pb->tick_count(), 1);
    EXPECT_EQ(pc->tick_count(), 1);

    // Finish middle port
    pb->set_finished(true);
    EXPECT_TRUE(reactor.poll_once(0));
    EXPECT_EQ(reactor.active_count(), size_t{2});

    // Remaining ports still tick
    EXPECT_EQ(pa->tick_count(), 2);
    EXPECT_EQ(pc->tick_count(), 2);
}

TEST(net_reactor, finished_in_on_ready_skips_tick)
{
    // A port that marks itself finished in on_ready should not get ticked
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 0; };

    // External counter that survives handler destruction (remove_finished()
    // destroys the unique_ptr during poll_once, so a raw pointer to the
    // handler would be use-after-free).
    int external_tick_count = 0;

    // Custom pollable that finishes itself in on_ready
    struct SelfFinishing : public Pollable
    {
        int pipe_r{-1};
        int pipe_w{-1};
        bool is_finished{false};
        int& tick_count_ref;

        explicit SelfFinishing(int& tc)
            : tick_count_ref(tc)
        {
            int fds[2];
            ::pipe(fds);
            pipe_r = fds[0];
            pipe_w = fds[1];
            (void)set_nonblocking(pipe_r);
            (void)set_nonblocking(pipe_w);
        }
        ~SelfFinishing() override
        {
            ::close(pipe_r);
            ::close(pipe_w);
        }
        SelfFinishing(SelfFinishing const&) = delete;
        auto operator=(SelfFinishing const&) -> SelfFinishing& = delete;
        SelfFinishing(SelfFinishing&&) = delete;
        auto operator=(SelfFinishing&&) -> SelfFinishing& = delete;

        [[nodiscard]] auto fd() const noexcept -> int override { return pipe_r; }
        void on_ready(int64_t /*now_ns*/) override
        {
            uint8_t buf[64];
            while (::read(pipe_r, buf, sizeof(buf)) > 0) {
            }
            is_finished = true;  // finish self
        }
        void tick(int64_t /*now_ns*/) override { ++tick_count_ref; }
        [[nodiscard]] auto finished() const noexcept -> bool override { return is_finished; }
    };

    auto port = std::make_unique<SelfFinishing>(external_tick_count);
    int const pipe_w = port->pipe_w;

    // Make readable
    uint8_t byte = 1;
    (void)::write(pipe_w, &byte, 1);

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(port));

    (void)reactor.poll_once(10);
    // on_ready fired and set finished=true, so tick should NOT have been called.
    // We check via the external counter since the handler is destroyed by remove_finished().
    EXPECT_EQ(external_tick_count, 0);
    EXPECT_EQ(reactor.active_count(), size_t{0});
}

TEST(net_reactor, hangup_delivered_as_on_ready)
{
    // poll() reports POLLHUP/POLLERR/POLLNVAL regardless of the requested
    // event mask. Before these were dispatched, a port whose fd died without
    // also being readable got no callback, never finished, and the reactor
    // spun hot on the dead fd forever.
    itc::StopToken stop{};
    auto clock = []() -> int64_t { return 0; };

    int external_on_ready_count = 0;

    struct HangupPort : public Pollable
    {
        int pipe_r{-1};
        bool is_finished{false};
        int& on_ready_count_ref;

        explicit HangupPort(int& c)
            : on_ready_count_ref(c)
        {
            int fds[2];
            ::pipe(fds);
            pipe_r = fds[0];
            (void)set_nonblocking(pipe_r);
            ::close(fds[1]);  // writer gone, no data buffered: POLLHUP, not POLLIN
        }
        ~HangupPort() override { ::close(pipe_r); }
        HangupPort(HangupPort const&) = delete;
        auto operator=(HangupPort const&) -> HangupPort& = delete;
        HangupPort(HangupPort&&) = delete;
        auto operator=(HangupPort&&) -> HangupPort& = delete;

        [[nodiscard]] auto fd() const noexcept -> int override { return pipe_r; }
        void on_ready(int64_t /*now_ns*/) override
        {
            ++on_ready_count_ref;
            uint8_t buf[16];
            if (::read(pipe_r, buf, sizeof(buf)) <= 0) {
                is_finished = true;  // EOF observed
            }
        }
        void tick(int64_t /*now_ns*/) override {}
        [[nodiscard]] auto finished() const noexcept -> bool override { return is_finished; }
    };

    auto port = std::make_unique<HangupPort>(external_on_ready_count);
    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(port));

    (void)reactor.poll_once(10);
    // The hangup must reach on_ready so the port can observe EOF and finish.
    EXPECT_EQ(external_on_ready_count, 1);
    EXPECT_EQ(reactor.active_count(), size_t{0});
}

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
        [[nodiscard]] auto poll_events() const noexcept -> short override
        {
            return static_cast<short>(POLLIN | POLLOUT);
        }
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

TEST(net_reactor, run_stops_on_flag)
{
    itc::StopToken stop{};
    int cycle = 0;
    auto clock = [&]() -> int64_t {
        ++cycle;
        if (cycle >= 3) {
            stop.request_stop();
        }
        return static_cast<int64_t>(cycle) * 1000;
    };

    auto mock = std::make_unique<MockPollable>();
    auto* ptr = mock.get();

    MessageReactor reactor{stop, clock, 0};
    reactor.add(std::move(mock));
    reactor.run();

    // Clock was called 3 times; tick should have run for cycles 1 and 2,
    // cycle 3 sets stop so poll_once returns false after tick
    EXPECT_TRUE(ptr->tick_count() >= 2);
    EXPECT_TRUE(ptr->tick_count() <= 3);
}

//
// Exhaustive error message coverage
//

TEST(net_error, all_errors_have_messages)
{
    // Verify every NetError code produces a non-"Unknown" message
    auto check = [](NetError e) {
        std::error_code ec = e;
        EXPECT_TRUE(!ec.message().empty());
        EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
    };
    check(NetError::socket_creation_failed);
    check(NetError::bind_failed);
    check(NetError::listen_failed);
    check(NetError::connect_failed);
    check(NetError::accept_failed);
    check(NetError::send_failed);
    check(NetError::receive_failed);
    check(NetError::getaddrinfo_failed);
    check(NetError::poll_failed);
    check(NetError::handler_limit_reached);
    check(NetError::buffer_full);
    check(NetError::connection_closed);
    check(NetError::would_block);
    check(NetError::invalid_address);
    check(NetError::not_connected);
    check(NetError::already_connected);
    check(NetError::socket_option_failed);
    check(NetError::invalid_argument);
    check(NetError::invalid_handle);
    check(NetError::not_supported);
}

//
// LoopbackPort Tests
//

#include "statusbar/net/net_loopback_port.hpp"

TEST(net_loopback, create_pair_valid)
{
    LoopbackPortConfig cfg{
        .mac_a = ieee::Eui48{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .mac_b = ieee::Eui48{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .frame_pool_size = 16,
    };
    auto [a, b] = create_loopback_pair(cfg);
    EXPECT_TRUE(a.valid());
    EXPECT_TRUE(b.valid());
}

TEST(net_loopback, hardware_address)
{
    LoopbackPortConfig cfg{
        .mac_a = ieee::Eui48{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .mac_b = ieee::Eui48{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    };
    auto [a, b] = create_loopback_pair(cfg);
    EXPECT_EQ(a.hardware_address(), cfg.mac_a);
    EXPECT_EQ(b.hardware_address(), cfg.mac_b);
}

TEST(net_loopback, interface_index_distinct)
{
    LoopbackPortConfig cfg{};
    auto [a, b] = create_loopback_pair(cfg);
    EXPECT_EQ(a.interface_index(), 1U);
    EXPECT_EQ(b.interface_index(), 2U);
}

TEST(net_loopback, fd_returns_negative_one)
{
    LoopbackPortConfig cfg{};
    auto [a, b] = create_loopback_pair(cfg);
    EXPECT_EQ(a.fd(), -1);
    EXPECT_EQ(b.fd(), -1);
}

TEST(net_loopback, tx_start_returns_slot)
{
    LoopbackPortConfig cfg{.frame_pool_size = 4};
    auto [a, b] = create_loopback_pair(cfg);
    auto result = a.tx_start(0);
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->buffer.size() >= ETHERNET_PORT_MIN_FRAME_BUFFER);
}

TEST(net_loopback, tx_commit_delivers_to_peer)
{
    LoopbackPortConfig cfg{.frame_pool_size = 4};
    auto [a, b] = create_loopback_pair(cfg);

    // TX on side A — commit with full buffer size to avoid span_copy assertion
    // in rx_start (the loopback port copies the full EthernetFrameBuffer)
    auto slot = a.tx_start(0);
    EXPECT_TRUE(slot.has_value());
    // Write a recognizable pattern
    slot->buffer[0] = 0xDE;
    slot->buffer[1] = 0xAD;
    auto commit_result = a.tx_commit(slot->handle, ETHERNET_PORT_MIN_FRAME_BUFFER);
    EXPECT_TRUE(commit_result.has_value());

    // RX on side B should see the frame
    EXPECT_EQ(b.rx_pending(), size_t{1});
    auto rx = b.rx_start();
    EXPECT_TRUE(rx.has_value());
    EXPECT_TRUE(rx->has_value());
    EXPECT_EQ((*rx)->buffer[0], 0xDE);
    EXPECT_EQ((*rx)->buffer[1], 0xAD);
    EXPECT_TRUE(b.rx_release((*rx)->handle).has_value());
}

TEST(net_loopback, tx_cancel_returns_slot_to_pool)
{
    LoopbackPortConfig cfg{.frame_pool_size = 1};
    auto [a, b] = create_loopback_pair(cfg);

    auto slot = a.tx_start(0);
    EXPECT_TRUE(slot.has_value());

    // Pool is now exhausted
    auto slot2 = a.tx_start(0);
    EXPECT_FALSE(slot2.has_value());

    // Cancel returns the slot
    EXPECT_TRUE(a.tx_cancel(slot->handle).has_value());

    // Now we can allocate again
    auto slot3 = a.tx_start(0);
    EXPECT_TRUE(slot3.has_value());
}

TEST(net_loopback, rx_start_empty_returns_nullopt)
{
    LoopbackPortConfig cfg{.frame_pool_size = 4};
    auto [a, b] = create_loopback_pair(cfg);
    auto rx = b.rx_start();
    EXPECT_TRUE(rx.has_value());
    EXPECT_FALSE(rx->has_value());  // nullopt — no frames pending
}

TEST(net_loopback, bidirectional_tx_rx)
{
    LoopbackPortConfig cfg{.frame_pool_size = 8};
    auto [a, b] = create_loopback_pair(cfg);

    // A sends to B (use full buffer length for span_copy compatibility)
    {
        auto slot = a.tx_start(0);
        slot->buffer[0] = 0x01;
        (void)a.tx_commit(slot->handle, ETHERNET_PORT_MIN_FRAME_BUFFER);
    }
    // B sends to A
    {
        auto slot = b.tx_start(0);
        slot->buffer[0] = 0x02;
        (void)b.tx_commit(slot->handle, ETHERNET_PORT_MIN_FRAME_BUFFER);
    }

    // B receives from A
    EXPECT_EQ(b.rx_pending(), size_t{1});
    auto rx_b = b.rx_start();
    EXPECT_TRUE(rx_b->has_value());
    EXPECT_EQ((*rx_b)->buffer[0], 0x01);
    (void)b.rx_release((*rx_b)->handle);

    // A receives from B
    EXPECT_EQ(a.rx_pending(), size_t{1});
    auto rx_a = a.rx_start();
    EXPECT_TRUE(rx_a->has_value());
    EXPECT_EQ((*rx_a)->buffer[0], 0x02);
    (void)a.rx_release((*rx_a)->handle);
}

TEST(net_loopback, tx_captures_recorded)
{
    LoopbackPortConfig cfg{.frame_pool_size = 4};
    auto [a, b] = create_loopback_pair(cfg);

    auto slot = a.tx_start(12345);
    slot->buffer[0] = 0xAB;
    (void)a.tx_commit(slot->handle, ETHERNET_PORT_MIN_FRAME_BUFFER);

    EXPECT_EQ(a.tx_pending(), size_t{1});
    auto cap = a.pop_tx();
    EXPECT_TRUE(cap.has_value());
    EXPECT_EQ(cap->frame[0], 0xAB);
    EXPECT_EQ(cap->launch_time_ns, 12345);
    EXPECT_EQ(a.tx_pending(), size_t{0});
}

TEST(net_loopback, pool_exhaustion_returns_error)
{
    LoopbackPortConfig cfg{.frame_pool_size = 2};
    auto [a, b] = create_loopback_pair(cfg);

    auto s1 = a.tx_start(0);
    EXPECT_TRUE(s1.has_value());
    auto s2 = a.tx_start(0);
    EXPECT_TRUE(s2.has_value());
    auto s3 = a.tx_start(0);
    EXPECT_FALSE(s3.has_value());
}

TEST(net_loopback, join_multicast_succeeds)
{
    LoopbackPortConfig cfg{};
    auto [a, b] = create_loopback_pair(cfg);
    ieee::Eui48 mcast{0x91, 0xE0, 0xF0, 0x00, 0xFE, 0x00};
    EXPECT_TRUE(a.join_multicast(mcast).has_value());
}

TEST(net_loopback, begin_end_cycle_succeed)
{
    LoopbackPortConfig cfg{};
    auto [a, b] = create_loopback_pair(cfg);
    a.begin_cycle();
    EXPECT_TRUE(a.end_cycle().has_value());
}

TEST(net_loopback, tx_flush_succeeds)
{
    LoopbackPortConfig cfg{};
    auto [a, b] = create_loopback_pair(cfg);
    EXPECT_TRUE(a.tx_flush().has_value());
}

//
// BpfPortContext Tests (no real hardware — just construction and pool logic)
//

#include "statusbar/net/net_bpf_port.hpp"

TEST(net_bpf_port, default_invalid)
{
    BpfPortContext port;
    EXPECT_FALSE(port.valid());
    EXPECT_EQ(port.fd(), -1);
    EXPECT_EQ(port.interface_index(), 0U);
}

TEST(net_bpf_port, move_construction)
{
    BpfPortContext a;
    BpfPortContext b{std::move(a)};
    EXPECT_FALSE(a.valid());
    EXPECT_FALSE(b.valid());
}

TEST(net_bpf_port, move_assignment)
{
    BpfPortContext a;
    BpfPortContext b;
    b = std::move(a);
    EXPECT_FALSE(a.valid());
    EXPECT_FALSE(b.valid());
}

TEST(net_bpf_port, tx_start_fails_when_not_open)
{
    // Pool is empty when not opened, so tx_start should fail
    BpfPortContext port;
    auto result = port.tx_start(0);
    EXPECT_FALSE(result.has_value());
}

TEST(net_bpf_port, tx_cancel_fails_with_bad_handle)
{
    BpfPortContext port;
    auto result = port.tx_cancel(9999);
    EXPECT_FALSE(result.has_value());
}

TEST(net_bpf_port, tx_commit_fails_with_bad_handle)
{
    // pool_ is empty on a default-constructed (unopened) port, so any
    // handle is out of range and the not_connected branch is unreachable.
    BpfPortContext port;
    auto result = port.tx_commit(9999, 64);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::invalid_handle));
}

TEST(net_bpf_port, rx_start_fails_when_not_open)
{
    BpfPortContext port;
    auto result = port.rx_start();
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::not_connected));
}

TEST(net_bpf_port, join_multicast_fails_when_not_open)
{
    BpfPortContext port;
    ieee::Eui48 const group{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01};
    auto result = port.join_multicast(group);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(NetError::not_connected));
}

TEST(net_bpf_port, hardware_address_default_is_zero)
{
    BpfPortContext port;
    auto const& mac = port.hardware_address();
    for (auto b : mac.value) {
        EXPECT_EQ(b, 0);
    }
}

TEST(net_bpf_port, rx_release_fails_with_bad_handle)
{
    BpfPortContext port;
    auto result = port.rx_release(9999);
    EXPECT_FALSE(result.has_value());
}

TEST(net_bpf_port, tx_flush_succeeds)
{
    BpfPortContext port;
    EXPECT_TRUE(port.tx_flush().has_value());
}

TEST(net_bpf_port, end_cycle_succeeds)
{
    BpfPortContext port;
    EXPECT_TRUE(port.end_cycle().has_value());
}

//
// RawEthernetPollable Tests
//

#include "statusbar/net/net_raw_ethernet_pollable.hpp"

TEST(net_raw_eth_pollable, construction_with_invalid_context)
{
    // Construct with a default (invalid) RawnetContext
    RawnetContext ctx;
    bool callback_called = false;
    RawEthernetPollable pollable{std::move(ctx), [&](int64_t, ieee::Eui48, std::span<uint8_t const>) { callback_called = true; }};
    // fd should be -1 for an invalid context
    EXPECT_EQ(pollable.fd(), -1);
    EXPECT_FALSE(pollable.finished());
}

TEST(net_raw_eth_pollable, close_sets_finished)
{
    RawnetContext ctx;
    RawEthernetPollable pollable{std::move(ctx), {}};
    EXPECT_FALSE(pollable.finished());
    pollable.close();
    EXPECT_TRUE(pollable.finished());
}

TEST(net_raw_eth_pollable, tick_does_nothing)
{
    RawnetContext ctx;
    RawEthernetPollable pollable{std::move(ctx), {}};
    // tick is a no-op, should not crash
    pollable.tick(12345);
    EXPECT_FALSE(pollable.finished());
}

TEST(net_raw_eth_pollable, on_ready_with_no_data)
{
    RawnetContext ctx;
    bool callback_called = false;
    RawEthernetPollable pollable{std::move(ctx), [&](int64_t, ieee::Eui48, std::span<uint8_t const>) { callback_called = true; }};
    // on_ready with invalid context — recv will fail immediately, no callback
    pollable.on_ready(0);
    EXPECT_FALSE(callback_called);
}

TEST(net_raw_eth_pollable, hardware_address_from_context)
{
    RawnetContext ctx;
    // Default context has zero MAC
    RawEthernetPollable pollable{std::move(ctx), {}};
    auto mac = pollable.hardware_address();
    EXPECT_EQ(mac, ieee::Eui48{});
}

TEST(net_raw_eth_pollable, send_avtp_with_invalid_context)
{
    RawnetContext ctx;
    RawEthernetPollable pollable{std::move(ctx), {}};
    ieee::Eui48 dest{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    std::array<uint8_t, 10> payload{};
    auto result = pollable.send_avtp(dest, payload);
    // Should fail since context is not open
    EXPECT_FALSE(result.has_value());
}

//
// Test Runner
//

int statusbar_net_net_test(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    int result = 0;
    result |= ::statusbar::test::TestRegister::run_section("net_test");
    return result;
}
