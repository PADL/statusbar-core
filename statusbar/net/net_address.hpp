#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Network address utilities
/// Provides SocketAddress wrapper around sockaddr_storage (IPv4, IPv6, and
/// AF_UNIX filesystem paths)

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_socket.hpp"
#include "statusbar/status/status.hpp"

#include <netdb.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace statusbar::net {

/// Wrapper around sockaddr_storage for type-safe address handling
class SocketAddress
{
  public:
    /// Default constructor creates an empty/invalid address
    SocketAddress() noexcept = default;

    /// Parse address from host and port strings using getaddrinfo
    /// @param host Hostname or numeric IP address (empty for wildcard/any)
    /// @param port Port number as a string (e.g., "8080")
    /// @param socket_type Socket type: SOCK_DGRAM for UDP or SOCK_STREAM for TCP
    [[nodiscard]] static auto from_string(std::string_view host, std::string_view port, int socket_type = SOCK_DGRAM)
        -> StatusValue<SocketAddress>;

    /// Create an IPv4 address from components
    /// @param addr IPv4 address in host byte order
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv4(uint32_t addr, uint16_t port) noexcept -> SocketAddress
    {
        SocketAddress result;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* sin = reinterpret_cast<sockaddr_in*>(&result.storage_);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = htonl(addr);
        result.length_ = sizeof(sockaddr_in);
        return result;
    }

    /// Create an IPv4 address from octets (a.b.c.d)
    /// @param a First octet
    /// @param b Second octet
    /// @param c Third octet
    /// @param d Fourth octet
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) noexcept -> SocketAddress
    {
        uint32_t const addr = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
            (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        return ipv4(addr, port);
    }

    /// Create an IPv4 any address (0.0.0.0)
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv4_any(uint16_t port) noexcept -> SocketAddress { return ipv4(INADDR_ANY, port); }

    /// Create an IPv4 loopback address (127.0.0.1)
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv4_loopback(uint16_t port) noexcept -> SocketAddress { return ipv4(INADDR_LOOPBACK, port); }

    /// Create an IPv6 address from components
    /// @param addr 16-byte IPv6 address
    /// @param port Port number (host byte order)
    /// @param scope_id Scope ID for link-local addresses (use if_nametoindex() to get interface index)
    [[nodiscard]] static auto ipv6(std::span<uint8_t const, 16> addr, uint16_t port, uint32_t scope_id = 0) noexcept
        -> SocketAddress;

    /// Create an IPv6 any address (::)
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv6_any(uint16_t port) noexcept -> SocketAddress
    {
        std::array<uint8_t, 16> const addr{};
        return ipv6(addr, port, 0);
    }

    /// Create an IPv6 loopback address (::1)
    /// @param port Port number in host byte order
    [[nodiscard]] static auto ipv6_loopback(uint16_t port) noexcept -> SocketAddress
    {
        std::array<uint8_t, 16> addr{};
        addr[15] = 1;
        return ipv6(addr, port, 0);
    }

    /// Create an IPv6 link-local address (fe80::...)
    /// @param addr 16-byte IPv6 address (should start with fe80::)
    /// @param port Port number (host byte order)
    /// @param scope_id Interface index from if_nametoindex()
    [[nodiscard]] static auto ipv6_link_local(std::span<uint8_t const, 16> addr, uint16_t port, uint32_t scope_id) noexcept
        -> SocketAddress
    {
        return ipv6(addr, port, scope_id);
    }

    /// Create an AF_LOCAL (AF_UNIX) address for an absolute filesystem path
    /// (no abstract namespace). Fails with NetError::invalid_address when
    /// @p path is not absolute (empty or not starting with '/'), contains a
    /// NUL, or does not fit in sun_path with its terminating NUL.
    /// @param path Absolute filesystem path of the socket
    [[nodiscard]] static auto local(std::string_view path) noexcept -> StatusValue<SocketAddress>;

    /// Get pointer to sockaddr for system calls
    [[nodiscard]] auto sockaddr() noexcept -> struct sockaddr*
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<struct sockaddr*>(&storage_);
    }

    /// Get const pointer to sockaddr for system calls
    [[nodiscard]] auto sockaddr() const noexcept -> struct sockaddr const*
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<struct sockaddr const*>(&storage_);
    }

    /// Get the length of the address structure
    [[nodiscard]] auto length() const noexcept -> socklen_t { return length_; }

    /// Get pointer to length for recvfrom/accept
    [[nodiscard]] auto length_ptr() noexcept -> socklen_t* { return &length_; }

    /// Set the length (after recvfrom/accept)
    /// @param len Address structure length returned by recvfrom/accept
    auto set_length(socklen_t len) noexcept { length_ = len; }

    /// Reset length to maximum (before recvfrom/accept)
    auto reset_length() noexcept { length_ = sizeof(storage_); }

    /// Get the address family (AF_INET, AF_INET6, etc.)
    [[nodiscard]] auto family() const noexcept -> int { return storage_.ss_family; }

    /// Check if the address is valid (has been set)
    [[nodiscard]] auto valid() const noexcept -> bool { return length_ > 0 && storage_.ss_family != AF_UNSPEC; }

    /// Get the port number (host byte order)
    [[nodiscard]] auto port() const noexcept -> uint16_t
    {
        if (storage_.ss_family == AF_INET) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const* sin = reinterpret_cast<sockaddr_in const*>(&storage_);
            return ntohs(sin->sin_port);
        }
        if (storage_.ss_family == AF_INET6) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const* sin6 = reinterpret_cast<sockaddr_in6 const*>(&storage_);
            return ntohs(sin6->sin6_port);
        }
        return 0;
    }

    /// Get the filesystem path (AF_UNIX only; empty for an unnamed peer, a
    /// Linux abstract/autobind name, or any other family). Views this
    /// object's storage. to_string() renders an abstract name as "@name".
    [[nodiscard]] auto path() const noexcept -> std::string_view;

    /// Get the scope ID (IPv6 only, for link-local addresses)
    [[nodiscard]] auto scope_id() const noexcept -> uint32_t
    {
        if (storage_.ss_family == AF_INET6) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const* sin6 = reinterpret_cast<sockaddr_in6 const*>(&storage_);
            return sin6->sin6_scope_id;
        }
        return 0;
    }

    /// Set the scope ID (IPv6 only, for link-local addresses)
    /// Use if_nametoindex("eth0") to get the interface index
    /// @param scope_id Interface index from if_nametoindex()
    auto set_scope_id(uint32_t scope_id) noexcept
    {
        if (storage_.ss_family == AF_INET6) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(&storage_);
            sin6->sin6_scope_id = scope_id;
        }
    }

    /// Format address to string (allocates)
    [[nodiscard]] auto to_string() const -> std::string;

  private:
    sockaddr_storage storage_{};
    socklen_t length_{0};
};

/// Create a UDP socket bound to the given address
/// @param addr The address to use (determines address family)
/// @param do_bind If true, bind to the address
/// @param dscp Optional DSCP value (0-63). If >= 0, sets the DSCP on the socket.
/// @param ipv6_only When true and `addr` is AF_INET6, sets IPV6_V6ONLY
///        before bind so the socket does not also claim IPv4. Required
///        when a separate AF_INET socket binds the same port.
[[nodiscard]] auto create_udp_socket(SocketAddress const& addr, bool do_bind, int dscp = -1, bool ipv6_only = false)
    -> StatusValue<FileDescriptor>;

/// Create a TCP socket optionally bound to the given address
/// For an AF_UNIX address this is a SOCK_STREAM unix socket: SO_REUSEADDR
/// and DSCP are not applied, and the caller owns any filesystem entry
/// bind creates (stale-path handling and unlink).
/// @param addr The address to use (determines address family)
/// @param do_bind If true, bind to the address
/// @param dscp Optional DSCP value (0-63). If >= 0, sets the DSCP on the socket (IP families only).
[[nodiscard]] auto create_tcp_socket(SocketAddress const& addr, bool do_bind, int dscp = -1) -> StatusValue<FileDescriptor>;

/// Create a TCP (or AF_UNIX stream) socket, bind, and listen
/// @param addr The address to bind to
/// @param backlog Listen backlog size
/// @param dscp Optional DSCP value (0-63) for accepted connections. If >= 0, the server
///             should apply this DSCP to accepted client sockets.
[[nodiscard]] auto create_tcp_listener(SocketAddress const& addr, int backlog = SOMAXCONN, int dscp = -1)
    -> StatusValue<FileDescriptor>;

}  // namespace statusbar::net
