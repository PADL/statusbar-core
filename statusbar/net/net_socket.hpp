#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Network socket utilities
/// Provides FileDescriptor RAII wrapper and socket configuration functions

#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/ip/ip_ipv4_address.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/status/status.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <expected>
#include <string_view>
#include <system_error>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

namespace statusbar::net {

// Re-export socket type constants so users don't need to #include <sys/socket.h>
inline constexpr int SocketStream = SOCK_STREAM;
inline constexpr int SocketDatagram = SOCK_DGRAM;

/// Alias to the canonical POSIX-fd RAII wrapper. The class itself lives in
/// `statusbar/buffer/file_descriptor.hpp` so the `bpf` module can share it
/// without depending on `net`. Existing `statusbar::net::FileDescriptor`
/// call sites continue to compile unchanged.
using FileDescriptor = ::statusbar::FileDescriptor;

/// Set a socket to non-blocking mode
/// @param fd Socket file descriptor
[[nodiscard]] inline auto set_nonblocking(int fd) noexcept -> Status
{
    int const flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return failure(NetError::socket_option_failed);
    }
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return failure(NetError::socket_option_failed);
    }
    return success();
}

/// Set a socket to blocking mode
/// @param fd Socket file descriptor
[[nodiscard]] inline auto set_blocking(int fd) noexcept -> Status
{
    int const flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return failure(NetError::socket_option_failed);
    }
    if (::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        return failure(NetError::socket_option_failed);
    }
    return success();
}

/// Set SO_REUSEADDR on a socket
/// @param fd Socket file descriptor
[[nodiscard]] inline auto set_reuse_addr(int fd) noexcept -> Status
{
    int const on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        return failure(NetError::socket_option_failed);
    }
    return success();
}

/// Set SO_REUSEPORT on a socket (if available)
/// @param fd Socket file descriptor
[[nodiscard]] inline auto set_reuse_port(int fd) noexcept -> Status
{
#if defined(SO_REUSEPORT)
    int const on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
        return failure(NetError::socket_option_failed);
    }
#else
    (void)fd;
#endif
    return success();
}

/// Check if an error indicates the operation would block
[[nodiscard]] inline auto would_block() noexcept -> bool
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
}

/// Check if an error indicates the operation was interrupted
[[nodiscard]] inline auto was_interrupted() noexcept -> bool
{
    return errno == EINTR;
}

/// Bind a socket to a specific network interface ("nic pinning"). Empty
/// `iface` is a no-op (returns success). Linux uses SO_BINDTODEVICE;
/// macOS / BSD use IP_BOUND_IF / IPV6_BOUND_IF (chosen by `family`).
/// Returns false and sets errno on failure; the caller decides whether
/// to log or propagate.
[[nodiscard]] inline auto bind_to_interface(int fd, int family, std::string_view iface) noexcept -> bool
{
    if (iface.empty()) {
        return true;
    }
#if defined(__linux__) && defined(SO_BINDTODEVICE)
    (void)family;
    return ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface.data(), static_cast<socklen_t>(iface.size())) == 0;
#else
    char name[IF_NAMESIZE]{};
    if (iface.size() >= sizeof(name)) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0; i < iface.size(); ++i) {
        name[i] = iface[i];
    }
    auto const idx = ::if_nametoindex(name);
    if (idx == 0) {
        return false;
    }
    int const idx_int = static_cast<int>(idx);
    if (family == AF_INET6) {
#    if defined(IPV6_BOUND_IF)
        return ::setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx_int, sizeof(idx_int)) == 0;
#    else
        errno = ENOSYS;
        return false;
#    endif
    }
#    if defined(IP_BOUND_IF)
    return ::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx_int, sizeof(idx_int)) == 0;
#    else
    errno = ENOSYS;
    return false;
#    endif
#endif
}

/// Set the DSCP (Differentiated Services Code Point) value on a socket
/// Works for both IPv4 and IPv6 sockets on macOS and Linux
/// @param fd The socket file descriptor
/// @param family The address family (AF_INET or AF_INET6)
/// @param dscp The DSCP value (0-63, 6 bits). Will be shifted into TOS/Traffic Class field.
/// @return Status indicating success or failure
[[nodiscard]] inline auto set_dscp(int fd, int family, uint8_t dscp) noexcept -> Status
{
    // DSCP is the upper 6 bits of the TOS/Traffic Class byte
    // The lower 2 bits are ECN (Explicit Congestion Notification)
    int const tos = (dscp & 0x3F) << 2;

    if (family == AF_INET6) {
        // IPv6: use IPV6_TCLASS
        if (::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0) {
            return failure(NetError::socket_creation_failed);
        }
    } else {
        // IPv4: use IP_TOS
        if (::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
            return failure(NetError::socket_creation_failed);
        }
    }

    return success();
}

/// Set the DSCP value using the raw TOS/Traffic Class byte
/// This preserves any ECN bits if needed
/// @param fd The socket file descriptor
/// @param family The address family (AF_INET or AF_INET6)
/// @param tos The full TOS/Traffic Class byte (DSCP << 2 | ECN)
/// @return Status indicating success or failure
[[nodiscard]] inline auto set_tos(int fd, int family, uint8_t tos) noexcept -> Status
{
    int const tos_val = tos;

    if (family == AF_INET6) {
        if (::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos_val, sizeof(tos_val)) < 0) {
            return failure(NetError::socket_creation_failed);
        }
    } else {
        if (::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos_val, sizeof(tos_val)) < 0) {
            return failure(NetError::socket_creation_failed);
        }
    }

    return success();
}

/// The current errno as an error code (system category), for failures whose
/// cause the caller wants to keep.
[[nodiscard]] inline auto errno_code() noexcept -> std::error_code
{
    return {errno, std::system_category()};
}

/// A non-blocking, close-on-exec IPv4 UDP socket.
[[nodiscard]] inline auto make_udp_socket() noexcept -> StatusValue<FileDescriptor>
{
    FileDescriptor fd{::socket(AF_INET, SOCK_DGRAM, 0)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    if (::fcntl(fd.get(), F_SETFD, FD_CLOEXEC) != 0 || !set_nonblocking(fd.get())) {
        return failure(errno_code());
    }
    return fd;
}

/// Join IPv4 multicast `group` on the interface with index `interface_index`
/// (0: the kernel's choice; on platforms without ip_mreqn, always that).
[[nodiscard]] inline auto join_group(int fd, ip::IPv4Address const& group, unsigned int interface_index) noexcept -> Status
{
#if defined(__linux__)
    ip_mreqn request{};
    request.imr_ifindex = static_cast<int>(interface_index);
#else
    (void)interface_index;
    ip_mreq request{};
    request.imr_interface.s_addr = htonl(INADDR_ANY);
#endif
    request.imr_multiaddr.s_addr = htonl(group.to_uint32());
    if (::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, sizeof(request)) != 0) {
        return failure(errno_code());
    }
    return success();
}

/// A UDP socket joined to IPv4 multicast `group` on the interface with index `interface_index`: the
/// kernel holds the membership, and reports it (IGMP), until the socket closes. Unbound, it receives
/// nothing. Errors: the socket's or the join's errno.
[[nodiscard]] inline auto open_group_membership(ip::IPv4Address const& group, unsigned int interface_index) noexcept
    -> StatusValue<FileDescriptor>
{
    auto fd = make_udp_socket();
    if (!fd) {
        return fd;
    }
    if (auto joined = join_group(fd->get(), group, interface_index); !joined) {
        return failure(joined.error());
    }
    return fd;
}

/// Prepare an IPv4 socket to send multicast: out of the interface with index
/// `interface_index` (0: the routing table's choice; Linux only otherwise),
/// with hop limit `ttl`, and looped back to local listeners when `loop`.
[[nodiscard]] inline auto set_multicast_send(int fd, unsigned int interface_index, uint8_t ttl, bool loop) noexcept -> Status
{
#if defined(__linux__)
    if (interface_index != 0) {
        ip_mreqn request{};
        request.imr_ifindex = static_cast<int>(interface_index);
        if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &request, sizeof(request)) != 0) {
            return failure(errno_code());
        }
    }
#else
    (void)interface_index;
#endif
    unsigned char const hops = ttl;
    unsigned char const looped = loop ? 1 : 0;
    if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &hops, sizeof(hops)) != 0 ||
        ::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &looped, sizeof(looped)) != 0) {
        return failure(errno_code());
    }
    return success();
}

}  // namespace statusbar::net
