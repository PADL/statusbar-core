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
#include <cstring>
#include <expected>
#include <optional>
#include <string_view>
#include <system_error>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#if !defined(__linux__)
#    include <ifaddrs.h>
#endif

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
/// Works for both IPv4 and IPv6 sockets on macOS and Linux. On Linux IP_TOS also resets SO_PRIORITY to the one
/// the TOS maps to (rt_tos2priority): set_priority() afterwards, not before.
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
/// This preserves any ECN bits if needed. On Linux IP_TOS also resets SO_PRIORITY to the one the TOS maps to:
/// set_priority() afterwards, not before.
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

/// @p err (default: the current errno) as a std::error_code, for the many call
/// sites that would otherwise spell out `{errno, std::system_category()}`.
/// Pass a saved errno once later calls may have changed it.
[[nodiscard]] inline auto errno_code(int const err = errno) noexcept -> std::error_code
{
    return {err, std::system_category()};
}

/// An IPv4 UDP socket, close-on-exec and non-blocking from birth.
///
/// Both flags are set at creation where the platform allows it. A descriptor
/// that is briefly inheritable is a descriptor a concurrent fork/exec in
/// another thread can leak into a child, and a daemon that spawns anything at
/// all has that thread.
[[nodiscard]] inline auto make_udp_socket() noexcept -> StatusValue<FileDescriptor>
{
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    FileDescriptor fd{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
#else
    FileDescriptor fd{::socket(AF_INET, SOCK_DGRAM, 0)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    if (::fcntl(fd.get(), F_SETFD, FD_CLOEXEC) != 0) {
        return failure(errno_code());
    }
    if (auto const nonblocking = set_nonblocking(fd.get()); !nonblocking) {
        return failure(errno_code());
    }
#endif
    return fd;
}

#if !defined(__linux__)
/// The first IPv4 address in an interface list that belongs to the interface
/// with index `interface_index`, in network order.
[[nodiscard]] inline auto first_ipv4_of(ifaddrs const* list, unsigned int const interface_index) noexcept -> std::optional<uint32_t>
{
    for (ifaddrs const* ifa = list; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ::if_nametoindex(ifa->ifa_name) != interface_index) {
            continue;
        }
        sockaddr_in address{};
        std::memcpy(&address, ifa->ifa_addr, sizeof(address));
        return address.sin_addr.s_addr;
    }
    return std::nullopt;
}

/// The IPv4 address of the interface with index `interface_index`, in network
/// order, for the BSD socket options that can only name an interface by
/// address. 0 is "any". nullopt for an index no interface has, or one with no
/// IPv4 address - which, to a multicast join, are the same thing.
[[nodiscard]] inline auto ipv4_of_interface(unsigned int const interface_index) noexcept -> std::optional<uint32_t>
{
    if (interface_index == 0) {
        return htonl(INADDR_ANY);
    }
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) {
        return std::nullopt;
    }
    auto const found = first_ipv4_of(list, interface_index);
    ::freeifaddrs(list);
    return found;
}
#endif

/// Join IPv4 multicast `group` on the interface with index `interface_index`
/// (0: the kernel's choice by routing table).
///
/// The interface is an index rather than a name because the caller has already
/// resolved it; taking a name here would mean a second if_nametoindex() per
/// join. Linux takes the index through ip_mreqn. Darwin accepts an ip_mreqn
/// but reads only the ip_mreq it begins with and ignores the index - a join by
/// lo0's index landed on the default route's interface, checked - so there and
/// on the BSDs the interface is named by its IPv4 address, looked up from the
/// index. An index no interface has fails as ENODEV, as it does on Linux.
/// @param fd An IPv4 datagram socket
/// @param group The multicast group to join (224.0.0.0/4)
/// @param interface_index Index of the interface to join on, or 0 for any
[[nodiscard]] inline auto join_group(int fd, ip::IPv4Address const& group, unsigned int interface_index) noexcept -> Status
{
    // Checked here rather than left to the kernel: Linux answers EINVAL but
    // not every stack does, and a membership that was never joined fails
    // later as silence on the socket, a long way from the mistake.
    if (!group.is_multicast()) {
        return failure(std::errc::invalid_argument);
    }
#if defined(__linux__)
    ip_mreqn request{};
    request.imr_ifindex = static_cast<int>(interface_index);
#else
    ip_mreq request{};
    if (auto const address = ipv4_of_interface(interface_index); address) {
        request.imr_interface.s_addr = *address;
    } else {
        return failure(std::error_code{ENODEV, std::system_category()});
    }
#endif
    request.imr_multiaddr.s_addr = htonl(group.to_uint32());
    if (::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, sizeof(request)) != 0) {
        return failure(errno_code());
    }
    return success();
}

/// Prepare an IPv4 socket to send multicast: out of the interface with index
/// `interface_index` (0: the routing table's choice), with TTL `ttl`, and
/// looped back to local listeners when `loop`.
///
/// Loopback is a parameter rather than a default because both answers are
/// needed. An RTCP session on a group has to hear its own reports to recognise
/// and skip its own SSRC; a talker that only sends does not, and the copy is
/// wasted work on every packet.
/// Unlike the join, IP_MULTICAST_IF does take the index through ip_mreqn on
/// Darwin and FreeBSD as well as Linux: reading the option back after setting
/// it by index names that interface's address, checked on a Mac.
/// @param fd An IPv4 datagram socket
/// @param interface_index Index of the egress interface, or 0 for the route
/// @param ttl Multicast TTL - 1 keeps traffic on the local link
/// @param loop Whether sends are looped back to listeners on this host
[[nodiscard]] inline auto set_multicast_send(int fd, unsigned int interface_index, uint8_t ttl, bool loop) noexcept -> Status
{
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
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
    // IP_MULTICAST_TTL and IP_MULTICAST_LOOP take a byte on BSD and macOS and
    // an int on Linux, where a byte is also accepted; a byte works on both.
    unsigned char const hops = ttl;
    unsigned char const looped = loop ? 1 : 0;
    if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &hops, sizeof(hops)) != 0) {
        return failure(errno_code());
    }
    if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &looped, sizeof(looped)) != 0) {
        return failure(errno_code());
    }
    return success();
}

/// The interface unicast leaves by on an IPv4 or IPv6 (`family`) socket: `interface_index`, or 0 for the route
/// again. Linux: IP_UNICAST_IF / IPV6_UNICAST_IF (both take the index in network order), refused (EINVAL) on a
/// socket bound to a device with SO_BINDTODEVICE; macOS and BSD: IP_BOUND_IF / IPV6_BOUND_IF.
[[nodiscard]] inline auto set_unicast_interface(int fd, int family, unsigned int interface_index) noexcept -> Status
{
#if defined(__linux__)
    uint32_t const index = htonl(interface_index);
    bool const set = family == AF_INET6 ? ::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &index, sizeof(index)) == 0
                                        : ::setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &index, sizeof(index)) == 0;
    return set ? success() : failure(errno_code());
#elif defined(IP_BOUND_IF) && defined(IPV6_BOUND_IF)
    int const index = static_cast<int>(interface_index);
    bool const set = family == AF_INET6 ? ::setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, sizeof(index)) == 0
                                        : ::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) == 0;
    return set ? success() : failure(errno_code());
#else
    (void)fd;
    (void)family;
    return interface_index == 0 ? success() : failure(std::errc::operation_not_supported);
#endif
}

/// The hop limit of unicast from an IPv4 or IPv6 (`family`) socket: `ttl`, or 0 for the host's default again
/// (IP_TTL / IPV6_UNICAST_HOPS).
[[nodiscard]] inline auto set_unicast_hops(int fd, int family, uint8_t ttl) noexcept -> Status
{
#if defined(__linux__)
    int const hops = ttl != 0 ? ttl : -1;  // -1: the default
#else
    int const hops = ttl != 0 ? ttl : family == AF_INET6 ? -1 : IPDEFTTL;
#endif
    bool const set = family == AF_INET6 ? ::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) == 0
                                        : ::setsockopt(fd, IPPROTO_IP, IP_TTL, &hops, sizeof(hops)) == 0;
    return set ? success() : failure(errno_code());
}

/// Send unicast from an IPv4 or IPv6 (`family`) socket out of interface `interface_index`, whatever the route
/// prefers (0: the route; set_unicast_interface(), so not on a socket bound to a device), with hop limit `ttl` (0:
/// the host's default; set_unicast_hops()). Both are set either way, so a reconfigured socket keeps nothing from
/// before. The unicast counterpart of set_multicast_send().
[[nodiscard]] inline auto set_unicast_send(int fd, int family, unsigned int interface_index, uint8_t ttl) noexcept -> Status
{
    if (auto pinned = set_unicast_interface(fd, family, interface_index); !pinned) {
        return pinned;
    }
    return set_unicast_hops(fd, family, ttl);
}

/// The socket's priority (SO_PRIORITY, Linux), which an mqprio root maps to a traffic class: 0 to 6 for anyone, 7
/// to 15 with CAP_NET_ADMIN or CAP_NET_RAW (EPERM otherwise). Call after set_dscp() or set_tos(): on Linux IP_TOS
/// resets the priority to the one the TOS maps to (rt_tos2priority). Elsewhere a no-op.
[[nodiscard]] inline auto set_priority(int fd, int priority) noexcept -> Status
{
#if defined(__linux__)
    if (::setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) != 0) {
        return failure(errno_code());
    }
#else
    (void)fd;
    (void)priority;
#endif
    return success();
}

/// A UDP socket that exists only to hold an IGMP membership for `group` on the
/// interface with index `interface_index`, for as long as the returned
/// descriptor lives.
///
/// An AF_XDP receiver takes frames before the kernel's IP stack sees them, so
/// nothing in that path ever sends an IGMP report - and a switch doing
/// multicast snooping stops forwarding the group, or never starts. A plain
/// socket joined to the group is what keeps the traffic arriving; it is never
/// read from, and the frames it would receive are the ones XDP already took.
///
/// Closing it leaves the group, so the value must be held for as long as the
/// receiver wants the traffic. That is why the membership is a descriptor
/// rather than a one-shot call.
///
/// @param group The multicast group to join
/// @param interface_index Interface to join on, from `if_nametoindex()`
/// @return The socket holding the membership, or the kernel's refusal: an
///         address that is not a group, or an interface that is not there.
[[nodiscard]] inline auto open_group_membership(ip::IPv4Address const& group, unsigned int interface_index) noexcept
    -> StatusValue<FileDescriptor>
{
    auto socket = make_udp_socket();
    if (!socket) {
        return failure(socket.error());
    }
    if (auto const joined = join_group(socket->get(), group, interface_index); !joined) {
        return failure(joined.error());
    }
    return socket;
}

}  // namespace statusbar::net
