// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_address.hpp"

#include "statusbar/net/net_posix_util.hpp"

#include <netdb.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace statusbar::net {

namespace {

/// Where sun_path begins in a sockaddr_un. Everything about an AF_UNIX
/// address is this offset plus a length the kernel reports; sun_path
/// itself is not a C string and need not be NUL-terminated.
constexpr size_t sun_path_offset = offsetof(sockaddr_un, sun_path);

/// Bytes of sun_path an address of this length carries, clamped to the
/// field so a length the kernel never wrote cannot widen the view.
auto sun_path_extent(sockaddr_un const& sun, socklen_t length) noexcept -> size_t
{
    auto const total = static_cast<size_t>(length);
    if (total <= sun_path_offset) {
        return 0;
    }
    return std::min(total - sun_path_offset, sizeof(sun.sun_path));
}

}  // namespace

auto SocketAddress::ipv6(std::span<uint8_t const, 16> addr, uint16_t port, uint32_t scope_id) noexcept -> SocketAddress
{
    SocketAddress result;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&result.storage_);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    sin6->sin6_scope_id = scope_id;
    span_copy(make_span(sin6->sin6_addr), addr);
    result.length_ = sizeof(sockaddr_in6);
    return result;
}

auto SocketAddress::local(std::string_view path) noexcept -> StatusValue<SocketAddress>
{
    SocketAddress result;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* sun = reinterpret_cast<sockaddr_un*>(&result.storage_);

    // Absolute only. A relative path is resolved against the current
    // directory at every syscall, so the owner's later unlink() can remove
    // a different file than the one it bound. '/' is also what tells a
    // path apart from an abstract name at a glance in a log.
    //
    // `>=` on the size, not `>`: the terminator has to fit too. sun_path is
    // 108 bytes on Linux and 104 on macOS, so the limit is a platform fact
    // and the test asserts against sizeof, not against 107.
    if (path.empty() || path.front() != '/' || path.size() >= sizeof(sun->sun_path) || path.find('\0') != std::string_view::npos) {
        return failure(NetError::invalid_address);
    }

    sun->sun_family = AF_UNIX;
    span_copy(make_span(sun->sun_path).first(path.size()), make_const_span(path));
    sun->sun_path[path.size()] = '\0';
    // Count the NUL in the length. The kernel accepts either, but a length
    // that includes it is what getsockname() hands back for the same
    // address, so a round trip compares equal.
    result.length_ = static_cast<socklen_t>(sun_path_offset + path.size() + 1);
    return success(result);
}

auto SocketAddress::path() const noexcept -> std::string_view
{
    if (storage_.ss_family != AF_UNIX) {
        return {};
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const& sun = *reinterpret_cast<sockaddr_un const*>(&storage_);
    size_t const extent = sun_path_extent(sun, length_);
    if (extent == 0) {
        return {};
    }
    // strnlen, not strlen: a path that fills sun_path exactly has no
    // terminator to find. An abstract name starts with the NUL and so
    // reads as empty here, which is what the header promises.
    return {sun.sun_path, ::strnlen(sun.sun_path, extent)};
}

auto SocketAddress::from_string(std::string_view host, std::string_view port, int socket_type) -> StatusValue<SocketAddress>
{
    // Null-terminate the strings (getaddrinfo needs C strings)
    std::array<char, 256> host_buf{};
    std::array<char, 64> port_buf{};

    if (host.size() >= host_buf.size() || port.size() >= port_buf.size()) {
        return failure(NetError::invalid_address);
    }

    span_copy(make_span(host_buf).first(host.size()), make_const_span(host));
    host_buf[host.size()] = '\0';
    span_copy(make_span(port_buf).first(port.size()), make_const_span(port));
    port_buf[port.size()] = '\0';

    char const* host_ptr = host.empty() ? nullptr : host_buf.data();
    char const* port_ptr = port.empty() ? nullptr : port_buf.data();

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (host_ptr == nullptr) {
        hints.ai_flags |= AI_PASSIVE;
    }

    struct addrinfo* result = nullptr;
    int const err = ::getaddrinfo(host_ptr, port_ptr, &hints, &result);
    if (err != 0) {
        return failure(NetError::getaddrinfo_failed);
    }

    SocketAddress addr;
    if (result != nullptr) {
        // Verify the libc-returned length fits in our sockaddr_storage
        // before the byte copy. AI_NUMERICHOST makes a hostile ai_addrlen
        // practically unreachable today, but a runtime check costs nothing
        // and removes the implicit trust on a value that is technically
        // outside our control.
        if (result->ai_addrlen > sizeof(addr.storage_)) {
            ::freeaddrinfo(result);
            return failure(NetError::getaddrinfo_failed);
        }
        // Copy ai_addrlen bytes from the returned sockaddr_* into our
        // sockaddr_storage. The result->ai_addr type is only known at
        // runtime via result->ai_family, so we copy raw bytes. POSIX
        // guarantees sockaddr_storage is alignment-compatible with every
        // sockaddr_* variant getaddrinfo can return, so viewing the
        // result through a sockaddr_storage lens is safe.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* src_storage = reinterpret_cast<sockaddr_storage const*>(result->ai_addr);
        span_copy(make_span(addr.storage_).first(result->ai_addrlen), make_const_span(*src_storage).first(result->ai_addrlen));
        addr.length_ = result->ai_addrlen;
        ::freeaddrinfo(result);
    }

    return success(addr);
}

namespace {

/// Render an AF_UNIX address that path() found no path in: a Linux abstract
/// or autobind name as "@name" (as ss(8) prints it), or "<unnamed>" for a
/// socket that never bound. An unnamed peer gets a word rather than an
/// empty string, so a log line about it does not look truncated — and so
/// it cannot be mistaken for a nameless failure.
auto local_nameless_to_string(sockaddr_un const& sun, socklen_t length) -> std::string
{
    // extent 0 is family-only, what Linux's accept() reports for a peer
    // that never bound; extent 1 is a lone NUL, bound to nothing a name is
    // made of; and Darwin reports that unbound peer as a sun_path of zeros
    // at full length. Nothing but NULs is no name on any of them.
    size_t const extent = sun_path_extent(sun, length);
    if (std::string_view{sun.sun_path, extent}.find_first_not_of('\0') == std::string_view::npos) {
        return "<unnamed>";
    }
    // An abstract name is a byte string, not a C string: it may hold NULs
    // and has no terminator, so the whole extent past the leading NUL is
    // the name.
    std::string result{"@"};
    result += std::string_view{sun.sun_path, extent}.substr(1);
    return result;
}

}  // namespace

auto SocketAddress::to_string() const -> std::string
{
    if (!valid()) {
        return "<invalid>";
    }

    if (storage_.ss_family == AF_UNIX) {
        if (auto const socket_path = path(); !socket_path.empty()) {
            return std::string{socket_path};
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return local_nameless_to_string(*reinterpret_cast<sockaddr_un const*>(&storage_), length_);
    }

    std::array<char, 128> host_buf{};
    std::array<char, 32> port_buf{};

    int const err = ::getnameinfo(
        sockaddr(), length_, host_buf.data(), host_buf.size(), port_buf.data(), port_buf.size(), NI_NUMERICHOST | NI_NUMERICSERV);

    if (err != 0) {
        return "<error>";
    }

    std::string result;
    if (storage_.ss_family == AF_INET6) {
        result = "[";
        result += host_buf.data();
        result += "]:";
    } else {
        result = host_buf.data();
        result += ":";
    }
    result += port_buf.data();
    return result;
}

auto create_udp_socket(SocketAddress const& addr, bool do_bind, int dscp, bool ipv6_only) -> StatusValue<FileDescriptor>
{
    int const fd = ::socket(addr.family(), SOCK_DGRAM, 0);
    if (fd < 0) {
        return failure(NetError::socket_creation_failed);
    }

    FileDescriptor result{fd};
    // SO_REUSEADDR and DSCP are IP notions. On an AF_UNIX socket the first
    // is accepted and does nothing and the second fails outright, so the
    // only thing asking for them can achieve is to fail the open.
    bool const is_local = addr.family() == AF_UNIX;

    if (do_bind) {
        if (!is_local) {
            if (auto status = set_reuse_addr(fd); !status) {
                return forward_failure(status);
            }
        }
        if (ipv6_only && addr.family() == AF_INET6) {
            int const on = 1;
            if (::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
                return failure(NetError::socket_option_failed);
            }
        }
        if (::bind(fd, addr.sockaddr(), addr.length()) < 0) {
            return failure(NetError::bind_failed);
        }
    }

    // Set DSCP if specified (IP families only)
    if (dscp >= 0 && !is_local) {
        if (auto status = set_dscp(fd, addr.family(), static_cast<uint8_t>(dscp)); !status) {
            return forward_failure(status);
        }
    }

    return success(std::move(result));
}

auto create_tcp_socket(SocketAddress const& addr, bool do_bind, int dscp) -> StatusValue<FileDescriptor>
{
    int const fd = ::socket(addr.family(), SOCK_STREAM, 0);
    if (fd < 0) {
        return failure(NetError::socket_creation_failed);
    }

    FileDescriptor result{fd};
    bool const is_local = addr.family() == AF_UNIX;

    if (do_bind) {
        if (!is_local) {
            if (auto status = set_reuse_addr(fd); !status) {
                return forward_failure(status);
            }
        }
        if (::bind(fd, addr.sockaddr(), addr.length()) < 0) {
            return failure(NetError::bind_failed);
        }
    }

    // Set DSCP if specified (IP families only)
    if (dscp >= 0 && !is_local) {
        if (auto status = set_dscp(fd, addr.family(), static_cast<uint8_t>(dscp)); !status) {
            return forward_failure(status);
        }
    }

    return success(std::move(result));
}

auto create_tcp_listener(SocketAddress const& addr, int backlog, int dscp) -> StatusValue<FileDescriptor>
{
    auto socket_result = create_tcp_socket(addr, true, dscp);
    if (!socket_result) {
        return socket_result;
    }

    if (::listen(socket_result->get(), backlog) < 0) {
        return failure(NetError::listen_failed);
    }

    return socket_result;
}

}  // namespace statusbar::net
