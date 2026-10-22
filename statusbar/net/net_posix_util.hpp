#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Thin wrappers around POSIX socket / Linux networking APIs that require
// reinterpret_cast at their boundaries:
//
//   - sockaddr_cast      - POSIX bind/connect/sendto take sockaddr*
//   - cmsg_data_as       - POSIX CMSG_DATA returns unsigned char*
//   - set_ifr_data       - Linux smuggles ethtool/hwtstamp via ifreq.ifr_data (char*)
//   - ifname_bytes       - ifreq.ifr_name is char[IFNAMSIZ] for interface-name copies
//   - hwaddr_bytes       - ifreq.ifr_hwaddr.sa_data holds 6 MAC bytes
//
// All of these are POSIX/Linux boundary crossings. They're isolated here
// so the reinterpret_cast is confined to one typed helper per pattern and
// call sites read cleanly.

#include "statusbar/ieee/ieee_ethernet.hpp"
#include "statusbar/status/status.hpp"

#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#if !defined(__linux__)
#    include <ifaddrs.h>

#    include <net/if_dl.h>
#endif

namespace statusbar::net {

/// Cast a pointer to a typed socket address (sockaddr_in, sockaddr_in6,
/// sockaddr_ll, sockaddr_storage, etc.) to the generic `sockaddr*` that
/// POSIX bind/connect/sendto/accept/etc. require.
template <typename Addr>
[[nodiscard]] inline auto sockaddr_cast(Addr& a) noexcept -> struct sockaddr*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<struct sockaddr*>(&a);
}

/// Const overload of sockaddr_cast.
template <typename Addr>
[[nodiscard]] inline auto sockaddr_cast(Addr const& a) noexcept -> struct sockaddr const*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<struct sockaddr const*>(&a);
}

/// Typed view of the payload attached to a control message (CMSG_DATA).
/// CMSG_DATA returns `unsigned char*`; callers expecting a specific
/// structure type (struct timespec, scm_timestamping, ...) use this helper.
template <typename T>
[[nodiscard]] inline auto cmsg_data_as(cmsghdr const* cmsg) noexcept -> T const*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<T const*>(CMSG_DATA(cmsg));
}

/// Set ifreq.ifr_data to a typed struct pointer. Linux uses ifr_data (of
/// type char*) as a smuggling slot for various typed ioctl payloads
/// (ethtool_cmd, ethtool_ts_info, hwtstamp_config, ...).
template <typename T>
inline void set_ifr_data(ifreq& ifr, T* data) noexcept
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ifr.ifr_data = reinterpret_cast<char*>(data);
}

/// View the ifreq.ifr_name buffer as a mutable byte span. Useful for
/// `span_copy` when filling the name from a string_view source.
[[nodiscard]] inline auto ifname_bytes(ifreq& ifr) noexcept -> std::span<uint8_t, IFNAMSIZ>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t, IFNAMSIZ>(reinterpret_cast<uint8_t*>(ifr.ifr_name), IFNAMSIZ);
}

/// Run one interface ioctl (SIOCGIFMTU, SIOCETHTOOL, SIOCGIFHWADDR...) on
/// @p ifr, after writing @p iface into ifr.ifr_name (the rest of @p ifr, e.g.
/// an ifr_data set with set_ifr_data, is left as the caller filled it). A
/// transient AF_INET datagram socket is the ioctl carrier. Errors:
/// no_such_device for an empty or over-long name; the socket's or the ioctl's errno.
[[nodiscard]] inline auto ifreq_ioctl(std::string_view const iface, unsigned long const request, ifreq& ifr) noexcept -> Status
{
    if (iface.empty() || iface.size() >= IFNAMSIZ) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
#if defined(SOCK_CLOEXEC)
    int const sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
    int const sock = ::socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (sock < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    std::memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    std::memcpy(ifr.ifr_name, iface.data(), iface.size());
    int const rc = ::ioctl(sock, request, &ifr);
    int const saved = errno;
    ::close(sock);
    if (rc < 0) {
        return failure(std::error_code{saved, std::system_category()});
    }
    return success();
}

#if defined(__linux__)

/// View the ifreq.ifr_hwaddr.sa_data as a fixed 6-byte span. This is the
/// MAC address payload returned by SIOCGIFHWADDR. Linux-only; BSD/macOS
/// use SIOCGIFHWADDR / ioctls with different structure layouts.
[[nodiscard]] inline auto hwaddr_bytes(ifreq& ifr) noexcept -> std::span<uint8_t, 6>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t, 6>(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data), 6);
}

/// Const overload of hwaddr_bytes.
[[nodiscard]] inline auto hwaddr_bytes(ifreq const& ifr) noexcept -> std::span<uint8_t const, 6>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::span<uint8_t const, 6>(reinterpret_cast<uint8_t const*>(ifr.ifr_hwaddr.sa_data), 6);
}

/// Read an interface's MAC address via SIOCGIFHWADDR. Allocates a transient
/// AF_INET datagram socket purely as the ioctl carrier and closes it before
/// returning. Returns nullopt on any failure (interface name out of range,
/// socket creation failure, ioctl error). The returned MAC has whatever
/// hardware-address-family the interface reports — caller is expected to
/// use this with Ethernet (`ARPHRD_ETHER`) interfaces.
[[nodiscard]] inline auto read_interface_mac(std::string_view iface) noexcept -> std::optional<ieee::Eui48>
{
    ifreq ifr{};
    if (!ifreq_ioctl(iface, SIOCGIFHWADDR, ifr)) {
        return std::nullopt;
    }
    ieee::Eui48 mac{};
    auto const src = hwaddr_bytes(ifr);
    auto const dst = mac.span();
    std::ranges::copy(src, dst.begin());
    return mac;
}

#else  // BSD / macOS

/// Read an interface's MAC address via `getifaddrs()`. macOS and the
/// BSDs do not expose SIOCGIFHWADDR; instead the link-layer address is
/// reported as an `AF_LINK` `sockaddr_dl` entry returned by getifaddrs.
/// Iterates the list, matches `iface` by name, and copies the 6-byte
/// MAC out of `LLADDR(sdl)` when `sdl_alen == 6`. Returns `nullopt` on
/// any failure (interface name out of range, getifaddrs failure, no
/// matching AF_LINK entry, non-Ethernet sdl_alen).
[[nodiscard]] inline auto read_interface_mac(std::string_view iface) noexcept -> std::optional<ieee::Eui48>
{
    if (iface.empty() || iface.size() >= IFNAMSIZ) {
        return std::nullopt;
    }
    char ifname_buf[IFNAMSIZ]{};
    std::memcpy(ifname_buf, iface.data(), iface.size());

    ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) != 0) {
        return std::nullopt;
    }
    std::optional<ieee::Eui48> result;
    for (ifaddrs const* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_LINK) {
            continue;
        }
        if (std::strncmp(ifa->ifa_name, ifname_buf, IFNAMSIZ) != 0) {
            continue;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — BSD sockaddr_dl overlay
        auto const* sdl = reinterpret_cast<sockaddr_dl const*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) {
            continue;
        }
        ieee::Eui48 mac{};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — LLADDR returns char*
        auto const* src = reinterpret_cast<uint8_t const*>(LLADDR(sdl));
        std::ranges::copy(std::span<uint8_t const>(src, 6), mac.span().begin());
        result = mac;
        break;
    }
    ::freeifaddrs(ifaddr);
    return result;
}

#endif  // __linux__

/// Read an interface's operational link (carrier) state via SIOCGIFFLAGS,
/// reporting the IFF_RUNNING flag (driver has detected link / resources allocated)
/// — distinct from IFF_UP (administrative state). Works on both Linux and the BSDs/
/// macOS. Returns true=link up, false=link down, or nullopt if the flags could not
/// be read (no such interface, no socket); callers treat nullopt as "unknown" and
/// leave their last-known state unchanged. Allocates a transient AF_INET datagram
/// socket purely as the ioctl carrier and closes it before returning.
[[nodiscard]] inline auto read_interface_carrier(std::string_view iface) noexcept -> std::optional<bool>
{
    int const sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return std::nullopt;
    }
    ifreq ifr{};
    auto const name = ifname_bytes(ifr);
    auto const n = std::min(iface.size(), name.size() - 1);
    for (size_t i = 0; i < n; ++i) {
        name[i] = static_cast<uint8_t>(iface[i]);
    }
    int const rc = ::ioctl(sock, SIOCGIFFLAGS, &ifr);
    ::close(sock);
    if (rc < 0) {
        return std::nullopt;
    }
    return (static_cast<unsigned>(ifr.ifr_flags) & IFF_RUNNING) != 0U;
}

}  // namespace statusbar::net
