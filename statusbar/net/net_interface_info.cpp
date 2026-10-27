// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_interface_info.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/net/net_posix_util.hpp"

#    include <fcntl.h>
#    include <unistd.h>

#    include <array>
#    include <cerrno>
#    include <charconv>
#    include <cstring>
#    include <filesystem>
#    include <span>
#    include <string>
#    include <string_view>
#    include <system_error>
#    include <utility>

#    include <linux/ethtool.h>
#    include <linux/sockios.h>
#    include <net/if.h>
#    include <sys/ioctl.h>
#    include <sys/socket.h>

namespace statusbar::net {

namespace {

[[nodiscard]] auto valid_name(std::string_view const name) noexcept -> bool
{
    return !name.empty() && name.size() < IFNAMSIZ && name.find('/') == std::string_view::npos;
}

[[nodiscard]] auto sysfs_path(std::string_view const name) -> std::filesystem::path
{
    return std::filesystem::path{"/sys/class/net"} / std::string{name};
}

/// Count the "tx-*" entries from @p it on: the iteration's error on failure.
[[nodiscard]] auto count_tx_queues(std::filesystem::directory_iterator it) -> StatusValue<uint16_t>
{
    std::error_code error;
    uint16_t count = 0;
    for (std::filesystem::directory_iterator const end{}; it != end; it.increment(error)) {
        if (it->path().filename().native().starts_with("tx-")) {
            ++count;
        }
    }
    if (error) {
        return failure(error);
    }
    return count;
}

/// Read the sysfs speed attribute at @p path into @p text, leaving a byte for
/// a NUL: the length read, unknown_link_speed when there is none, or the errno.
[[nodiscard]] auto read_speed(std::filesystem::path const& path, std::span<char> const text) -> StatusValue<size_t>
{
    FileDescriptor const fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (!fd.valid()) {
        return failure(std::error_code{errno, std::system_category()});
    }
    ssize_t const n = ::read(fd.get(), text.data(), text.size() - 1);
    if (n < 0) {
        // EINVAL: the driver reports no speed (link down, or none at all).
        if (errno == EINVAL) {
            return failure(make_unknown_link_speed());
        }
        return failure(std::error_code{errno, std::system_category()});
    }
    return static_cast<size_t>(n);
}

/// A sysfs speed in Mb/s: bad_message when not a number, unknown_link_speed
/// for SPEED_UNKNOWN (-1) or out of range.
[[nodiscard]] auto parse_link_speed(std::string_view const text) -> StatusValue<uint32_t>
{
    long long speed = 0;
    auto const parsed = std::from_chars(text.data(), text.data() + text.size(), speed);
    if (parsed.ec != std::errc{}) {
        return failure(std::make_error_code(std::errc::bad_message));
    }
    if (speed <= 0 || speed > 0xFFFF'FFFFLL) {  // SPEED_UNKNOWN (-1)
        return failure(make_unknown_link_speed());
    }
    return static_cast<uint32_t>(speed);
}

}  // namespace

auto interface_index(std::string_view const interface_name) -> StatusValue<int>
{
    if (!valid_name(interface_name)) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
    unsigned int const index = ::if_nametoindex(std::string{interface_name}.c_str());
    if (index == 0) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
    return static_cast<int>(index);
}

auto tx_queue_count(std::string_view const interface_name) -> StatusValue<uint16_t>
{
    if (!valid_name(interface_name)) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
    // The error_code overloads throughout: nothing may throw out of here.
    std::error_code error;
    std::filesystem::directory_iterator it{sysfs_path(interface_name) / "queues", error};
    if (error) {
        return failure(error);
    }
    return count_tx_queues(std::move(it));
}

auto driver_name(std::string_view const interface_name) -> StatusValue<std::string>
{
    ethtool_drvinfo info{};
    info.cmd = ETHTOOL_GDRVINFO;
    ifreq ifr{};
    set_ifr_data(ifr, &info);
    if (auto status = ifreq_ioctl(interface_name, SIOCETHTOOL, ifr); !status) {
        return failure(status.error());
    }
    return std::string{info.driver, ::strnlen(info.driver, sizeof(info.driver))};
}

auto link_speed_mbps(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    if (!valid_name(interface_name)) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
    std::array<char, 32> text{};
    auto const length = read_speed(sysfs_path(interface_name) / "speed", text);
    if (!length) {
        return failure(length.error());
    }
    return parse_link_speed(std::string_view{text.data(), *length});
}

auto interface_mtu(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    ifreq ifr{};
    if (auto status = ifreq_ioctl(interface_name, SIOCGIFMTU, ifr); !status) {
        return failure(status.error());
    }
    return static_cast<uint32_t>(ifr.ifr_mtu);
}

}  // namespace statusbar::net

#endif  // __linux__
