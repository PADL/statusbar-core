// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_interface_info.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_posix_util.hpp"

#    include <fcntl.h>
#    include <unistd.h>

#    include <array>
#    include <cerrno>
#    include <charconv>
#    include <cstring>
#    include <filesystem>
#    include <string>
#    include <system_error>

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
    std::string const path = (sysfs_path(interface_name) / "speed").string();
    int const fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    std::array<char, 32> text{};
    ssize_t const n = ::read(fd, text.data(), text.size() - 1);
    int const saved = errno;
    ::close(fd);
    if (n < 0) {
        // EINVAL: the driver reports no speed (link down, or none at all).
        if (saved == EINVAL) {
            return failure(make_unknown_link_speed());
        }
        return failure(std::error_code{saved, std::system_category()});
    }
    long long speed = 0;
    auto const [end, ec] = std::from_chars(text.data(), text.data() + n, speed);
    (void)end;
    if (ec != std::errc{}) {
        return failure(std::make_error_code(std::errc::bad_message));
    }
    if (speed <= 0 || speed > 0xFFFF'FFFFLL) {  // SPEED_UNKNOWN (-1)
        return failure(make_unknown_link_speed());
    }
    return static_cast<uint32_t>(speed);
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
