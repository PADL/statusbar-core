// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_interface_info.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/buffer/span_utils.hpp"
#    include "statusbar/net/net_posix_util.hpp"

#    include <dirent.h>
#    include <fcntl.h>
#    include <unistd.h>

#    include <algorithm>
#    include <array>
#    include <cerrno>
#    include <charconv>
#    include <cstring>

#    include <linux/ethtool.h>
#    include <linux/sockios.h>
#    include <net/if.h>
#    include <sys/ioctl.h>
#    include <sys/socket.h>
#    include <sys/stat.h>

namespace statusbar::net {

namespace {

/// Prefix of the sysfs directory each interface gets.
constexpr std::string_view SYSFS_NET = "/sys/class/net/";

/// errno as an error_code in the **generic** category, not the system
/// category.
///
/// Which category this is matters for one comparison and not the other,
/// and the difference is easy to state backwards. Against a `std::errc`,
/// either category compares equal: `ec == std::errc::no_such_device` goes
/// through the category's `default_error_condition`, and the system
/// category maps a POSIX errno straight onto the generic one. Against
/// another `error_code` it does not, because `error_code` equality
/// compares the category identity too — so a caller writing
/// `== std::make_error_code(std::errc::no_such_device)`, which is the
/// form this module's own tests use, sees false for a system-category
/// code of the very same value.
[[nodiscard]] auto errno_error(int value) noexcept -> std::error_code
{
    return std::error_code{value, std::generic_category()};
}

/// Map a filesystem errno onto the interface vocabulary. A missing sysfs
/// directory means a missing interface, and a caller should see one
/// answer for that regardless of whether the fact came from an ioctl or
/// from a path.
[[nodiscard]] auto sysfs_error(int value) noexcept -> std::error_code
{
    if (value == ENOENT || value == ENOTDIR) {
        return std::make_error_code(std::errc::no_such_device);
    }
    return errno_error(value);
}

/// Checked before any syscall.
///
/// An over-long name would otherwise be truncated into `ifr_name` and we
/// would silently query a *different* interface. `filename_too_long` is
/// reported rather than `no_such_device` because no kernel interface
/// query produces it, so the two cases stay distinguishable to a caller
/// and the early return is observable in a test.
[[nodiscard]] auto validate_name(std::string_view name) noexcept -> Status
{
    if (name.empty()) {
        return failure(std::make_error_code(std::errc::no_such_device));
    }
    if (name.size() >= IFNAMSIZ) {
        return failure(std::make_error_code(std::errc::filename_too_long));
    }
    return success();
}

/// Run an SIOC* ioctl that takes an `ifreq` naming an interface.
[[nodiscard]] auto ifreq_ioctl(std::string_view name, unsigned long request, ifreq& ifr) noexcept -> Status
{
    if (auto status = validate_name(name); !status) {
        return status;
    }
    // AF_INET/SOCK_DGRAM is the conventional unprivileged handle for
    // interface ioctls; none of these queries sends or receives anything.
    FileDescriptor const socket_fd{::socket(AF_INET, SOCK_DGRAM, 0)};
    if (!socket_fd.valid()) {
        return failure(errno_error(errno));
    }
    span_copy(ifname_bytes(ifr).first(name.size()), make_const_span(name));
    if (::ioctl(socket_fd.get(), request, &ifr) < 0) {
        return failure(errno_error(errno));
    }
    return success();
}

/// Run an SIOCETHTOOL command whose payload is `data`.
template <typename Command>
[[nodiscard]] auto ethtool_ioctl(std::string_view name, Command& data) noexcept -> Status
{
    ifreq ifr{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ifr.ifr_data = reinterpret_cast<char*>(&data);
    return ifreq_ioctl(name, SIOCETHTOOL, ifr);
}

/// Build "/sys/class/net/<name>/<suffix>" into a fixed buffer. Returns the
/// length written, or 0 if it would not fit.
[[nodiscard]] auto sysfs_path(std::span<char> out, std::string_view name, std::string_view suffix) noexcept -> std::size_t
{
    std::array<std::string_view, 3> const parts{SYSFS_NET, name, suffix};
    if (SYSFS_NET.size() + name.size() + suffix.size() + 1 > out.size()) {
        return 0;
    }
    auto* cursor = out.data();
    for (auto const part : parts) {
        cursor = std::copy(part.begin(), part.end(), cursor);
    }
    *cursor = '\0';
    return static_cast<std::size_t>(cursor - out.data());
}

/// Count directory entries beginning with `prefix`.
[[nodiscard]] auto count_entries(char const* path, std::string_view prefix) noexcept -> StatusValue<std::size_t>
{
    DIR* dir = ::opendir(path);
    if (dir == nullptr) {
        return failure(sysfs_error(errno));
    }
    std::size_t count = 0;
    while (dirent const* entry = ::readdir(dir)) {
        if (std::string_view{entry->d_name}.starts_with(prefix)) {
            ++count;
        }
    }
    ::closedir(dir);
    return success(count);
}

/// Read a small sysfs attribute. The errno is reported as-is, because for
/// the one attribute we read this way (`speed`) EINVAL is meaningful.
[[nodiscard]] auto read_attribute(char const* path, std::span<char> out) noexcept -> StatusValue<std::size_t>
{
    FileDescriptor const attribute{::open(path, O_RDONLY | O_CLOEXEC)};
    if (!attribute.valid()) {
        return failure(sysfs_error(errno));
    }
    ssize_t const read_length = ::read(attribute.get(), out.data(), out.size() - 1);
    if (read_length < 0) {
        return failure(errno_error(errno));
    }
    out[static_cast<std::size_t>(read_length)] = '\0';
    return success(static_cast<std::size_t>(read_length));
}

/// Longest path we build: the prefix, an interface name, and "/queues".
constexpr std::size_t MAX_SYSFS_PATH = 64 + IFNAMSIZ;

/// Path-build and list the interface's TX queue directories.
[[nodiscard]] auto count_tx_queues(std::string_view name) noexcept -> StatusValue<std::size_t>
{
    std::array<char, MAX_SYSFS_PATH> path{};
    if (sysfs_path(path, name, "/queues") == 0) {
        return failure(std::make_error_code(std::errc::filename_too_long));
    }
    return count_entries(path.data(), "tx-");
}

/// Whether the interface's own sysfs directory is there.
[[nodiscard]] auto interface_exists(std::string_view name) noexcept -> bool
{
    std::array<char, MAX_SYSFS_PATH> path{};
    if (sysfs_path(path, name, "") == 0) {
        return false;
    }
    struct stat info{};
    return ::stat(path.data(), &info) == 0;
}

/// Decide what a failed read of the `speed` attribute means.
///
/// Two different things look like "no file": the interface is gone, or the
/// interface is there but has no `speed` attribute. Only the first is
/// `no_such_device`; the second is an interface with no notion of a link
/// speed, which is the same answer as a link that is down.
[[nodiscard]] auto speed_unavailable(std::error_code read_failure, std::string_view name) noexcept -> std::error_code
{
    if (read_failure == errno_error(EINVAL)) {
        // The attribute exists but the driver declines to answer: the link
        // is down, or it has no speed to report.
        return make_unknown_link_speed();
    }
    if (read_failure != std::make_error_code(std::errc::no_such_device)) {
        return read_failure;
    }
    return interface_exists(name) ? make_unknown_link_speed() : read_failure;
}

/// Path-build and read the `speed` attribute, translating its failures.
[[nodiscard]] auto read_speed_text(std::string_view name, std::span<char> text) noexcept -> StatusValue<std::size_t>
{
    std::array<char, MAX_SYSFS_PATH> path{};
    if (sysfs_path(path, name, "/speed") == 0) {
        return failure(std::make_error_code(std::errc::filename_too_long));
    }
    auto const length = read_attribute(path.data(), text);
    if (length) {
        return length;
    }
    return failure(speed_unavailable(length.error(), name));
}

}  // namespace

auto make_unknown_link_speed() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::network_down);
}

auto interface_index(std::string_view const interface_name) -> StatusValue<int>
{
    ifreq ifr{};
    if (auto status = ifreq_ioctl(interface_name, SIOCGIFINDEX, ifr); !status) {
        return forward_failure(status);
    }
    return success(ifr.ifr_ifindex);
}

auto interface_mtu(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    ifreq ifr{};
    if (auto status = ifreq_ioctl(interface_name, SIOCGIFMTU, ifr); !status) {
        return forward_failure(status);
    }
    return success(static_cast<uint32_t>(ifr.ifr_mtu));
}

auto driver_name(std::string_view const interface_name) -> StatusValue<std::string>
{
    ethtool_drvinfo info{};
    info.cmd = ETHTOOL_GDRVINFO;
    if (auto status = ethtool_ioctl(interface_name, info); !status) {
        return forward_failure(status);
    }
    // The kernel does not promise a terminator in a full field.
    return success(std::string{info.driver, ::strnlen(info.driver, sizeof(info.driver))});
}

auto tx_queue_count(std::string_view const interface_name) -> StatusValue<uint16_t>
{
    if (auto status = validate_name(interface_name); !status) {
        return forward_failure(status);
    }
    auto const count = count_tx_queues(interface_name);
    if (!count) {
        return forward_failure(count);
    }
    // Never report a plausible-looking 0: an interface with no TX queue
    // cannot carry an mqprio map at all, and that is a different answer
    // from "it has none configured yet".
    //
    // Defensive, and honestly so: neither branch is reachable on a current
    // kernel. `queues/` only exists once the device is registered, and
    // registration creates tx-0, so a successful listing cannot be empty;
    // and no NIC has 65536 queues. Deleting the check does not fail any
    // test. It stays because the cost is one comparison and the
    // alternative -- handing a shaper a queue count of 0 -- is an mqprio
    // map whose classes point at queues that are never serviced.
    if (*count == 0 || *count > UINT16_MAX) {
        return failure(std::make_error_code(std::errc::not_supported));
    }
    return success(static_cast<uint16_t>(*count));
}

auto parse_link_speed(std::string_view const text) -> StatusValue<uint32_t>
{
    // Split out as a pure function on purpose: it is what makes the
    // down-link verdict testable with no NIC, no privilege and no sysfs.
    long long speed = 0;
    auto const parsed = std::from_chars(text.data(), text.data() + text.size(), speed);
    if (parsed.ec != std::errc{}) {
        return failure(std::make_error_code(std::errc::bad_message));
    }
    if (speed <= 0 || speed > static_cast<long long>(UINT32_MAX)) {
        // SPEED_UNKNOWN is -1, and some drivers print 0. Neither is a speed.
        return failure(make_unknown_link_speed());
    }
    return success(static_cast<uint32_t>(speed));
}

auto link_speed_mbps(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    // Read from sysfs rather than ETHTOOL_GLINKSETTINGS: that ioctl needs a
    // two-call handshake to learn its own link-mode word count, and sysfs
    // gives the same number with a single read. A driver with no speed to
    // report fails the *read* with EINVAL, which is the signal we want.
    if (auto status = validate_name(interface_name); !status) {
        return forward_failure(status);
    }
    std::array<char, 32> text{};
    auto const length = read_speed_text(interface_name, text);
    if (!length) {
        return forward_failure(length);
    }
    return parse_link_speed(std::string_view{text.data(), *length});
}

}  // namespace statusbar::net

#endif  // __linux__
