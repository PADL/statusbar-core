// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/bpf/bpf_device_base.hpp"

#include "statusbar/bpf/bpf.hpp"
#include "statusbar/bpf/bpf_base.hpp"
#include "statusbar/buffer/buffer.hpp"
#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/status/status.hpp"

#ifndef __APPLE__
#    include "statusbar/net/net_posix_util.hpp"
#endif

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

namespace statusbar::bpf {

BpfDeviceBase::BpfDeviceBase(std::string network_device, FilterParams filter_params, int file_descriptor)
    : network_device_{std::move(network_device)}
    , filter_params_{filter_params}
    , file_descriptor_{file_descriptor}
{}

BpfDeviceBase::~BpfDeviceBase() noexcept = default;

auto BpfDeviceBase::get_mtu() const -> StatusValue<size_t>
{
    if (!is_valid()) {
        return failure(BpfError::invalid_file_descriptor);
    }

    ifreq ifr{};
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", network_device_.c_str());

    if (ioctl(file_descriptor_, SIOCGIFMTU, &ifr) < 0) {
        return failure(BpfError::get_mtu_failed);
    }

    return success(static_cast<size_t>(ifr.ifr_mtu));
}

auto BpfDeviceBase::get_mac_address() const -> StatusValue<ieee::Eui48>
{
    if (!is_valid()) {
        return failure(BpfError::invalid_file_descriptor);
    }

#ifdef __APPLE__
    // macOS doesn't support SIOCGIFHWADDR, would need to use IOKit or getifaddrs
    return failure(BpfError::operation_not_supported);
#else
    ifreq ifr{};
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", network_device_.c_str());

    if (ioctl(file_descriptor_, SIOCGIFHWADDR, &ifr) < 0) {
        return failure(BpfError::get_mac_address_failed);
    }

    ieee::Eui48 mac{};
    span_copy(mac.span(), ::statusbar::net::hwaddr_bytes(ifr));
    return success(mac);
#endif
}

auto BpfDeviceBase::set_blocking(bool blocking) -> Status
{
    if (!is_valid()) {
        return failure(BpfError::invalid_file_descriptor);
    }

    int flags = fcntl(file_descriptor_, F_GETFL, 0);
    if (flags < 0) {
        return failure(BpfError::set_blocking_failed);
    }

    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    if (fcntl(file_descriptor_, F_SETFL, flags) < 0) {
        return failure(BpfError::set_blocking_failed);
    }

    blocking_ = blocking;
    return success();
}

auto BpfDeviceBase::is_blocking() const -> bool
{
    return blocking_;
}

}  // namespace statusbar::bpf