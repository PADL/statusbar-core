// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_phc.hpp"

#include <system_error>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <fcntl.h>
#    include <time.h>
#    include <unistd.h>

#    include <cerrno>
#    include <cstring>

#    include <linux/ethtool.h>
#    include <linux/ptp_clock.h>
#    include <sys/ioctl.h>
#endif

namespace statusbar::net::phc {

#if defined(__linux__)
// The mirrors spelled in the header, against the UAPI.
static_assert(
    static_cast<uint32_t>(PinFunction::none) == PTP_PF_NONE &&
    static_cast<uint32_t>(PinFunction::external_timestamp) == PTP_PF_EXTTS);
static_assert(
    static_cast<uint32_t>(PinFunction::periodic_output) == PTP_PF_PEROUT &&
    static_cast<uint32_t>(PinFunction::physical_sync) == PTP_PF_PHYSYNC);
static_assert(
    PEROUT_ONE_SHOT == PTP_PEROUT_ONE_SHOT && PEROUT_DUTY_CYCLE == PTP_PEROUT_DUTY_CYCLE && PEROUT_PHASE == PTP_PEROUT_PHASE);
#endif

namespace {

[[nodiscard]] auto invalid_argument() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::invalid_argument);
}

/// Whether @p within, an offset inside a period, is one: not negative and
/// below @p period.
[[nodiscard]] constexpr auto fits_in_period(std::optional<int64_t> const within, int64_t const period) noexcept -> bool
{
    return !within.has_value() || (*within >= 0 && *within < period);
}

}  // namespace

namespace {

/// The flag bits for what @p output asks for, checks aside.
[[nodiscard]] constexpr auto flags_asked_for(PeriodicOutput const& output) noexcept -> uint32_t
{
    uint32_t flags = output.one_shot ? PEROUT_ONE_SHOT : 0U;
    flags |= output.phase_ns.has_value() ? PEROUT_PHASE : 0U;
    flags |= output.on_ns.has_value() ? PEROUT_DUTY_CYCLE : 0U;
    return flags;
}

}  // namespace

auto perout_flags(PeriodicOutput const& output) noexcept -> StatusValue<uint32_t>
{
    if (output.period_ns < 0) {
        return failure(invalid_argument());
    }
    if (output.period_ns == 0) {
        return uint32_t{0};  // off: nothing else is looked at
    }
    if (!fits_in_period(output.phase_ns, output.period_ns) || !fits_in_period(output.on_ns, output.period_ns)) {
        return failure(invalid_argument());
    }
    return flags_asked_for(output);
}

#if defined(__linux__)

namespace {

[[nodiscard]] auto errno_failure() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected{std::error_code{errno, std::generic_category()}};
}

[[nodiscard]] auto to_kernel(ClockTime const& time) noexcept -> ptp_clock_time
{
    ptp_clock_time out{};
    out.sec = time.sec;
    out.nsec = time.nsec;
    return out;
}

/// The descriptor's clock id, as linux/posix-timers' FD_TO_CLOCKID spells it.
[[nodiscard]] constexpr auto clock_id_of(int const fd) noexcept -> clockid_t
{
    return static_cast<clockid_t>((~static_cast<unsigned int>(fd) << 3U) | 3U);
}

}  // namespace

auto phc_index(std::string_view const interface_name) -> StatusValue<std::optional<int>>
{
    ethtool_ts_info info{};
    info.cmd = ETHTOOL_GET_TS_INFO;
    if (auto status = ethtool_ioctl(interface_name, &info); !status) {
        return forward_failure(status);
    }
    if (info.phc_index < 0) {
        return std::optional<int>{};
    }
    return std::optional<int>{info.phc_index};
}

auto phc_device_path(int const index) -> std::string
{
    return "/dev/ptp" + std::to_string(index);
}

auto PhcDevice::open(std::string_view const path) -> Status
{
    close();
    std::string const node{path};
    FileDescriptor fd{::open(node.c_str(), O_RDWR | O_CLOEXEC)};
    bool writable = fd.valid();
    if (!fd.valid() && (errno == EACCES || errno == EPERM || errno == EROFS)) {
        fd = FileDescriptor{::open(node.c_str(), O_RDONLY | O_CLOEXEC)};
    }
    if (!fd.valid()) {
        return failure(std::error_code{errno, std::generic_category()});
    }
    fd_ = std::move(fd);
    writable_ = writable;
    return success();
}

auto PhcDevice::capabilities() -> StatusValue<Capabilities>
{
    if (!is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    ptp_clock_caps caps{};
    if (::ioctl(fd_.get(), PTP_CLOCK_GETCAPS2, &caps) != 0) {
        return errno_failure();
    }
    return Capabilities{
        .max_adjustment_ppb = caps.max_adj,
        .alarms = caps.n_alarm,
        .external_timestamp_channels = caps.n_ext_ts,
        .periodic_output_channels = caps.n_per_out,
        .pps = caps.pps != 0,
        .pins = caps.n_pins,
        .cross_timestamping = caps.cross_timestamping != 0,
        .adjust_phase = caps.adjust_phase != 0,
        .max_phase_adjustment_ns = caps.max_phase_adj,
    };
}

auto PhcDevice::time_ns() -> StatusValue<int64_t>
{
    if (!is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    timespec now{};
    if (::clock_gettime(clock_id_of(fd_.get()), &now) != 0) {
        return errno_failure();
    }
    return static_cast<int64_t>(now.tv_sec) * 1'000'000'000 + now.tv_nsec;
}

auto PhcDevice::pin(uint32_t const index) -> StatusValue<Pin>
{
    if (!is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    ptp_pin_desc desc{};
    desc.index = index;
    if (::ioctl(fd_.get(), PTP_PIN_GETFUNC2, &desc) != 0) {
        return errno_failure();
    }
    return Pin{
        .index = desc.index,
        .name = std::string{desc.name, ::strnlen(desc.name, sizeof(desc.name))},
        .function = static_cast<PinFunction>(desc.func),
        .channel = desc.chan,
    };
}

auto PhcDevice::set_pin(uint32_t const index, PinFunction const function, uint32_t const channel) -> Status
{
    if (!is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    if (!writable_) {
        return failure(std::make_error_code(std::errc::operation_not_permitted));
    }
    ptp_pin_desc desc{};
    desc.index = index;
    desc.func = static_cast<unsigned int>(function);
    desc.chan = channel;
    if (::ioctl(fd_.get(), PTP_PIN_SETFUNC2, &desc) != 0) {
        return errno_failure();
    }
    return success();
}

auto PhcDevice::periodic_output(PeriodicOutput const& output) -> Status
{
    if (!is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    auto const flags = perout_flags(output);
    if (!flags) {
        return forward_failure(flags);
    }
    if (!writable_) {
        return failure(std::make_error_code(std::errc::operation_not_permitted));
    }
    ptp_perout_request request{};
    request.index = output.channel;
    request.flags = *flags;
    request.period = to_kernel(clock_time_from_ns(output.period_ns));
    // The first union: the start, or the phase under PEROUT_PHASE. The
    // second: the on-time under PEROUT_DUTY_CYCLE, else reserved and zero.
    request.start = to_kernel(clock_time_from_ns(output.phase_ns.value_or(output.start_ns)));
    if (output.on_ns.has_value()) {
        request.on = to_kernel(clock_time_from_ns(*output.on_ns));
    }
    if (::ioctl(fd_.get(), PTP_PEROUT_REQUEST2, &request) != 0) {
        return errno_failure();
    }
    return success();
}

#endif  // __linux__

}  // namespace statusbar::net::phc
