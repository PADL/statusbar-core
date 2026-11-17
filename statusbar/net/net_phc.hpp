#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A PTP hardware clock's pins and periodic outputs: the `/dev/ptpN` ioctls
/// (`linux/ptp_clock.h`) that make a NIC's clock drive a signal out of a pin -
/// a pulse per second on an SMA connector, a 10 MHz reference, a word clock -
/// and tell a pin what it is for. What a PTP daemon does *not* do: it keeps
/// the clock right, and this is for what the clock then drives.
///
/// A clock has `n_pins` pins, each with a function (`PinFunction`) and a
/// channel: a pin set to `periodic_output` on channel 2 is where periodic
/// output channel 2 comes out. A `PeriodicOutput` names a channel, a period
/// and either a start time or a phase; its duty cycle is optional and a
/// one-shot pulse is a flag. Both the pin functions and the outputs persist
/// in the hardware until changed, so a daemon sets them once and a period of
/// 0 turns an output off.
///
/// `phc_index()` finds the clock behind an interface (`ETHTOOL_GET_TS_INFO`),
/// and `PhcDevice` holds one open. Reading capabilities and pin functions
/// needs read access to the device node; setting anything needs write
/// access, which on most distributions means root. The pure parts - the
/// split of a time into the kernel's seconds and nanoseconds, the flags and
/// the check of a request - build and are tested everywhere; the device is
/// Linux only.

#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace statusbar::net::phc {

/// What a pin does: PTP_PF_*.
enum class PinFunction : uint32_t
{
    none = 0,                ///< PTP_PF_NONE
    external_timestamp = 1,  ///< PTP_PF_EXTTS: an edge on the pin is timestamped
    periodic_output = 2,     ///< PTP_PF_PEROUT: the pin carries a periodic output channel
    physical_sync = 3,       ///< PTP_PF_PHYSYNC
};

/// What a clock can do, as PTP_CLOCK_GETCAPS2 reports it.
struct Capabilities
{
    int32_t max_adjustment_ppb{0};
    int32_t alarms{0};
    int32_t external_timestamp_channels{0};
    int32_t periodic_output_channels{0};
    bool pps{false};
    int32_t pins{0};
    bool cross_timestamping{false};
    bool adjust_phase{false};
    int32_t max_phase_adjustment_ns{0};

    [[nodiscard]] constexpr auto operator==(Capabilities const&) const noexcept -> bool = default;
};

/// One pin as PTP_PIN_GETFUNC2 describes it.
struct Pin
{
    uint32_t index{0};
    std::string name{};
    PinFunction function{PinFunction::none};
    /// The channel of its function: periodic output channel `channel` for a
    /// `periodic_output` pin, external timestamp channel for an
    /// `external_timestamp` one.
    uint32_t channel{0};
};

/// A periodic output request in plain nanoseconds: PTP_PEROUT_REQUEST2.
struct PeriodicOutput
{
    /// The channel, below Capabilities::periodic_output_channels. A pin set to
    /// `periodic_output` on this channel is where it comes out.
    uint32_t channel{0};
    /// The period. 0 turns the channel off; everything else is then ignored.
    int64_t period_ns{0};
    /// The clock time of the first edge, on the PHC's own timescale. Ignored
    /// when `phase_ns` is given.
    int64_t start_ns{0};
    /// PTP_PEROUT_PHASE: instead of a start, where within each period the
    /// edge falls, so the output is aligned to the clock's seconds (a PPS at
    /// phase 0 rises on the second) whenever it is enabled. Below the period.
    std::optional<int64_t> phase_ns{};
    /// PTP_PEROUT_DUTY_CYCLE: how long the output is high each period, for a
    /// driver that can do other than its default. Below the period.
    std::optional<int64_t> on_ns{};
    /// PTP_PEROUT_ONE_SHOT: one pulse at the start (or phase), not a train.
    bool one_shot{false};
};

/// The PTP_PEROUT_* flag bits a request carries.
inline constexpr uint32_t PEROUT_ONE_SHOT = 1U << 0U;
inline constexpr uint32_t PEROUT_DUTY_CYCLE = 1U << 1U;
inline constexpr uint32_t PEROUT_PHASE = 1U << 2U;

/// A time as `struct ptp_clock_time` carries it: whole seconds and the
/// nanoseconds within them, the nanoseconds never negative.
struct ClockTime
{
    int64_t sec{0};
    uint32_t nsec{0};

    [[nodiscard]] constexpr auto operator==(ClockTime const&) const noexcept -> bool = default;
};

/// @p ns split into seconds and nanoseconds, the nanoseconds in [0, 1e9): a
/// negative time borrows a second rather than carrying a negative remainder.
[[nodiscard]] constexpr auto clock_time_from_ns(int64_t const ns) noexcept -> ClockTime
{
    constexpr int64_t NS_PER_S = 1'000'000'000;
    int64_t sec = ns / NS_PER_S;
    int64_t nsec = ns % NS_PER_S;
    if (nsec < 0) {
        nsec += NS_PER_S;
        --sec;
    }
    return ClockTime{.sec = sec, .nsec = static_cast<uint32_t>(nsec)};
}

/// The flags @p output asks for, once it has passed the checks the kernel
/// would make too late to be told apart: `invalid_argument` for a negative
/// period, a phase or an on-time that is negative or not below the period.
/// A period of 0 is a request to turn the channel off and has no flags.
[[nodiscard]] auto perout_flags(PeriodicOutput const& output) noexcept -> StatusValue<uint32_t>;

#if defined(__linux__)

/// The PTP hardware clock behind an interface (ETHTOOL_GET_TS_INFO's
/// phc_index): the N of its `/dev/ptpN`, or nullopt for an interface whose
/// timestamps are software only (`lo`, most virtual devices). Needs no
/// privilege.
/// @param interface_name Interface name
/// @return The index, nullopt for no clock, or the ioctl's error
///         (`no_such_device`, `operation_not_supported` for a driver with no
///         ethtool at all).
[[nodiscard]] auto phc_index(std::string_view interface_name) -> StatusValue<std::optional<int>>;

/// The device node for a clock index: "/dev/ptpN".
[[nodiscard]] auto phc_device_path(int index) -> std::string;

/// One PTP hardware clock, open. Opened for writing where the caller may,
/// read-only where not, so a daemon without the privilege can still read
/// what it would have set. Not thread-safe.
class PhcDevice
{
  public:
    PhcDevice() noexcept = default;

    /// Open @p path ("/dev/ptp0"), read-write when permitted, else
    /// read-only; writable() says which. Errors: open(2)'s. A device that was
    /// open is closed first.
    [[nodiscard]] auto open(std::string_view path) -> Status;
    void close() noexcept { fd_ = FileDescriptor{}; }
    [[nodiscard]] auto is_open() const noexcept -> bool { return fd_.valid(); }
    /// Whether set_pin() and periodic_output() can succeed: the node was
    /// opened for writing.
    [[nodiscard]] auto writable() const noexcept -> bool { return writable_; }
    [[nodiscard]] auto fd() const noexcept -> int { return fd_.get(); }

    /// PTP_CLOCK_GETCAPS2. Errors: the ioctl's; `bad_file_descriptor` when closed.
    [[nodiscard]] auto capabilities() -> StatusValue<Capabilities>;

    /// The clock's own time, through clock_gettime() on the descriptor's
    /// clock id: the timescale a PeriodicOutput's start is on.
    [[nodiscard]] auto time_ns() -> StatusValue<int64_t>;

    /// PTP_PIN_GETFUNC2 for pin @p index. Errors: `invalid_argument` for an
    /// index the clock has no pin at, else the ioctl's.
    [[nodiscard]] auto pin(uint32_t index) -> StatusValue<Pin>;

    /// PTP_PIN_SETFUNC2: give pin @p index @p function on @p channel. A
    /// function on a channel another pin already has is refused by most
    /// drivers (`invalid_argument`); set that pin to `none` first. Errors:
    /// `operation_not_permitted` when not writable(), else the ioctl's.
    [[nodiscard]] auto set_pin(uint32_t index, PinFunction function, uint32_t channel) -> Status;

    /// PTP_PEROUT_REQUEST2 for @p output, after perout_flags()'s checks. A
    /// driver without the flags asked for (a phase, a duty cycle) refuses
    /// with `operation_not_supported`. Errors: perout_flags()'s,
    /// `operation_not_permitted` when not writable(), else the ioctl's.
    [[nodiscard]] auto periodic_output(PeriodicOutput const& output) -> Status;

  private:
    FileDescriptor fd_{};
    bool writable_{false};
};

#endif  // __linux__

}  // namespace statusbar::net::phc
