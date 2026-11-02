#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One interface's carrier from rtnetlink: one RTM_GETLINK at open, then link notifications (RTMGRP_LINK).
/// Its carrier_down_count shows a carrier lost and regained before the notification was sent. Linux only.

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/net/net_message_reactor.hpp"
#    include "statusbar/sg14/inplace_function.h"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <optional>
#    include <span>
#    include <utility>

namespace statusbar::net {

/// A link's carrier as one RTM_NEWLINK reports it.
struct LinkCarrier
{
    bool carrier{false};     ///< IFLA_CARRIER, else IFF_LOWER_UP
    uint32_t down_count{0};  ///< IFLA_CARRIER_DOWN_COUNT: carrier losses since the device registered (0: not sent)

    auto operator==(LinkCarrier const&) const noexcept -> bool = default;
};

/// The carrier in one netlink message when it is an RTM_NEWLINK of `ifindex`; nullopt for any other message.
/// bad_message when it is truncated or an attribute overruns.
[[nodiscard]] auto parse_link_carrier(std::span<uint8_t const> message, int ifindex) -> StatusValue<std::optional<LinkCarrier>>;

/// An RTM_GETLINK of `ifindex` into `out` (the kernel answers with one RTM_NEWLINK): its length.
/// Errors: invalid_argument for an ifindex of 0 or less, the builder's when `out` is too small.
[[nodiscard]] auto build_get_link(std::span<uint8_t> out, int ifindex, uint32_t seq) -> StatusValue<size_t>;

/// A reactor Pollable that reports the link's state when opened, then each RTM_NEWLINK of one interface (a
/// carrier change, or any other change of the link). Reactor thread only; allocation-free once open.
class CarrierWatch final : public Pollable
{
  public:
    using OnChange = sg14::inplace_function<void(LinkCarrier const&), 64>;

    CarrierWatch(int const ifindex, OnChange on_change) noexcept
        : ifindex_{ifindex}
        , on_change_{std::move(on_change)}
    {}

    /// Open a non-blocking NETLINK_ROUTE socket in RTMGRP_LINK and ask for the link's state, which the
    /// first on_ready() reports. Errors: socket()'s, bind()'s or sendto()'s errno.
    [[nodiscard]] auto open() -> Status;

    [[nodiscard]] auto fd() const noexcept -> int override { return fd_.get(); }
    /// Reads every notification queued. After an overrun (ENOBUFS) the link's state is asked for again
    /// once the queue is drained; an error reply to that request, or another socket error, finishes the watch.
    void on_ready(int64_t now_ns) override;
    void tick(int64_t /*now_ns*/) override {}
    [[nodiscard]] auto finished() const noexcept -> bool override { return failed_; }

  private:
    /// Send an RTM_GETLINK of ifindex_; its reply arrives with the notifications.
    [[nodiscard]] auto request_link() noexcept -> Status;
    /// After an overrun, with the queue drained (the kernel drops replies while it is congested): request_link().
    void resync();
    /// Each message of one datagram to report().
    void deliver(std::span<uint8_t const> datagram);
    /// One message: this interface's RTM_NEWLINK to on_change_, an error reply finishing the watch.
    void report(std::span<uint8_t const> message);

    FileDescriptor fd_{};
    int ifindex_{0};
    OnChange on_change_;
    bool failed_{false};
    bool resync_{false};                   ///< an overrun since the last request_link()
    std::array<uint8_t, 32768> buffer_{};  ///< an RTM_NEWLINK with its statistics is a few KiB
};

}  // namespace statusbar::net

#endif  // __linux__
