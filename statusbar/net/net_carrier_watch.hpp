#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One interface's carrier from rtnetlink link notifications (RTMGRP_LINK): event-driven, and its
/// carrier_down_count shows a carrier lost and regained before the notification was sent. Linux only.

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/net/net_message_reactor.hpp"
#    include "statusbar/sg14/inplace_function.h"
#    include "statusbar/status/status.hpp"

#    include <array>
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

/// A reactor Pollable that reports each RTM_NEWLINK of one interface (a carrier change, or any other
/// change of the link). Reactor thread only; allocation-free once open.
class CarrierWatch final : public Pollable
{
  public:
    using OnChange = sg14::inplace_function<void(LinkCarrier const&), 64>;

    CarrierWatch(int const ifindex, OnChange on_change) noexcept
        : ifindex_{ifindex}
        , on_change_{std::move(on_change)}
    {}

    /// Open a non-blocking NETLINK_ROUTE socket in RTMGRP_LINK. Errors: socket()'s or bind()'s errno.
    [[nodiscard]] auto open() -> Status;

    [[nodiscard]] auto fd() const noexcept -> int override { return fd_.get(); }
    /// Reads every notification queued; one lost to an overrun (ENOBUFS) is skipped, the next one carrying
    /// the count. Another error finishes the watch.
    void on_ready(int64_t now_ns) override;
    void tick(int64_t /*now_ns*/) override {}
    [[nodiscard]] auto finished() const noexcept -> bool override { return failed_; }

  private:
    /// Each message of one datagram handed to on_change_ when it is this interface's.
    void deliver(std::span<uint8_t const> datagram);

    FileDescriptor fd_{};
    int ifindex_{0};
    OnChange on_change_;
    bool failed_{false};
    std::array<uint8_t, 32768> buffer_{};  ///< an RTM_NEWLINK with its statistics is a few KiB
};

}  // namespace statusbar::net

#endif  // __linux__
