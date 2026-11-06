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

/// Whether `message` is an RTM_DELLINK of `ifindex` in AF_UNSPEC: the link is gone (a bridge's view of its
/// port, AF_BRIDGE, is not).
[[nodiscard]] auto is_link_removed(std::span<uint8_t const> message, int ifindex) noexcept -> bool;

/// An RTM_GETLINK of `ifindex` into `out` (the kernel answers with one RTM_NEWLINK): its length.
/// Errors: invalid_argument for an ifindex of 0 or less, the builder's when `out` is too small.
[[nodiscard]] auto build_get_link(std::span<uint8_t> out, int ifindex, uint32_t seq) -> StatusValue<size_t>;

/// A reactor Pollable that reports the link's state when opened, then each RTM_NEWLINK of one interface (a
/// carrier change, or any other change of the link). Reactor thread only; allocation-free once open.
class CarrierWatch final : public Pollable
{
  public:
    /// Called on the reactor thread with each state of the link.
    using OnChange = sg14::inplace_function<void(LinkCarrier const&), 64>;

    /// Watch @p ifindex, reporting to @p on_change; nothing happens before open().
    CarrierWatch(int const ifindex, OnChange on_change) noexcept
        : ifindex_{ifindex}
        , on_change_{std::move(on_change)}
    {}

    /// Open a non-blocking NETLINK_ROUTE socket in RTMGRP_LINK and ask for the link's state, which the
    /// first on_ready() reports. Errors: socket()'s, bind()'s or sendto()'s errno.
    [[nodiscard]] auto open() -> Status;

    /// The netlink socket, -1 before open().
    [[nodiscard]] auto fd() const noexcept -> int override { return fd_.get(); }
    /// Reads every notification queued, asking again after an overrun or a cut datagram. A lasting error
    /// reply, a second cut, the link's removal (reported as no carrier) or a socket error finish the watch.
    void on_ready(int64_t now_ns) override;
    /// Nothing is timed: the watch is event-driven.
    void tick(int64_t /*now_ns*/) override {}
    /// True once the watch has stopped (see on_ready()).
    [[nodiscard]] auto finished() const noexcept -> bool override { return failed_; }

  private:
    /// Send an RTM_GETLINK of ifindex_; its reply arrives with the notifications.
    [[nodiscard]] auto request_link() noexcept -> Status;
    /// After an overrun, with the queue drained (the kernel drops replies while it is congested): request_link().
    void resync();
    /// A datagram of @p length octets in buffer_: delivered, or a resync when it was cut short.
    void on_received(size_t length);
    /// Each message of one datagram to report().
    void deliver(std::span<uint8_t const> datagram);
    /// One message: this interface's RTM_NEWLINK to on_change_, an error reply finishing the watch.
    void report(std::span<uint8_t const> message);

    FileDescriptor fd_{};
    int ifindex_{0};
    OnChange on_change_;
    bool failed_{false};
    bool resync_{false};                   ///< an overrun since the last request_link()
    bool truncated_{false};                ///< a datagram cut short since the last whole RTM_NEWLINK
    std::array<uint8_t, 32768> buffer_{};  ///< an RTM_NEWLINK with its statistics is a few KiB
};

}  // namespace statusbar::net

#endif  // __linux__
