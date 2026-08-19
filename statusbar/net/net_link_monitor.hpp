#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// LinkMonitor — a reactor Pollable that polls a network interface's operational
/// link (carrier) state and invokes a callback on every up<->down transition,
/// including once for the first observed state. This replaces a one-shot
/// "assume link up at startup" with continuous link tracking, so a real cable
/// unplug / switch reboot / port flap emits genuine up/down events into the
/// protocol stack (e.g. an AVB supervisor's LinkUp/LinkDown) instead of leaving
/// it stuck on a stale assumption.
///
/// It is a tick-only Pollable (fd() == -1): the reactor calls tick() each cycle
/// and the monitor reads the carrier at most once per poll interval (default
/// 500 ms — link state changes are slow, and SIOCGIFFLAGS is a syscall).
///
/// The link reader is injectable so the transition/throttle logic is unit
/// testable without a real interface; the production constructor uses
/// read_interface_carrier() (SIOCGIFFLAGS / IFF_RUNNING).

#include "statusbar/net/net_message_reactor.hpp"  // Pollable
#include "statusbar/net/net_posix_util.hpp"       // read_interface_carrier
#include "statusbar/sg14/inplace_function.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace statusbar::net {

class LinkMonitor : public Pollable
{
  public:
    /// Fired on a transition (and on the first observed state). @p up is the new
    /// link state; @p now_ns is the reactor clock passed to tick().
    /// Allocation-free inplace_function; captures must fit in 64 bytes.
    using OnChange = statusbar::sg14::inplace_function<void(bool up, int64_t now_ns), 64>;

    /// Returns the current link state: true=up, false=down, nullopt=unknown
    /// (the monitor then leaves its last-known state unchanged and emits nothing).
    using Reader = statusbar::sg14::inplace_function<std::optional<bool>(), 64>;

    static constexpr int64_t DEFAULT_POLL_INTERVAL_NS = 500'000'000;  // 500 ms

    /// Production: poll @p iface's carrier via read_interface_carrier().
    LinkMonitor(std::string_view iface, OnChange on_change, int64_t poll_interval_ns = DEFAULT_POLL_INTERVAL_NS)
        : reader_{[name = std::string{iface}]() { return read_interface_carrier(name); }}
        , on_change_{std::move(on_change)}
        , poll_interval_ns_{poll_interval_ns}
    {}

    /// Test seam: inject the link-state reader.
    LinkMonitor(Reader reader, OnChange on_change, int64_t poll_interval_ns)
        : reader_{std::move(reader)}
        , on_change_{std::move(on_change)}
        , poll_interval_ns_{poll_interval_ns}
    {}

    // -- Pollable interface --

    [[nodiscard]] auto fd() const noexcept -> int override { return -1; }  // tick-only

    void on_ready(int64_t /*now_ns*/) override {}

    void tick(int64_t now_ns) override
    {
        if (now_ns < next_poll_ns_) {
            return;
        }
        next_poll_ns_ = now_ns + poll_interval_ns_;

        auto const up = reader_ ? reader_() : std::optional<bool>{};
        if (!up.has_value()) {
            return;  // unknown — keep the last-known state, emit nothing
        }
        if (!last_up_.has_value() || *last_up_ != *up) {
            last_up_ = up;
            if (on_change_) {
                on_change_(*up, now_ns);
            }
        }
    }

    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

    /// Last observed link state (nullopt until the first successful read).
    [[nodiscard]] auto link_up() const noexcept -> std::optional<bool> { return last_up_; }

  private:
    Reader reader_;
    OnChange on_change_;
    int64_t poll_interval_ns_;
    int64_t next_poll_ns_{0};
    std::optional<bool> last_up_{};
};

}  // namespace statusbar::net
