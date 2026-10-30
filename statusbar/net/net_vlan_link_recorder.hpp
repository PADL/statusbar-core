#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A `VlanControl` that records registrations instead of making them.
///
/// Shipped rather than kept in core's own test directory because the
/// tests that need it are a *consumer's*. Whether a listener registers
/// the right VID on the right parent, and whether it removes at shutdown
/// only what it created, is most of what can go wrong — and asserting it
/// should not need `CAP_NET_ADMIN`, a NIC with `rx-vlan-filter`, or a
/// kernel whose link configuration the test then has to put back.
///
/// It also lets a caller program the two answers that are otherwise hard
/// to reach: that a link was *adopted* rather than created, and that the
/// kernel refused with a message.

#include "statusbar/net/net_vlan_link.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace statusbar::net::vlan {

#if defined(__linux__)

class VlanRecorder final : public VlanControl
{
  public:
    enum class Operation : std::uint8_t
    {
        add_vlan,
        remove_link,
        bring_up,
    };

    /// One recorded call. `vid` and `parent_ifindex` are meaningful only
    /// for an `add_vlan`.
    struct Request
    {
        Operation operation{Operation::add_vlan};
        int parent_ifindex{0};
        std::string name;
        std::uint16_t vid{0};
    };

    VlanRecorder() = default;
    ~VlanRecorder() override = default;
    VlanRecorder(VlanRecorder const&) = delete;
    auto operator=(VlanRecorder const&) -> VlanRecorder& = delete;
    VlanRecorder(VlanRecorder&&) = delete;
    auto operator=(VlanRecorder&&) -> VlanRecorder& = delete;

    /// Every call made, in order.
    [[nodiscard]] auto requests() const noexcept -> std::span<Request const> { return requests_; }

    /// Forget the history, so one test can assert several phases.
    auto clear() noexcept -> void { requests_.clear(); }

    /// Whether some `add_vlan` asked for this VID on this parent. The
    /// question a listener's test actually wants to ask.
    [[nodiscard]] auto registered(int parent_ifindex, std::uint16_t vid) const noexcept -> bool
    {
        return std::ranges::any_of(requests_, [&](Request const& request) {
            return request.operation == Operation::add_vlan && request.parent_ifindex == parent_ifindex && request.vid == vid;
        });
    }

    /// Report `ownership` from the next successful `add_vlan`. An
    /// adoption is otherwise reachable only by arranging for a link to
    /// exist already, which is the thing this recorder exists to avoid.
    auto set_next_ownership(LinkOwnership ownership) noexcept -> void { next_ownership_ = ownership; }

    /// Fail the next call with `error` and report `message` from
    /// `last_message()`, the way a kernel refusal would. The call is
    /// still recorded: what a caller *attempted* is usually the thing to
    /// assert.
    auto fail_next(std::error_code error, std::string message = {}) -> void
    {
        next_failure_ = error;
        next_message_ = std::move(message);
    }

    auto add_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid) -> StatusValue<LinkOwnership> override
    {
        requests_.push_back(Request{
            .operation = Operation::add_vlan,
            .parent_ifindex = parent_ifindex,
            .name = std::string{name},
            .vid = vid,
        });
        if (auto failure_code = take_failure()) {
            return failure(*failure_code);
        }
        return success(std::exchange(next_ownership_, LinkOwnership::created));
    }

    auto remove_link(std::string_view name) -> Status override
    {
        requests_.push_back(Request{.operation = Operation::remove_link, .name = std::string{name}});
        if (auto failure_code = take_failure()) {
            return failure(*failure_code);
        }
        return success();
    }

    auto bring_up(std::string_view name) -> Status override
    {
        requests_.push_back(Request{.operation = Operation::bring_up, .name = std::string{name}});
        if (auto failure_code = take_failure()) {
            return failure(*failure_code);
        }
        return success();
    }

    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return last_message_; }

  private:
    /// Consume a programmed failure, publishing its message the way the
    /// client publishes the kernel's.
    [[nodiscard]] auto take_failure() noexcept -> std::optional<std::error_code>
    {
        last_message_ = next_message_;
        next_message_.clear();
        return std::exchange(next_failure_, std::nullopt);
    }

    std::vector<Request> requests_;
    LinkOwnership next_ownership_{LinkOwnership::created};
    std::optional<std::error_code> next_failure_;
    std::string next_message_;
    std::string last_message_;
};

#endif  // defined(__linux__)

}  // namespace statusbar::net::vlan
