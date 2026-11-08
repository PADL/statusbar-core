#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// An `RxFlowControl` that keeps a pretend NIC's classifier table, for consumers to test that
/// they install their rules and leave the NIC as they found it, without CAP_NET_ADMIN or a NIC.

#include "statusbar/net/net_rx_flow.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <vector>

namespace statusbar::net {

class RxFlowRecorder final : public RxFlowControl
{
  public:
    RxFlowRecorder() = default;
    ~RxFlowRecorder() override = default;

    /// The RX queue count the NIC reports.
    auto set_rx_queue_count(uint32_t const queues) noexcept -> void { rx_queues_ = queues; }
    /// The ntuple flag as it stands.
    auto set_ntuple_flag(bool const enabled) noexcept -> void { ntuple_ = enabled; }
    /// A rule already in the table, as a previous owner or an administrator left it.
    auto place(RxFlowRule const& rule) -> void { put(rule); }
    /// Make the insert after `inserts` more succeed fail with `error`, once.
    auto fail_insert_after(size_t const inserts, std::error_code const error) noexcept -> void
    {
        fail_after_ = inserts;
        insert_error_ = error;
    }
    /// A NIC without flow rules: every call fails with operation_not_supported.
    auto set_unsupported() noexcept -> void { unsupported_ = true; }

    [[nodiscard]] auto ntuple_flag() const noexcept -> bool { return ntuple_; }
    [[nodiscard]] auto ntuple_writes() const noexcept -> size_t { return ntuple_writes_; }
    [[nodiscard]] auto rules() const noexcept -> std::vector<RxFlowRule> const& { return rules_; }

    [[nodiscard]] auto ntuple(std::string_view) -> StatusValue<bool> override
    {
        if (unsupported_) {
            return failure(std::make_error_code(std::errc::operation_not_supported));
        }
        return ntuple_;
    }

    [[nodiscard]] auto set_ntuple(std::string_view, bool const enabled) -> Status override
    {
        ++ntuple_writes_;
        ntuple_ = enabled;
        if (!enabled) {
            rules_.clear();  // igb and igc drop every rule with the flag
        }
        return success();
    }

    [[nodiscard]] auto rule(std::string_view, uint32_t const location) -> StatusValue<std::optional<RxFlowRule>> override
    {
        if (unsupported_) {
            return failure(std::make_error_code(std::errc::operation_not_supported));
        }
        auto const found = find(location);
        return found == rules_.end() ? std::optional<RxFlowRule>{} : std::optional{*found};
    }

    [[nodiscard]] auto insert(std::string_view, RxFlowRule const& rule) -> Status override
    {
        if (unsupported_) {
            return failure(std::make_error_code(std::errc::operation_not_supported));
        }
        if (fail_after_ && (*fail_after_)-- == 0) {
            fail_after_.reset();
            return failure(insert_error_);
        }
        put(rule);
        return success();
    }

    [[nodiscard]] auto remove(std::string_view, uint32_t const location) -> Status override
    {
        auto const found = find(location);
        if (found == rules_.end()) {
            return failure(std::make_error_code(std::errc::invalid_argument));
        }
        rules_.erase(found);
        return success();
    }

    [[nodiscard]] auto rx_queues(std::string_view) -> StatusValue<uint32_t> override { return rx_queues_; }

  private:
    auto find(uint32_t const location) -> std::vector<RxFlowRule>::iterator
    {
        return std::ranges::find(rules_, location, &RxFlowRule::location);
    }

    auto put(RxFlowRule const& rule) -> void
    {
        if (auto const found = find(rule.location); found != rules_.end()) {
            *found = rule;
            return;
        }
        rules_.push_back(rule);
    }

    std::vector<RxFlowRule> rules_;
    std::optional<size_t> fail_after_;
    std::error_code insert_error_;
    size_t ntuple_writes_{0};
    uint32_t rx_queues_{4};
    bool ntuple_{false};
    bool unsupported_{false};
};

}  // namespace statusbar::net
