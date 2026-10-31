#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// An `RssControl` that keeps a pretend NIC's table instead of a real one.
///
/// Shipped rather than kept in core's own test directory because the thing it
/// makes testable is a *consumer's* obligation: that a transport steers the
/// NIC it was given and leaves the table as it found it. Asserting that needs
/// neither `CAP_NET_ADMIN` nor a multi-queue NIC — and it cannot be asserted
/// any other way here, since no interface on any host this was written on has
/// an indirection table at all.
///
/// It also programs the two answers that are otherwise out of reach: a NIC
/// that resized its table while we held the old one, and a write the kernel
/// refuses.

#include "statusbar/net/net_rss.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace statusbar::net {

class RssRecorder final : public RssControl
{
  public:
    /// One recorded write.
    struct Write
    {
        std::string interface_name;
        RssIndirection table;
    };

    RssRecorder() = default;
    ~RssRecorder() override = default;

    /// The table the pretend NIC reports. Empty means a NIC with no RSS.
    auto set_table(RssIndirection table) -> void { table_ = std::move(table); }

    /// How many RX queues it claims. 0 means a driver that will not say, which
    /// is what makes plan_rss_steer defer to the driver's own check.
    auto set_rx_queues(uint32_t queues) noexcept -> void { rx_queues_ = queues; }

    /// Make the next read fail, once.
    auto fail_next_read(std::error_code error) -> void { next_read_error_ = error; }

    /// Make the next write fail, once, leaving the table as it was.
    auto fail_next_write(std::error_code error) -> void { next_write_error_ = error; }

    /// The table as it now stands, after everything written to it.
    [[nodiscard]] auto table() const noexcept -> RssIndirection const& { return table_; }

    /// Every write made, in order. Its size is the question most of these
    /// tests ask: a guard that writes twice, or not at all, is the bug.
    [[nodiscard]] auto writes() const noexcept -> std::span<Write const> { return writes_; }

    /// How many times the table was read.
    [[nodiscard]] auto reads() const noexcept -> size_t { return reads_; }

    [[nodiscard]] auto indirection(std::string_view interface_name) -> StatusValue<RssIndirection> override
    {
        (void)interface_name;
        ++reads_;
        if (auto const error = take(next_read_error_); error) {
            return failure(*error);
        }
        if (table_.empty()) {
            return failure(std::make_error_code(std::errc::operation_not_supported));
        }
        return table_;
    }

    [[nodiscard]] auto set_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status override
    {
        if (auto const error = take(next_write_error_); error) {
            return failure(*error);
        }
        writes_.push_back(
            Write{.interface_name = std::string{interface_name}, .table = RssIndirection(table.begin(), table.end())});
        table_.assign(table.begin(), table.end());
        return success();
    }

    /// The same shape as the real one: read, plan, write only if the plan says
    /// to. Written this way so the double cannot disagree with the NIC about
    /// when a write happens, which is what half of these tests count.
    [[nodiscard]] auto steer_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection> override
    {
        auto const current = indirection(interface_name);
        if (!current) {
            return failure(current.error());
        }
        auto const plan = detail::plan_rss_steer(*current, rx_queues_, queue_id);
        if (!plan) {
            return failure(plan.error());
        }
        if (plan->wanted.has_value()) {
            if (auto const status = set_indirection(interface_name, *plan->wanted); !status) {
                return failure(status.error());
            }
        }
        return plan->previous;
    }

  private:
    /// Consume a programmed one-shot error, if one is armed.
    static auto take(std::optional<std::error_code>& slot) -> std::optional<std::error_code>
    {
        auto error = slot;
        slot.reset();
        return error;
    }

    RssIndirection table_;
    std::vector<Write> writes_;
    std::optional<std::error_code> next_read_error_;
    std::optional<std::error_code> next_write_error_;
    uint32_t rx_queues_{0};
    size_t reads_{0};
};

}  // namespace statusbar::net
