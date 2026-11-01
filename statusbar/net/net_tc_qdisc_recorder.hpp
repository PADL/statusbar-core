#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A `TcControl` that records requests instead of sending them.
///
/// This is test support, and it is shipped rather than kept in core's own
/// test directory because the tests that need it are a *consumer's*: a
/// shaper's correctness is mostly the sequence of qdisc requests it
/// makes, and asserting that sequence should not need a NIC, a root
/// session, or a kernel whose qdisc configuration the test then has to
/// put back.
///
/// It also lets a caller program a failure, so the paths that only run
/// when the kernel refuses something — a replace that has to delete and
/// retry, a driver that will not offload — are reachable in a unit test.

#include "statusbar/net/net_tc_qdisc.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace statusbar::net::tc {

#if defined(__linux__)

class TcRecorder final : public TcControl
{
  public:
    enum class Operation : std::uint8_t
    {
        replace_mqprio,
        replace_cbs,
        replace_etf,
        replace_kind,
        remove,
        get,
    };

    /// One recorded call. Only the fields the operation carries are set.
    struct Request
    {
        Operation operation{Operation::get};
        int ifindex{0};
        std::uint32_t handle{0};
        std::uint32_t parent{0};
        std::string kind;
        MqprioQdisc mqprio{};
        CbsQdisc cbs{};
        EtfQdisc etf{};
    };

    TcRecorder() = default;
    ~TcRecorder() override = default;
    TcRecorder(TcRecorder const&) = delete;
    auto operator=(TcRecorder const&) -> TcRecorder& = delete;
    TcRecorder(TcRecorder&&) = delete;
    auto operator=(TcRecorder&&) -> TcRecorder& = delete;

    /// Every call made, in order.
    [[nodiscard]] auto requests() const noexcept -> std::span<Request const> { return requests_; }

    /// Forget the history, so one test can assert several phases.
    auto clear() noexcept -> void { requests_.clear(); }

    /// Fail the next write with `error` and report `message` from
    /// `last_message()`, the way a kernel refusal would. The call is still
    /// recorded: what a caller *attempted* is usually the thing to assert.
    auto fail_next_write(std::error_code error, std::string message = {}) -> void
    {
        next_write_failure_ = error;
        next_write_message_ = std::move(message);
    }

    /// What `get()` answers for any parent with no answer of its own. Unset
    /// means `invalid_handle`, i.e. nothing installed there.
    auto set_get_result(QdiscInfo info) -> void { get_result_ = info; }
    auto clear_get_result() noexcept -> void { get_result_.reset(); }

    /// What `get()` answers for `parent` alone, taking precedence over
    /// `set_get_result`. A caller that reads a root and then a class needs the
    /// two to differ, which one result cannot express.
    auto set_get_result_for(std::uint32_t parent, QdiscInfo info) -> void { by_parent_.emplace_back(parent, info); }

    auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status override
    {
        requests_.push_back(Request{
            .operation = Operation::replace_mqprio,
            .ifindex = ifindex,
            .handle = make_handle(qdisc.major, 0),
            .parent = ROOT,
            .kind = "mqprio",
            .mqprio = qdisc,
        });
        return take_write_result();
    }

    auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status override
    {
        requests_.push_back(Request{
            .operation = Operation::replace_cbs,
            .ifindex = ifindex,
            .handle = make_handle(qdisc.handle_major, 0),
            .parent = qdisc.parent,
            .kind = "cbs",
            .cbs = qdisc,
        });
        return take_write_result();
    }

    auto replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status override
    {
        // Handle 0, as the request carries: nothing hangs off an etf.
        requests_.push_back(Request{
            .operation = Operation::replace_etf,
            .ifindex = ifindex,
            .parent = qdisc.parent,
            .kind = "etf",
            .etf = qdisc,
        });
        return take_write_result();
    }

    auto replace_kind(int ifindex, std::uint32_t parent, std::string_view kind) -> Status override
    {
        requests_.push_back(Request{
            .operation = Operation::replace_kind,
            .ifindex = ifindex,
            .parent = parent,
            .kind = std::string{kind},
        });
        return take_write_result();
    }

    auto remove(int ifindex, std::uint32_t handle, std::uint32_t parent) -> Status override
    {
        requests_.push_back(Request{
            .operation = Operation::remove,
            .ifindex = ifindex,
            .handle = handle,
            .parent = parent,
        });
        return take_write_result();
    }

    auto get(int ifindex, std::uint32_t parent) -> StatusValue<QdiscInfo> override
    {
        requests_.push_back(Request{.operation = Operation::get, .ifindex = ifindex, .parent = parent});
        return answer_for(parent);
    }

    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return last_message_; }

  private:
    /// The parent's own answer where it has one, else the default, else
    /// nothing installed there.
    [[nodiscard]] auto answer_for(std::uint32_t parent) const -> StatusValue<QdiscInfo>
    {
        for (auto const& [at, info] : by_parent_) {
            if (at == parent) {
                return success(info);
            }
        }
        if (!get_result_) {
            return failure(NetError::invalid_handle);
        }
        return success(*get_result_);
    }

    /// Consume any programmed failure, so `fail_next_write` affects one
    /// call rather than every call after it.
    [[nodiscard]] auto take_write_result() -> Status
    {
        last_message_ = next_write_message_;
        next_write_message_.clear();
        if (!next_write_failure_) {
            return success();
        }
        auto const error = *next_write_failure_;
        next_write_failure_.reset();
        return failure(error);
    }

    std::vector<Request> requests_;
    std::optional<QdiscInfo> get_result_;
    std::vector<std::pair<std::uint32_t, QdiscInfo>> by_parent_;
    std::optional<std::error_code> next_write_failure_;
    std::string next_write_message_;
    std::string last_message_;
};

#endif  // __linux__

}  // namespace statusbar::net::tc
