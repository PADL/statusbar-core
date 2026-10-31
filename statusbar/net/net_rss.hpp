#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The NIC's RSS indirection table, and steering every hash bucket of it to a
/// single RX queue.
///
/// An AF_XDP socket binds to one RX queue. A NIC with RSS hashes incoming
/// flows across all of its queues, so by default most of a multicast stream
/// lands on queues the socket is not watching and those frames go to the
/// kernel instead - a receiver that works on a single-queue NIC and silently
/// loses most of its packets on a normal one. Pointing every bucket at the
/// socket's queue is what `ethtool -X <if> equal 1` does by hand.

#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace statusbar::net {

/// A NIC's RSS indirection table: entry i is the RX queue that hash bucket i
/// is steered to.
using RssIndirection = std::vector<uint32_t>;

/// The interface's RSS indirection table as the NIC reports it.
///
/// Needs no privilege, which is what makes it usable as a startup check: read
/// the table, and if rss_steered_to() says it is single-queue when we did not
/// put it there, it is a leftover from a run that died before restoring.
///
/// An interface with no indirection table - `lo`, a veth, most virtual
/// interfaces - fails with `std::errc::operation_not_supported`,
/// distinguishably from a name that does not exist.
/// @param interface_name The interface to read, 1 to IFNAMSIZ-1 bytes
[[nodiscard]] auto rss_indirection(std::string_view interface_name) -> StatusValue<RssIndirection>;

/// Point every RSS hash bucket of `interface_name` at `queue_id`, and return
/// the table as it was.
///
/// The previous table is returned so the caller can put it back with
/// set_rss_indirection(). Doing so matters: the change is to the NIC, not to
/// our socket, and it degrades every other user of that interface - the host's
/// own traffic included - until someone runs `ethtool -X <if> default`. A
/// caller that drops the returned table has reconfigured the machine
/// permanently.
///
/// Nothing is written when every bucket already goes to `queue_id`, which
/// avoids a privileged syscall and, on some drivers, a link reset.
///
/// Writing needs CAP_NET_ADMIN; reading does not. An interface with no
/// indirection table - `lo`, a veth, most virtual interfaces - fails with
/// `std::errc::operation_not_supported`, distinguishably, because for a
/// caller that is "nothing to steer" rather than a fault.
/// @param interface_name The interface to steer, 1 to IFNAMSIZ-1 bytes
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto set_rss_indirection_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection>;

/// Write `table` as the interface's RSS indirection table: the counterpart of
/// set_rss_indirection_all, for restoring what it returned. An empty table
/// asks the driver for its own default, as `ethtool -X <if> default` does.
/// Needs CAP_NET_ADMIN.
/// @param interface_name The interface to write to
/// @param table One RX queue index per hash bucket
[[nodiscard]] auto set_rss_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status;

/// A table of `entries` buckets, every one of them `queue_id`. Public because
/// a caller restoring or auditing a table needs to build the one we would
/// have written.
/// @param entries How many hash buckets the table has
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto rss_indirection_all(size_t entries, uint32_t queue_id) -> RssIndirection;

/// Whether every bucket of a non-empty table already goes to `queue_id`.
///
/// With rss_indirection() this is the startup check: a table that is
/// single-queue when we did not put it there is the previous run's leftover,
/// not a configuration. An empty table is not steered anywhere.
/// @param table The table to examine
/// @param queue_id The RX queue to test for
[[nodiscard]] auto rss_steered_to(std::span<uint32_t const> table, uint32_t queue_id) noexcept -> bool;

namespace detail {

/// What set_rss_indirection_all decides once it has the current table. Split
/// out with no syscall in it so the decision can be tested without a NIC.
struct RssSteerPlan
{
    /// The table as it was, for the caller to restore.
    RssIndirection previous;
    /// The table to write, or nullopt when every bucket already goes there.
    std::optional<RssIndirection> wanted;
};

/// Decide what to write given the table the NIC reports, how many RX queues
/// it has, and the queue we want.
///
/// `operation_not_supported` for an empty table: the NIC has no RSS, so there
/// is nothing to steer. `invalid_argument` for a queue the NIC does not have,
/// refused here rather than offered to a driver that may do something worse
/// than reject it.
/// @param current The table as the NIC reports it
/// @param rx_queues The NIC's RX queue count, or 0 when it would not say
/// @param queue_id The RX queue every bucket should land on
[[nodiscard]] auto plan_rss_steer(std::span<uint32_t const> current, uint32_t rx_queues, uint32_t queue_id)
    -> StatusValue<RssSteerPlan>;

}  // namespace detail

// ---------------------------------------------------------------------------
// Who owns putting the table back
// ---------------------------------------------------------------------------
//
// The answer is RssSteering, and it is an RAII guard rather than a documented
// duty, because the documented duty is what the caller this module was
// modelled on already failed to do: it steered, dropped the previous table on
// the floor, and left every other user of that NIC - the host's own TCP
// included - on a single-queue table until an administrator ran
// `ethtool -X <if> default`. A return value nobody reads is not a restore
// mechanism.
//
// It is best-effort and nothing can make it more than that. A crash or a
// SIGKILL leaks the change whatever user space intended, so a caller that
// needs the table to always be right must ALSO check at startup, with
// rss_indirection() and rss_steered_to(): a single-queue table we did not
// write is the previous run's leftover. Say so out loud rather than trusting
// the destructor.

/// The two writes and one read a steerer needs of a NIC.
///
/// An interface rather than free calls so that the restore protocol can be
/// tested at all: a real steer needs a multi-queue NIC and CAP_NET_ADMIN,
/// which no test host here has, and "the table came back byte for byte" is
/// the whole point of this module. RssEthtool is the real one; RssRecorder in
/// net_rss_recorder.hpp is the double.
class RssControl
{
  public:
    RssControl() = default;
    virtual ~RssControl() = default;
    RssControl(RssControl const&) = delete;
    auto operator=(RssControl const&) -> RssControl& = delete;
    RssControl(RssControl&&) = delete;
    auto operator=(RssControl&&) -> RssControl& = delete;

    /// The table as the NIC reports it.
    [[nodiscard]] virtual auto indirection(std::string_view interface_name) -> StatusValue<RssIndirection> = 0;

    /// Write a table as given.
    [[nodiscard]] virtual auto set_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status = 0;

    /// Steer every bucket to one queue, returning the table as it was.
    [[nodiscard]] virtual auto steer_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection> = 0;
};

/// The RssControl that talks to a NIC, through ethtool's ioctls.
class RssEthtool final : public RssControl
{
  public:
    [[nodiscard]] auto indirection(std::string_view interface_name) -> StatusValue<RssIndirection> override
    {
        return rss_indirection(interface_name);
    }

    [[nodiscard]] auto set_indirection(std::string_view interface_name, std::span<uint32_t const> table) -> Status override
    {
        return set_rss_indirection(interface_name, table);
    }

    [[nodiscard]] auto steer_all(std::string_view interface_name, uint32_t queue_id) -> StatusValue<RssIndirection> override
    {
        return set_rss_indirection_all(interface_name, queue_id);
    }
};

/// Holds an interface steered to one RX queue, and puts the table back.
///
/// Make one with steer() and keep it for as long as the socket holds the
/// queue. Destruction restores; restore() does the same thing where the
/// caller wants to see the error, since a destructor has nobody to report to.
/// release() gives up the restore on purpose, for a dedicated appliance NIC
/// where the single-queue table IS the configuration.
///
/// Nothing is owed when the NIC was already steered where we wanted it: there
/// was no write, so there is nothing to undo, and the guard will not issue one
/// - a write can cost a link reset on some drivers.
class RssSteering
{
  public:
    /// A guard that owes nothing.
    RssSteering() = default;

    ~RssSteering();

    RssSteering(RssSteering&& other) noexcept;
    auto operator=(RssSteering&& other) noexcept -> RssSteering&;

    RssSteering(RssSteering const&) = delete;
    auto operator=(RssSteering const&) -> RssSteering& = delete;

    /// Steer `interface_name` to `queue_id` and remember the table as it was.
    ///
    /// Fails with whatever set_rss_indirection_all() fails with, and in
    /// particular `operation_not_supported` for a NIC with no RSS, which a
    /// caller reads as "nothing to steer" rather than as a fault.
    /// @param control The NIC to steer; must outlive the guard
    /// @param interface_name The interface to steer
    /// @param queue_id The RX queue every bucket should land on
    [[nodiscard]] static auto steer(RssControl& control, std::string_view interface_name, uint32_t queue_id)
        -> StatusValue<RssSteering>;

    /// Put the remembered table back. Success when there was nothing owed, so
    /// it is safe to call twice; on failure the guard keeps owing the restore
    /// and the destructor will try once more.
    ///
    /// Refuses with `std::errc::state_not_recoverable` when the NIC's table is
    /// no longer the size we read - its channel count changed underneath us,
    /// and the table we hold no longer describes it. Writing it anyway would
    /// be a guess at the new layout.
    [[nodiscard]] auto restore() -> Status;

    /// Give up the restore deliberately, leaving the NIC steered.
    auto release() noexcept -> void;

    /// Whether a restore is still owed.
    [[nodiscard]] auto holds_table() const noexcept -> bool { return control_ != nullptr; }

    /// The table as it was before the steer, while one is owed.
    [[nodiscard]] auto previous() const noexcept -> std::span<uint32_t const> { return previous_; }

    /// The interface this guard owes a restore on.
    [[nodiscard]] auto interface_name() const noexcept -> std::string_view { return interface_; }

  private:
    RssSteering(RssControl& control, std::string_view interface_name, RssIndirection previous);

    /// Whether the table we remember can still be written: success, or the
    /// reason not. Reads the NIC, so it is the first half of restore().
    [[nodiscard]] auto restorable() const -> Status;

    RssControl* control_{nullptr};
    std::string interface_;
    RssIndirection previous_;
};

}  // namespace statusbar::net
