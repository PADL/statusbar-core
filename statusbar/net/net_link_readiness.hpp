#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One interface's readiness for IPv4 traffic from rtnetlink, for a caller that waits out an adapter reset its own
/// qdisc change set off (igb and igc reset asynchronously when an offload switches the transmit mode): the carrier
/// (RTM_NEWLINK), the IPv4 addresses (RTM_NEWADDR, RTM_DELADDR) and the qdisc changes (RTM_NEWQDISC, RTM_DELQDISC).

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/net/net_carrier_watch.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <optional>
#    include <span>

namespace statusbar::net {

/// An IPv4 address in network order.
using Ipv4Octets = std::array<uint8_t, 4>;

/// One IPv4 address of an interface, as an RTM_NEWADDR (added) or an RTM_DELADDR (removed) reports it.
struct Ipv4AddressChange
{
    bool added{false};
    Ipv4Octets address{};  ///< IFA_LOCAL, else IFA_ADDRESS

    auto operator==(Ipv4AddressChange const&) const noexcept -> bool = default;
};

/// The change in one netlink message when it is an IPv4 RTM_NEWADDR or RTM_DELADDR of `ifindex` naming an address;
/// nullopt for any other message. bad_message when it is truncated or an attribute overruns.
[[nodiscard]] auto parse_ipv4_address(std::span<uint8_t const> message, int ifindex)
    -> StatusValue<std::optional<Ipv4AddressChange>>;

/// An RTM_GETADDR dump of every interface's IPv4 addresses into `out`: its length. Errors: the builder's when `out`
/// is too small.
[[nodiscard]] auto build_get_ipv4_addresses(std::span<uint8_t> out, uint32_t seq) -> StatusValue<size_t>;

/// Whether `message` is an RTM_NEWQDISC or RTM_DELQDISC of `ifindex`.
[[nodiscard]] auto is_qdisc_change(std::span<uint8_t const> message, int ifindex) noexcept -> bool;

/// One interface's link as the rtnetlink messages applied so far report it, checked against its last qdisc change.
/// Allocation-free.
class LinkReadiness
{
  public:
    /// The IPv4 addresses told apart; more are not tracked (the first ones still count as present).
    static constexpr size_t MAX_ADDRESSES = 8;

    /// Of @p ifindex, nothing reported yet.
    explicit LinkReadiness(int const ifindex) noexcept
        : ifindex_{ifindex}
    {}

    /// One message, read at @p now_ns: the interface's RTM_NEWLINK (true), an IPv4 address change or a qdisc change
    /// (false); any other message is ignored (false). Errors: bad_message for a malformed one (nothing changes),
    /// no_such_device for the interface's RTM_DELLINK.
    [[nodiscard]] auto apply(std::span<uint8_t const> message, int64_t now_ns) -> StatusValue<bool>;
    /// Forget the addresses, before a dump reports them afresh.
    void forget_addresses() noexcept { address_count_ = 0; }
    /// Notifications were lost at @p now_ns (an overrun): a qdisc change may have gone unseen, so one is assumed
    /// unless one was seen; a carrier loss seen still counts.
    void notifications_lost(int64_t now_ns) noexcept;

    /// The interface watched.
    [[nodiscard]] auto ifindex() const noexcept -> int { return ifindex_; }
    /// Whether an RTM_NEWLINK has been applied: until then there is no carrier.
    [[nodiscard]] auto reported() const noexcept -> bool { return baseline_down_count_.has_value(); }
    /// The carrier as last reported (IFLA_CARRIER, else IFF_LOWER_UP).
    [[nodiscard]] auto carrier() const noexcept -> bool { return link_.carrier; }
    /// Whether the carrier was lost since the last qdisc change: a report of none after one of a carrier, a down
    /// count past the one reported then, or no carrier at that change.
    [[nodiscard]] auto carrier_lost() const noexcept -> bool { return carrier_lost_; }
    /// Whether the interface has an IPv4 address.
    [[nodiscard]] auto has_ipv4() const noexcept -> bool { return address_count_ > 0; }
    /// When a qdisc of the interface was last added, changed or deleted, as read; nullopt for never.
    [[nodiscard]] auto last_qdisc_change_ns() const noexcept -> std::optional<int64_t> { return qdisc_change_ns_; }

  private:
    void apply_link(LinkCarrier const& link) noexcept;
    void apply_qdisc_change(int64_t now_ns) noexcept;
    void apply_address(Ipv4AddressChange const& change) noexcept;
    void remove_address(Ipv4Octets const& address) noexcept;

    int ifindex_;
    std::optional<uint32_t> baseline_down_count_{};  ///< the down count at the last qdisc change (or first report)
    LinkCarrier link_{};
    bool carrier_lost_{false};
    std::optional<int64_t> qdisc_change_ns_{};
    std::array<Ipv4Octets, MAX_ADDRESSES> addresses_{};
    size_t address_count_{0};
};

/// A NETLINK_ROUTE socket in the link, IPv4 address and tc groups feeding one interface's LinkReadiness. Opened
/// before a change, it holds every event from then on. Blocking use only (await_reset()); not a reactor Pollable.
class LinkWatch
{
  public:
    /// Watch @p ifindex; nothing happens before open().
    explicit LinkWatch(int const ifindex) noexcept
        : readiness_{ifindex}
    {}

    /// Open the socket, join the groups and ask for the link and the IPv4 addresses. Errors: socket(), bind() or
    /// sendto()'s errno.
    [[nodiscard]] auto open() -> Status;
    /// The netlink socket, -1 before open().
    [[nodiscard]] auto fd() const noexcept -> int { return fd_.get(); }
    /// Apply everything queued at @p now_ns, without blocking; after an overrun or a cut datagram, ask again. Read
    /// right after a change, so the change is timed. Errors: recv() or sendto()'s errno, a refused request
    /// (no_such_device for an unknown link), apply()'s.
    [[nodiscard]] auto read(int64_t now_ns) -> Status;
    /// The interface as read so far.
    [[nodiscard]] auto readiness() const noexcept -> LinkReadiness const& { return readiness_; }

  private:
    /// What one recv() did.
    enum class Received : uint8_t
    {
        drained,      ///< nothing queued
        delivered,    ///< a datagram applied
        interrupted,  ///< nothing read: a signal came first
        lost,         ///< an overrun or a cut datagram: notifications lost
    };

    /// One recv() into buffer_ (length_ octets when delivered).
    [[nodiscard]] auto receive() -> StatusValue<Received>;
    [[nodiscard]] auto deliver(std::span<uint8_t const> datagram, int64_t now_ns) -> Status;
    [[nodiscard]] auto deliver_one(std::span<uint8_t const> message, int64_t now_ns) -> Status;
    /// A message ending the address dump, done or refused.
    void track_dump(std::span<uint8_t const> message) noexcept;
    /// Notifications were lost: a change is assumed, and the link and the addresses are asked for again.
    void lose_notifications(int64_t now_ns) noexcept;
    /// Ask for the link, then for the IPv4 addresses (start_dump()).
    [[nodiscard]] auto request() -> Status;
    /// A wanted IPv4 address dump, once none runs; the addresses are forgotten until it reports them.
    [[nodiscard]] auto start_dump() -> Status;
    [[nodiscard]] auto send(std::span<uint8_t const> request) noexcept -> Status;

    FileDescriptor fd_{};
    LinkReadiness readiness_;
    bool lost_{false};                     ///< notifications lost since the last request
    bool dump_running_{false};             ///< an RTM_GETADDR dump not yet done
    bool dump_wanted_{false};              ///< an RTM_GETADDR dump to start once none runs
    size_t length_{0};                     ///< the datagram in buffer_, as received
    std::array<uint8_t, 32768> buffer_{};  ///< an RTM_NEWLINK with its statistics is a few KiB
};

/// No carrier loss this long after the last qdisc change: no reset came. Above linkwatch's one-second batching of
/// the carrier-loss notification.
inline constexpr int64_t RESET_SETTLE_NS = 2'000'000'000;
/// The whole wait for an adapter reset, from the last qdisc change.
inline constexpr int64_t RESET_TIMEOUT_NS = 30'000'000'000;

/// What a wait for an adapter reset waits for.
struct ResetWaitPolicy
{
    /// The link is back only with an IPv4 address too: for an interface that has one, where a network manager
    /// may withdraw it with the carrier.
    bool ipv4{false};
};

/// Where a wait for an adapter reset stands.
enum class ResetWaitState : uint8_t
{
    waiting,    ///< not settled yet
    unchanged,  ///< no qdisc changed: nothing to wait for
    no_reset,   ///< qdiscs changed, but no carrier loss within the settle time
    ready,      ///< the carrier was lost and is back, with an IPv4 address when the policy asks
    timed_out,  ///< the carrier was lost and is not back within the timeout
};

/// Where a wait stands at @p now_ns, as `link` reports the interface.
[[nodiscard]] auto reset_wait_state(LinkReadiness const& link, ResetWaitPolicy const& policy, int64_t now_ns) noexcept
    -> ResetWaitState;

/// Block on `watch` (open, and opened before the change) until reset_wait_state() is no longer waiting, on the
/// monotonic_ns() clock. Errors: read()'s, poll()'s errno (EINTR included: a signal ends the wait).
[[nodiscard]] auto await_reset(LinkWatch& watch, ResetWaitPolicy const& policy) -> StatusValue<ResetWaitState>;

}  // namespace statusbar::net

#endif  // __linux__
