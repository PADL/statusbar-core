// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_link_readiness.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/net/net_message_reactor.hpp"
#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/net/net_posix_util.hpp"
#    include "statusbar/net/net_socket.hpp"

#    include <poll.h>

#    include <algorithm>
#    include <cerrno>
#    include <climits>
#    include <cstddef>
#    include <system_error>
#    include <utility>

#    include <linux/if_addr.h>
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>

namespace statusbar::net {

namespace {

using netlink::bad_message;
using netlink::load;

constexpr size_t ADDRESS_HEADER = netlink::MESSAGE_HEADER + sizeof(ifaddrmsg);
constexpr size_t QDISC_HEADER = netlink::MESSAGE_HEADER + sizeof(tcmsg);
static_assert(
    sizeof(ifaddrmsg) == 8 && offsetof(ifaddrmsg, ifa_family) == 0 && offsetof(ifaddrmsg, ifa_index) == 4 && sizeof(tcmsg) == 20 &&
    offsetof(tcmsg, tcm_ifindex) == 4);

/// The requests' sequence numbers: the watch has one of each outstanding at most.
constexpr uint32_t LINK_SEQ = 1;
constexpr uint32_t ADDRESSES_SEQ = 2;

[[nodiscard]] auto message_type(std::span<uint8_t const> const message) noexcept -> uint16_t
{
    return load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type));
}

/// `message` cut to its nlmsg_len, which must hold `header` octets; bad_message otherwise.
[[nodiscard]] auto framed(std::span<uint8_t const> const message, size_t const header) -> StatusValue<std::span<uint8_t const>>
{
    auto const length = load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_len));
    if (length < header || length > message.size()) {
        return failure(bad_message());
    }
    return message.first(length);
}

/// One address attribute into `local` (IFA_LOCAL) or `address` (IFA_ADDRESS); bad_message unless it holds 4 octets.
[[nodiscard]] auto parse_address_attribute(
    uint16_t const type,
    std::span<uint8_t const> const payload,
    std::optional<Ipv4Octets>& local,
    std::optional<Ipv4Octets>& address) -> Status
{
    auto const masked = type & netlink::ATTRIBUTE_TYPE_MASK;
    if (masked != IFA_LOCAL && masked != IFA_ADDRESS) {
        return success();
    }
    if (payload.size() != sizeof(Ipv4Octets)) {
        return failure(bad_message());
    }
    std::ranges::copy(payload, (masked == IFA_LOCAL ? local : address).emplace().begin());
    return success();
}

/// IFA_LOCAL, else IFA_ADDRESS (a point-to-point peer's when both are sent), of an IPv4 address message's attributes.
[[nodiscard]] auto address_of(std::span<uint8_t const> const attributes) -> StatusValue<std::optional<Ipv4Octets>>
{
    std::optional<Ipv4Octets> local;
    std::optional<Ipv4Octets> address;
    auto const status = netlink::walk_attributes(attributes, [&](uint16_t type, std::span<uint8_t const> payload) {
        return parse_address_attribute(type, payload, local, address);
    });
    return status ? StatusValue<std::optional<Ipv4Octets>>{local ? local : address} : failure(status.error());
}

/// The change a framed IPv4 address message of `ifindex` reports; nullopt for another family or interface.
[[nodiscard]] auto address_change(std::span<uint8_t const> const body, int const ifindex)
    -> StatusValue<std::optional<Ipv4AddressChange>>
{
    if (body[netlink::MESSAGE_HEADER + offsetof(ifaddrmsg, ifa_family)] != AF_INET ||
        load<uint32_t>(body, netlink::MESSAGE_HEADER + offsetof(ifaddrmsg, ifa_index)) != static_cast<uint32_t>(ifindex)) {
        return std::optional<Ipv4AddressChange>{};
    }
    bool const added = message_type(body) == RTM_NEWADDR;
    return address_of(body.subspan(ADDRESS_HEADER)).transform([added](std::optional<Ipv4Octets> const& address) {
        return address.transform(
            [added](Ipv4Octets const& octets) { return Ipv4AddressChange{.added = added, .address = octets}; });
    });
}

[[nodiscard]] auto message_seq(std::span<uint8_t const> const message) noexcept -> uint32_t
{
    return load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_seq));
}

/// The errno of an NLMSG_ERROR refusing one of the watch's requests, else 0.
[[nodiscard]] auto refusal(std::span<uint8_t const> const message) noexcept -> int
{
    if (message.size() < netlink::MESSAGE_HEADER + sizeof(int32_t) || message_type(message) != NLMSG_ERROR) {
        return 0;
    }
    auto const error = load<int32_t>(message, netlink::MESSAGE_HEADER);
    bool const ours = message_seq(message) == LINK_SEQ || message_seq(message) == ADDRESSES_SEQ;
    return ours && error < 0 ? -error : 0;
}

/// Whether `bytes` start with an RTM_NEWLINK of @p ifindex (as parse_link_carrier() reads one), whole or cut.
[[nodiscard]] auto starts_with_link_report(std::span<uint8_t const> const bytes, int const ifindex) noexcept -> bool
{
    return bytes.size() >= netlink::MESSAGE_HEADER + sizeof(ifinfomsg) && message_type(bytes) == RTM_NEWLINK &&
        bytes[netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_family)] == AF_UNSPEC &&
        load<int32_t>(bytes, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_index)) == ifindex;
}

}  // namespace

auto parse_ipv4_address(std::span<uint8_t const> const message, int const ifindex) -> StatusValue<std::optional<Ipv4AddressChange>>
{
    if (message.size() < netlink::MESSAGE_HEADER ||
        (message_type(message) != RTM_NEWADDR && message_type(message) != RTM_DELADDR)) {
        return std::optional<Ipv4AddressChange>{};
    }
    return framed(message, ADDRESS_HEADER).and_then([ifindex](std::span<uint8_t const> const body) {
        return address_change(body, ifindex);
    });
}

auto build_get_ipv4_addresses(std::span<uint8_t> const out, uint32_t const seq) -> StatusValue<size_t>
{
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, ADDRESS_HEADER, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq);
    // ifaddrmsg: family AF_INET, prefix length, flags and scope 0, index 0 (the kernel dumps every interface's).
    b.append(uint8_t{AF_INET}).append(uint8_t{0}).append(uint8_t{0}).append(uint8_t{0}).append(uint32_t{0});
    return netlink::finish(b, ADDRESS_HEADER);
}

auto is_qdisc_change(std::span<uint8_t const> const message, int const ifindex) noexcept -> bool
{
    if (message.size() < QDISC_HEADER || (message_type(message) != RTM_NEWQDISC && message_type(message) != RTM_DELQDISC)) {
        return false;
    }
    return load<int32_t>(message, netlink::MESSAGE_HEADER + offsetof(tcmsg, tcm_ifindex)) == ifindex;
}

auto LinkReadiness::apply(std::span<uint8_t const> const message, int64_t const now_ns) -> StatusValue<bool>
{
    auto const link = parse_link_carrier(message, ifindex_);
    if (!link || *link) {
        return link.transform([this](std::optional<LinkCarrier> const& reported) {
            apply_link(*reported);
            return true;
        });
    }
    auto const address = parse_ipv4_address(message, ifindex_);
    if (!address || *address) {
        return address.transform([this](std::optional<Ipv4AddressChange> const& change) {
            apply_address(*change);
            return false;
        });
    }
    if (is_qdisc_change(message, ifindex_)) {
        apply_qdisc_change(now_ns);
    }
    return is_link_removed(message, ifindex_) ? StatusValue<bool>{failure(std::make_error_code(std::errc::no_such_device))}
                                              : StatusValue<bool>{false};
}

void LinkReadiness::notifications_lost(int64_t const now_ns) noexcept
{
    // Only the change is assumed: a carrier loss already seen still counts.
    qdisc_change_ns_ = qdisc_change_ns_.value_or(now_ns);
}

void LinkReadiness::apply_link(LinkCarrier const& link) noexcept
{
    if (!baseline_down_count_) {
        baseline_down_count_ = link.down_count;
    }
    carrier_lost_ = carrier_lost_ || (link_.carrier && !link.carrier) || link.down_count > *baseline_down_count_;
    link_ = link;
}

void LinkReadiness::apply_qdisc_change(int64_t const now_ns) noexcept
{
    // A reset is checked against the latest change only: one before it does not count, but a carrier down now does.
    qdisc_change_ns_ = now_ns;
    baseline_down_count_ = baseline_down_count_.transform([this](uint32_t) { return link_.down_count; });
    carrier_lost_ = reported() && !link_.carrier;
}

void LinkReadiness::apply_address(Ipv4AddressChange const& change) noexcept
{
    remove_address(change.address);
    if (change.added && address_count_ < MAX_ADDRESSES) {
        addresses_[address_count_++] = change.address;
    }
}

void LinkReadiness::remove_address(Ipv4Octets const& address) noexcept
{
    auto const known = std::span{addresses_}.first(address_count_);
    if (auto const at = std::ranges::find(known, address); at != known.end()) {
        *at = known.back();
        --address_count_;
    }
}

auto LinkWatch::open() -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    sockaddr_nl const local{
        .nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_TC};
    if (::bind(fd.get(), sockaddr_cast(local), sizeof(local)) < 0) {
        return failure(errno_code());
    }
    fd_ = std::move(fd);
    return request();
}

auto LinkWatch::read(int64_t const now_ns) -> Status
{
    for (;;) {
        auto const received = receive();
        if (!received) {
            return forward_failure(received);
        }
        if (*received == Received::drained) {
            return std::exchange(lost_, false) ? request() : start_dump();
        }
        if (*received == Received::lost) {
            lose_notifications(now_ns);
        }
        if (*received == Received::delivered) {
            if (auto const status = deliver(std::span<uint8_t const>{buffer_.data(), length_}, now_ns); !status) {
                return status;
            }
        }
    }
}

void LinkWatch::lose_notifications(int64_t const now_ns) noexcept
{
    readiness_.notifications_lost(now_ns);
    lost_ = true;
}

auto LinkWatch::receive() -> StatusValue<Received>
{
    // MSG_TRUNC: the datagram's whole length, so one longer than the buffer is known to be cut.
    auto const received = ::recv(fd_.get(), buffer_.data(), buffer_.size(), MSG_DONTWAIT | MSG_TRUNC);
    if (received < 0) {
        int const error = errno;
        return error == EAGAIN || error == EWOULDBLOCK ? StatusValue<Received>{Received::drained}
            : error == EINTR                           ? StatusValue<Received>{Received::interrupted}
            : error == ENOBUFS                         ? StatusValue<Received>{Received::lost}
                                                       : failure(errno_code(error));
    }
    length_ = static_cast<size_t>(received);
    return length_ > buffer_.size() ? cut() : StatusValue<Received>{Received::delivered};
}

auto LinkWatch::cut() noexcept -> StatusValue<Received>
{
    // Cut short (a link with many VFs): lost, as on an overrun. Only our link's report cut again after asking
    // is refused: another interface's is cut whatever the buffer, and holds nothing of ours.
    if (!starts_with_link_report(std::span<uint8_t const>{buffer_}, readiness_.ifindex())) {
        return Received::lost;
    }
    return std::exchange(cut_, true) && asked_after_cut_
        ? StatusValue<Received>{failure(std::make_error_code(std::errc::message_size))}
        : StatusValue<Received>{Received::lost};
}

auto LinkWatch::deliver(std::span<uint8_t const> const datagram, int64_t const now_ns) -> Status
{
    auto const result = netlink::walk_messages(datagram, [&](std::span<uint8_t const> const message) -> std::optional<Status> {
        auto const status = deliver_one(message, now_ns);
        return status ? std::nullopt : std::optional<Status>{status};
    });
    return result.value_or(success());
}

auto LinkWatch::deliver_one(std::span<uint8_t const> const message, int64_t const now_ns) -> Status
{
    track_dump(message);
    auto const error = refusal(message);
    if (error != 0 && !netlink::transient_error(error)) {
        return failure(errno_code(error));
    }
    if (error != 0) {
        lose_notifications(now_ns);  // asked again once drained
        return success();
    }
    return apply(message, now_ns);
}

auto LinkWatch::apply(std::span<uint8_t const> const message, int64_t const now_ns) -> Status
{
    auto const applied = readiness_.apply(message, now_ns);
    if (applied && *applied) {
        cut_ = asked_after_cut_ = false;
    }
    return applied ? success() : Status{failure(applied.error())};
}

void LinkWatch::track_dump(std::span<uint8_t const> const message) noexcept
{
    bool const ends_dump = message_seq(message) == ADDRESSES_SEQ && (message_type(message) == NLMSG_DONE || refusal(message) != 0);
    dump_running_ = dump_running_ && !ends_dump;
}

auto LinkWatch::request() -> Status
{
    std::array<uint8_t, netlink::MESSAGE_HEADER + sizeof(ifinfomsg)> link{};
    asked_after_cut_ = cut_;
    dump_wanted_ = true;
    return build_get_link(link, readiness_.ifindex(), LINK_SEQ)
        .and_then([&](size_t const length) { return send(std::span{link}.first(length)); })
        .and_then([this] { return start_dump(); });
}

auto LinkWatch::start_dump() -> Status
{
    if (dump_running_ || !dump_wanted_) {
        return success();  // a running dump may have passed the interface: another follows it
    }
    std::array<uint8_t, ADDRESS_HEADER> addresses{};
    readiness_.forget_addresses();
    dump_running_ = true;
    dump_wanted_ = false;
    return build_get_ipv4_addresses(addresses, ADDRESSES_SEQ).and_then([&](size_t const length) {
        return send(std::span{addresses}.first(length));
    });
}

auto LinkWatch::send(std::span<uint8_t const> const request) noexcept -> Status
{
    sockaddr_nl const kernel{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
    bool const sent = ::sendto(fd_.get(), request.data(), request.size(), 0, sockaddr_cast(kernel), sizeof(kernel)) >= 0;
    return sent ? success() : Status{failure(errno_code())};
}

auto reset_wait_state(LinkReadiness const& link, ResetWaitPolicy const& policy, int64_t const now_ns) noexcept -> ResetWaitState
{
    auto const changed_ns = link.last_qdisc_change_ns();
    if (!changed_ns) {
        return ResetWaitState::unchanged;
    }
    if (link.carrier_lost() && link.carrier() && (!policy.ipv4 || link.has_ipv4())) {
        return ResetWaitState::ready;
    }
    if (!link.carrier_lost() && now_ns - *changed_ns >= policy.settle_ns) {
        return ResetWaitState::no_reset;
    }
    return now_ns - *changed_ns >= policy.timeout_ns ? ResetWaitState::timed_out : ResetWaitState::waiting;
}

namespace {

/// How long until reset_wait_state() may change without a message: the settle time, else the timeout.
[[nodiscard]] auto poll_timeout_ms(LinkReadiness const& link, ResetWaitPolicy const& policy, int64_t const now_ns) noexcept -> int
{
    int64_t const elapsed_ns = now_ns - link.last_qdisc_change_ns().value_or(now_ns);
    int64_t const bound_ns = !link.carrier_lost() && elapsed_ns < policy.settle_ns ? policy.settle_ns : policy.timeout_ns;
    int64_t const left_ms = (bound_ns - elapsed_ns + 999'999) / 1'000'000;
    return static_cast<int>(std::clamp<int64_t>(left_ms, 0, INT_MAX));
}

}  // namespace

auto await_reset(LinkWatch& watch, ResetWaitPolicy const& policy) -> StatusValue<ResetWaitState>
{
    for (;;) {
        int64_t const now_ns = monotonic_ns();
        if (auto const read = watch.read(now_ns); !read) {
            return forward_failure(read);
        }
        if (auto const state = reset_wait_state(watch.readiness(), policy, now_ns); state != ResetWaitState::waiting) {
            return state;
        }
        pollfd ready{.fd = watch.fd(), .events = POLLIN, .revents = 0};
        if (::poll(&ready, 1, poll_timeout_ms(watch.readiness(), policy, now_ns)) < 0) {
            return failure(errno_code());
        }
    }
}

}  // namespace statusbar::net

#endif  // __linux__
