// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_carrier_watch.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/net/net_posix_util.hpp"
#    include "statusbar/net/net_socket.hpp"

#    include <array>
#    include <cerrno>
#    include <cstddef>
#    include <system_error>

#    include <linux/if_link.h>
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>

namespace statusbar::net {

namespace {

using netlink::bad_message;
using netlink::load;

constexpr size_t LINK_HEADER = netlink::MESSAGE_HEADER + sizeof(ifinfomsg);
/// The RTM_GETLINK's sequence number: the watch has one request outstanding at most.
constexpr uint32_t REQUEST_SEQ = 1;
/// IFF_LOWER_UP (linux/if.h, which clashes with the libc <net/if.h> others include).
constexpr uint32_t LOWER_UP = 1U << 16;
static_assert(
    sizeof(ifinfomsg) == 16 && offsetof(ifinfomsg, ifi_family) == 0 && offsetof(ifinfomsg, ifi_index) == 4 &&
    offsetof(ifinfomsg, ifi_flags) == 8);

/// One link attribute into `link` (and `carrier` when IFLA_CARRIER is sent).
[[nodiscard]] auto parse_link_attribute(
    uint16_t const type, std::span<uint8_t const> const payload, LinkCarrier& link, std::optional<bool>& carrier) -> Status
{
    auto const masked = type & netlink::ATTRIBUTE_TYPE_MASK;
    if (masked == IFLA_CARRIER && payload.size() == 1) {
        carrier = payload[0] != 0;
        return success();
    }
    if (masked == IFLA_CARRIER_DOWN_COUNT && payload.size() == sizeof(uint32_t)) {
        link.down_count = load<uint32_t>(payload, 0);
        return success();
    }
    bool const malformed = masked == IFLA_CARRIER || masked == IFLA_CARRIER_DOWN_COUNT;
    return malformed ? Status{failure(bad_message())} : success();
}

/// The attributes of an RTM_NEWLINK `message` into a LinkCarrier, `flags` its ifi_flags.
[[nodiscard]] auto link_carrier(std::span<uint8_t const> const message, uint32_t const flags) -> StatusValue<LinkCarrier>
{
    LinkCarrier link{};
    std::optional<bool> carrier;
    auto const status =
        netlink::walk_attributes(message.subspan(LINK_HEADER), [&](uint16_t type, std::span<uint8_t const> payload) {
            return parse_link_attribute(type, payload, link, carrier);
        });
    link.carrier = carrier.value_or((flags & LOWER_UP) != 0);
    return status ? StatusValue<LinkCarrier>{link} : failure(status.error());
}

/// Whether @p error (a negative errno) is momentary: the request is not refused for good.
[[nodiscard]] constexpr auto transient_error(int32_t const error) noexcept -> bool
{
    return error == -ENOBUFS || error == -EAGAIN || error == -EBUSY || error == -EINTR;
}

/// True for an NLMSG_ERROR answering our RTM_GETLINK with an error that lasts (ENODEV: no such link).
[[nodiscard]] auto is_error_reply(std::span<uint8_t const> const message) noexcept -> bool
{
    if (message.size() < netlink::MESSAGE_HEADER + sizeof(int32_t) ||
        load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) != NLMSG_ERROR) {
        return false;
    }
    auto const error = load<int32_t>(message, netlink::MESSAGE_HEADER);
    return load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_seq)) == REQUEST_SEQ && error != 0 && !transient_error(error);
}

/// True for an RTM_DELLINK of @p ifindex: the link is gone.
[[nodiscard]] auto is_link_removed(std::span<uint8_t const> const message, int const ifindex) noexcept -> bool
{
    return message.size() >= LINK_HEADER && load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) == RTM_DELLINK &&
        load<int32_t>(message, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_index)) == ifindex;
}

}  // namespace

auto parse_link_carrier(std::span<uint8_t const> const message, int const ifindex) -> StatusValue<std::optional<LinkCarrier>>
{
    if (message.size() < netlink::MESSAGE_HEADER || load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) != RTM_NEWLINK) {
        return std::optional<LinkCarrier>{};
    }
    auto const length = load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_len));
    if (length < LINK_HEADER || length > message.size()) {
        return failure(bad_message());
    }
    auto const body = message.first(length);
    // Another family's view of the link (AF_BRIDGE for a bridge port) carries no carrier count.
    if (load<int32_t>(body, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_index)) != ifindex ||
        body[netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_family)] != AF_UNSPEC) {
        return std::optional<LinkCarrier>{};
    }
    return link_carrier(body, load<uint32_t>(body, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_flags)))
        .transform([](LinkCarrier const& link) { return std::optional{link}; });
}

auto build_get_link(std::span<uint8_t> const out, int const ifindex, uint32_t const seq) -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the RTM_GETLINK request, field by field
    if (ifindex <= 0) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, LINK_HEADER, RTM_GETLINK, NLM_F_REQUEST, seq);
    // ifinfomsg: family AF_UNSPEC, pad, type 0, the index, flags 0, change 0.
    b.append(uint8_t{AF_UNSPEC})
        .append(uint8_t{0})
        .append(uint16_t{0})
        .append(int32_t{ifindex})
        .append(uint32_t{0})
        .append(uint32_t{0});
    return netlink::finish(b, LINK_HEADER);
}

auto CarrierWatch::open() -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    sockaddr_nl const local{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = RTMGRP_LINK};
    if (::bind(fd.get(), sockaddr_cast(local), sizeof(local)) < 0) {
        return failure(errno_code());
    }
    fd_ = std::move(fd);
    return request_link();
}

void CarrierWatch::on_ready(int64_t /*now_ns*/)
{
    while (!failed_) {
        // MSG_TRUNC: the message's whole length, so one longer than the buffer is known to be cut.
        auto const received = ::recv(fd_.get(), buffer_.data(), buffer_.size(), MSG_DONTWAIT | MSG_TRUNC);
        if (received >= 0) {
            on_received(static_cast<size_t>(received));
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            resync();
            return;
        }
        // An overrun (ENOBUFS) lost notifications: once the queue is drained, the link is asked for again.
        resync_ = resync_ || errno == ENOBUFS;
        failed_ = errno != ENOBUFS && errno != EINTR;
    }
}

void CarrierWatch::on_received(size_t const length)
{
    if (length > buffer_.size()) {
        // Cut short (a link with many VFs): lost, as on an overrun. A resync cut short too finishes the watch.
        failed_ = truncated_;
        resync_ = truncated_ = true;
        return;
    }
    deliver(std::span<uint8_t const>{buffer_.data(), length});
}

void CarrierWatch::resync()
{
    if (resync_) {
        resync_ = false;
        failed_ = !request_link().has_value();
    }
}

auto CarrierWatch::request_link() noexcept -> Status
{
    std::array<uint8_t, LINK_HEADER> request{};
    return build_get_link(request, ifindex_, REQUEST_SEQ).and_then([&](size_t const length) -> Status {
        sockaddr_nl const kernel{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
        bool const sent = ::sendto(fd_.get(), request.data(), length, 0, sockaddr_cast(kernel), sizeof(kernel)) >= 0;
        return sent ? success() : Status{failure(errno_code())};
    });
}

void CarrierWatch::deliver(std::span<uint8_t const> const datagram)
{
    for (size_t at = 0; at + netlink::MESSAGE_HEADER <= datagram.size();) {
        auto const length = load<uint32_t>(datagram, at);
        if (length < netlink::MESSAGE_HEADER || length > datagram.size() - at) {
            return;
        }
        report(datagram.subspan(at, length));
        at += netlink::align4(length);
    }
}

void CarrierWatch::report(std::span<uint8_t const> const message)
{
    if (auto const link = parse_link_carrier(message, ifindex_); link && *link) {
        truncated_ = false;
        on_change_(**link);
        return;
    }
    if (is_link_removed(message, ifindex_)) {
        on_change_(LinkCarrier{});  // no carrier, and nothing more to watch
        failed_ = true;
        return;
    }
    failed_ = failed_ || is_error_reply(message);
}

}  // namespace statusbar::net

#endif  // __linux__
