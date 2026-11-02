// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_carrier_watch.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/net/net_posix_util.hpp"

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
/// IFF_LOWER_UP (linux/if.h, which clashes with the libc <net/if.h> others include).
constexpr uint32_t LOWER_UP = 1U << 16;
static_assert(sizeof(ifinfomsg) == 16 && offsetof(ifinfomsg, ifi_index) == 4 && offsetof(ifinfomsg, ifi_flags) == 8);

/// One link attribute into `link` (and `carrier` when IFLA_CARRIER is sent).
[[nodiscard]] auto take_link_attribute(
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
            return take_link_attribute(type, payload, link, carrier);
        });
    link.carrier = carrier.value_or((flags & LOWER_UP) != 0);
    return status ? StatusValue<LinkCarrier>{link} : failure(status.error());
}

[[nodiscard]] auto errno_code() noexcept -> std::error_code
{
    return {errno, std::system_category()};
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
    if (load<int32_t>(body, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_index)) != ifindex) {
        return std::optional<LinkCarrier>{};
    }
    return link_carrier(body, load<uint32_t>(body, netlink::MESSAGE_HEADER + offsetof(ifinfomsg, ifi_flags)))
        .transform([](LinkCarrier const& link) { return std::optional{link}; });
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
    return success();
}

void CarrierWatch::on_ready(int64_t /*now_ns*/)
{
    for (;;) {
        auto const received = ::recv(fd_.get(), buffer_.data(), buffer_.size(), MSG_DONTWAIT);
        if (received >= 0) {
            deliver(std::span<uint8_t const>{buffer_.data(), static_cast<size_t>(received)});
            continue;
        }
        if (errno != ENOBUFS && errno != EINTR) {
            failed_ = errno != EAGAIN && errno != EWOULDBLOCK;
            return;
        }
    }
}

void CarrierWatch::deliver(std::span<uint8_t const> const datagram)
{
    for (size_t at = 0; at + netlink::MESSAGE_HEADER <= datagram.size();) {
        auto const length = load<uint32_t>(datagram, at);
        if (length < netlink::MESSAGE_HEADER || length > datagram.size() - at) {
            return;
        }
        if (auto const link = parse_link_carrier(datagram.subspan(at, length), ifindex_); link && *link) {
            on_change_(**link);
        }
        at += netlink::align4(length);
    }
}

}  // namespace statusbar::net

#endif  // __linux__
