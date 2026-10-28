// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netlink.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_posix_util.hpp"

#    include <algorithm>
#    include <cerrno>
#    include <utility>

#    include <linux/netlink.h>
#    include <sys/socket.h>
#    include <sys/time.h>

namespace statusbar::net::netlink {

static_assert(MESSAGE_HEADER == sizeof(nlmsghdr) && ATTRIBUTE_HEADER == sizeof(nlattr));
static_assert(offsetof(nlmsghdr, nlmsg_type) == 4 && offsetof(nlmsghdr, nlmsg_flags) == 6);
static_assert(offsetof(nlmsghdr, nlmsg_seq) == 8 && offsetof(nlmsghdr, nlmsg_pid) == 12);
static_assert(
    ATTRIBUTE_TYPE_MASK == static_cast<uint16_t>(NLA_TYPE_MASK) && align4(5) == NLMSG_ALIGN(5) && align4(5) == NLA_ALIGN(5));

namespace {

[[nodiscard]] auto errno_code() noexcept -> std::error_code
{
    return {errno, std::system_category()};
}

/// The extended ack's NLMSGERR_ATTR_MSG after the struct nlmsgerr (capped or not) of `message`.
void read_ext_ack_message(
    std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text)
{
    size_t const skip = (flags & NLM_F_CAPPED) != 0 ? sizeof(nlmsgerr) : sizeof(nlmsgerr) + request_size - MESSAGE_HEADER;
    auto const found = find_attribute(message.subspan(std::min(MESSAGE_HEADER + align4(skip), message.size())), NLMSGERR_ATTR_MSG);
    if (found && *found) {
        auto const msg = without_trailing_nuls(**found);
        text.assign(msg.begin(), msg.end());
    }
}

/// Bind netlink socket `fd` to a port id the kernel assigns: that id.
[[nodiscard]] auto bind_port_id(int const fd) noexcept -> StatusValue<uint32_t>
{
    sockaddr_nl const local{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
    if (::bind(fd, sockaddr_cast(local), sizeof(local)) < 0) {
        return failure(errno_code());
    }
    sockaddr_nl bound{};
    socklen_t bound_size = sizeof(bound);
    if (::getsockname(fd, sockaddr_cast(bound), &bound_size) < 0) {
        return failure(errno_code());
    }
    return bound.nl_pid;
}

/// Set up netlink socket `fd` (extended, capped acks; a 1 s receive timeout) and bind it: its port id.
[[nodiscard]] auto configure_socket(int const fd) noexcept -> StatusValue<uint32_t>
{
    // Extended acks carry the kernel's reason; capped acks keep our request out of the reply. Both best effort.
    int const on = 1;
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &on, sizeof(on));
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof(on));
    timeval const timeout{.tv_sec = 1, .tv_usec = 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return failure(errno_code());
    }
    return bind_port_id(fd);
}

}  // namespace

void put_header(BufferSerializerBuilder& b, size_t const length, uint16_t const type, uint16_t const flags, uint32_t const seq)
{
    b.append(static_cast<uint32_t>(length)).append(type).append(flags).append(seq).append(uint32_t{0});
}

auto finish(BufferSerializerBuilder const& b, size_t const expected) -> StatusValue<size_t>
{
    if (b.error()) {
        return failure(b.error());
    }
    if (b.position() != expected) {
        return failure(std::make_error_code(std::errc::message_size));
    }
    return expected;
}

auto find_attribute(std::span<uint8_t const> const attributes, uint16_t const type)
    -> StatusValue<std::optional<std::span<uint8_t const>>>
{
    for (size_t at = 0; at + ATTRIBUTE_HEADER <= attributes.size();) {
        auto const len = load<uint16_t>(attributes, at);
        if (len < ATTRIBUTE_HEADER || at + len > attributes.size()) {
            return failure(bad_message());
        }
        if ((load<uint16_t>(attributes, at + 2) & ATTRIBUTE_TYPE_MASK) == type) {
            return attributes.subspan(at + ATTRIBUTE_HEADER, len - ATTRIBUTE_HEADER);
        }
        at += align4(len);
    }
    return std::nullopt;
}

auto without_trailing_nuls(std::span<uint8_t const> const bytes) noexcept -> std::span<uint8_t const>
{
    size_t n = bytes.size();
    while (n > 0 && bytes[n - 1] == 0) {
        --n;
    }
    return bytes.first(n);
}

auto ack_status(std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text)
    -> Status
{
    if (message.size() < MESSAGE_HEADER + sizeof(nlmsgerr)) {
        return failure(bad_message());
    }
    auto const error = load<int32_t>(message, MESSAGE_HEADER);
    if (error != 0 && (flags & NLM_F_ACK_TLVS) != 0) {
        read_ext_ack_message(message, flags, request_size, text);
    }
    return error == 0 ? success() : failure(std::error_code{-error, std::system_category()});
}

auto dump_status(std::span<uint8_t const> const message) noexcept -> Status
{
    int32_t const error = message.size() >= MESSAGE_HEADER + sizeof(int32_t) ? load<int32_t>(message, MESSAGE_HEADER) : 0;
    return error == 0 ? success() : failure(std::error_code{-error, std::system_category()});
}

//
// Socket
//

auto Socket::open(int const protocol) noexcept -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    return configure_socket(fd.get()).transform([&](uint32_t const portid) {
        portid_ = portid;
        fd_ = std::move(fd);
    });
}

auto Socket::send(std::span<uint8_t const> const request) noexcept -> Status
{
    sockaddr_nl const kernel{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
    if (::sendto(fd_.get(), request.data(), request.size(), 0, sockaddr_cast(kernel), sizeof(kernel)) < 0) {
        return failure(errno_code());
    }
    return success();
}

auto Socket::receive(std::span<uint8_t> const buffer) noexcept -> StatusValue<std::span<uint8_t const>>
{
    for (;;) {
        // MSG_TRUNC: the length of the datagram even when it did not fit.
        ssize_t const received = ::recv(fd_.get(), buffer.data(), buffer.size(), MSG_TRUNC);
        if (received >= 0 && static_cast<size_t>(received) > buffer.size()) {
            return failure(std::make_error_code(std::errc::message_size));
        }
        if (received >= 0) {
            return std::span<uint8_t const>{buffer.data(), static_cast<size_t>(received)};
        }
        if (errno != EINTR) {
            return failure(errno == EAGAIN || errno == EWOULDBLOCK ? std::make_error_code(std::errc::timed_out) : errno_code());
        }
    }
}

}  // namespace statusbar::net::netlink

#endif  // __linux__
