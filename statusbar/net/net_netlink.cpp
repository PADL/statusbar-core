// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netlink.hpp"

#include <algorithm>
#include <cstddef>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"
#    include "statusbar/net/net_socket.hpp"

#    include <linux/netlink.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#endif

namespace statusbar::net::netlink {

#if defined(__linux__)
// The constants spelled in the header, against the UAPI they mirror.
static_assert(MESSAGE_HEADER == sizeof(nlmsghdr) && ATTRIBUTE_HEADER == sizeof(nlattr) && ERROR_PAYLOAD == sizeof(nlmsgerr));
static_assert(OFFSET_LENGTH == offsetof(nlmsghdr, nlmsg_len) && OFFSET_TYPE == offsetof(nlmsghdr, nlmsg_type));
static_assert(OFFSET_FLAGS == offsetof(nlmsghdr, nlmsg_flags) && OFFSET_SEQUENCE == offsetof(nlmsghdr, nlmsg_seq));
static_assert(OFFSET_PORT_ID == offsetof(nlmsghdr, nlmsg_pid) && TYPE_MASK == static_cast<uint16_t>(NLA_TYPE_MASK));
static_assert(ATTRIBUTE_NESTED == NLA_F_NESTED);
static_assert(FLAG_REQUEST == NLM_F_REQUEST && FLAG_MULTI == NLM_F_MULTI && FLAG_ACK == NLM_F_ACK);
static_assert(FLAG_DUMP == NLM_F_DUMP && FLAG_CAPPED == NLM_F_CAPPED && FLAG_ACK_TLVS == NLM_F_ACK_TLVS);
static_assert(TYPE_ERROR == NLMSG_ERROR && TYPE_DONE == NLMSG_DONE && TYPE_MIN_FAMILY == NLMSG_MIN_TYPE);
static_assert(ERROR_ATTR_MSG == NLMSGERR_ATTR_MSG && align4(5) == NLMSG_ALIGN(5) && align4(8) == NLA_ALIGN(8));
#endif

namespace {

/// The errno `error` carries (a negative errno, as struct nlmsgerr stores it)
/// as a system error; success when it is 0.
[[nodiscard]] auto status_of(int32_t const error) noexcept -> Status
{
    if (error == 0) {
        return success();
    }
    return failure(std::error_code{-error, std::system_category()});
}

/// Where an NLMSG_ERROR's extended-ack attributes start: after the struct
/// nlmsgerr, and after the echoed request unless the kernel capped it.
[[nodiscard]] constexpr auto ack_attributes_at(uint16_t const flags, size_t const request_size) noexcept -> size_t
{
    size_t const echoed = (flags & FLAG_CAPPED) != 0 ? 0 : request_size - std::min(request_size, MESSAGE_HEADER);
    return MESSAGE_HEADER + align4(ERROR_PAYLOAD + echoed);
}

/// The kernel's reason in an NLMSG_ERROR, when it gave one, assigned to `text`.
void read_ack_text(std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text)
{
    size_t const at = std::min(ack_attributes_at(flags, request_size), message.size());
    auto const found = find_attribute(message.subspan(at), ERROR_ATTR_MSG);
    if (found && *found) {
        auto const reason = without_trailing_nuls(**found);
        text.assign(reason.begin(), reason.end());
    }
}

}  // namespace

//
// Writing
//

void put_header(BufferSerializerBuilder& b, size_t const length, uint16_t const type, uint16_t const flags, uint32_t const seq)
{
    b.append(static_cast<uint32_t>(length)).append(type).append(flags).append(seq).append(uint32_t{0});
}

void put_attribute_header(BufferSerializerBuilder& b, size_t const payload, uint16_t const type)
{
    b.append(static_cast<uint16_t>(ATTRIBUTE_HEADER + payload)).append(type);
}

void put_padding(BufferSerializerBuilder& b, size_t const payload)
{
    static constexpr std::array<uint8_t, 4> ZEROS{};
    b.append(std::span<uint8_t const>{ZEROS}.first(align4(payload) - payload));
}

void put_attribute(BufferSerializerBuilder& b, uint16_t const type, std::span<uint8_t const> const payload)
{
    put_attribute_header(b, payload.size(), type);
    b.append(payload);
    put_padding(b, payload.size());
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

//
// Reading
//

auto find_attribute(std::span<uint8_t const> const attributes, uint16_t const type)
    -> StatusValue<std::optional<std::span<uint8_t const>>>
{
    for (size_t at = 0; at + ATTRIBUTE_HEADER <= attributes.size();) {
        size_t const length = load<uint16_t>(attributes, at);
        if (length < ATTRIBUTE_HEADER || length > attributes.size() - at) {
            return failure(bad_message());
        }
        if ((load<uint16_t>(attributes, at + 2) & TYPE_MASK) == type) {
            return attributes.subspan(at + ATTRIBUTE_HEADER, length - ATTRIBUTE_HEADER);
        }
        at += align4(length);
    }
    return std::nullopt;
}

auto without_trailing_nuls(std::span<uint8_t const> const bytes) noexcept -> std::span<uint8_t const>
{
    size_t length = bytes.size();
    while (length > 0 && bytes[length - 1] == 0) {
        --length;
    }
    return bytes.first(length);
}

auto ack_status(std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text)
    -> Status
{
    if (message.size() < MESSAGE_HEADER + ERROR_PAYLOAD) {
        return failure(bad_message());
    }
    auto const error = load<int32_t>(message, MESSAGE_HEADER);
    if (error != 0 && (flags & FLAG_ACK_TLVS) != 0) {
        read_ack_text(message, flags, request_size, text);
    }
    return status_of(error);
}

auto dump_status(std::span<uint8_t const> const message) noexcept -> Status
{
    if (message.size() < MESSAGE_HEADER + sizeof(int32_t)) {
        return success();  // a bare NLMSG_DONE, as older kernels send it
    }
    return status_of(load<int32_t>(message, MESSAGE_HEADER));
}

auto end_status(
    std::span<uint8_t const> const message, uint16_t const type, uint16_t const flags, size_t const request_size, std::string& text)
    -> std::optional<Status>
{
    if (type == TYPE_ERROR) {
        return ack_status(message, flags, request_size, text);
    }
    if (type == TYPE_DONE) {
        return dump_status(message);
    }
    return std::nullopt;
}

#if defined(__linux__)

//
// Socket
//

namespace {

/// Netlink socket `fd` bound to a port id the kernel picks: that id.
[[nodiscard]] auto bind_to_kernel_port(int const fd) noexcept -> StatusValue<uint32_t>
{
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
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

/// The acknowledgement options and the receive timeout on `fd`. The two ack
/// options are advisory: an older kernel answers without them, less helpfully.
[[nodiscard]] auto configure(int const fd) noexcept -> Status
{
    int const on = 1;
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &on, sizeof(on));
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof(on));
    timeval const patience{.tv_sec = 1, .tv_usec = 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience)) < 0) {
        return failure(errno_code());
    }
    return success();
}

}  // namespace

auto Socket::open(int const protocol) noexcept -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol)};
    if (!fd.valid()) {
        return failure(errno_code());
    }
    return adopt(std::move(fd));
}

auto Socket::adopt(FileDescriptor fd) noexcept -> Status
{
    if (auto configured = configure(fd.get()); !configured) {
        return configured;
    }
    auto const port = bind_to_kernel_port(fd.get());
    if (!port) {
        return failure(port.error());
    }
    port_id_ = *port;
    fd_ = std::move(fd);
    return success();
}

auto Socket::send(std::span<uint8_t const> const request) noexcept -> Status
{
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(fd_.get(), request.data(), request.size(), 0, sockaddr_cast(kernel), sizeof(kernel)) < 0) {
        return failure(errno_code());
    }
    return success();
}

auto Socket::receive(std::span<uint8_t> const buffer) noexcept -> StatusValue<std::span<uint8_t const>>
{
    for (;;) {
        // MSG_TRUNC: the datagram's whole length even when it did not fit, so a
        // cut reply is told from a complete one; the cut datagram is gone.
        ssize_t const received = ::recv(fd_.get(), buffer.data(), buffer.size(), MSG_TRUNC);
        if (received >= 0 && static_cast<size_t>(received) > buffer.size()) {
            return failure(std::make_error_code(std::errc::message_size));
        }
        if (received >= 0) {
            return buffer.first(static_cast<size_t>(received));
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return failure(std::make_error_code(std::errc::timed_out));
        }
        if (errno != EINTR) {
            return failure(errno_code());
        }
    }
}

#endif  // __linux__

}  // namespace statusbar::net::netlink
