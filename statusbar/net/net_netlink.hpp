#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Netlink plumbing for the request/reply clients in this module (the netdev
/// family's device query, a link query): the message and attribute framing
/// of linux/netlink.h written and read in host byte order, and, on Linux, a
/// blocking socket that sends one request and reads its replies up to the
/// acknowledgement.
///
/// The framing half builds everywhere, with the wire constants spelled here
/// rather than taken from the kernel headers, so a reply captured on a Linux
/// box can be parsed and tested on any host; the Linux build checks every
/// constant against the UAPI. Only netlink::Socket needs the kernel.

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <system_error>

namespace statusbar::net::netlink {

//
// Wire constants - linux/netlink.h, checked against it on Linux
//

/// sizeof(struct nlmsghdr): nlmsg_len (u32), nlmsg_type (u16), nlmsg_flags
/// (u16), nlmsg_seq (u32), nlmsg_pid (u32).
inline constexpr size_t MESSAGE_HEADER = 16;
/// sizeof(struct nlattr) / struct rtattr: nla_len (u16), nla_type (u16).
inline constexpr size_t ATTRIBUTE_HEADER = 4;
/// Where each nlmsghdr field lies.
inline constexpr size_t OFFSET_LENGTH = 0;
inline constexpr size_t OFFSET_TYPE = 4;
inline constexpr size_t OFFSET_FLAGS = 6;
inline constexpr size_t OFFSET_SEQUENCE = 8;
inline constexpr size_t OFFSET_PORT_ID = 12;
/// nlattr::nla_type without NLA_F_NESTED (bit 15) and NLA_F_NET_BYTEORDER (bit 14).
inline constexpr uint16_t TYPE_MASK = 0x3FFF;
/// NLA_F_NESTED: the kernel's strict validation wants it on every nest a request carries.
inline constexpr uint16_t ATTRIBUTE_NESTED = 0x8000;

/// nlmsg_flags: NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_DUMP (ROOT | MATCH),
/// and the two an NLMSG_ERROR carries: NLM_F_CAPPED (the request is not echoed)
/// and NLM_F_ACK_TLVS (extended-ack attributes follow).
inline constexpr uint16_t FLAG_REQUEST = 0x0001;
inline constexpr uint16_t FLAG_MULTI = 0x0002;
inline constexpr uint16_t FLAG_ACK = 0x0004;
inline constexpr uint16_t FLAG_DUMP = 0x0300;
inline constexpr uint16_t FLAG_CAPPED = 0x0100;
inline constexpr uint16_t FLAG_ACK_TLVS = 0x0200;

/// nlmsg_type: NLMSG_ERROR (an acknowledgement, positive or negative),
/// NLMSG_DONE (the end of a dump), and NLMSG_MIN_TYPE, the first type a
/// protocol or generic-netlink family may use.
inline constexpr uint16_t TYPE_ERROR = 0x0002;
inline constexpr uint16_t TYPE_DONE = 0x0003;
inline constexpr uint16_t TYPE_MIN_FAMILY = 0x0010;

/// struct nlmsgerr: the error (an int) followed by the request's nlmsghdr.
inline constexpr size_t ERROR_PAYLOAD = 4 + MESSAGE_HEADER;
/// enum nlmsgerr_attrs: NLMSGERR_ATTR_MSG, the kernel's reason as text.
inline constexpr uint16_t ERROR_ATTR_MSG = 1;

/// Room for any request a client of this module builds: the largest is well
/// under 64 octets, and 256 leaves room for a dump request with a few filters.
inline constexpr size_t MAX_REQUEST_SIZE = 256;
using RequestBuffer = std::array<uint8_t, MAX_REQUEST_SIZE>;

/// NLMSG_ALIGN / NLA_ALIGN / RTA_ALIGN: `n` rounded up to a multiple of 4.
[[nodiscard]] constexpr auto align4(size_t const n) noexcept -> size_t
{
    return (n + 3U) & ~size_t{3};
}

/// The error every reader here answers for a message or attribute that is cut
/// short, overruns its container, or is not the message asked about.
[[nodiscard]] inline auto bad_message() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::bad_message);
}

/// Whether `error` (an errno from the socket) is momentary, so the request is
/// worth sending again: a kernel short of socket buffers, an interrupted call,
/// a receive that would block.
[[nodiscard]] constexpr auto transient_error(int const error) noexcept -> bool
{
    return error == ENOBUFS || error == EAGAIN || error == EINTR || error == EBUSY;
}

/// The host-order T at offset `at` of `bytes`. The caller has checked that
/// `bytes` holds it; every reader below does.
template <typename T>
[[nodiscard]] auto load(std::span<uint8_t const> const bytes, size_t const at) noexcept -> T
{
    T value{};
    span_load(value, bytes.subspan(at, sizeof(T)));
    return value;
}

//
// Writing
//

/// Append a struct nlmsghdr of `length` octets in all: `type`, `flags`, `seq`,
/// and a port id of 0 (the kernel).
void put_header(BufferSerializerBuilder& b, size_t length, uint16_t type, uint16_t flags, uint32_t seq);

/// Append a struct nlattr header for an attribute of `type` whose payload is
/// `payload` octets. The payload follows, then put_padding() to the boundary.
void put_attribute_header(BufferSerializerBuilder& b, size_t payload, uint16_t type);

/// Append the zero octets that take a `payload`-octet attribute to its
/// 4-octet boundary (none when it is aligned already).
void put_padding(BufferSerializerBuilder& b, size_t payload);

/// Append one whole attribute: header, `payload`, padding.
void put_attribute(BufferSerializerBuilder& b, uint16_t type, std::span<uint8_t const> payload);

/// The octets a `payload`-octet attribute takes in a message, padding included.
[[nodiscard]] constexpr auto attribute_size(size_t const payload) noexcept -> size_t
{
    return align4(ATTRIBUTE_HEADER + payload);
}

/// A builder's result once a message is written: `expected` octets, else the
/// builder's error (the buffer was short), else message_size when the length
/// the header announced and what was written disagree.
[[nodiscard]] auto finish(BufferSerializerBuilder const& b, size_t expected) -> StatusValue<size_t>;

//
// Reading
//

/// Call `visit` (raw nla_type, payload) -> Status for each attribute of
/// `attributes` in turn, stopping at the first failure, which is the result;
/// bad_message for an attribute that is shorter than its header or overruns
/// the span. The type is handed over unmasked: callers apply TYPE_MASK.
template <typename Visit>
[[nodiscard]] auto walk_attributes(std::span<uint8_t const> const attributes, Visit const& visit) -> Status
{
    for (size_t at = 0; at + ATTRIBUTE_HEADER <= attributes.size();) {
        size_t const length = load<uint16_t>(attributes, at);
        if (length < ATTRIBUTE_HEADER || length > attributes.size() - at) {
            return failure(bad_message());
        }
        uint16_t const type = load<uint16_t>(attributes, at + 2);
        if (auto status = visit(type, attributes.subspan(at + ATTRIBUTE_HEADER, length - ATTRIBUTE_HEADER)); !status) {
            return status;
        }
        at += align4(length);
    }
    return success();
}

/// Call `visit` (message) -> std::optional<Status> for each message of
/// `datagram`, each cut to its own nlmsg_len, header included: the first
/// result `visit` gives ends the walk and is returned; bad_message for a
/// message shorter than its header or longer than what is left; nullopt when
/// every message was visited and none answered.
template <typename Visit>
[[nodiscard]] auto walk_messages(std::span<uint8_t const> const datagram, Visit const& visit) -> std::optional<Status>
{
    for (size_t at = 0; at + MESSAGE_HEADER <= datagram.size();) {
        size_t const length = load<uint32_t>(datagram, at + OFFSET_LENGTH);
        if (length < MESSAGE_HEADER || length > datagram.size() - at) {
            return failure(bad_message());
        }
        if (auto result = visit(datagram.subspan(at, length))) {
            return result;
        }
        at += align4(length);
    }
    return std::nullopt;
}

/// The payload of the first attribute of `attributes` whose masked type is
/// `type`; nullopt when there is none. bad_message for an attribute before
/// it that is malformed; the attributes after it are not looked at.
[[nodiscard]] auto find_attribute(std::span<uint8_t const> attributes, uint16_t type)
    -> StatusValue<std::optional<std::span<uint8_t const>>>;

/// `bytes` without the NUL octets at its end: a netlink string attribute
/// carries its terminator, and sometimes padding too.
[[nodiscard]] auto without_trailing_nuls(std::span<uint8_t const> bytes) noexcept -> std::span<uint8_t const>;

/// What an NLMSG_ERROR says about the request of `request_size` octets it
/// answers: success when its error is 0 (the plain acknowledgement), else the
/// errno it carries as a system error. With `flags` holding FLAG_ACK_TLVS the
/// kernel's reason (NLMSGERR_ATTR_MSG) is assigned to `text`; the attributes
/// follow the echoed request unless FLAG_CAPPED says it was left out.
/// bad_message when the message is shorter than a struct nlmsgerr.
[[nodiscard]] auto ack_status(std::span<uint8_t const> message, uint16_t flags, size_t request_size, std::string& text) -> Status;

/// What an NLMSG_DONE says about the dump it ends: success, or the error its
/// payload carries (an older kernel sends none, which is success).
[[nodiscard]] auto dump_status(std::span<uint8_t const> message) noexcept -> Status;

/// Whether `message` (of nlmsg_type `type` and nlmsg_flags `flags`) ends a
/// request: ack_status() for an NLMSG_ERROR, dump_status() for an NLMSG_DONE,
/// nullopt for anything else, which is a reply to hand to the caller.
[[nodiscard]] auto end_status(
    std::span<uint8_t const> message, uint16_t type, uint16_t flags, size_t request_size, std::string& text)
    -> std::optional<Status>;

#if defined(__linux__)

//
// Socket - Linux only
//

/// A blocking netlink socket for one request at a time: bound to a port id
/// the kernel assigns, asking for extended and capped acknowledgements, with
/// a receive timeout of a second so a request the kernel drops unread does
/// not hang its caller. The replies land in a buffer the caller owns.
///
/// Not thread-safe, and not for a real-time thread: every request blocks on
/// the kernel.
class Socket
{
  public:
    /// How often a request refused with a transient error, or whose reply was
    /// cut short of the buffer, is sent again before the error is the answer.
    static constexpr unsigned MAX_ATTEMPTS = 4;

    Socket() noexcept = default;

    /// Open a socket of `protocol` (NETLINK_ROUTE, NETLINK_GENERIC) and bind
    /// it. Errors: the socket's errno.
    [[nodiscard]] auto open(int protocol) noexcept -> Status;

    /// True between a successful open() and close().
    [[nodiscard]] auto is_open() const noexcept -> bool { return fd_.valid(); }

    /// Close the socket; a no-op when it is not open.
    void close() noexcept { fd_ = FileDescriptor{}; }

    /// The port id the kernel bound the socket to (0 when closed).
    [[nodiscard]] auto port_id() const noexcept -> uint32_t { return port_id_; }

    /// One request: `build` (out, seq) -> StatusValue<size_t> writes it under
    /// the next sequence number, it is sent, and every reply the kernel
    /// addresses to it is read into `buffer` and handed to `on_reply`
    /// (message, nlmsg_type) -> Status, until the acknowledgement (or a
    /// dump's NLMSG_DONE), whose status is the result. Replies to other
    /// requests, and messages for other port ids, are skipped. A reply
    /// `on_reply` refuses ends the request with that refusal.
    ///
    /// Errors: bad_file_descriptor when closed, the builder's, `on_reply`'s,
    /// the kernel's refusal (an errno), timed_out when nothing answers,
    /// message_size when the reply did not fit `buffer` after MAX_ATTEMPTS.
    template <typename Build, typename OnReply>
    [[nodiscard]] auto request(std::span<uint8_t> const buffer, Build const& build, OnReply const& on_reply) -> Status
    {
        if (!is_open()) {
            return failure(std::make_error_code(std::errc::bad_file_descriptor));
        }
        last_message_.clear();
        for (unsigned attempt = 1;; ++attempt) {
            auto outcome = once(buffer, build, on_reply);
            if (outcome || attempt >= MAX_ATTEMPTS || !again(outcome.error())) {
                return outcome;
            }
        }
    }

    /// request() for a request the kernel only acknowledges: any other reply
    /// is read and ignored.
    template <typename Build>
    [[nodiscard]] auto request(std::span<uint8_t> const buffer, Build const& build) -> Status
    {
        return request(buffer, build, [](std::span<uint8_t const>, uint16_t) -> Status { return success(); });
    }

    /// The kernel's extended-ack reason for the last request that failed;
    /// empty when none was given, or the request succeeded.
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return last_message_; }

  private:
    /// Whether a request that ended in `error` is sent again: the socket's
    /// transient errors and a reply that did not fit (the datagram is lost,
    /// so the request is).
    [[nodiscard]] static auto again(std::error_code const& error) noexcept -> bool
    {
        return error == std::errc::message_size || (error.category() == std::system_category() && transient_error(error.value()));
    }

    /// One attempt at request(): built under a fresh sequence number, sent,
    /// its replies read until one ends it.
    template <typename Build, typename OnReply>
    [[nodiscard]] auto once(std::span<uint8_t> const buffer, Build const& build, OnReply const& on_reply) -> Status
    {
        RequestBuffer request{};
        uint32_t const seq = ++sequence_;
        auto const sent = build_and_send(request, seq, build);
        if (!sent) {
            return failure(sent.error());
        }
        return read_replies(buffer, seq, *sent, on_reply);
    }

    /// `build` writes the request for sequence `seq` into `request`, which is
    /// sent: its length.
    template <typename Build>
    [[nodiscard]] auto build_and_send(RequestBuffer& request, uint32_t const seq, Build const& build) -> StatusValue<size_t>
    {
        auto const built = build(std::span<uint8_t>{request}, seq);
        if (!built) {
            return failure(built.error());
        }
        if (auto sent = send(std::span<uint8_t const>{request.data(), *built}); !sent) {
            return failure(sent.error());
        }
        return *built;
    }

    /// Datagrams read into `buffer` until one holds the end of request `seq`.
    template <typename OnReply>
    [[nodiscard]] auto read_replies(
        std::span<uint8_t> const buffer, uint32_t const seq, size_t const request_size, OnReply const& on_reply) -> Status
    {
        for (;;) {
            auto const datagram = receive(buffer);
            if (!datagram) {
                return failure(datagram.error());
            }
            if (auto done = deliver_all(*datagram, seq, request_size, on_reply)) {
                return *done;
            }
        }
    }

    /// Each message of `datagram` addressed to request `seq` on this port,
    /// delivered: the first result, else nullopt (the request goes on).
    template <typename OnReply>
    [[nodiscard]] auto deliver_all(
        std::span<uint8_t const> const datagram, uint32_t const seq, size_t const request_size, OnReply const& on_reply)
        -> std::optional<Status>
    {
        return walk_messages(datagram, [&](std::span<uint8_t const> const message) -> std::optional<Status> {
            if (load<uint32_t>(message, OFFSET_SEQUENCE) != seq || load<uint32_t>(message, OFFSET_PORT_ID) != port_id_) {
                return std::nullopt;
            }
            return deliver(message, request_size, on_reply);
        });
    }

    /// One message of the request: its end_status() when it ends the request,
    /// else `on_reply`'s refusal, else nullopt.
    template <typename OnReply>
    [[nodiscard]] auto deliver(std::span<uint8_t const> const message, size_t const request_size, OnReply const& on_reply)
        -> std::optional<Status>
    {
        uint16_t const type = load<uint16_t>(message, OFFSET_TYPE);
        if (auto end = end_status(message, type, load<uint16_t>(message, OFFSET_FLAGS), request_size, last_message_)) {
            return end;
        }
        auto status = on_reply(message, type);
        return status ? std::nullopt : std::optional<Status>{status};
    }

    /// `fd`, open: configured, bound, and made this socket's.
    [[nodiscard]] auto adopt(FileDescriptor fd) noexcept -> Status;

    /// `request` to the kernel. Errors: the socket's errno.
    [[nodiscard]] auto send(std::span<uint8_t const> request) noexcept -> Status;

    /// One datagram into `buffer`: the octets received; timed_out when the
    /// receive timeout passed; message_size when it did not fit (and is lost).
    [[nodiscard]] auto receive(std::span<uint8_t> buffer) noexcept -> StatusValue<std::span<uint8_t const>>;

    FileDescriptor fd_{};
    uint32_t port_id_{0};
    uint32_t sequence_{0};
    std::string last_message_{};
};

#endif  // __linux__

}  // namespace statusbar::net::netlink
