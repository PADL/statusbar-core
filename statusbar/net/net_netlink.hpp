#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Netlink plumbing shared by the rtnetlink and generic-netlink clients: a blocking socket that
/// sends one request and reads its replies up to the ack, and attribute writing, walking and
/// parsing. Host byte order throughout. Linux only.

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <optional>
#    include <span>
#    include <string>
#    include <system_error>

namespace statusbar::net::netlink {

/// sizeof(struct nlmsghdr) and sizeof(struct nlattr) / struct rtattr (linux/netlink.h).
inline constexpr size_t MESSAGE_HEADER = 16;
inline constexpr size_t ATTRIBUTE_HEADER = 4;
/// nlattr::nla_type without NLA_F_NESTED / NLA_F_NET_BYTEORDER.
inline constexpr uint16_t ATTRIBUTE_TYPE_MASK = 0x3FFF;

/// Room for any request a client builds (the largest, tc's mqprio, is 136 octets).
inline constexpr size_t MAX_REQUEST_SIZE = 256;
using RequestBuffer = std::array<uint8_t, MAX_REQUEST_SIZE>;

/// NLMSG_ALIGN / NLA_ALIGN / RTA_ALIGN: `n` rounded up to 4.
[[nodiscard]] constexpr auto align4(size_t const n) noexcept -> size_t
{
    return (n + 3U) & ~size_t{3};
}

/// The error every parser here returns for a truncated or malformed message.
[[nodiscard]] inline auto bad_message() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::bad_message);
}

/// The T at `at` of `bytes`; the caller has checked `bytes` holds it.
template <typename T>
[[nodiscard]] auto load(std::span<uint8_t const> const bytes, size_t const at) noexcept -> T
{
    T value{};
    span_load(value, bytes.subspan(at, sizeof(T)));
    return value;
}

/// Append a struct nlattr / rtattr header for a `payload`-octet attribute of `type`.
void put_attribute_header(BufferSerializerBuilder& b, size_t payload, uint16_t type);

/// Append a struct nlmsghdr (nlmsg_pid 0: to the kernel).
void put_header(BufferSerializerBuilder& b, size_t length, uint16_t type, uint16_t flags, uint32_t seq);

/// A builder's result: `expected` octets written, else its error (message_size when the length arithmetic is wrong).
[[nodiscard]] auto finish(BufferSerializerBuilder const& b, size_t expected) -> StatusValue<size_t>;

/// Call `visit` (raw nla_type, payload) -> Status for each attribute of `attributes`, stopping
/// at its first failure; bad_message for an attribute that overruns. Callers mask the type.
template <typename Visit>
[[nodiscard]] auto walk_attributes(std::span<uint8_t const> const attributes, Visit const& visit) -> Status
{
    for (size_t at = 0; at + ATTRIBUTE_HEADER <= attributes.size();) {
        auto const len = load<uint16_t>(attributes, at);
        if (len < ATTRIBUTE_HEADER || at + len > attributes.size()) {
            return failure(bad_message());
        }
        if (auto status =
                visit(load<uint16_t>(attributes, at + 2), attributes.subspan(at + ATTRIBUTE_HEADER, len - ATTRIBUTE_HEADER));
            !status) {
            return status;
        }
        at += align4(len);
    }
    return success();
}

/// The payload of the first attribute whose masked type is `type`, nullopt when none is;
/// bad_message for an attribute before it that overruns. Nothing after it is checked.
[[nodiscard]] auto find_attribute(std::span<uint8_t const> attributes, uint16_t type)
    -> StatusValue<std::optional<std::span<uint8_t const>>>;

/// `bytes` without its trailing NULs.
[[nodiscard]] auto without_trailing_nuls(std::span<uint8_t const> bytes) noexcept -> std::span<uint8_t const>;

/// An NLMSG_ERROR of `request_size`'s request: its error (success for the ack), the
/// extended ack's NLMSGERR_ATTR_MSG into `text`. bad_message when truncated.
[[nodiscard]] auto ack_status(std::span<uint8_t const> message, uint16_t flags, size_t request_size, std::string& text) -> Status;

/// A dump's NLMSG_DONE: its payload is the dump's error (0 when complete).
[[nodiscard]] auto dump_status(std::span<uint8_t const> message) noexcept -> Status;

/// The end of a request: an NLMSG_ERROR's ack_status() (its extended-ack text into `text`) or an
/// NLMSG_DONE's dump_status(); nullopt for any other message.
[[nodiscard]] auto end_status(
    std::span<uint8_t const> message, uint16_t type, uint16_t flags, size_t request_size, std::string& text)
    -> std::optional<Status>;

/// A blocking netlink socket bound to a kernel-assigned port id, with extended and capped
/// acks and a 1 s receive timeout. Replies land in a buffer the caller owns. Not thread-safe.
class Socket
{
  public:
    /// Open a socket of `protocol` (NETLINK_ROUTE, NETLINK_GENERIC). Errors: the socket's errno.
    [[nodiscard]] auto open(int protocol) noexcept -> Status;
    /// True between a successful open() and close().
    [[nodiscard]] auto is_open() const noexcept -> bool { return fd_.valid(); }
    /// Close the socket (a no-op when not open).
    void close() noexcept { fd_ = FileDescriptor{}; }

    /// Build a request with `build` (out, seq) -> StatusValue<size_t> under the next sequence number,
    /// send it and read its replies into `buffer`, each but the ack (or a dump's NLMSG_DONE) handed to
    /// `on_reply` (message, type) -> Status. Errors: bad_file_descriptor, the builder's, `on_reply`'s, the kernel's.
    template <typename Build, typename OnReply>
    [[nodiscard]] auto request(std::span<uint8_t> const buffer, Build const& build, OnReply const& on_reply) -> Status
    {
        RequestBuffer request{};
        uint32_t const seq = ++seq_;
        last_message_.clear();
        return build(std::span<uint8_t>{request}, seq).and_then([&](size_t const length) {
            return transact(std::span<uint8_t const>{request.data(), length}, seq, buffer, on_reply);
        });
    }

    /// request() of a request the kernel only acknowledges: any other reply is ignored.
    template <typename Build>
    [[nodiscard]] auto request(std::span<uint8_t> const buffer, Build const& build) -> Status
    {
        return request(buffer, build, [](std::span<uint8_t const>, uint16_t) { return success(); });
    }

    /// The kernel's extended-ack message for the last failed request (empty: none given, or it succeeded).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return last_message_; }

  private:
    /// request() once built: `request` (sequence `seq`) sent, each reply addressed to it read into
    /// `buffer` and deliver()ed until one ends the request.
    template <typename OnReply>
    [[nodiscard]] auto transact(
        std::span<uint8_t const> const request, uint32_t const seq, std::span<uint8_t> const buffer, OnReply const& on_reply)
        -> Status
    {
        if (!is_open()) {
            return failure(std::make_error_code(std::errc::bad_file_descriptor));
        }
        if (auto sent = send(request); !sent) {
            return sent;
        }
        for (;;) {
            auto const received = receive(buffer);
            if (!received) {
                return failure(received.error());
            }
            if (auto done = for_each_reply(*received, seq, request.size(), on_reply)) {
                return *done;
            }
        }
    }

    [[nodiscard]] auto send(std::span<uint8_t const> request) noexcept -> Status;
    /// One datagram into `buffer`: timed_out after the receive timeout, message_size when it did not fit.
    [[nodiscard]] auto receive(std::span<uint8_t> buffer) noexcept -> StatusValue<std::span<uint8_t const>>;

    /// Each message of datagram `reply` addressed to request `seq` deliver()ed: the first result, else nullopt.
    template <typename OnReply>
    [[nodiscard]] auto for_each_reply(
        std::span<uint8_t const> const reply, uint32_t const seq, size_t const request_size, OnReply const& on_reply)
        -> std::optional<Status>
    {
        for (size_t offset = 0; offset + MESSAGE_HEADER <= reply.size();) {
            auto const length = load<uint32_t>(reply, offset);
            if (length < MESSAGE_HEADER || length > reply.size() - offset) {
                return failure(bad_message());
            }
            if (load<uint32_t>(reply, offset + 8) == seq && load<uint32_t>(reply, offset + 12) == portid_) {
                if (auto done = deliver(reply.subspan(offset, length), request_size, on_reply)) {
                    return done;
                }
            }
            offset += align4(length);
        }
        return std::nullopt;
    }

    /// One message of the request: its end_status(), else `on_reply`'s failure, else nullopt.
    template <typename OnReply>
    [[nodiscard]] auto deliver(std::span<uint8_t const> const message, size_t const request_size, OnReply const& on_reply)
        -> std::optional<Status>
    {
        auto const type = load<uint16_t>(message, 4);
        if (auto end = end_status(message, type, load<uint16_t>(message, 6), request_size, last_message_)) {
            return end;
        }
        auto status = on_reply(message, type);
        return status ? std::nullopt : std::optional<Status>{status};
    }

    FileDescriptor fd_{};
    uint32_t portid_{0};
    uint32_t seq_{0};
    std::string last_message_{};
};

}  // namespace statusbar::net::netlink

#endif  // __linux__
