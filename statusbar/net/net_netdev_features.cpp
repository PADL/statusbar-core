// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netdev_features.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"

#    include <cstddef>
#    include <system_error>

#    include <linux/genetlink.h>
#    include <linux/netlink.h>

#    if __has_include(<linux/netdev.h>)
#        include <linux/netdev.h>
#    endif

namespace statusbar::net::netdev {

// The layouts the builders write field by field, and the constants mirrored from the uapi.
static_assert(sizeof(genlmsghdr) == 4);
static_assert(GENL_CONTROLLER_ID == GENL_ID_CTRL && CTRL_GETFAMILY == CTRL_CMD_GETFAMILY && CTRL_NEWFAMILY == CTRL_CMD_NEWFAMILY);
static_assert(CTRL_FAMILY_ID == CTRL_ATTR_FAMILY_ID && CTRL_FAMILY_NAME == CTRL_ATTR_FAMILY_NAME);
#    if __has_include(<linux/netdev.h>)  // 6.3+
static_assert(FAMILY_VERSION == NETDEV_FAMILY_VERSION && CMD_DEV_GET == NETDEV_CMD_DEV_GET);
static_assert(DEV_IFINDEX == NETDEV_A_DEV_IFINDEX && DEV_XDP_FEATURES == NETDEV_A_DEV_XDP_FEATURES);
static_assert(XDP_ACT_XSK_ZEROCOPY == NETDEV_XDP_ACT_XSK_ZEROCOPY);
#    endif
#    if defined(HAVE_NETDEV_XSK_FEATURES)  // 6.8+, detected by CMake
static_assert(DEV_XDP_RX_METADATA_FEATURES == NETDEV_A_DEV_XDP_RX_METADATA_FEATURES);
static_assert(DEV_XSK_FEATURES == NETDEV_A_DEV_XSK_FEATURES);
static_assert(XSK_TX_TIMESTAMP == NETDEV_XSK_FLAGS_TX_TIMESTAMP && XSK_TX_CHECKSUM == NETDEV_XSK_FLAGS_TX_CHECKSUM);
#    endif
#    if defined(HAVE_NETDEV_XSK_LAUNCH_TIME)  // 6.15+, detected by CMake
static_assert(XSK_TX_LAUNCH_TIME_FIFO == NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO);
#    endif

namespace {

using netlink::align4;
using netlink::bad_message;
using netlink::load;
using netlink::walk_attributes;

constexpr size_t GENL_HEADER = netlink::MESSAGE_HEADER + sizeof(genlmsghdr);
constexpr size_t NLA_HEADER = netlink::ATTRIBUTE_HEADER;
constexpr uint16_t REQUEST_FLAGS = NLM_F_REQUEST | NLM_F_ACK;
/// GENL_NAMSIZ less its NUL.
constexpr size_t MAX_FAMILY_NAME = GENL_NAMSIZ - 1;

void put_genl_header(
    BufferSerializerBuilder& b,
    size_t const length,
    uint16_t const type,
    uint32_t const seq,
    uint8_t const cmd,
    uint8_t const version)
{
    netlink::put_header(b, length, type, REQUEST_FLAGS, seq);
    b.append(cmd).append(version).append(uint16_t{0});
}

void put_attribute_header(BufferSerializerBuilder& b, size_t const payload, uint16_t const type)
{
    b.append(static_cast<uint16_t>(NLA_HEADER + payload)).append(type);
}

/// The attributes of a generic netlink message of nlmsg_type `type` and command `cmd`.
[[nodiscard]] auto genl_attributes(std::span<uint8_t const> const message, uint16_t const type, uint8_t const cmd)
    -> StatusValue<std::span<uint8_t const>>
{
    if (message.size() < GENL_HEADER) {
        return failure(bad_message());
    }
    auto const length = load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_len));
    if (length < GENL_HEADER || length > message.size() || load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) != type ||
        message[netlink::MESSAGE_HEADER + offsetof(genlmsghdr, cmd)] != cmd) {
        return failure(bad_message());
    }
    return message.subspan(GENL_HEADER, length - GENL_HEADER);
}

/// A fixed-size attribute's value into `out`; bad_message when its payload is another size.
template <typename T>
[[nodiscard]] auto take_scalar(std::span<uint8_t const> const payload, T& out) -> Status
{
    if (payload.size() != sizeof(T)) {
        return failure(bad_message());
    }
    out = load<T>(payload, 0);
    return success();
}

}  // namespace

//
// Builders and parsers
//

auto build_get_family(std::span<uint8_t> const out, std::string_view const name, uint32_t const seq) -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    if (name.empty() || name.size() > MAX_FAMILY_NAME) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    size_t const attribute = NLA_HEADER + name.size() + 1;
    size_t const length = GENL_HEADER + align4(attribute);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, GENL_CONTROLLER_ID, seq, CTRL_GETFAMILY, 1);
    put_attribute_header(b, name.size() + 1, CTRL_FAMILY_NAME);
    for (char const c : name) {
        b.append(static_cast<uint8_t>(c));
    }
    b.append(uint8_t{0});
    for (size_t i = attribute; i < align4(attribute); ++i) {
        b.append(uint8_t{0});
    }
    return netlink::finish(b, length);
}

auto build_dev_get(std::span<uint8_t> const out, uint16_t const family_id, int const ifindex, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    constexpr size_t length = GENL_HEADER + NLA_HEADER + sizeof(uint32_t);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, family_id, seq, CMD_DEV_GET, FAMILY_VERSION);
    put_attribute_header(b, sizeof(uint32_t), DEV_IFINDEX);
    b.append(static_cast<uint32_t>(ifindex));
    return netlink::finish(b, length);
}

auto parse_family_id(std::span<uint8_t const> const message) -> StatusValue<uint16_t>
{
    std::optional<uint16_t> id;
    auto const status =
        genl_attributes(message, GENL_CONTROLLER_ID, CTRL_NEWFAMILY).and_then([&](std::span<uint8_t const> const attributes) {
            return walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
                return (type & netlink::ATTRIBUTE_TYPE_MASK) == CTRL_FAMILY_ID ? take_scalar(payload, id.emplace()) : success();
            });
        });
    if (!status || !id) {
        return failure(status ? bad_message() : status.error());
    }
    return *id;
}

auto parse_dev(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<DeviceFeatures>
{
    DeviceFeatures device{};
    std::optional<uint32_t> ifindex;
    auto const status = genl_attributes(message, family_id, CMD_DEV_GET).and_then([&](std::span<uint8_t const> const attributes) {
        return walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            switch (type & netlink::ATTRIBUTE_TYPE_MASK) {
                case DEV_IFINDEX:
                    return take_scalar(payload, ifindex.emplace());
                case DEV_XDP_FEATURES:
                    return take_scalar(payload, device.xdp_features);
                case DEV_XSK_FEATURES:
                    return take_scalar(payload, device.xsk.flags);
                default:
                    return success();
            }
        });
    });
    if (!status || !ifindex) {
        return failure(status ? bad_message() : status.error());
    }
    device.ifindex = static_cast<int>(*ifindex);
    return device;
}

//
// NetdevClient
//

auto NetdevClient::open() -> Status
{
    auto const status = socket_.open(NETLINK_GENERIC).and_then([&] { return resolve_family(); });
    if (!status) {
        socket_.close();
    }
    return status;
}

auto NetdevClient::resolve_family() -> Status
{
    Wanted wanted{.type = GENL_CONTROLLER_ID};
    auto const status = send([](std::span<uint8_t> out, uint32_t seq) { return build_get_family(out, FAMILY_NAME, seq); }, wanted);
    if (!status || !wanted.family_id) {
        return failure(status ? bad_message() : status.error());
    }
    family_id_ = *wanted.family_id;
    return success();
}

auto NetdevClient::features(int const ifindex) -> StatusValue<DeviceFeatures>
{
    Wanted wanted{.type = family_id_};
    auto const status =
        send([&](std::span<uint8_t> out, uint32_t seq) { return build_dev_get(out, family_id_, ifindex, seq); }, wanted);
    if (!status || !wanted.device) {
        return failure(status ? bad_message() : status.error());  // an ack without a reply is malformed
    }
    return *wanted.device;
}

template <typename Build>
auto NetdevClient::send(Build const& build, Wanted& wanted) -> Status
{
    RequestBuffer request{};
    uint32_t const seq = ++seq_;
    return build(std::span<uint8_t>{request}, seq).and_then([&](size_t const length) {
        return transact(std::span<uint8_t const>{request.data(), length}, seq, wanted);
    });
}

auto NetdevClient::transact(std::span<uint8_t const> const request, uint32_t const seq, Wanted& wanted) -> Status
{
    last_message_.clear();
    if (!socket_.is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    return socket_.transact(
        request, seq, reply_, [&](std::span<uint8_t const> const message, uint16_t const type, uint16_t const flags) {
            return read_reply(message, type, flags, request.size(), wanted);
        });
}

auto NetdevClient::read_reply(
    std::span<uint8_t const> const message, uint16_t const type, uint16_t const flags, size_t const request_size, Wanted& wanted)
    -> std::optional<Status>
{
    if (type == NLMSG_ERROR) {
        return netlink::ack_status(message, flags, request_size, last_message_);
    }
    if (type != wanted.type) {
        return std::nullopt;
    }
    auto const taken = wanted.type == GENL_CONTROLLER_ID
        ? parse_family_id(message).transform([&](uint16_t const id) { wanted.family_id = id; })
        : parse_dev(message, wanted.type).transform([&](DeviceFeatures const& device) { wanted.device = device; });
    return taken ? std::nullopt : std::optional<Status>{taken};
}

auto query_xsk_features(int const ifindex) -> StatusValue<XskFeatures>
{
    NetdevClient client;
    return client.open().and_then([&] { return client.features(ifindex); }).transform([](DeviceFeatures const& device) {
        return device.xsk;
    });
}

}  // namespace statusbar::net::netdev

#endif  // __linux__
