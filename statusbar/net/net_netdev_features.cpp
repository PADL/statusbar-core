// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netdev_features.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/buffer/span_utils.hpp"

#    include <array>
#    include <cstddef>
#    include <system_error>

#    include <linux/genetlink.h>
#    include <linux/netlink.h>

#    if __has_include(<linux/netdev.h>)
#        include <linux/netdev.h>
#    endif

namespace statusbar::net::netdev {

// The layouts the builders write field by field, and the constants mirrored from the uapi.
static_assert(sizeof(genlmsghdr) == 4 && GENL_HEADER == NLMSG_HDRLEN + GENL_HDRLEN);
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

constexpr size_t NLA_HEADER = netlink::ATTRIBUTE_HEADER;
constexpr uint16_t REQUEST_FLAGS = NLM_F_REQUEST | NLM_F_ACK;
/// GENL_NAMSIZ less its NUL.
constexpr size_t MAX_FAMILY_NAME = GENL_NAMSIZ - 1;

/// A fixed-size attribute's value into `out`; bad_message when its payload is another size.
template <typename T>
[[nodiscard]] auto parse_scalar(std::span<uint8_t const> const payload, T& out) -> Status
{
    if (payload.size() != sizeof(T)) {
        return failure(bad_message());
    }
    out = load<T>(payload, 0);
    return success();
}

}  // namespace

//
// Generic netlink framing
//

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

auto genl_attributes(std::span<uint8_t const> const message, uint16_t const type, uint8_t const cmd)
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
    netlink::put_attribute_header(b, name.size() + 1, CTRL_FAMILY_NAME);
    // The name, its NUL, then the padding to the attribute's 4-octet boundary.
    std::array<uint8_t, 4> constexpr zeros{};
    b.append(make_const_span(name)).append(std::span{zeros}.first(1 + align4(attribute) - attribute));
    return netlink::finish(b, length);
}

auto build_dev_get(std::span<uint8_t> const out, uint16_t const family_id, int const ifindex, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    constexpr size_t length = GENL_HEADER + NLA_HEADER + sizeof(uint32_t);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, family_id, seq, CMD_DEV_GET, FAMILY_VERSION);
    netlink::put_attribute_header(b, sizeof(uint32_t), DEV_IFINDEX);
    b.append(static_cast<uint32_t>(ifindex));
    return netlink::finish(b, length);
}

auto parse_family_id(std::span<uint8_t const> const message) -> StatusValue<uint16_t>
{
    std::optional<uint16_t> id;
    auto const status =
        genl_attributes(message, GENL_CONTROLLER_ID, CTRL_NEWFAMILY).and_then([&](std::span<uint8_t const> const attributes) {
            return walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
                return (type & netlink::ATTRIBUTE_TYPE_MASK) == CTRL_FAMILY_ID ? parse_scalar(payload, id.emplace()) : success();
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
                    return parse_scalar(payload, ifindex.emplace());
                case DEV_XDP_FEATURES:
                    return parse_scalar(payload, device.xdp_features);
                case DEV_XSK_FEATURES:
                    return parse_scalar(payload, device.xsk.flags);
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

auto resolve_family_id(netlink::Socket& socket, std::span<uint8_t> const reply) -> StatusValue<uint16_t>
{
    std::optional<uint16_t> id;
    auto const status = socket.request(
        reply,
        [](std::span<uint8_t> out, uint32_t seq) { return build_get_family(out, FAMILY_NAME, seq); },
        [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            return type == GENL_CONTROLLER_ID ? parse_family_id(message).transform([&](uint16_t const got) { id = got; })
                                              : success();
        });
    if (!status || !id) {
        return failure(status ? bad_message() : status.error());
    }
    return *id;
}

auto NetdevClient::open() -> Status
{
    auto const status = socket_.open(NETLINK_GENERIC).and_then([&] { return resolve_family_id(socket_, reply_); });
    if (!status) {
        socket_.close();
        return failure(status.error());
    }
    family_id_ = *status;
    return success();
}

auto NetdevClient::features(int const ifindex) -> StatusValue<DeviceFeatures>
{
    std::optional<DeviceFeatures> device;
    auto const status = request(
        [&](std::span<uint8_t> out, uint32_t seq) { return build_dev_get(out, family_id_, ifindex, seq); },
        [&](std::span<uint8_t const> const message) {
            return parse_dev(message, family_id_).transform([&](DeviceFeatures const& got) { device = got; });
        });
    if (!status || !device) {
        return failure(status ? bad_message() : status.error());  // an ack without a reply is malformed
    }
    return *device;
}

auto query_xsk_features(int const ifindex) -> StatusValue<XskFeatures>
{
    NetdevClient client;
    return client.open().and_then([&] { return client.features(ifindex); }).transform([](DeviceFeatures const& device) {
        return device.xsk;
    });
}

auto launch_time_supported(int const ifindex) -> StatusValue<bool>
{
    return query_xsk_features(ifindex).transform([](XskFeatures const xsk) { return xsk.launch_time(); });
}

}  // namespace statusbar::net::netdev

#endif  // __linux__
