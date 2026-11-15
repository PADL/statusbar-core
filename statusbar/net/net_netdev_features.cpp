// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netdev_features.hpp"

#include "statusbar/buffer/span_utils.hpp"

#include <cstddef>
#include <optional>
#include <system_error>

#if defined(__linux__)
#    include <linux/genetlink.h>
#    include <linux/netlink.h>
#    if __has_include(<linux/netdev.h>)
#        include <linux/netdev.h>
#    endif
#endif

namespace statusbar::net::netdev {

#if defined(__linux__)
// The constants spelled in the header, against the UAPI they mirror. The netdev
// header arrived with Linux 6.3, xsk-features with 6.8 and the launch-time flag
// with 6.15: each is checked where the build's headers have it. The header
// spells them as enumerators, which #if cannot see (only NETDEV_FAMILY_VERSION
// is a macro), so the two later arrivals are found at configure time
// (HAVE_NETDEV_XSK_FEATURES, HAVE_NETDEV_XSK_LAUNCH_TIME; net/CMakeLists.txt).
static_assert(GENL_MESSAGE_HEADER == sizeof(genlmsghdr) && GENL_HEADER == NLMSG_HDRLEN + GENL_HDRLEN);
static_assert(GENL_CONTROLLER_ID == GENL_ID_CTRL && CTRL_NEWFAMILY == CTRL_CMD_NEWFAMILY && CTRL_GETFAMILY == CTRL_CMD_GETFAMILY);
static_assert(
    CTRL_FAMILY_ID == CTRL_ATTR_FAMILY_ID && CTRL_FAMILY_NAME == CTRL_ATTR_FAMILY_NAME && MAX_FAMILY_NAME == GENL_NAMSIZ - 1);
#    if defined(NETDEV_FAMILY_VERSION)
static_assert(FAMILY_NAME == NETDEV_FAMILY_NAME && FAMILY_VERSION == NETDEV_FAMILY_VERSION && CMD_DEV_GET == NETDEV_CMD_DEV_GET);
static_assert(DEV_IFINDEX == NETDEV_A_DEV_IFINDEX && DEV_XDP_FEATURES == NETDEV_A_DEV_XDP_FEATURES);
static_assert(DEV_XDP_ZC_MAX_SEGS == NETDEV_A_DEV_XDP_ZC_MAX_SEGS);
#        if defined(HAVE_NETDEV_XSK_FEATURES)
static_assert(
    DEV_XDP_RX_METADATA_FEATURES == NETDEV_A_DEV_XDP_RX_METADATA_FEATURES && DEV_XSK_FEATURES == NETDEV_A_DEV_XSK_FEATURES);
static_assert(XSK_TX_TIMESTAMP == NETDEV_XSK_FLAGS_TX_TIMESTAMP && XSK_TX_CHECKSUM == NETDEV_XSK_FLAGS_TX_CHECKSUM);
#        endif
#    endif
#    if defined(HAVE_NETDEV_XSK_LAUNCH_TIME)
static_assert(XSK_TX_LAUNCH_TIME_FIFO == NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO);
#    endif
#endif

namespace {

/// A fixed-size attribute's value into `out`; bad_message when the payload is another size.
template <typename T>
[[nodiscard]] auto read_scalar(std::span<uint8_t const> const payload, T& out) -> Status
{
    if (payload.size() != sizeof(T)) {
        return failure(netlink::bad_message());
    }
    out = netlink::load<T>(payload, 0);
    return success();
}

/// One NETDEV_A_DEV_* attribute of a dev-get reply into `device`; the ifindex
/// into `ifindex`, so a reply without one is told from one of interface 0.
[[nodiscard]] auto read_dev_attribute(
    uint16_t const type, std::span<uint8_t const> const payload, DeviceFeatures& device, std::optional<uint32_t>& ifindex) -> Status
{
    switch (type & netlink::TYPE_MASK) {
        case DEV_IFINDEX:
            return read_scalar(payload, ifindex.emplace());
        case DEV_XDP_FEATURES:
            return read_scalar(payload, device.xdp_features);
        case DEV_XDP_RX_METADATA_FEATURES:
            return read_scalar(payload, device.xdp_rx_metadata);
        case DEV_XSK_FEATURES:
            return read_scalar(payload, device.xsk.flags);
        default:
            return success();  // the zero-copy segment count and whatever a later kernel adds
    }
}

/// `found`, or the error that stopped the walk, or bad_message when the walk
/// finished without finding what the message had to carry.
template <typename T>
[[nodiscard]] auto required(Status const& walked, std::optional<T> const& found) -> StatusValue<T>
{
    if (!walked) {
        return failure(walked.error());
    }
    if (!found) {
        return failure(netlink::bad_message());
    }
    return *found;
}

}  // namespace

//
// Framing
//

void put_genl_header(
    BufferSerializerBuilder& b,
    size_t const length,
    uint16_t const type,
    uint32_t const seq,
    uint8_t const cmd,
    uint8_t const version)
{
    netlink::put_header(b, length, type, netlink::FLAG_REQUEST | netlink::FLAG_ACK, seq);
    b.append(cmd).append(version).append(uint16_t{0});
}

auto genl_attributes(std::span<uint8_t const> const message, uint16_t const type, uint8_t const cmd)
    -> StatusValue<std::span<uint8_t const>>
{
    if (message.size() < GENL_HEADER) {
        return failure(netlink::bad_message());
    }
    size_t const length = netlink::load<uint32_t>(message, netlink::OFFSET_LENGTH);
    bool const framed = length >= GENL_HEADER && length <= message.size();
    bool const addressed =
        netlink::load<uint16_t>(message, netlink::OFFSET_TYPE) == type && message[netlink::MESSAGE_HEADER] == cmd;
    if (!framed || !addressed) {
        return failure(netlink::bad_message());
    }
    return message.subspan(GENL_HEADER, length - GENL_HEADER);
}

namespace {

/// One request of `length` octets into `out`: the netlink and generic-netlink
/// headers for `type`, `cmd` and `version` under sequence `seq`, then what
/// `attributes` (builder) appends; finish() checks the length announced.
template <typename Attributes>
[[nodiscard]] auto build_message(
    std::span<uint8_t> const out,
    size_t const length,
    uint16_t const type,
    uint32_t const seq,
    uint8_t const cmd,
    uint8_t const version,
    Attributes const& attributes) -> StatusValue<size_t>
{
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, type, seq, cmd, version);
    attributes(b);
    return netlink::finish(b, length);
}

}  // namespace

auto build_get_family(std::span<uint8_t> const out, std::string_view const name, uint32_t const seq) -> StatusValue<size_t>
{
    if (name.empty() || name.size() > MAX_FAMILY_NAME) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    // The name travels with its NUL, as the controller expects a string attribute.
    std::array<uint8_t, MAX_FAMILY_NAME + 1> with_nul{};
    span_copy(std::span<uint8_t>{with_nul}.first(name.size()), make_const_span(name));
    size_t const length = GENL_HEADER + netlink::attribute_size(name.size() + 1);
    return build_message(out, length, GENL_CONTROLLER_ID, seq, CTRL_GETFAMILY, 1, [&](BufferSerializerBuilder& b) {
        netlink::put_attribute(b, CTRL_FAMILY_NAME, std::span<uint8_t const>{with_nul}.first(name.size() + 1));
    });
}

auto build_dev_get(std::span<uint8_t> const out, uint16_t const family_id, int const ifindex, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t LENGTH = GENL_HEADER + netlink::attribute_size(sizeof(uint32_t));
    uint32_t const index = static_cast<uint32_t>(ifindex);
    return build_message(out, LENGTH, family_id, seq, CMD_DEV_GET, FAMILY_VERSION, [&](BufferSerializerBuilder& b) {
        netlink::put_attribute(b, DEV_IFINDEX, make_const_span(index));
    });
}

auto parse_family_id(std::span<uint8_t const> const message) -> StatusValue<uint16_t>
{
    std::optional<uint16_t> id;
    auto const walked =
        genl_attributes(message, GENL_CONTROLLER_ID, CTRL_NEWFAMILY).and_then([&](std::span<uint8_t const> const attributes) {
            return netlink::walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
                return (type & netlink::TYPE_MASK) == CTRL_FAMILY_ID ? read_scalar(payload, id.emplace()) : success();
            });
        });
    return required(walked, id);
}

auto parse_dev(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<DeviceFeatures>
{
    DeviceFeatures device{};
    std::optional<uint32_t> ifindex;
    auto const walked = genl_attributes(message, family_id, CMD_DEV_GET).and_then([&](std::span<uint8_t const> const attributes) {
        return netlink::walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            return read_dev_attribute(type, payload, device, ifindex);
        });
    });
    return required(walked, ifindex).transform([&](uint32_t const index) {
        device.ifindex = static_cast<int>(index);
        return device;
    });
}

#if defined(__linux__)

//
// The client
//

auto resolve_family_id(netlink::Socket& socket, std::span<uint8_t> const reply) -> StatusValue<uint16_t>
{
    std::optional<uint16_t> id;
    auto const asked = socket.request(
        reply,
        [](std::span<uint8_t> const out, uint32_t const seq) { return build_get_family(out, FAMILY_NAME, seq); },
        [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            if (type != GENL_CONTROLLER_ID) {
                return success();
            }
            return parse_family_id(message).transform([&](uint16_t const got) { id = got; });
        });
    return required(asked, id);
}

auto NetdevClient::open() -> Status
{
    if (auto opened = socket_.open(NETLINK_GENERIC); !opened) {
        return opened;
    }
    auto const family = resolve_family_id(socket_, reply_);
    if (!family) {
        socket_.close();
        return failure(family.error());
    }
    family_id_ = *family;
    return success();
}

auto NetdevClient::features(int const ifindex) -> StatusValue<DeviceFeatures>
{
    std::optional<DeviceFeatures> device;
    auto const asked = socket_.request(
        reply_,
        [&](std::span<uint8_t> const out, uint32_t const seq) { return build_dev_get(out, family_id_, ifindex, seq); },
        [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            if (type != family_id_) {
                return success();
            }
            return parse_dev(message, family_id_).transform([&](DeviceFeatures const& got) { device = got; });
        });
    return required(asked, device);
}

auto query_xsk_features(int const ifindex) -> StatusValue<XskFeatures>
{
    NetdevClient client;
    if (auto opened = client.open(); !opened) {
        return failure(opened.error());
    }
    return client.features(ifindex).transform([](DeviceFeatures const& device) { return device.xsk; });
}

auto launch_time_supported(int const ifindex) -> StatusValue<bool>
{
    return query_xsk_features(ifindex).transform([](XskFeatures const xsk) { return xsk.launch_time(); });
}

#endif  // __linux__

}  // namespace statusbar::net::netdev
