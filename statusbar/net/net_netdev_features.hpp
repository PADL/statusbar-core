#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A generic-netlink client for the kernel's netdev family (Documentation/netlink/specs/netdev.yaml):
/// a device's XDP and AF_XDP features, as `ynl ... --do dev-get` reports them. Linux only.

#if defined(__linux__)

#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <optional>
#    include <span>
#    include <string>
#    include <string_view>

namespace statusbar::net::netdev {

//
// Wire constants - linux/genetlink.h, linux/netdev.h
//

/// GENL_ID_CTRL: the controller family, which resolves family names.
inline constexpr uint16_t GENL_CONTROLLER_ID = 0x10;
/// CTRL_CMD_NEWFAMILY / CTRL_CMD_GETFAMILY and their attributes.
inline constexpr uint8_t CTRL_NEWFAMILY = 1;
inline constexpr uint8_t CTRL_GETFAMILY = 3;
inline constexpr uint16_t CTRL_FAMILY_ID = 1;
inline constexpr uint16_t CTRL_FAMILY_NAME = 2;
/// The family the kernel registers as "netdev", version NETDEV_FAMILY_VERSION.
inline constexpr std::string_view FAMILY_NAME = "netdev";
inline constexpr uint8_t FAMILY_VERSION = 1;
/// NETDEV_CMD_DEV_GET and the dev attributes it answers with.
inline constexpr uint8_t CMD_DEV_GET = 1;
inline constexpr uint16_t DEV_IFINDEX = 1;
inline constexpr uint16_t DEV_XDP_FEATURES = 3;
inline constexpr uint16_t DEV_XDP_RX_METADATA_FEATURES = 5;
inline constexpr uint16_t DEV_XSK_FEATURES = 6;
/// NETDEV_XSK_FLAGS_*: the AF_XDP TX metadata a driver honours.
inline constexpr uint64_t XSK_TX_TIMESTAMP = 1;
inline constexpr uint64_t XSK_TX_CHECKSUM = 2;
inline constexpr uint64_t XSK_TX_LAUNCH_TIME_FIFO = 4;
/// NETDEV_XDP_ACT_XSK_ZEROCOPY: the driver runs AF_XDP zero-copy.
inline constexpr uint64_t XDP_ACT_XSK_ZEROCOPY = 8;

/// A device's netdev xsk-features: the AF_XDP TX metadata requests its driver honours.
struct XskFeatures
{
    uint64_t flags{0};  ///< NETDEV_XSK_FLAGS_* (0 also when the kernel predates xsk-features)

    [[nodiscard]] constexpr auto tx_timestamp() const noexcept -> bool { return (flags & XSK_TX_TIMESTAMP) != 0; }
    [[nodiscard]] constexpr auto tx_checksum() const noexcept -> bool { return (flags & XSK_TX_CHECKSUM) != 0; }
    /// XDP_TXMD_FLAGS_LAUNCH_TIME is honoured (igc, stmmac); the queue needs an offloaded ETF qdisc too.
    [[nodiscard]] constexpr auto launch_time() const noexcept -> bool { return (flags & XSK_TX_LAUNCH_TIME_FIFO) != 0; }

    auto operator==(XskFeatures const&) const noexcept -> bool = default;
};

/// One device as NETDEV_CMD_DEV_GET reports it.
struct DeviceFeatures
{
    int ifindex{0};
    uint64_t xdp_features{0};  ///< NETDEV_XDP_ACT_* (XDP_ACT_XSK_ZEROCOPY among them)
    XskFeatures xsk{};

    auto operator==(DeviceFeatures const&) const noexcept -> bool = default;
};

/// Room for either request the builders write (both are under 40 octets).
inline constexpr size_t MAX_REQUEST_SIZE = 64;
using RequestBuffer = std::array<uint8_t, MAX_REQUEST_SIZE>;

/// Build CTRL_CMD_GETFAMILY for `name` (NLM_F_REQUEST | NLM_F_ACK) into `out`: the message
/// length. invalid_argument for an empty name or one over 15 octets; BufferError when `out` is short.
[[nodiscard]] auto build_get_family(std::span<uint8_t> out, std::string_view name, uint32_t seq) -> StatusValue<size_t>;

/// Build NETDEV_CMD_DEV_GET for `ifindex` to family `family_id` (NLM_F_REQUEST | NLM_F_ACK)
/// into `out`: the message length.
[[nodiscard]] auto build_dev_get(std::span<uint8_t> out, uint16_t family_id, int ifindex, uint32_t seq) -> StatusValue<size_t>;

/// The CTRL_ATTR_FAMILY_ID of one CTRL_CMD_NEWFAMILY message (nlmsghdr + genlmsghdr +
/// attributes). bad_message when truncated, malformed, another message or without the id.
[[nodiscard]] auto parse_family_id(std::span<uint8_t const> message) -> StatusValue<uint16_t>;

/// The features in one NETDEV_CMD_DEV_GET reply of family `family_id`. bad_message when
/// truncated, malformed, another message, or without NETDEV_A_DEV_IFINDEX; absent features are 0.
[[nodiscard]] auto parse_dev(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<DeviceFeatures>;

/// A blocking NETLINK_GENERIC socket for netdev queries: each call sends one request and
/// waits (at most about a second) for its acknowledgement. Not thread-safe; not for real-time threads.
class NetdevClient
{
  public:
    /// A closed client; open() it before features().
    NetdevClient() noexcept = default;

    /// Open the socket and resolve the netdev family. Errors: the socket's errno; ENOENT
    /// when the kernel has no netdev family (before 6.3). Closed again on failure.
    [[nodiscard]] auto open() -> Status;
    /// True after a successful open().
    [[nodiscard]] auto is_open() const noexcept -> bool { return socket_.is_open(); }

    /// NETDEV_CMD_DEV_GET for `ifindex`. Errors: ENODEV for no such device, else the request's.
    [[nodiscard]] auto features(int ifindex) -> StatusValue<DeviceFeatures>;

    /// The kernel's extended-ack message for the last failed request (empty: none given).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return last_message_; }

  private:
    /// What a transaction parses from the replies before its ack.
    struct Wanted
    {
        uint16_t type{0};  ///< GENL_CONTROLLER_ID: a family id; else the netdev family: a device
        std::optional<uint16_t> family_id{};
        std::optional<DeviceFeatures> device{};
    };

    /// CTRL_CMD_GETFAMILY "netdev" into family_id_.
    [[nodiscard]] auto resolve_family() -> Status;
    /// Build one request with `build` (out, seq) -> StatusValue<size_t> under the next sequence number and transact it.
    template <typename Build>
    [[nodiscard]] auto send(Build const& build, Wanted& wanted) -> Status;
    /// Send `request` (sequence `seq`) and read up to its NLMSG_ERROR ack, parsing into `wanted`.
    [[nodiscard]] auto transact(std::span<uint8_t const> request, uint32_t seq, Wanted& wanted) -> Status;
    /// One message addressed to the transaction: its result if it ends it, else nullopt.
    [[nodiscard]] auto read_reply(
        std::span<uint8_t const> message, uint16_t type, uint16_t flags, size_t request_size, Wanted& wanted)
        -> std::optional<Status>;

    netlink::Socket socket_{};
    uint32_t seq_{0};
    uint16_t family_id_{0};
    std::string last_message_{};
    std::array<uint8_t, 4096> reply_{};  ///< family and dev-get replies are under 1 KiB
};

/// One NetdevClient query: `ifindex`'s xsk-features. Errors: NetdevClient::open()'s and features()'s.
[[nodiscard]] auto query_xsk_features(int ifindex) -> StatusValue<XskFeatures>;

}  // namespace statusbar::net::netdev

#endif  // __linux__
