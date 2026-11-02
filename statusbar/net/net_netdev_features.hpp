#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A generic-netlink client for the kernel's netdev family
/// (Documentation/netlink/specs/netdev.yaml): what a device's driver can do
/// for XDP and AF_XDP, as `ynl --family netdev --do dev-get` reports it, and
/// the one question this tree asks of it - whether the NIC honours a launch
/// time in an AF_XDP frame's TX metadata.
///
/// The framing (constants, builders, parsers) builds everywhere and is tested
/// against captured replies on any host; the client that talks to the kernel
/// is Linux only. XdpContext::open() asks the same question of the same
/// family for its own XdpConfig::tx_launch_time; launch_time_supported() is
/// the standalone form, to ask once per device and hand the answer to every
/// user of the queue (the stream socket, the shaper).

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/net/net_netlink.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace statusbar::net::netdev {

//
// Wire constants - linux/genetlink.h and linux/netdev.h, checked against them
// on Linux where the headers have them
//

/// GENL_ID_CTRL: the generic-netlink controller, which resolves a family's
/// name to the id the kernel gave it (NLMSG_MIN_TYPE).
inline constexpr uint16_t GENL_CONTROLLER_ID = 0x10;
/// CTRL_CMD_NEWFAMILY (the controller's answer) and CTRL_CMD_GETFAMILY (the question).
inline constexpr uint8_t CTRL_NEWFAMILY = 1;
inline constexpr uint8_t CTRL_GETFAMILY = 3;
/// CTRL_ATTR_FAMILY_ID (u16) and CTRL_ATTR_FAMILY_NAME (a NUL-terminated string).
inline constexpr uint16_t CTRL_FAMILY_ID = 1;
inline constexpr uint16_t CTRL_FAMILY_NAME = 2;
/// GENL_NAMSIZ less the NUL: the longest family name.
inline constexpr size_t MAX_FAMILY_NAME = 15;
/// NETDEV_FAMILY_NAME and NETDEV_FAMILY_VERSION.
inline constexpr std::string_view FAMILY_NAME = "netdev";
inline constexpr uint8_t FAMILY_VERSION = 1;
/// NETDEV_CMD_DEV_GET, and the NETDEV_A_DEV_* attributes its reply carries.
inline constexpr uint8_t CMD_DEV_GET = 1;
inline constexpr uint16_t DEV_IFINDEX = 1;                   ///< u32
inline constexpr uint16_t DEV_XDP_FEATURES = 3;              ///< u64, NETDEV_XDP_ACT_*
inline constexpr uint16_t DEV_XDP_ZC_MAX_SEGS = 4;           ///< u32
inline constexpr uint16_t DEV_XDP_RX_METADATA_FEATURES = 5;  ///< u64, NETDEV_XDP_RX_METADATA_*
inline constexpr uint16_t DEV_XSK_FEATURES = 6;              ///< u64, NETDEV_XSK_FLAGS_* (Linux 6.8)
/// NETDEV_XSK_FLAGS_*: the AF_XDP TX metadata requests the driver honours.
inline constexpr uint64_t XSK_TX_TIMESTAMP = 1;         ///< XDP_TXMD_FLAGS_TIMESTAMP (6.8)
inline constexpr uint64_t XSK_TX_CHECKSUM = 2;          ///< XDP_TXMD_FLAGS_CHECKSUM (6.8)
inline constexpr uint64_t XSK_TX_LAUNCH_TIME_FIFO = 4;  ///< XDP_TXMD_FLAGS_LAUNCH_TIME (6.15)

/// A device's xsk-features: which AF_XDP TX metadata requests its driver acts on.
struct XskFeatures
{
    /// NETDEV_XSK_FLAGS_*; 0 when the driver honours none, and also when the
    /// kernel predates the attribute (6.8) and so reports none.
    uint64_t flags{0};

    [[nodiscard]] constexpr auto tx_timestamp() const noexcept -> bool { return (flags & XSK_TX_TIMESTAMP) != 0; }
    [[nodiscard]] constexpr auto tx_checksum() const noexcept -> bool { return (flags & XSK_TX_CHECKSUM) != 0; }
    /// The driver acts on XDP_TXMD_FLAGS_LAUNCH_TIME (igc and stmmac, so far).
    /// The queue still needs an ETF qdisc offloaded to it for the NIC to hold
    /// the frame until then (net_tc_launch_time.hpp lays one).
    [[nodiscard]] constexpr auto launch_time() const noexcept -> bool { return (flags & XSK_TX_LAUNCH_TIME_FIFO) != 0; }

    [[nodiscard]] constexpr auto operator==(XskFeatures const&) const noexcept -> bool = default;
};

/// One device as NETDEV_CMD_DEV_GET reports it. An attribute the kernel did not
/// send reads as 0.
struct DeviceFeatures
{
    int ifindex{0};
    uint64_t xdp_features{0};     ///< NETDEV_XDP_ACT_*: the XDP program actions the driver supports
    uint64_t xdp_rx_metadata{0};  ///< NETDEV_XDP_RX_METADATA_*: the RX hints the driver fills
    XskFeatures xsk{};

    [[nodiscard]] constexpr auto operator==(DeviceFeatures const&) const noexcept -> bool = default;
};

/// Room for any request the builders write (both are under 48 octets).
inline constexpr size_t MAX_REQUEST_SIZE = netlink::MAX_REQUEST_SIZE;
using RequestBuffer = netlink::RequestBuffer;

/// sizeof(struct genlmsghdr): cmd (u8), version (u8), reserved (u16).
inline constexpr size_t GENL_MESSAGE_HEADER = 4;
/// Where a generic-netlink message's attributes start: after the nlmsghdr and the genlmsghdr.
inline constexpr size_t GENL_HEADER = netlink::MESSAGE_HEADER + GENL_MESSAGE_HEADER;

//
// Framing
//

/// Append a struct nlmsghdr (NLM_F_REQUEST | NLM_F_ACK, `length` octets in all,
/// nlmsg_type `type`, sequence `seq`) and a struct genlmsghdr for `cmd` at `version`.
void put_genl_header(BufferSerializerBuilder& b, size_t length, uint16_t type, uint32_t seq, uint8_t cmd, uint8_t version);

/// The attributes of one generic-netlink message, when it is of nlmsg_type
/// `type` and command `cmd` and its nlmsg_len fits what was handed over;
/// bad_message otherwise.
[[nodiscard]] auto genl_attributes(std::span<uint8_t const> message, uint16_t type, uint8_t cmd)
    -> StatusValue<std::span<uint8_t const>>;

/// CTRL_CMD_GETFAMILY for the family called `name`, written into `out`: the
/// message's length. invalid_argument for an empty name or one longer than
/// MAX_FAMILY_NAME; the buffer's error when `out` is too short.
[[nodiscard]] auto build_get_family(std::span<uint8_t> out, std::string_view name, uint32_t seq) -> StatusValue<size_t>;

/// NETDEV_CMD_DEV_GET for `ifindex`, addressed to family `family_id`, written
/// into `out`: the message's length.
[[nodiscard]] auto build_dev_get(std::span<uint8_t> out, uint16_t family_id, int ifindex, uint32_t seq) -> StatusValue<size_t>;

/// The CTRL_ATTR_FAMILY_ID in one CTRL_CMD_NEWFAMILY message (nlmsghdr,
/// genlmsghdr, attributes). bad_message when it is truncated, malformed,
/// another message, or carries no id.
[[nodiscard]] auto parse_family_id(std::span<uint8_t const> message) -> StatusValue<uint16_t>;

/// The device in one NETDEV_CMD_DEV_GET reply of family `family_id`.
/// bad_message when it is truncated, malformed, another message, or carries no
/// NETDEV_A_DEV_IFINDEX; a feature attribute that is absent reads as 0.
[[nodiscard]] auto parse_dev(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<DeviceFeatures>;

#if defined(__linux__)

//
// The client - Linux only
//

/// CTRL_CMD_GETFAMILY "netdev" over `socket` (open on NETLINK_GENERIC), its
/// replies read into `reply`: the family's id. Errors: the request's; ENOENT
/// when the kernel has no netdev family (before 6.3).
[[nodiscard]] auto resolve_family_id(netlink::Socket& socket, std::span<uint8_t> reply) -> StatusValue<uint16_t>;

/// A NETLINK_GENERIC socket for netdev queries: open() resolves the family,
/// then each features() sends one request and waits (about a second at most)
/// for its acknowledgement. Not thread-safe; not for a real-time thread.
class NetdevClient
{
  public:
    /// Closed; open() it before features().
    NetdevClient() noexcept = default;

    /// Open the socket and resolve the netdev family. Errors: the socket's
    /// errno; ENOENT when the kernel has no netdev family (before 6.3). The
    /// client is closed again on failure.
    [[nodiscard]] auto open() -> Status;

    /// True after a successful open(), until close().
    [[nodiscard]] auto is_open() const noexcept -> bool { return socket_.is_open(); }

    /// Close the socket; a no-op when closed.
    void close() noexcept { socket_.close(); }

    /// NETDEV_CMD_DEV_GET for `ifindex`. Errors: ENODEV for no such device,
    /// else the request's; bad_message for an acknowledgement with no reply.
    [[nodiscard]] auto features(int ifindex) -> StatusValue<DeviceFeatures>;

    /// The netdev family's id as open() resolved it (0 when closed).
    [[nodiscard]] auto family_id() const noexcept -> uint16_t { return family_id_; }

    /// One request built by `build` (out, seq), each netdev reply handed to `parse` (message) -> Status.
    /// Errors: the socket's request()'s.
    template <typename Build, typename Parse>
    [[nodiscard]] auto request(Build const& build, Parse const& parse) -> Status
    {
        return socket_.request(reply_, build, [&](std::span<uint8_t const> const message, uint16_t const type) -> Status {
            return type == family_id_ ? parse(message) : success();
        });
    }

    /// The kernel's extended-ack reason for the last request that failed (empty: none given).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return socket_.last_message(); }

  private:
    netlink::Socket socket_{};
    uint16_t family_id_{0};
    std::array<uint8_t, 4096> reply_{};  ///< a family and a dev-get reply are each well under 1 KiB
};

/// One query: `ifindex`'s xsk-features, through a client opened and closed for
/// it. Errors: NetdevClient::open()'s and features()'s.
[[nodiscard]] auto query_xsk_features(int ifindex) -> StatusValue<XskFeatures>;

/// Whether `ifindex`'s driver acts on an AF_XDP launch time
/// (NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO): the one netdev question this tree
/// asks, to ask once per device and hand to every user of its queues. A
/// kernel before 6.15 has no such flag and answers false, which is also what
/// it does with a launch time. Errors: query_xsk_features()'s.
[[nodiscard]] auto launch_time_supported(int ifindex) -> StatusValue<bool>;

#endif  // __linux__

}  // namespace statusbar::net::netdev
