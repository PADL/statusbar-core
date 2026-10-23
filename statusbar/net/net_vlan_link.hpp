#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_vlan_link.hpp
/// @brief Create and delete an 802.1Q VLAN link over rtnetlink, the way
/// `ip link add link <if> name <if>.<vid> type vlan id <vid>` and `ip link del
/// <name>` do, without libnl or iproute2.
///
/// What it is for: registering a VID with a NIC's receive VLAN filter. A NIC
/// with rx-vlan-filter on (igb's is fixed on) drops frames tagged with a VID
/// nobody registered, before any socket sees them. The kernel registers a VID
/// (ndo_vlan_rx_add_vid) when a VLAN link on it is registered, whether or not
/// the link is up, and unregisters it when the last such link is deleted. The
/// link is left down: a down VLAN link takes no addresses and, for frames on
/// its VID, only the real device's ETH_P_ALL taps (packet sockets bound to
/// it) see them.
///
/// Two layers, as net_tc_qdisc's: pure builders (build_new_vlan,
/// build_delete_link) writing one RTM_NEWLINK / RTM_DELLINK request into a
/// caller buffer (socket-free, unit-tested against hand-checked bytes), and
/// VlanLinkClient, which sends them over a tc::TcClient's NETLINK_ROUTE
/// socket. It implements VlanControl, the interface a caller takes so tests
/// can record requests.
///
/// Needs CAP_NET_ADMIN, and the 8021q module (the kernel loads it on demand,
/// as rtnl-link-vlan). Linux only.

#if defined(__linux__)

#    include "statusbar/net/net_tc_qdisc.hpp"
#    include "statusbar/status/status.hpp"

#    include <cstddef>
#    include <cstdint>
#    include <span>
#    include <string>
#    include <string_view>

namespace statusbar::net::vlan {

/// The longest interface name (IFNAMSIZ - 1).
inline constexpr size_t MAX_LINK_NAME = 15;

/// The VLAN link's name for @p vid on @p interface: `<interface>.<vid>` (ip's
/// and vconfig's convention), with @p interface cut short when the whole would
/// pass MAX_LINK_NAME.
[[nodiscard]] auto vlan_link_name(std::string_view interface, uint16_t vid) -> std::string;

/// Build `ip link add link <parent> name <name> type vlan id <vid>`
/// (RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL: an
/// existing link of that name, or of that VID on the parent, is EEXIST) into
/// @p out. Returns the message length. Errors: invalid_argument for a parent
/// ifindex of 0 or less, an empty name or one over MAX_LINK_NAME, or a VID
/// outside 1..4094; BufferError::insufficient_space when @p out is too small.
[[nodiscard]] auto build_new_vlan(std::span<uint8_t> out, int parent_ifindex, std::string_view name, uint16_t vid, uint32_t seq)
    -> StatusValue<size_t>;

/// Build `ip link del <name>` (RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, the link
/// named by IFLA_IFNAME) into @p out. Returns the message length. Errors:
/// invalid_argument for an empty name or one over MAX_LINK_NAME.
[[nodiscard]] auto build_delete_link(std::span<uint8_t> out, std::string_view name, uint32_t seq) -> StatusValue<size_t>;

/// The link requests a caller makes (VlanLinkClient in a host; a recorder in tests).
class VlanControl
{
  public:
    virtual ~VlanControl() = default;

    /// Create VLAN link @p name for @p vid on @p parent_ifindex. Errors: the
    /// netlink errno (EEXIST: that name, or that VID on the parent, is already
    /// there; EPERM without CAP_NET_ADMIN).
    [[nodiscard]] virtual auto add_vlan(int parent_ifindex, std::string_view name, uint16_t vid) -> Status = 0;
    /// Delete link @p name. Errors: the netlink errno (ENODEV: no such link).
    [[nodiscard]] virtual auto remove_link(std::string_view name) -> Status = 0;
    /// The kernel's extended-ack message for the last failed request.
    [[nodiscard]] virtual auto last_message() const noexcept -> std::string const& = 0;

  protected:
    VlanControl() noexcept = default;
};

/// VlanControl over a blocking NETLINK_ROUTE socket (a tc::TcClient's). Not
/// thread-safe; meant for the reactor thread.
class VlanLinkClient final : public VlanControl
{
  public:
    VlanLinkClient() noexcept = default;

    /// Open and bind the socket. Errors: the socket's errno.
    [[nodiscard]] auto open() noexcept -> Status { return rtnl_.open(); }
    [[nodiscard]] auto is_open() const noexcept -> bool { return rtnl_.is_open(); }

    [[nodiscard]] auto add_vlan(int parent_ifindex, std::string_view name, uint16_t vid) -> Status override;
    [[nodiscard]] auto remove_link(std::string_view name) -> Status override;
    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return rtnl_.last_message(); }

  private:
    tc::TcClient rtnl_{};
};

}  // namespace statusbar::net::vlan

#endif  // __linux__
