#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Create and delete an 802.1Q VLAN link over rtnetlink.
///
/// This exists for one non-obvious reason. A NIC with `rx-vlan-filter`
/// enabled discards any frame carrying a VLAN ID that nothing has
/// registered with the hardware — in the MAC, before any socket, any BPF
/// filter or any tap sees it. On igb the feature is fixed on and
/// `ethtool -K` cannot turn it off. AVB streams are tagged, normally
/// VID 2, so an AVB listener on such a NIC receives **nothing at all**,
/// with no error and no counter moving anywhere a caller can see. It
/// looks exactly like a talker that is not sending.
///
/// The kernel registers a VID with the hardware for as long as a VLAN
/// link on that device exists. The link does not need to be up and needs
/// no address, so the fix is to create `eth0.2`, leave it down, and let
/// the real device's `ETH_P_ALL` taps and AF_XDP sockets see the tagged
/// frames as normal. Leaving it down is the behaviour we want, not an
/// oversight: bringing it up gives the host an extra interface, which may
/// pick up an address or start answering ARP.
///
/// Two layers, as in `net_tc_qdisc.hpp` and for the same reason:
///
///   1. **Pure message builders**, which write a complete netlink request
///      into a caller-supplied buffer and return its length. No socket,
///      no privilege — so the bytes we send, the part most likely to be
///      wrong, are checked in CI.
///   2. **A thin client behind an interface** (`VlanControl`), so a
///      listener's tests can record what it registered instead of
///      needing `CAP_NET_ADMIN` and a kernel whose link configuration
///      the test then has to put back.
///
/// Linux only: the module does not exist elsewhere rather than stub out.

#include "statusbar/net/net_error.hpp"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace statusbar::net::vlan {

#if defined(__linux__)

/// Covers every request this module builds. The larger of the two is the
/// create: 16 (nlmsghdr) + 16 (ifinfomsg) + 8 (IFLA_LINK) + 20
/// (IFLA_IFNAME, padded) + 24 (IFLA_LINKINFO nesting the kind and the
/// VLAN id) = 80 bytes for a 15-byte name. A request therefore lives on
/// the stack with no allocation.
inline constexpr std::size_t MAX_REQUEST_SIZE = 128;

/// IFNAMSIZ - 1: the kernel's limit on a link name, not counting the
/// terminator it insists on.
inline constexpr std::size_t MAX_LINK_NAME_LENGTH = 15;

/// 802.1Q gives both ends of the VID range a meaning that is not "a
/// VLAN": 0 marks a priority-tagged frame carrying no VLAN membership,
/// and 4095 is reserved. A link for either is a configuration mistake,
/// so the builders refuse them even though the kernel would take VID 0.
inline constexpr std::uint16_t MIN_VLAN_ID = 1;
inline constexpr std::uint16_t MAX_VLAN_ID = 4094;

/// The conventional name for a VLAN link: parent, a dot, the VID.
///
/// A link name is at most 15 bytes, and a parent name may be 15 bytes on
/// its own, so the result is sometimes a truncation. The **parent** is
/// what gets clipped and the VID is kept whole, because the VID is the
/// part that makes the name mean anything, and because a name derived
/// this way must come out the same on a later call that wants to delete
/// the link again.
///
/// Truncation is not injective: two parents sharing a prefix map to one
/// name. That is what `VlanLinkClient::add_vlan` checks for rather than
/// assuming, since adopting the wrong link is the silent failure this
/// whole module exists to prevent.
///
/// @param interface Parent interface name, e.g. "eth0".
/// @param vid VLAN id; not range-checked here, the builders do that.
/// @return The link name, or an empty string if `interface` is empty.
[[nodiscard]] auto vlan_link_name(std::string_view interface, std::uint16_t vid) -> std::string;

/// Build `ip link add link <parent> name <name> type vlan id <vid>`.
///
/// The request asks for exclusive creation (`NLM_F_EXCL`). Without it the
/// kernel treats `RTM_NEWLINK` on an existing link as a *change* and
/// would silently re-point somebody else's VLAN link at our VID.
///
/// @param out Buffer to write into; `MAX_REQUEST_SIZE` always suffices.
/// @param parent_ifindex ifindex of the real device; must be positive.
/// @param name Link name, 1..MAX_LINK_NAME_LENGTH bytes.
/// @param vid VLAN id, MIN_VLAN_ID..MAX_VLAN_ID.
/// @param seq Netlink sequence number to stamp on the request.
/// @return Bytes written, or `invalid_argument`.
[[nodiscard]] auto build_new_vlan(
    std::span<std::uint8_t> out, int parent_ifindex, std::string_view name, std::uint16_t vid, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build `ip link del <name>`, naming the link rather than its ifindex.
///
/// `ip` resolves the name to an ifindex with a separate `RTM_GETLINK`
/// first and deletes by index; the kernel accepts `IFLA_IFNAME` directly,
/// which is one round trip instead of two and leaves no window in which
/// the index could be freed and handed to a different link.
///
/// @param out Buffer to write into; `MAX_REQUEST_SIZE` always suffices.
/// @param name Link name, 1..MAX_LINK_NAME_LENGTH bytes.
/// @param seq Netlink sequence number to stamp on the request.
/// @return Bytes written, or `invalid_argument`.
[[nodiscard]] auto build_delete_link(std::span<std::uint8_t> out, std::string_view name, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// A parsed `NLMSG_ERROR`: the kernel's errno, and its extended-ack text
/// when it sent any.
struct AckResult
{
    /// 0 for a plain acknowledgement, else the errno the kernel reported.
    int error{0};

    /// `NLMSGERR_ATTR_MSG`, empty when the kernel sent none. A refusal
    /// from the 8021q driver carries real text — "8021q: VLANs not
    /// supported on device" — which is the difference between a
    /// diagnostic and a bare EOPNOTSUPP. A refusal from the permission
    /// check carries none, because it fires before any ext-ack is set.
    std::string message;
};

/// Parse an `NLMSG_ERROR` reply.
///
/// Exposed because the shape of the reply is the subtle part. The kernel
/// echoes the offending request back after the `nlmsgerr` unless it set
/// `NLM_F_CAPPED`, and the ext-ack TLVs come after all of it — so an
/// offset computed as `sizeof(nlmsgerr)` reads the echoed request's own
/// bytes as attributes. Every error reply this module provokes in
/// practice is uncapped.
///
/// @param message One complete netlink message.
/// @return The errno and text, or `invalid_argument` if it is not an
///         `NLMSG_ERROR` or is truncated.
[[nodiscard]] auto parse_ack(std::span<std::uint8_t const> message) -> StatusValue<AckResult>;

/// Whether a registration created the link or found one already there.
enum class LinkOwnership : std::uint8_t
{
    /// We made it, so we may remove it.
    created,

    /// It was already there, made by another instance or an
    /// administrator. The VID is registered, which is all the caller
    /// needed — but removing it would break whoever owns it.
    adopted,
};

/// What an existing VLAN link says about itself, read without privilege.
struct VlanLinkFacts
{
    /// The VLAN id the link registers with the parent's hardware.
    std::uint16_t vid{0};

    /// ifindex of the parent device, resolved from the name the kernel
    /// reports. 0 if the parent has since gone away.
    int parent_ifindex{0};

    /// Whether the link is administratively up. We create links down and
    /// leave them down; a link that is up is one somebody else is using.
    bool up{false};
};

/// Read a VLAN link's VID and parent, without `CAP_NET_ADMIN`.
///
/// Uses the 8021q module's own `SIOCGIFVLAN` queries, which need no
/// privilege, rather than an `RTM_GETLINK` dump and a nested-attribute
/// parse. This is how `add_vlan` decides whether a name collision is the
/// link it wanted, and how a caller can ask whether a VID is already
/// registered before trying to register it.
///
/// @param name Link name to query.
/// @return Its facts, `invalid_argument` if the device exists but is not
///         a VLAN, `no_such_device` if there is no such device, or
///         `ENAMETOOLONG` if the name could not be one.
[[nodiscard]] auto read_vlan_link(std::string_view name) -> StatusValue<VlanLinkFacts>;

/// Registering a VLAN ID, as an interface, so a listener's tests can
/// assert what it registered without touching a kernel.
class VlanControl
{
  public:
    VlanControl() = default;
    virtual ~VlanControl() = default;
    VlanControl(VlanControl const&) = delete;
    auto operator=(VlanControl const&) -> VlanControl& = delete;
    VlanControl(VlanControl&&) = delete;
    auto operator=(VlanControl&&) -> VlanControl& = delete;

    /// Ensure a VLAN link exists, and say who owns it.
    ///
    /// Success means the VID is registered with the parent's hardware,
    /// whether or not this call is what registered it. The returned
    /// ownership is what a caller must consult before removing the link
    /// at shutdown; it is returned rather than latched so there is no
    /// question of which call it refers to.
    ///
    /// A name held by a *different* VLAN link — another VID, or another
    /// parent — is a failure (`EEXIST`) rather than an adoption, with
    /// `last_message()` naming the conflict.
    [[nodiscard]] virtual auto add_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid)
        -> StatusValue<LinkOwnership> = 0;

    /// Delete a link by name. Unconditional: the ownership returned by
    /// `add_vlan` is what decides whether calling this is right.
    [[nodiscard]] virtual auto remove_link(std::string_view name) -> Status = 0;

    /// The kernel's extended-ack text for the last call, or empty.
    [[nodiscard]] virtual auto last_message() const noexcept -> std::string const& = 0;
};

/// A `VlanControl` that talks to the kernel over `NETLINK_ROUTE`.
///
/// Links the client created are removed when it is destroyed; links it
/// adopted are left alone. That asymmetry is the ownership policy, and it
/// is the reason `add_vlan` reports which happened.
class VlanLinkClient final : public VlanControl
{
  public:
    VlanLinkClient() = default;

    /// Removes every link this client created. Errors cannot be reported
    /// from here; call `remove_created_links()` first to see them.
    ~VlanLinkClient() override;

    VlanLinkClient(VlanLinkClient const&) = delete;
    auto operator=(VlanLinkClient const&) -> VlanLinkClient& = delete;
    VlanLinkClient(VlanLinkClient&&) = delete;
    auto operator=(VlanLinkClient&&) -> VlanLinkClient& = delete;

    /// Open and bind the netlink socket. Needs no privilege; the
    /// privilege is needed to write, not to ask.
    [[nodiscard]] auto open() -> Status;

    [[nodiscard]] auto add_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid)
        -> StatusValue<LinkOwnership> override;

    [[nodiscard]] auto remove_link(std::string_view name) -> Status override;

    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return last_message_; }

    /// Remove every link this client created, youngest first, and forget
    /// them. Adopted links are not touched. The destructor calls this and
    /// discards the result, so a caller who wants to know calls it first.
    [[nodiscard]] auto remove_created_links() -> Status;

    /// Links this client created and has not removed, oldest first.
    [[nodiscard]] auto created_links() const noexcept -> std::span<std::string const> { return created_; }

    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// The same question as valid(), under the name another implementation
    /// of this module gives it.
    [[nodiscard]] auto is_open() const noexcept -> bool { return valid(); }
    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }

  private:
    /// Send one built request and read its acknowledgement.
    [[nodiscard]] auto transact(std::span<std::uint8_t const> request) -> Status;

    /// Decide whether an `EEXIST` is the link we asked for.
    [[nodiscard]] auto adopt_existing(std::string_view name, int parent_ifindex, std::uint16_t vid) -> StatusValue<LinkOwnership>;

    /// Turn the kernel's answer to a create into an ownership verdict.
    [[nodiscard]] auto finish_add(Status const& status, std::string_view name, int parent_ifindex, std::uint16_t vid)
        -> StatusValue<LinkOwnership>;

    /// Whether this client created `name` and still has it.
    [[nodiscard]] auto holds(std::string_view name) const noexcept -> bool;

    [[nodiscard]] auto read_ack(std::uint32_t seq) -> Status;
    [[nodiscard]] auto apply_ack(std::span<std::uint8_t const> reply, std::uint32_t seq) -> Status;
    [[nodiscard]] auto record_ack(std::span<std::uint8_t const> message) -> Status;

    int fd_{-1};
    std::uint32_t sequence_{0};
    std::string last_message_;
    std::vector<std::string> created_;
};

#endif  // defined(__linux__)

}  // namespace statusbar::net::vlan
