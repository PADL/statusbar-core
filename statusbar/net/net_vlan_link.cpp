// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_vlan_link.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"

#    include <cstddef>
#    include <system_error>

#    include <linux/if_link.h>
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <net/if.h>
#    include <sys/socket.h>

namespace statusbar::net::vlan {

// The layouts the builders write field by field.
static_assert(sizeof(nlmsghdr) == 16);
static_assert(sizeof(ifinfomsg) == 16);
static_assert(offsetof(ifinfomsg, ifi_index) == 4 && offsetof(ifinfomsg, ifi_change) == 12);
static_assert(sizeof(rtattr) == 4);
static_assert(MAX_LINK_NAME + 1 == IFNAMSIZ);

namespace {

constexpr size_t NLMSG_HEADER = sizeof(nlmsghdr);
constexpr size_t IFINFO_SIZE = sizeof(ifinfomsg);
constexpr size_t RTA_HEADER = sizeof(rtattr);
constexpr uint16_t NEW_FLAGS = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
constexpr uint16_t DELETE_FLAGS = NLM_F_REQUEST | NLM_F_ACK;
constexpr uint16_t MAX_VID = 4094;
constexpr std::string_view KIND = "vlan";

[[nodiscard]] constexpr auto align4(size_t const n) noexcept -> size_t
{
    return RTA_ALIGN(n);
}

/// A NUL-terminated string attribute, padded to 4.
[[nodiscard]] constexpr auto string_size(std::string_view const s) noexcept -> size_t
{
    return align4(RTA_HEADER + s.size() + 1);
}

void put_rta(BufferSerializerBuilder& b, size_t const payload, uint16_t const type)
{
    b.append(static_cast<uint16_t>(RTA_HEADER + payload)).append(type);
}

void put_string(BufferSerializerBuilder& b, uint16_t const type, std::string_view const s)
{
    put_rta(b, s.size() + 1, type);
    for (char const c : s) {
        b.append(static_cast<uint8_t>(c));
    }
    for (size_t i = RTA_HEADER + s.size(); i < string_size(s); ++i) {
        b.append(uint8_t{0});  // the NUL, then the padding
    }
}

void put_header(BufferSerializerBuilder& b, size_t const length, uint16_t const type, uint16_t const flags, uint32_t const seq)
{
    b.append(static_cast<uint32_t>(length)).append(type).append(flags).append(seq).append(uint32_t{0});  // nlmsg_pid: the kernel
    // ifinfomsg: family AF_UNSPEC, pad, type 0, index 0 (the link is named), flags 0, change 0.
    b.append(uint8_t{AF_UNSPEC}).append(uint8_t{0}).append(uint16_t{0}).append(int32_t{0}).append(uint32_t{0}).append(uint32_t{0});
}

[[nodiscard]] auto valid_name(std::string_view const name) noexcept -> bool
{
    return !name.empty() && name.size() <= MAX_LINK_NAME;
}

[[nodiscard]] auto finish(BufferSerializerBuilder const& b, size_t const expected) -> StatusValue<size_t>
{
    if (b.error()) {
        return failure(b.error());
    }
    if (b.position() != expected) {  // a builder's length arithmetic is wrong
        return failure(std::make_error_code(std::errc::message_size));
    }
    return expected;
}

}  // namespace

auto vlan_link_name(std::string_view const interface, uint16_t const vid) -> std::string
{
    std::string const suffix = "." + std::to_string(vid);
    std::string name{interface.substr(0, MAX_LINK_NAME - suffix.size())};
    name += suffix;
    return name;
}

auto build_new_vlan(
    std::span<uint8_t> const out, int const parent_ifindex, std::string_view const name, uint16_t const vid, uint32_t const seq)
    -> StatusValue<size_t>
{
    if (parent_ifindex <= 0 || !valid_name(name) || vid == 0 || vid > MAX_VID) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    constexpr size_t LINK = RTA_HEADER + sizeof(uint32_t);
    constexpr size_t VLAN_ID = align4(RTA_HEADER + sizeof(uint16_t));
    constexpr size_t INFO_DATA = RTA_HEADER + VLAN_ID;
    constexpr size_t LINKINFO = RTA_HEADER + string_size(KIND) + INFO_DATA;
    size_t const length = NLMSG_HEADER + IFINFO_SIZE + string_size(name) + LINK + LINKINFO;

    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_header(b, length, RTM_NEWLINK, NEW_FLAGS, seq);
    put_string(b, IFLA_IFNAME, name);
    put_rta(b, sizeof(uint32_t), IFLA_LINK);
    b.append(static_cast<uint32_t>(parent_ifindex));
    // IFLA_LINKINFO nests IFLA_INFO_KIND "vlan" and IFLA_INFO_DATA, which
    // nests IFLA_VLAN_ID (iproute2's iplink.c and iplink_vlan.c).
    put_rta(b, LINKINFO - RTA_HEADER, IFLA_LINKINFO);
    put_string(b, IFLA_INFO_KIND, KIND);
    put_rta(b, INFO_DATA - RTA_HEADER, IFLA_INFO_DATA);
    put_rta(b, sizeof(uint16_t), IFLA_VLAN_ID);
    b.append(vid).append(uint16_t{0});  // the VID, then the padding
    return finish(b, length);
}

auto build_delete_link(std::span<uint8_t> const out, std::string_view const name, uint32_t const seq) -> StatusValue<size_t>
{
    if (!valid_name(name)) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    size_t const length = NLMSG_HEADER + IFINFO_SIZE + string_size(name);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_header(b, length, RTM_DELLINK, DELETE_FLAGS, seq);
    put_string(b, IFLA_IFNAME, name);
    return finish(b, length);
}

auto VlanLinkClient::add_vlan(int const parent_ifindex, std::string_view const name, uint16_t const vid) -> Status
{
    return rtnl_.request(
        [&](std::span<uint8_t> out, uint32_t seq) { return build_new_vlan(out, parent_ifindex, name, vid, seq); });
}

auto VlanLinkClient::remove_link(std::string_view const name) -> Status
{
    return rtnl_.request([&](std::span<uint8_t> out, uint32_t seq) { return build_delete_link(out, name, seq); });
}

}  // namespace statusbar::net::vlan

#endif  // __linux__
