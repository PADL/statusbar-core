// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// A VLAN link brought up with no address over one end of a veth pair: a group joined on it is
// reported tagged with its VID (IGMP, seen on the other end's VLAN link), and left when the
// membership closes. Needs root (it creates the pair and the links); skips without it.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/ip/ip_ipv4_address.hpp"
#    include "statusbar/net/net_interface_info.hpp"
#    include "statusbar/net/net_socket.hpp"
#    include "statusbar/net/net_vlan_link.hpp"

#    include <ifaddrs.h>
#    include <unistd.h>

#    include <array>
#    include <chrono>
#    include <cstdint>
#    include <cstdlib>
#    include <cstring>
#    include <format>
#    include <optional>
#    include <print>
#    include <string>
#    include <string_view>
#    include <thread>

#    include <arpa/inet.h>
#    include <linux/if_packet.h>
#    include <net/ethernet.h>
#    include <net/if.h>
#    include <netinet/in.h>
#    include <netinet/ip.h>
#    include <sys/socket.h>

using namespace statusbar;
using statusbar::ip::IPv4Address;

namespace {

constexpr std::string_view NEAR = "nvlveth0";
constexpr std::string_view FAR = "nvlveth1";
constexpr uint16_t VID = 2;
constexpr IPv4Address GROUP{239, 69, 233, 7};

/// The veth pair, both ends up, and the far end's VLAN link for VID (up); removed on destruction.
class VethPair
{
  public:
    VethPair()
    {
        (void)std::system(std::format("ip link del {} 2>/dev/null", NEAR).c_str());
        ok_ = std::system(std::format(
                              "ip link add {0} type veth peer name {1} && ip link set {0} up && ip link set {1} up && "
                              "ip link add link {1} name {1}.{2} type vlan id {2} && ip link set {1}.{2} up",
                              NEAR,
                              FAR,
                              VID)
                              .c_str()) == 0;
    }
    ~VethPair() { (void)std::system(std::format("ip link del {} 2>/dev/null", NEAR).c_str()); }
    VethPair(VethPair const&) = delete;
    auto operator=(VethPair const&) -> VethPair& = delete;
    VethPair(VethPair&&) = delete;
    auto operator=(VethPair&&) -> VethPair& = delete;

    [[nodiscard]] auto ok() const noexcept -> bool { return ok_; }

  private:
    bool ok_{false};
};

/// One IGMP message as received: its IP source, and the group it reports joined or left.
struct IgmpReport
{
    IPv4Address source{};
    IPv4Address group{};
    bool joined{false};
};

/// The first group record of an IGMPv3 report (RFC 3376 Section 4.2), or a v2 report or leave (RFC 2236).
auto parse_igmp(std::span<uint8_t const> const packet) -> std::optional<IgmpReport>
{
    iphdr header{};
    if (packet.size() < sizeof(header)) {
        return std::nullopt;
    }
    std::memcpy(&header, packet.data(), sizeof(header));
    auto const igmp = packet.subspan(size_t{header.ihl} * 4U);
    if (header.protocol != IPPROTO_IGMP || igmp.size() < 8) {
        return std::nullopt;
    }
    IgmpReport report{.source = IPv4Address{ntohl(header.saddr)}};
    auto const quad = [&](size_t const at) { return IPv4Address{igmp[at], igmp[at + 1], igmp[at + 2], igmp[at + 3]}; };
    if (igmp[0] == 0x16 || igmp[0] == 0x17) {  // v2 report, leave
        report.group = quad(4);
        report.joined = igmp[0] == 0x16;
        return report;
    }
    if (igmp[0] != 0x22 || igmp.size() < 16) {
        return std::nullopt;
    }
    report.group = quad(12);
    report.joined = igmp[8] == 2 || igmp[8] == 4;  // MODE_IS_EXCLUDE, CHANGE_TO_EXCLUDE_MODE (no sources: joined)
    return report;
}

/// The IPv4 packets arriving on the far end's VLAN link (an AF_PACKET socket bound to it).
class Capture
{
  public:
    explicit Capture(std::string const& interface)
        : fd_{::socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IP))}
    {
        sockaddr_ll address{};
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_IP);
        address.sll_ifindex = static_cast<int>(::if_nametoindex(interface.c_str()));
        ok_ = fd_.valid() && address.sll_ifindex != 0 &&
            ::bind(fd_.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address)) == 0;
    }

    [[nodiscard]] auto ok() const noexcept -> bool { return ok_; }

    /// The first IGMP message about GROUP within about a second.
    auto next_report() -> std::optional<IgmpReport>
    {
        std::array<uint8_t, 2048> buffer{};
        for (int i = 0; i < 100; ++i) {
            auto const n = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
            if (n <= 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
                continue;
            }
            auto const report = parse_igmp(std::span<uint8_t const>{buffer.data(), static_cast<size_t>(n)});
            if (report && report->group == GROUP) {
                return report;
            }
        }
        return std::nullopt;
    }

  private:
    net::FileDescriptor fd_;
    bool ok_{false};
};

/// Whether `name` has an IPv6 address.
auto has_ipv6_address(std::string const& name) -> bool
{
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) {
        return false;
    }
    bool found = false;
    for (auto const* entry = list; entry != nullptr; entry = entry->ifa_next) {
        found = found || (entry->ifa_addr != nullptr && entry->ifa_addr->sa_family == AF_INET6 && name == entry->ifa_name);
    }
    ::freeifaddrs(list);
    return found;
}

}  // namespace

TEST(vlan_link_veth, a_group_joined_on_an_up_vlan_link_is_reported_tagged_and_left)
{
    if (::geteuid() != 0) {
        std::println("  skipped: needs root to create veth pairs and VLAN links");
        return;
    }
    VethPair const pair;
    net::vlan::VlanLinkClient client;
    auto const parent = net::interface_index(NEAR);
    if (!pair.ok() || !client.open() || !parent) {
        std::println("  skipped: cannot create a veth pair with a VLAN link");
        return;
    }
    std::string const link = net::vlan::vlan_link_name(NEAR, VID);
    Capture capture{net::vlan::vlan_link_name(FAR, VID)};
    EXPECT_TRUE(capture.ok());
    EXPECT_TRUE(client.add_vlan(*parent, link, VID).has_value());
    EXPECT_TRUE(client.bring_up(link).has_value());
    EXPECT_FALSE(has_ipv6_address(link));
    auto const index = net::interface_index(link);
    EXPECT_TRUE(index.has_value());
    if (!index) {
        return;
    }
    auto membership = net::open_group_membership(GROUP, static_cast<unsigned int>(*index));
    EXPECT_TRUE(membership.has_value());
    auto const joined = capture.next_report();
    EXPECT_TRUE(joined && joined->joined);
    // An address-less link reports from 0.0.0.0 under IGMPv3 (RFC 3376 Section 4.2.13).
    EXPECT_TRUE(joined && joined->source == IPv4Address{});
    membership = net::FileDescriptor{};
    std::optional<IgmpReport> left;
    for (int i = 0; i < 3 && (!left || left->joined); ++i) {
        left = capture.next_report();  // past the join's retransmissions
    }
    EXPECT_TRUE(left && !left->joined);
    EXPECT_TRUE(client.remove_link(link).has_value());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_vlan_link_veth_test)
