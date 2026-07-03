// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for IP module
// Tests IPv4, IPv6, and UDP protocol headers

#include "statusbar/ip/ip.hpp"

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <print>
#include <span>
#include <string>

using namespace statusbar;
using namespace statusbar::ip;

// IPv4Address tests

TEST(ipv4_address, default_constructor)
{
    IPv4Address addr;
    EXPECT_TRUE(addr.is_unspecified());
    EXPECT_EQ(addr.to_uint32(), 0U);
}

TEST(ipv4_address, octet_constructor)
{
    IPv4Address addr(192, 168, 1, 1);
    EXPECT_EQ(addr.octet(0), 192);
    EXPECT_EQ(addr.octet(1), 168);
    EXPECT_EQ(addr.octet(2), 1);
    EXPECT_EQ(addr.octet(3), 1);
    EXPECT_EQ(addr.to_uint32(), 0xC0A80101U);
}

TEST(ipv4_address, uint32_constructor)
{
    IPv4Address addr(0xC0A80101U);  // 192.168.1.1
    EXPECT_EQ(addr.octet(0), 192);
    EXPECT_EQ(addr.octet(1), 168);
    EXPECT_EQ(addr.octet(2), 1);
    EXPECT_EQ(addr.octet(3), 1);
}

TEST(ipv4_address, loopback)
{
    IPv4Address addr(127, 0, 0, 1);
    EXPECT_TRUE(addr.is_loopback());
    EXPECT_FALSE(addr.is_unspecified());
    EXPECT_FALSE(addr.is_multicast());
}

TEST(ipv4_address, multicast)
{
    IPv4Address addr(224, 0, 0, 1);
    EXPECT_TRUE(addr.is_multicast());
    EXPECT_FALSE(addr.is_loopback());
}

TEST(ipv4_address, broadcast)
{
    IPv4Address addr(255, 255, 255, 255);
    EXPECT_TRUE(addr.is_broadcast());
}

TEST(ipv4_address, private_10)
{
    IPv4Address addr(10, 0, 0, 1);
    EXPECT_TRUE(addr.is_private());
}

TEST(ipv4_address, private_172)
{
    IPv4Address addr(172, 16, 0, 1);
    EXPECT_TRUE(addr.is_private());

    IPv4Address addr2(172, 31, 255, 255);
    EXPECT_TRUE(addr2.is_private());

    IPv4Address addr3(172, 15, 0, 1);
    EXPECT_FALSE(addr3.is_private());
}

TEST(ipv4_address, private_192)
{
    IPv4Address addr(192, 168, 0, 1);
    EXPECT_TRUE(addr.is_private());
}

TEST(ipv4_address, comparison)
{
    IPv4Address a(192, 168, 1, 1);
    IPv4Address b(192, 168, 1, 1);
    IPv4Address c(192, 168, 1, 2);

    EXPECT_TRUE(a == b);
    EXPECT_TRUE(a != c);
    EXPECT_TRUE(a < c);
}

TEST(ipv4_address, static_size)
{
    EXPECT_EQ(IPv4Address::size(), 4U);
}

TEST(ipv4_address, span_const)
{
    IPv4Address const addr(192, 168, 1, 1);
    auto s = addr.span();
    EXPECT_EQ(s.size(), 4U);
    // Network byte order: 192.168.1.1 = 0xC0A80101
    EXPECT_EQ(s[0], 192);
    EXPECT_EQ(s[1], 168);
    EXPECT_EQ(s[2], 1);
    EXPECT_EQ(s[3], 1);
}

TEST(ipv4_address, span_mutable)
{
    IPv4Address addr(192, 168, 1, 1);
    auto s = addr.span();
    EXPECT_EQ(s.size(), 4U);
    // Modify through span
    s[3] = 100;
    EXPECT_EQ(addr.octet(3), 100);
}

TEST(ipv4_address, serialization)
{
    IPv4Address addr(192, 168, 1, 1);
    std::array<uint8_t, 4> buf{};
    auto stored = store_unchecked(buf, addr);
    EXPECT_EQ(stored, 4U);
    EXPECT_EQ(buf[0], 192);
    EXPECT_EQ(buf[1], 168);
    EXPECT_EQ(buf[2], 1);
    EXPECT_EQ(buf[3], 1);

    IPv4Address loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 4U);
    EXPECT_TRUE(loaded == addr);
}

TEST(ipv4_address, assignment)
{
    IPv4Address a(192, 168, 1, 1);
    IPv4Address b;
    b = a;
    EXPECT_TRUE(a == b);

    IPv4Address c;
    c = std::move(a);
    EXPECT_TRUE(c == b);
}

// IPv4Header tests

TEST(ipv4_header, default_constructor)
{
    IPv4Header hdr;
    EXPECT_EQ(sizeof(hdr), 20U);
}

TEST(ipv4_header, init)
{
    IPv4Header hdr;
    hdr.init(IPv4Header::PROTOCOL_UDP, 100);

    EXPECT_EQ(hdr.version(), 4);
    EXPECT_EQ(hdr.ihl(), 5);
    EXPECT_EQ(hdr.header_length(), 20U);
    EXPECT_EQ(hdr.protocol.get(), IPv4Header::PROTOCOL_UDP);
    EXPECT_EQ(hdr.total_length.get(), 120U);  // 20 + 100
    EXPECT_EQ(hdr.ttl.get(), 64);
    EXPECT_TRUE(hdr.dont_fragment());
}

TEST(ipv4_header, version_ihl)
{
    IPv4Header hdr;
    hdr.set_version(4);
    hdr.set_ihl(5);

    EXPECT_EQ(hdr.version(), 4);
    EXPECT_EQ(hdr.ihl(), 5);
    EXPECT_EQ(hdr.version_ihl.get(), 0x45);
}

TEST(ipv4_header, payload_length_underflow_guard)
{
    IPv4Header hdr;
    hdr.set_version(4);
    hdr.set_ihl(5);  // header_length() == 20
    // Malformed: total_length < header_length must NOT wrap to a huge uint16.
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(10);
    EXPECT_EQ(hdr.payload_length(), 0U);
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(120);
    EXPECT_EQ(hdr.payload_length(), 100U);
}

TEST(ipv4_header, dscp_ecn)
{
    IPv4Header hdr;
    hdr.set_dscp(0x2E);  // EF DSCP
    hdr.set_ecn(0x01);

    EXPECT_EQ(hdr.dscp(), 0x2E);
    EXPECT_EQ(hdr.ecn(), 0x01);
}

TEST(ipv4_header, flags_fragment)
{
    IPv4Header hdr;
    hdr.set_flags(0x02);  // Don't fragment
    hdr.set_fragment_offset(0x1000);

    EXPECT_EQ(hdr.flags(), 0x02);
    EXPECT_TRUE(hdr.dont_fragment());
    EXPECT_FALSE(hdr.more_fragments());
    EXPECT_EQ(hdr.fragment_offset(), 0x1000);
}

TEST(ipv4_header, payload_length)
{
    IPv4Header hdr;
    hdr.init(IPv4Header::PROTOCOL_TCP, 1000);

    EXPECT_EQ(hdr.payload_length(), 1000);
}

TEST(ipv4_header, serialization)
{
    IPv4Header hdr;
    hdr.init(IPv4Header::PROTOCOL_UDP, 100);
    hdr.src_addr = IPv4Address(192, 168, 1, 1);
    hdr.dst_addr = IPv4Address(192, 168, 1, 2);

    std::array<uint8_t, 20> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 20U);

    IPv4Header loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 20U);

    EXPECT_EQ(loaded.version(), 4);
    EXPECT_EQ(loaded.ihl(), 5);
    EXPECT_EQ(loaded.protocol.get(), IPv4Header::PROTOCOL_UDP);
    EXPECT_TRUE(loaded.src_addr == hdr.src_addr);
    EXPECT_TRUE(loaded.dst_addr == hdr.dst_addr);
}

TEST(ipv4_header, can_load)
{
    std::array<uint8_t, 20> buf{};
    IPv4Header hdr;

    auto result = statusbar::protocol::can_load(buf, &hdr);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 20U);

    std::array<uint8_t, 19> small_buf{};
    auto fail_result = statusbar::protocol::can_load(small_buf, &hdr);
    EXPECT_FALSE(fail_result.has_value());
}

// IPv6Address tests

TEST(ipv6_address, default_constructor)
{
    IPv6Address addr;
    EXPECT_TRUE(addr.is_unspecified());
}

TEST(ipv6_address, word_constructor)
{
    IPv6Address addr(0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
    EXPECT_EQ(addr.word(0), 0x2001);
    EXPECT_EQ(addr.word(1), 0x0db8);
    EXPECT_EQ(addr.word(7), 0x0001);
}

TEST(ipv6_address, loopback)
{
    IPv6Address addr(0, 0, 0, 0, 0, 0, 0, 1);
    EXPECT_TRUE(addr.is_loopback());
    EXPECT_FALSE(addr.is_unspecified());
}

TEST(ipv6_address, multicast)
{
    IPv6Address addr(0xFF02, 0, 0, 0, 0, 0, 0, 1);  // All nodes link-local
    EXPECT_TRUE(addr.is_multicast());
}

TEST(ipv6_address, link_local)
{
    IPv6Address addr(0xFE80, 0, 0, 0, 0, 0, 0, 1);
    EXPECT_TRUE(addr.is_link_local());
}

TEST(ipv6_address, unique_local)
{
    IPv6Address addr(0xFC00, 0, 0, 0, 0, 0, 0, 1);
    EXPECT_TRUE(addr.is_unique_local());
}

TEST(ipv6_address, ipv4_mapped)
{
    // ::ffff:192.168.1.1
    IPv6Address addr(0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0101);
    EXPECT_TRUE(addr.is_ipv4_mapped());
}

TEST(ipv6_address, comparison)
{
    IPv6Address a(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    IPv6Address b(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    IPv6Address c(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    EXPECT_TRUE(a == b);
    EXPECT_TRUE(a != c);
    EXPECT_TRUE(a < c);
}

TEST(ipv6_address, static_size)
{
    EXPECT_EQ(IPv6Address::size(), 16U);
}

TEST(ipv6_address, span_const)
{
    IPv6Address const addr(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    auto s = addr.span();
    EXPECT_EQ(s.size(), 16U);
    EXPECT_EQ(s[0], 0x20);
    EXPECT_EQ(s[1], 0x01);
    EXPECT_EQ(s[14], 0x00);
    EXPECT_EQ(s[15], 0x01);
}

TEST(ipv6_address, span_mutable)
{
    IPv6Address addr;
    auto s = addr.span();
    s[15] = 1;
    EXPECT_TRUE(addr.is_loopback());
}

TEST(ipv6_address, serialization)
{
    IPv6Address addr(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    std::array<uint8_t, 16> buf{};
    auto stored = store_unchecked(buf, addr);
    EXPECT_EQ(stored, 16U);
    EXPECT_EQ(buf[0], 0x20);
    EXPECT_EQ(buf[1], 0x01);
    EXPECT_EQ(buf[15], 0x01);

    IPv6Address loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 16U);
    EXPECT_TRUE(loaded == addr);
}

// IPv6Header tests

TEST(ipv6_header, default_constructor)
{
    IPv6Header hdr;
    EXPECT_EQ(sizeof(hdr), 40U);
}

TEST(ipv6_header, init)
{
    IPv6Header hdr;
    hdr.init(IPv6Header::NEXT_HEADER_UDP, 100);

    EXPECT_EQ(hdr.version(), 6);
    EXPECT_EQ(hdr.next_header.get(), IPv6Header::NEXT_HEADER_UDP);
    EXPECT_EQ(hdr.payload_length.get(), 100);
    EXPECT_EQ(hdr.hop_limit.get(), 64);
}

TEST(ipv6_header, version)
{
    IPv6Header hdr;
    hdr.set_version(6);
    EXPECT_EQ(hdr.version(), 6);
}

TEST(ipv6_header, traffic_class)
{
    IPv6Header hdr;
    hdr.set_traffic_class(0xAB);
    EXPECT_EQ(hdr.traffic_class(), 0xAB);
}

TEST(ipv6_header, flow_label)
{
    IPv6Header hdr;
    hdr.set_flow_label(0x12345);
    EXPECT_EQ(hdr.flow_label(), 0x12345);
}

TEST(ipv6_header, serialization)
{
    IPv6Header hdr;
    hdr.init(IPv6Header::NEXT_HEADER_UDP, 100);
    hdr.src_addr = IPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    hdr.dst_addr = IPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    std::array<uint8_t, 40> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 40U);

    IPv6Header loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 40U);

    EXPECT_EQ(loaded.version(), 6);
    EXPECT_EQ(loaded.next_header.get(), IPv6Header::NEXT_HEADER_UDP);
    EXPECT_TRUE(loaded.src_addr == hdr.src_addr);
    EXPECT_TRUE(loaded.dst_addr == hdr.dst_addr);
}

TEST(ipv6_header, can_load)
{
    std::array<uint8_t, 40> buf{};
    IPv6Header hdr;

    auto result = statusbar::protocol::can_load(buf, &hdr);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 40U);

    std::array<uint8_t, 39> small_buf{};
    auto fail_result = statusbar::protocol::can_load(small_buf, &hdr);
    EXPECT_FALSE(fail_result.has_value());
}

TEST(ipv6_header, dscp_ecn)
{
    IPv6Header hdr;
    hdr.init(IPv6Header::NEXT_HEADER_UDP, 100);
    hdr.set_traffic_class(0xBD);  // DSCP=0x2F (47), ECN=0x01

    EXPECT_EQ(hdr.dscp(), 0x2F);
    EXPECT_EQ(hdr.ecn(), 0x01);
}

// UdpHeader tests

TEST(udp_header, default_constructor)
{
    UdpHeader hdr;
    EXPECT_EQ(sizeof(hdr), 8U);
}

TEST(udp_header, constructor_with_params)
{
    UdpHeader hdr(12345, 80, 108);

    EXPECT_EQ(hdr.src_port.get(), 12345);
    EXPECT_EQ(hdr.dst_port.get(), 80);
    EXPECT_EQ(hdr.length.get(), 108);
}

TEST(udp_header, init)
{
    UdpHeader hdr;
    hdr.init(12345, 80, 100);

    EXPECT_EQ(hdr.src_port.get(), 12345);
    EXPECT_EQ(hdr.dst_port.get(), 80);
    EXPECT_EQ(hdr.length.get(), 108);  // 8 + 100
    EXPECT_EQ(hdr.payload_length(), 100);
}

TEST(udp_header, payload_length)
{
    UdpHeader hdr;
    hdr.length = 108;  // Header + 100 bytes payload

    EXPECT_EQ(hdr.payload_length(), 100);
}

TEST(udp_header, well_known_ports)
{
    // Port numbers are now in the statusbar::ip::port namespace
    EXPECT_EQ(port::DNS, 53);
    EXPECT_EQ(port::DHCP_SERVER, 67);
    EXPECT_EQ(port::DHCP_CLIENT, 68);
    EXPECT_EQ(port::NTP, 123);
    EXPECT_EQ(port::MDNS, 5353);

    // AVB/TSN ports
    EXPECT_EQ(port::ATDECC, 17221);
    EXPECT_EQ(port::AVTP, 17220);
}

TEST(udp_header, serialization)
{
    UdpHeader hdr;
    hdr.init(12345, 80, 100);

    std::array<uint8_t, 8> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 8U);

    UdpHeader loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 8U);

    EXPECT_EQ(loaded.src_port.get(), 12345);
    EXPECT_EQ(loaded.dst_port.get(), 80);
    EXPECT_EQ(loaded.length.get(), 108);
}

TEST(udp_header, can_load)
{
    std::array<uint8_t, 8> buf{};
    UdpHeader hdr;

    auto result = statusbar::protocol::can_load(buf, &hdr);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 8U);

    std::array<uint8_t, 7> small_buf{};
    auto fail_result = statusbar::protocol::can_load(small_buf, &hdr);
    EXPECT_FALSE(fail_result.has_value());
}

// Combined tests

TEST(ip_combined, ipv4_udp_packet)
{
    // Create a complete IPv4/UDP packet header
    std::array<uint8_t, 28> buf{};  // 20 + 8

    IPv4Header ip_hdr;
    ip_hdr.init(IPv4Header::PROTOCOL_UDP, 8 + 100);  // UDP header + payload
    ip_hdr.src_addr = IPv4Address(192, 168, 1, 1);
    ip_hdr.dst_addr = IPv4Address(192, 168, 1, 2);

    UdpHeader udp_hdr;
    udp_hdr.init(12345, 80, 100);

    (void)store_unchecked(buf, ip_hdr);
    (void)store_unchecked(make_span(buf).subspan(20), udp_hdr);

    // Read back
    IPv4Header ip_loaded;
    UdpHeader udp_loaded;

    (void)load_unchecked(buf, &ip_loaded);
    (void)load_unchecked(make_const_span(buf).subspan(20), &udp_loaded);

    EXPECT_EQ(ip_loaded.version(), 4);
    EXPECT_EQ(ip_loaded.protocol.get(), IPv4Header::PROTOCOL_UDP);
    EXPECT_EQ(udp_loaded.src_port.get(), 12345);
    EXPECT_EQ(udp_loaded.dst_port.get(), 80);
}

TEST(ip_combined, ipv6_udp_packet)
{
    // Create a complete IPv6/UDP packet header
    std::array<uint8_t, 48> buf{};  // 40 + 8

    IPv6Header ip_hdr;
    ip_hdr.init(IPv6Header::NEXT_HEADER_UDP, 8 + 100);  // UDP header + payload
    ip_hdr.src_addr = IPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    ip_hdr.dst_addr = IPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);

    UdpHeader udp_hdr;
    udp_hdr.init(12345, 80, 100);

    (void)store_unchecked(buf, ip_hdr);
    (void)store_unchecked(make_span(buf).subspan(40), udp_hdr);

    // Read back
    IPv6Header ip_loaded;
    UdpHeader udp_loaded;

    (void)load_unchecked(buf, &ip_loaded);
    (void)load_unchecked(make_const_span(buf).subspan(40), &udp_loaded);

    EXPECT_EQ(ip_loaded.version(), 6);
    EXPECT_EQ(ip_loaded.next_header.get(), IPv6Header::NEXT_HEADER_UDP);
    EXPECT_EQ(udp_loaded.src_port.get(), 12345);
    EXPECT_EQ(udp_loaded.dst_port.get(), 80);
}

//
// ARP Tests
//

TEST(ip_arp_ipv4addr, default_constructor)
{
    IPv4Address addr;
    EXPECT_EQ(addr.octet(0), 0);
    EXPECT_EQ(addr.octet(1), 0);
    EXPECT_EQ(addr.octet(2), 0);
    EXPECT_EQ(addr.octet(3), 0);
}

TEST(ip_arp_ipv4addr, octet_constructor)
{
    IPv4Address addr(192, 168, 1, 100);
    EXPECT_EQ(addr.octet(0), 192);
    EXPECT_EQ(addr.octet(1), 168);
    EXPECT_EQ(addr.octet(2), 1);
    EXPECT_EQ(addr.octet(3), 100);
}

TEST(ip_arp_ipv4addr, comparison)
{
    IPv4Address a(192, 168, 1, 1);
    IPv4Address b(192, 168, 1, 1);
    IPv4Address c(192, 168, 1, 2);

    EXPECT_TRUE(a == b);
    EXPECT_TRUE(a != c);
    EXPECT_TRUE(a < c);
}

TEST(ip_arp_header, default_constructor)
{
    ArpHeader hdr;
    EXPECT_EQ(sizeof(hdr), 28U);
    EXPECT_EQ(hdr.hardware_type.get(), ARP_HARDWARE_ETHERNET);
    EXPECT_EQ(hdr.protocol_type.get(), ARP_PROTOCOL_IPV4);
    EXPECT_EQ(hdr.hardware_addr_len, 6);
    EXPECT_EQ(hdr.protocol_addr_len, 4);
}

TEST(ip_arp_header, init_request)
{
    using statusbar::ieee::Eui48;
    ArpHeader hdr;
    Eui48 sender_mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    IPv4Address sender_ip(192, 168, 1, 1);
    IPv4Address target_ip(192, 168, 1, 100);

    hdr.init_request(sender_mac, sender_ip, target_ip);

    EXPECT_TRUE(hdr.is_request());
    EXPECT_FALSE(hdr.is_reply());
    EXPECT_TRUE(hdr.is_ethernet_ipv4());
    EXPECT_TRUE(hdr.sender_hardware_addr == sender_mac);
    EXPECT_TRUE(hdr.sender_protocol_addr == sender_ip);
    EXPECT_TRUE(hdr.target_protocol_addr == target_ip);
}

TEST(ip_arp_header, init_reply)
{
    using statusbar::ieee::Eui48;
    ArpHeader hdr;
    Eui48 sender_mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    Eui48 target_mac(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    IPv4Address sender_ip(192, 168, 1, 100);
    IPv4Address target_ip(192, 168, 1, 1);

    hdr.init_reply(sender_mac, sender_ip, target_mac, target_ip);

    EXPECT_TRUE(hdr.is_reply());
    EXPECT_FALSE(hdr.is_request());
    EXPECT_TRUE(hdr.is_ethernet_ipv4());
    EXPECT_TRUE(hdr.sender_hardware_addr == sender_mac);
    EXPECT_TRUE(hdr.target_hardware_addr == target_mac);
}

TEST(ip_arp_header, rarp_operations)
{
    ArpHeader hdr;
    hdr.operation = ARP_OP_RARP_REQUEST;
    EXPECT_TRUE(hdr.is_rarp_request());
    EXPECT_FALSE(hdr.is_rarp_reply());

    hdr.operation = ARP_OP_RARP_REPLY;
    EXPECT_TRUE(hdr.is_rarp_reply());
    EXPECT_FALSE(hdr.is_rarp_request());
}

TEST(ip_arp_header, serialization)
{
    using statusbar::ieee::Eui48;
    ArpHeader hdr;
    Eui48 sender_mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    IPv4Address sender_ip(192, 168, 1, 1);
    IPv4Address target_ip(192, 168, 1, 100);
    hdr.init_request(sender_mac, sender_ip, target_ip);

    std::array<uint8_t, 28> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 28U);

    ArpHeader loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 28U);

    EXPECT_TRUE(loaded.is_request());
    EXPECT_TRUE(loaded.sender_hardware_addr == sender_mac);
    EXPECT_TRUE(loaded.sender_protocol_addr == sender_ip);
    EXPECT_TRUE(loaded.target_protocol_addr == target_ip);
}

TEST(ip_arp_names, arp_op_name)
{
    EXPECT_TRUE(std::string(arp_op_name(ARP_OP_REQUEST)) == "Request");
    EXPECT_TRUE(std::string(arp_op_name(ARP_OP_REPLY)) == "Reply");
    EXPECT_TRUE(std::string(arp_op_name(ARP_OP_RARP_REQUEST)) == "RARP Request");
    EXPECT_TRUE(std::string(arp_op_name(ARP_OP_RARP_REPLY)) == "RARP Reply");
    EXPECT_TRUE(std::string(arp_op_name(255)) == "Unknown");
}

//
// ICMP Tests
//

TEST(ip_icmp_header, default_constructor)
{
    IcmpHeader hdr;
    EXPECT_EQ(sizeof(hdr), 8U);
}

TEST(ip_icmp_header, type_code_constructor)
{
    IcmpHeader hdr(ICMP_TYPE_ECHO_REQUEST, 0);
    EXPECT_EQ(hdr.type.get(), ICMP_TYPE_ECHO_REQUEST);
    EXPECT_EQ(hdr.code.get(), 0);
    EXPECT_EQ(hdr.checksum.get(), 0);
}

TEST(ip_icmp_header, init_echo_request)
{
    IcmpHeader hdr;
    hdr.init_echo_request(1234, 5678);

    EXPECT_TRUE(hdr.is_echo_request());
    EXPECT_FALSE(hdr.is_echo_reply());
    EXPECT_EQ(hdr.identifier.get(), 1234);
    EXPECT_EQ(hdr.sequence.get(), 5678);
}

TEST(ip_icmp_header, init_echo_reply)
{
    IcmpHeader hdr;
    hdr.init_echo_reply(4321, 8765);

    EXPECT_TRUE(hdr.is_echo_reply());
    EXPECT_FALSE(hdr.is_echo_request());
    EXPECT_EQ(hdr.identifier.get(), 4321);
    EXPECT_EQ(hdr.sequence.get(), 8765);
}

TEST(ip_icmp_header, serialization)
{
    IcmpHeader hdr;
    hdr.init_echo_request(1234, 5678);

    std::array<uint8_t, 8> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 8U);

    IcmpHeader loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 8U);

    EXPECT_TRUE(loaded.is_echo_request());
    EXPECT_EQ(loaded.identifier.get(), 1234);
    EXPECT_EQ(loaded.sequence.get(), 5678);
}

TEST(ip_icmp_names, icmp_type_name)
{
    EXPECT_TRUE(std::string(icmp_type_name(ICMP_TYPE_ECHO_REPLY)) == "Echo Reply");
    EXPECT_TRUE(std::string(icmp_type_name(ICMP_TYPE_ECHO_REQUEST)) == "Echo Request");
    EXPECT_TRUE(std::string(icmp_type_name(ICMP_TYPE_DEST_UNREACHABLE)) == "Destination Unreachable");
    EXPECT_TRUE(std::string(icmp_type_name(ICMP_TYPE_TIME_EXCEEDED)) == "Time Exceeded");
    EXPECT_TRUE(std::string(icmp_type_name(250)) == "Unknown");
}

TEST(ip_icmp_constants, codes)
{
    // Verify ICMP code constants are defined correctly
    EXPECT_EQ(ICMP_CODE_NET_UNREACHABLE, 0);
    EXPECT_EQ(ICMP_CODE_HOST_UNREACHABLE, 1);
    EXPECT_EQ(ICMP_CODE_PROTOCOL_UNREACHABLE, 2);
    EXPECT_EQ(ICMP_CODE_PORT_UNREACHABLE, 3);
    EXPECT_EQ(ICMP_CODE_FRAGMENTATION_NEEDED, 4);
    EXPECT_EQ(ICMP_CODE_TTL_EXCEEDED, 0);
    EXPECT_EQ(ICMP_CODE_FRAGMENT_REASSEMBLY_EXCEEDED, 1);
}

//
// ICMPv6 Tests
//

TEST(ip_icmpv6_header, default_constructor)
{
    Icmpv6Header hdr;
    EXPECT_EQ(sizeof(hdr), 4U);
}

TEST(ip_icmpv6_header, type_code_constructor)
{
    Icmpv6Header hdr(ICMPV6_TYPE_ECHO_REQUEST, 0);
    EXPECT_EQ(hdr.type.get(), ICMPV6_TYPE_ECHO_REQUEST);
    EXPECT_EQ(hdr.code.get(), 0);
}

TEST(ip_icmpv6_header, type_checks)
{
    Icmpv6Header hdr;

    hdr.type = ICMPV6_TYPE_ECHO_REQUEST;
    EXPECT_TRUE(hdr.is_echo_request());
    EXPECT_FALSE(hdr.is_echo_reply());
    EXPECT_TRUE(hdr.is_informational());
    EXPECT_FALSE(hdr.is_error());

    hdr.type = ICMPV6_TYPE_ECHO_REPLY;
    EXPECT_TRUE(hdr.is_echo_reply());
    EXPECT_FALSE(hdr.is_echo_request());

    hdr.type = ICMPV6_TYPE_NEIGHBOR_SOLICITATION;
    EXPECT_TRUE(hdr.is_neighbor_solicitation());

    hdr.type = ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT;
    EXPECT_TRUE(hdr.is_neighbor_advertisement());

    hdr.type = ICMPV6_TYPE_ROUTER_SOLICITATION;
    EXPECT_TRUE(hdr.is_router_solicitation());

    hdr.type = ICMPV6_TYPE_ROUTER_ADVERTISEMENT;
    EXPECT_TRUE(hdr.is_router_advertisement());

    hdr.type = ICMPV6_TYPE_DEST_UNREACHABLE;
    EXPECT_TRUE(hdr.is_error());
    EXPECT_FALSE(hdr.is_informational());
}

TEST(ip_icmpv6_echo, init_request)
{
    Icmpv6EchoHeader echo;
    echo.init_echo_request(1234, 5678);

    EXPECT_EQ(echo.type.get(), ICMPV6_TYPE_ECHO_REQUEST);
    EXPECT_EQ(echo.code.get(), 0);
    EXPECT_EQ(echo.identifier.get(), 1234);
    EXPECT_EQ(echo.sequence.get(), 5678);
}

TEST(ip_icmpv6_echo, init_reply)
{
    Icmpv6EchoHeader echo;
    echo.init_echo_reply(4321, 8765);

    EXPECT_EQ(echo.type.get(), ICMPV6_TYPE_ECHO_REPLY);
    EXPECT_EQ(echo.identifier.get(), 4321);
    EXPECT_EQ(echo.sequence.get(), 8765);
}

TEST(ip_icmpv6_echo, serialization)
{
    Icmpv6EchoHeader echo;
    echo.init_echo_request(1234, 5678);

    std::array<uint8_t, 8> buf{};
    auto stored = store_unchecked(buf, echo);
    EXPECT_EQ(stored, 8U);

    Icmpv6EchoHeader loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 8U);

    EXPECT_EQ(loaded.type.get(), ICMPV6_TYPE_ECHO_REQUEST);
    EXPECT_EQ(loaded.identifier.get(), 1234);
    EXPECT_EQ(loaded.sequence.get(), 5678);
}

TEST(ip_icmpv6_neighbor, solicitation_size)
{
    Icmpv6NeighborSolicitation ns;
    EXPECT_EQ(sizeof(ns), 24U);
}

TEST(ip_icmpv6_neighbor, advertisement_flags)
{
    Icmpv6NeighborAdvertisement na;

    na.set_router(true);
    na.set_solicited(true);
    na.set_override(true);

    EXPECT_TRUE(na.is_router());
    EXPECT_TRUE(na.is_solicited());
    EXPECT_TRUE(na.is_override());

    na.set_router(false);
    EXPECT_FALSE(na.is_router());
    EXPECT_TRUE(na.is_solicited());
    EXPECT_TRUE(na.is_override());
}

TEST(ip_icmpv6_router, solicitation_size)
{
    Icmpv6RouterSolicitation rs;
    EXPECT_EQ(sizeof(rs), 8U);
}

TEST(ip_icmpv6_names, icmpv6_type_name)
{
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_ECHO_REQUEST)) == "Echo Request");
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_ECHO_REPLY)) == "Echo Reply");
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_NEIGHBOR_SOLICITATION)) == "Neighbor Solicitation");
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT)) == "Neighbor Advertisement");
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_ROUTER_SOLICITATION)) == "Router Solicitation");
    EXPECT_TRUE(std::string(icmpv6_type_name(ICMPV6_TYPE_ROUTER_ADVERTISEMENT)) == "Router Advertisement");
    EXPECT_TRUE(std::string(icmpv6_type_name(0)) == "Unknown");
}

TEST(ip_icmpv6_constants, codes)
{
    // Verify ICMPv6 code constants
    EXPECT_EQ(ICMPV6_CODE_NO_ROUTE, 0);
    EXPECT_EQ(ICMPV6_CODE_ADMIN_PROHIBITED, 1);
    EXPECT_EQ(ICMPV6_CODE_PORT_UNREACHABLE, 4);
    EXPECT_EQ(ICMPV6_CODE_HOP_LIMIT_EXCEEDED, 0);
}

//
// IGMP Tests
//

TEST(ip_igmp_address, default_constructor)
{
    IPv4Address addr;
    EXPECT_EQ(addr.octet(0), 0);
    EXPECT_EQ(addr.octet(1), 0);
    EXPECT_EQ(addr.octet(2), 0);
    EXPECT_EQ(addr.octet(3), 0);
}

TEST(ip_igmp_address, octet_constructor)
{
    IPv4Address addr(224, 0, 0, 1);
    EXPECT_EQ(addr.octet(0), 224);
    EXPECT_EQ(addr.octet(1), 0);
    EXPECT_EQ(addr.octet(2), 0);
    EXPECT_EQ(addr.octet(3), 1);
}

TEST(ip_igmp_address, comparison)
{
    IPv4Address a(224, 0, 0, 1);
    IPv4Address b(224, 0, 0, 1);
    IPv4Address c(224, 0, 0, 2);

    EXPECT_TRUE(a == b);
    EXPECT_TRUE(a != c);
    EXPECT_TRUE(a < c);
}

TEST(ip_igmp_header, default_constructor)
{
    IgmpHeader hdr;
    EXPECT_EQ(sizeof(hdr), 8U);
}

TEST(ip_igmp_header, type_constructor)
{
    IgmpHeader hdr(IGMP_TYPE_MEMBERSHIP_QUERY);
    EXPECT_EQ(hdr.type.get(), IGMP_TYPE_MEMBERSHIP_QUERY);
    EXPECT_EQ(hdr.max_resp_time.get(), 0);
}

TEST(ip_igmp_header, init_membership_query)
{
    IgmpHeader hdr;
    hdr.init_membership_query(100);

    EXPECT_TRUE(hdr.is_membership_query());
    EXPECT_FALSE(hdr.is_membership_report());
    EXPECT_FALSE(hdr.is_leave_group());
    EXPECT_EQ(hdr.max_resp_time.get(), 100);
}

TEST(ip_igmp_header, init_membership_report)
{
    IgmpHeader hdr;
    IPv4Address group(224, 0, 0, 251);  // mDNS multicast
    hdr.init_membership_report(group);

    EXPECT_TRUE(hdr.is_membership_report());
    EXPECT_FALSE(hdr.is_membership_query());
    EXPECT_FALSE(hdr.is_leave_group());
    EXPECT_TRUE(hdr.group_addr == group);
}

TEST(ip_igmp_header, init_leave_group)
{
    IgmpHeader hdr;
    IPv4Address group(224, 0, 0, 251);
    hdr.init_leave_group(group);

    EXPECT_TRUE(hdr.is_leave_group());
    EXPECT_FALSE(hdr.is_membership_query());
    EXPECT_FALSE(hdr.is_membership_report());
    EXPECT_TRUE(hdr.group_addr == group);
}

TEST(ip_igmp_header, membership_report_versions)
{
    IgmpHeader hdr;

    hdr.type = IGMP_TYPE_MEMBERSHIP_REPORT_V1;
    EXPECT_TRUE(hdr.is_membership_report());

    hdr.type = IGMP_TYPE_MEMBERSHIP_REPORT_V2;
    EXPECT_TRUE(hdr.is_membership_report());

    hdr.type = IGMP_TYPE_MEMBERSHIP_REPORT_V3;
    EXPECT_TRUE(hdr.is_membership_report());
}

TEST(ip_igmp_header, serialization)
{
    IgmpHeader hdr;
    IPv4Address group(224, 0, 0, 251);
    hdr.init_membership_report(group);

    std::array<uint8_t, 8> buf{};
    auto stored = store_unchecked(buf, hdr);
    EXPECT_EQ(stored, 8U);

    IgmpHeader loaded;
    auto loaded_size = load_unchecked(buf, &loaded);
    EXPECT_EQ(loaded_size, 8U);

    EXPECT_TRUE(loaded.is_membership_report());
    EXPECT_TRUE(loaded.group_addr == group);
}

TEST(ip_igmp_names, igmp_type_name)
{
    EXPECT_TRUE(std::string(igmp_type_name(IGMP_TYPE_MEMBERSHIP_QUERY)) == "Membership Query");
    EXPECT_TRUE(std::string(igmp_type_name(IGMP_TYPE_MEMBERSHIP_REPORT_V1)) == "Membership Report (v1)");
    EXPECT_TRUE(std::string(igmp_type_name(IGMP_TYPE_MEMBERSHIP_REPORT_V2)) == "Membership Report (v2)");
    EXPECT_TRUE(std::string(igmp_type_name(IGMP_TYPE_MEMBERSHIP_REPORT_V3)) == "Membership Report (v3)");
    EXPECT_TRUE(std::string(igmp_type_name(IGMP_TYPE_LEAVE_GROUP)) == "Leave Group");
    EXPECT_TRUE(std::string(igmp_type_name(0xFF)) == "Unknown");
}

//
// Tests: Runtime coverage for constexpr name functions
//

TEST(ip_rt_coverage, arp_op_names)
{
    uint16_t volatile req = ARP_OP_REQUEST;
    uint16_t volatile reply = ARP_OP_REPLY;
    uint16_t volatile rarp_req = ARP_OP_RARP_REQUEST;
    uint16_t volatile rarp_reply = ARP_OP_RARP_REPLY;
    uint16_t volatile unknown = 255;

    EXPECT_TRUE(std::string(arp_op_name(req))[0] == 'R');
    EXPECT_TRUE(std::string(arp_op_name(reply))[0] == 'R');
    EXPECT_TRUE(std::string(arp_op_name(rarp_req))[0] == 'R');
    EXPECT_TRUE(std::string(arp_op_name(rarp_reply))[0] == 'R');
    EXPECT_TRUE(std::string(arp_op_name(unknown))[0] == 'U');
}

TEST(ip_rt_coverage, icmpv6_type_names)
{
    uint8_t volatile echo_req = ICMPV6_TYPE_ECHO_REQUEST;
    uint8_t volatile echo_reply = ICMPV6_TYPE_ECHO_REPLY;
    uint8_t volatile ns = ICMPV6_TYPE_NEIGHBOR_SOLICITATION;
    uint8_t volatile na = ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT;
    uint8_t volatile rs = ICMPV6_TYPE_ROUTER_SOLICITATION;
    uint8_t volatile ra = ICMPV6_TYPE_ROUTER_ADVERTISEMENT;
    uint8_t volatile unknown = 0;

    EXPECT_TRUE(std::string(icmpv6_type_name(echo_req))[0] == 'E');
    EXPECT_TRUE(std::string(icmpv6_type_name(echo_reply))[0] == 'E');
    EXPECT_TRUE(std::string(icmpv6_type_name(ns))[0] == 'N');
    EXPECT_TRUE(std::string(icmpv6_type_name(na))[0] == 'N');
    EXPECT_TRUE(std::string(icmpv6_type_name(rs))[0] == 'R');
    EXPECT_TRUE(std::string(icmpv6_type_name(ra))[0] == 'R');
    EXPECT_TRUE(std::string(icmpv6_type_name(unknown))[0] == 'U');
}

TEST(ip_rt_coverage, igmp_type_names)
{
    uint8_t volatile query = IGMP_TYPE_MEMBERSHIP_QUERY;
    uint8_t volatile report_v1 = IGMP_TYPE_MEMBERSHIP_REPORT_V1;
    uint8_t volatile report_v2 = IGMP_TYPE_MEMBERSHIP_REPORT_V2;
    uint8_t volatile report_v3 = IGMP_TYPE_MEMBERSHIP_REPORT_V3;
    uint8_t volatile leave = IGMP_TYPE_LEAVE_GROUP;
    uint8_t volatile unknown = 0xFF;

    EXPECT_TRUE(std::string(igmp_type_name(query))[0] == 'M');
    EXPECT_TRUE(std::string(igmp_type_name(report_v1))[0] == 'M');
    EXPECT_TRUE(std::string(igmp_type_name(report_v2))[0] == 'M');
    EXPECT_TRUE(std::string(igmp_type_name(report_v3))[0] == 'M');
    EXPECT_TRUE(std::string(igmp_type_name(leave))[0] == 'L');
    EXPECT_TRUE(std::string(igmp_type_name(unknown))[0] == 'U');
}

//
// Tests: IP header validation
//

TEST(ipv4_is_valid, valid_header)
{
    IPv4Header hdr{};
    // Version=4, IHL=5 => version_ihl = (4 << 4) | 5 = 0x45
    hdr.version_ihl = 0x45;
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(20);  // Minimum valid
    EXPECT_TRUE(hdr.is_valid());
}

TEST(ipv4_is_valid, wrong_version)
{
    IPv4Header hdr{};
    // Version=6, IHL=5 => 0x65
    hdr.version_ihl = 0x65;
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(20);
    EXPECT_FALSE(hdr.is_valid());
}

TEST(ipv4_is_valid, ihl_too_small)
{
    IPv4Header hdr{};
    // Version=4, IHL=3 => 0x43
    hdr.version_ihl = 0x43;
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(20);
    EXPECT_FALSE(hdr.is_valid());
}

TEST(ipv4_is_valid, total_length_too_small)
{
    IPv4Header hdr{};
    // Version=4, IHL=5 => 0x45
    hdr.version_ihl = 0x45;
    hdr.total_length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(10);  // Less than header (20)
    EXPECT_FALSE(hdr.is_valid());
}

TEST(ipv6_is_valid, valid_header)
{
    IPv6Header hdr{};
    hdr.init(0, 0);  // Sets version=6 internally
    EXPECT_TRUE(hdr.is_valid());
}

TEST(ipv6_is_valid, wrong_version)
{
    IPv6Header hdr{};
    hdr.set_version(4);  // Should be 6
    EXPECT_FALSE(hdr.is_valid());
}

TEST(udp_is_valid, valid_header)
{
    UdpHeader hdr{};
    hdr.length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(8);  // Minimum valid
    EXPECT_TRUE(hdr.is_valid());
}

TEST(udp_is_valid, length_too_small)
{
    UdpHeader hdr{};
    hdr.length = statusbar::ieee::IeeeOrderedUInt<uint16_t>(4);  // Less than 8
    EXPECT_FALSE(hdr.is_valid());
}

// ===========================================================================
// IPv4 checksum tests
// ===========================================================================

TEST(ipv4_checksum, calculate_initialized_header)
{
    IPv4Header hdr{};
    hdr.init(IPv4Header::PROTOCOL_UDP, 100);
    hdr.src_addr = IPv4Address(192, 168, 1, 1);
    hdr.dst_addr = IPv4Address(192, 168, 1, 2);

    // With checksum field zero, calculate should produce a non-zero checksum
    hdr.header_checksum = 0;
    uint16_t checksum = calculate_ipv4_checksum(hdr);
    EXPECT_NE(checksum, static_cast<uint16_t>(0));
}

TEST(ipv4_checksum, update_and_verify)
{
    IPv4Header hdr{};
    hdr.init(IPv4Header::PROTOCOL_UDP, 100);
    hdr.src_addr = IPv4Address(10, 0, 0, 1);
    hdr.dst_addr = IPv4Address(10, 0, 0, 2);

    // Update sets the checksum field
    update_ipv4_checksum(hdr);
    EXPECT_NE(static_cast<uint16_t>(hdr.header_checksum), static_cast<uint16_t>(0));

    // Verify should pass after update
    EXPECT_TRUE(verify_ipv4_checksum(hdr));
}

TEST(ipv4_checksum, verify_fails_on_corruption)
{
    IPv4Header hdr{};
    hdr.init(IPv4Header::PROTOCOL_TCP, 200);
    hdr.src_addr = IPv4Address(172, 16, 0, 1);
    hdr.dst_addr = IPv4Address(172, 16, 0, 2);

    update_ipv4_checksum(hdr);
    EXPECT_TRUE(verify_ipv4_checksum(hdr));

    // Corrupt a field — checksum should no longer verify
    hdr.ttl = 128;
    EXPECT_FALSE(verify_ipv4_checksum(hdr));
}

TEST(ipv4_checksum, verify_fails_with_zero_checksum)
{
    IPv4Header hdr{};
    hdr.init(IPv4Header::PROTOCOL_UDP, 50);
    hdr.src_addr = IPv4Address(1, 2, 3, 4);
    hdr.dst_addr = IPv4Address(5, 6, 7, 8);

    // Without update, checksum is zero — verify should fail
    EXPECT_FALSE(verify_ipv4_checksum(hdr));
}

TEST(ipv4_checksum, update_recalculates_after_field_change)
{
    IPv4Header hdr{};
    hdr.init(IPv4Header::PROTOCOL_UDP, 100);
    hdr.src_addr = IPv4Address(192, 168, 0, 1);
    hdr.dst_addr = IPv4Address(192, 168, 0, 2);
    update_ipv4_checksum(hdr);
    uint16_t checksum1 = hdr.header_checksum;

    // Change a field and recalculate
    hdr.ttl = 128;
    update_ipv4_checksum(hdr);
    uint16_t checksum2 = hdr.header_checksum;

    // Checksums should differ
    EXPECT_NE(checksum1, checksum2);

    // But both should verify after update
    EXPECT_TRUE(verify_ipv4_checksum(hdr));
}

// Test runner

TEST_MAIN(statusbar_ip, ip_test)