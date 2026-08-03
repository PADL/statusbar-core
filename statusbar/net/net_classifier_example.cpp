// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Example: build a multi-rule TcamClassifier covering the common
/// AVB / TSN / ATDECC mix plus generic IPv4 / IPv6 UDP traffic.
///
/// Demonstrates:
///   - the semantic rule-builder DSL (ethertype, vlan modes, AVTP
///     subtype, IPv4 protocol, IPv6 next header)
///   - combining library-defined and user-defined result flags
///   - how a single conceptual rule ("ATDECC management plane")
///     fans out to multiple CompiledRules when it spans disjoint
///     byte patterns (ADP / AECP / ACMP share EtherType but have
///     different subtype bytes)
///   - classify_first vs classify_all for a few sample frames
///
/// Build with the rest of the project; the resulting binary is
/// installed as `statusbar-net-classifier`.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_tcam_classifier.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <print>
#include <string_view>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

// ---------- Well-known constants ----------

// EtherTypes
constexpr std::uint16_t ETHERTYPE_GPTP = 0x88F7;
constexpr std::uint16_t ETHERTYPE_AVTP = 0x22F0;
constexpr std::uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr std::uint16_t ETHERTYPE_IPV6 = 0x86DD;

// IEEE 1722-2016 AVTP subtypes
constexpr std::uint8_t AVTP_SUBTYPE_61883 = 0x00;  // carries AM824 audio
constexpr std::uint8_t AVTP_SUBTYPE_AAF = 0x02;    // AAF PCM / Raw audio
constexpr std::uint8_t AVTP_SUBTYPE_CRF = 0x04;    // Clock Reference Format
constexpr std::uint8_t AVTP_SUBTYPE_ADP = 0xFA;    // ATDECC ADP
constexpr std::uint8_t AVTP_SUBTYPE_AECP = 0xFB;   // ATDECC AECP
constexpr std::uint8_t AVTP_SUBTYPE_ACMP = 0xFC;   // ATDECC ACMP

constexpr std::uint8_t IP_PROTO_UDP = 17;

// ---------- User-defined result flags ----------
//
// Bits 16..63 are ours to claim. Name them once; the library will
// never use or reassign these bits.
namespace my_app::rx {
inline constexpr std::uint64_t gptp = flag::user_bit<0>;        // bit 16
inline constexpr std::uint64_t avtp_crf = flag::user_bit<1>;    // bit 17
inline constexpr std::uint64_t avtp_am824 = flag::user_bit<2>;  // bit 18
inline constexpr std::uint64_t avtp_aaf = flag::user_bit<3>;    // bit 19
inline constexpr std::uint64_t atdecc = flag::user_bit<4>;      // bit 20
inline constexpr std::uint64_t ipv4_udp = flag::user_bit<5>;    // bit 21
inline constexpr std::uint64_t ipv6_udp = flag::user_bit<6>;    // bit 22
}  // namespace my_app::rx

// ---------- Rule construction ----------

static auto build_rules(std::uint16_t avb_vlan) -> std::vector<CompiledRule<>>
{
    std::vector<CompiledRule<>> rules;
    auto append = [&](auto const& built) { rules.insert(rules.end(), built.begin(), built.end()); };

    // 1. gPTP — typically untagged on the AVB interface (per
    //    802.1AS). EtherType 0x88F7.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_GPTP)
               .vlan_untagged()
               .result(my_app::rx::gptp | flag::rx_gptp | flag::process)
               .priority(10)
               .build());

    // 2. AVTP CRF (media clock) in the AVB VLAN.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_AVTP)
               .vlan_tagged_exact(avb_vlan)
               .avtp_subtype(AVTP_SUBTYPE_CRF)
               .result(my_app::rx::avtp_crf | flag::rx_avtp_stream | flag::process)
               .priority(20)
               .build());

    // 3. AVTP AM824 (IEC 61883-6 audio) in the AVB VLAN. AM824 rides
    //    inside the 61883/IIDC AVTP subtype.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_AVTP)
               .vlan_tagged_exact(avb_vlan)
               .avtp_subtype(AVTP_SUBTYPE_61883)
               .result(my_app::rx::avtp_am824 | flag::rx_avtp_stream | flag::process)
               .priority(20)
               .build());

    // 4. AVTP AAF (raw PCM audio) in the AVB VLAN.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_AVTP)
               .vlan_tagged_exact(avb_vlan)
               .avtp_subtype(AVTP_SUBTYPE_AAF)
               .result(my_app::rx::avtp_aaf | flag::rx_avtp_stream | flag::process)
               .priority(20)
               .build());

    // 5. ATDECC (ADP + AECP + ACMP), untagged. All three share the
    //    AVTP EtherType but have different subtype bytes, and a TCAM
    //    entry can only express an exact compare on one byte pattern.
    //    One conceptual rule therefore fans out to three compiled
    //    rules carrying the same result flags.
    for (auto subtype : {AVTP_SUBTYPE_ADP, AVTP_SUBTYPE_AECP, AVTP_SUBTYPE_ACMP}) {
        append(ClassifierRuleBuilder<>{}
                   .ethertype(ETHERTYPE_AVTP)
                   .vlan_untagged()
                   .avtp_subtype(subtype)
                   .result(my_app::rx::atdecc | flag::process)
                   .priority(30)
                   .build());
    }

    // 6. Any IPv4 UDP, untagged. The "protocol" byte at IPv4 header
    //    offset +9 tells us the L4 protocol; 17 == UDP.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_IPV4)
               .vlan_untagged()
               .ipv4_protocol(IP_PROTO_UDP)
               .result(my_app::rx::ipv4_udp | flag::process)
               .priority(40)
               .build());

    // 7. Any IPv6 UDP, untagged. The "next header" byte at IPv6
    //    offset +6 serves the same role.
    append(ClassifierRuleBuilder<>{}
               .ethertype(ETHERTYPE_IPV6)
               .vlan_untagged()
               .ipv6_next_header(IP_PROTO_UDP)
               .result(my_app::rx::ipv6_udp | flag::process)
               .priority(40)
               .build());

    return rules;
}

// ---------- Demo frames ----------

namespace {

struct Frame
{
    std::string_view name;
    std::array<std::uint8_t, 32> bytes;
};

auto make_avtp_aaf_tagged(std::uint16_t vid) -> Frame
{
    Frame f{.name = "AVTP AAF, VLAN 2", .bytes = {}};
    // DA (multicast placeholder), SA zeroed for brevity
    for (int i = 0; i < 6; ++i) {
        f.bytes[i] = 0x91;
    }
    f.bytes[12] = 0x81;
    f.bytes[13] = 0x00;  // TPID
    f.bytes[14] = static_cast<std::uint8_t>((vid >> 8) & 0x0F);
    f.bytes[15] = static_cast<std::uint8_t>(vid & 0xFF);
    f.bytes[16] = 0x22;
    f.bytes[17] = 0xF0;  // AVTP
    f.bytes[18] = AVTP_SUBTYPE_AAF;
    return f;
}

auto make_gptp_untagged() -> Frame
{
    Frame f{.name = "gPTP, untagged", .bytes = {}};
    f.bytes[12] = 0x88;
    f.bytes[13] = 0xF7;
    return f;
}

auto make_atdecc_adp_untagged() -> Frame
{
    Frame f{.name = "ATDECC ADP, untagged", .bytes = {}};
    f.bytes[12] = 0x22;
    f.bytes[13] = 0xF0;  // AVTP
    f.bytes[14] = AVTP_SUBTYPE_ADP;
    return f;
}

auto make_ipv4_udp_untagged() -> Frame
{
    Frame f{.name = "IPv4 UDP, untagged", .bytes = {}};
    f.bytes[12] = 0x08;
    f.bytes[13] = 0x00;  // IPv4
    f.bytes[14] = 0x45;  // version/IHL
    f.bytes[23] = IP_PROTO_UDP;
    return f;
}

auto make_ipv6_udp_untagged() -> Frame
{
    Frame f{.name = "IPv6 UDP, untagged", .bytes = {}};
    f.bytes[12] = 0x86;
    f.bytes[13] = 0xDD;
    f.bytes[14] = 0x60;  // version
    f.bytes[20] = IP_PROTO_UDP;
    return f;
}

auto make_unknown() -> Frame
{
    Frame f{.name = "unknown ARP", .bytes = {}};
    f.bytes[12] = 0x08;
    f.bytes[13] = 0x06;  // ARP
    return f;
}

}  // namespace

// ---------- Main ----------

int main()
{
    constexpr std::uint16_t avb_vlan = 2;
    auto rules = build_rules(avb_vlan);

    // 1 gptp + 3 avtp + 3 atdecc + 1 ipv4 + 1 ipv6 = 9 rules.
    // Capacity 16 leaves room for two more without rebuilding.
    TcamClassifier<32, 16> tc;
    tc.set_rules(rules, flag::forward_tap);

    std::println("Configured {} rules (capacity {}), default = forward_tap.\n", tc.rule_count(), decltype(tc)::capacity);

    Frame const samples[] = {
        make_gptp_untagged(),
        make_avtp_aaf_tagged(avb_vlan),
        make_atdecc_adp_untagged(),
        make_ipv4_udp_untagged(),
        make_ipv6_udp_untagged(),
        make_unknown(),
    };

    for (auto const& f : samples) {
        auto const result = tc.classify_first(f.bytes);
        std::println(
            "{:<24} -> 0x{:016x}  (sys=0x{:04x} user=0x{:012x})",
            f.name,
            result,
            flag::system_bits(result),
            flag::user_bits(result) >> flag::USER_BIT_FIRST);
    }
    return 0;
}
