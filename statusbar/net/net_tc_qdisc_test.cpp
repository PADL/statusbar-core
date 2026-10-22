// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The rtnetlink qdisc request builders, against bytes checked by hand from
// linux/rtnetlink.h (nlmsghdr, tcmsg, rtattr) and linux/pkt_sched.h
// (tc_mqprio_qopt, tc_cbs_qopt, TCA_CBS_PARMS), framed as iproute2's
// q_mqprio.c and q_cbs.c frame them. Netlink is host byte order: the
// expected bytes are little-endian. No socket is opened (changing qdiscs needs
// CAP_NET_ADMIN); the interface helpers are exercised on loopback only.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_interface_info.hpp"
#    include "statusbar/net/net_tc_qdisc.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <print>
#    include <span>
#    include <system_error>

namespace {

using namespace statusbar::net;
using namespace statusbar::net::tc;

constexpr bool LITTLE = std::endian::native == std::endian::little;

/// Byte-exact compare with a dump of the first difference.
auto same_bytes(std::span<uint8_t const> const got, std::span<uint8_t const> const want) -> bool
{
    if (got.size() != want.size()) {
        std::println("  length {} want {}", got.size(), want.size());
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            std::println("  byte {}: {:02x} want {:02x}", i, got[i], want[i]);
            return false;
        }
    }
    return true;
}

TEST(tc_qdisc, handles)
{
    EXPECT_EQ(make_handle(0x9000, 0), uint32_t{0x9000'0000});
    EXPECT_EQ(make_handle(0x9000, 1), uint32_t{0x9000'0001});
    EXPECT_EQ(ROOT, uint32_t{0xFFFF'FFFF});
}

// igb's AVB layout on a 4-queue i210: TC0 legacy on queues 2-3, TC1 (class B)
// on queue 1, TC2 (class A) on queue 0; PCP 3 -> TC2, PCP 2 -> TC1, the rest TC0.
// `tc qdisc replace dev <if3> root handle 9000: mqprio num_tc 3
//  map 0 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 queues 2@2 1@1 1@0 hw 0`
TEST(tc_qdisc, mqprio_three_traffic_classes)
{
    if (!LITTLE) {
        return;
    }
    MqprioQdisc q{};
    q.major = 0x9000;
    q.num_tc = 3;
    q.prio_tc_map[2] = 1;
    q.prio_tc_map[3] = 2;
    q.count[0] = 2;
    q.offset[0] = 2;
    q.count[1] = 1;
    q.offset[1] = 1;
    q.count[2] = 1;
    q.offset[2] = 0;
    q.hw = false;

    // clang-format off
    std::array<uint8_t, 136> want{
        // nlmsghdr: len 136, RTM_NEWQDISC (36), REQUEST|ACK|REPLACE|CREATE (0x0505), seq 7, pid 0
        0x88, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x07, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: AF_UNSPEC, pads, ifindex 3, handle 9000:0, parent TC_H_ROOT, info 0
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x90,  0xff, 0xff, 0xff, 0xff,  0x00, 0x00, 0x00, 0x00,
        // TCA_KIND (1), len 4 + 7: "mqprio\0", one pad byte
        0x0b, 0x00, 0x01, 0x00,  'm', 'q', 'p', 'r', 'i', 'o', 0x00,  0x00,
        // TCA_OPTIONS (2), len 4 + 82 (flat struct tc_mqprio_qopt)
        0x56, 0x00, 0x02, 0x00,
        // num_tc 3
        0x03,
        // prio_tc_map[16]
        0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // hw: TC_MQPRIO_HW_OFFLOAD_NONE
        0x00,
        // count[16] (u16): 2, 1, 1, then zeros
        0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // offset[16] (u16): 2, 1, 0, then zeros
        0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // NLA_ALIGN padding of the 86-byte attribute
        0x00, 0x00,
    };
    // clang-format on

    RequestBuffer out{};
    auto const length = build_replace_mqprio(out, 3, q, 7);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));

    // hw 1 changes exactly the hw byte (offset 16 + 20 + 12 + 4 + 1 + 16 = 69)
    q.hw = true;
    auto const offloaded = build_replace_mqprio(out, 3, q, 7);
    EXPECT_TRUE(offloaded.has_value());
    want[69] = 0x01;
    EXPECT_TRUE(same_bytes(std::span{out}.first(*offloaded), want));
}

TEST(tc_qdisc, mqprio_refuses_a_bad_map)
{
    RequestBuffer out{};
    MqprioQdisc q{};
    q.num_tc = 1;
    EXPECT_FALSE(build_replace_mqprio(out, 3, q, 1).has_value());  // major 0: no major:N classes
    q.num_tc = 0;
    q.major = 0x9000;
    EXPECT_FALSE(build_replace_mqprio(out, 3, q, 1).has_value());  // num_tc 0
    q.num_tc = 2;
    q.prio_tc_map[5] = 2;  // TC 2 of 2
    EXPECT_FALSE(build_replace_mqprio(out, 3, q, 1).has_value());
    q.prio_tc_map[5] = 1;
    EXPECT_TRUE(build_replace_mqprio(out, 3, q, 1).has_value());
    // too small a buffer is an error, not an overrun
    std::array<uint8_t, 100> small{};
    EXPECT_FALSE(build_replace_mqprio(small, 3, q, 1).has_value());
}

// `tc qdisc replace dev <if3> parent 9000:1 cbs idleslope 20736 sendslope -979264
//  hicredit 32 locredit -230 offload 1` (the class A numbers of avb_entity_shaper_test)
TEST(tc_qdisc, cbs)
{
    if (!LITTLE) {
        return;
    }
    CbsQdisc const q{
        .parent = make_handle(0x9000, 1),
        .offload = true,
        .hicredit = 32,
        .locredit = -230,
        .idleslope_kbps = 20736,
        .sendslope_kbps = -979264,
    };
    // clang-format off
    std::array<uint8_t, 72> const want{
        // nlmsghdr: len 72, RTM_NEWQDISC, REQUEST|ACK|REPLACE|CREATE, seq 8, pid 0
        0x48, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x08, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: ifindex 3, handle 0 (kernel assigns), parent 9000:1
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x00, 0x90,  0x00, 0x00, 0x00, 0x00,
        // TCA_KIND, len 4 + 4: "cbs\0"
        0x08, 0x00, 0x01, 0x00,  'c', 'b', 's', 0x00,
        // TCA_OPTIONS (nest), len 4 + 24
        0x1c, 0x00, 0x02, 0x00,
        // TCA_CBS_PARMS (1), len 4 + 20
        0x18, 0x00, 0x01, 0x00,
        // struct tc_cbs_qopt: offload 1, _pad[3]
        0x01, 0x00, 0x00, 0x00,
        // hicredit 32
        0x20, 0x00, 0x00, 0x00,
        // locredit -230 = 0xffffff1a
        0x1a, 0xff, 0xff, 0xff,
        // idleslope 20736 = 0x00005100
        0x00, 0x51, 0x00, 0x00,
        // sendslope -979264 = 0xfff10ec0
        0xc0, 0x0e, 0xf1, 0xff,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_replace_cbs(out, 3, q, 8);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
}

// `tc qdisc del dev <if3> root handle 9000:`
TEST(tc_qdisc, delete_root)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 36> const want{
        // nlmsghdr: len 36, RTM_DELQDISC (37), REQUEST|ACK (0x0005), seq 9, pid 0
        0x24, 0x00, 0x00, 0x00,  0x25, 0x00,  0x05, 0x00,  0x09, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: ifindex 3, handle 9000:0, parent TC_H_ROOT; no attributes
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x90,  0xff, 0xff, 0xff, 0xff,  0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_delete(out, 3, make_handle(0x9000, 0), ROOT, 9);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
}

// `tc qdisc replace dev <if3> parent 9000:1 pfifo_fast`: what removing a cbs
// puts back (deleting an mqprio child would leave noop_qdisc on the queue).
TEST(tc_qdisc, replace_option_less_kind)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 52> const want{
        0x34, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x0a, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x00, 0x90,  0x00, 0x00, 0x00, 0x00,
        // TCA_KIND, len 4 + 11: "pfifo_fast\0", one pad byte; no TCA_OPTIONS
        0x0f, 0x00, 0x01, 0x00,  'p', 'f', 'i', 'f', 'o', '_', 'f', 'a', 's', 't', 0x00,  0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_replace_kind(out, 3, make_handle(0x9000, 1), "pfifo_fast", 10);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
    EXPECT_FALSE(build_replace_kind(out, 3, make_handle(0x9000, 1), "", 10).has_value());
    EXPECT_FALSE(build_replace_kind(out, 3, make_handle(0x9000, 1), "a_kind_far_too_long", 10).has_value());
}

TEST(tc_qdisc, interface_info_on_loopback)
{
    auto const index = interface_index("lo");
    EXPECT_TRUE(index.has_value() && *index > 0);
    auto const queues = tx_queue_count("lo");
    EXPECT_TRUE(queues.has_value() && *queues >= 1);
    auto const mtu = interface_mtu("lo");
    EXPECT_TRUE(mtu.has_value() && *mtu >= 1500);
    // loopback has no speed: reading it fails with EINVAL, "unknown", not a fault
    auto const speed = link_speed_mbps("lo");
    EXPECT_TRUE(!speed.has_value() && speed.error() == make_unknown_link_speed());
    EXPECT_FALSE(interface_index("no-such-if0").has_value());
    EXPECT_FALSE(tx_queue_count("no-such-if0").has_value());
    EXPECT_FALSE(driver_name("no-such-if0").has_value());
    auto const missing = link_speed_mbps("no-such-if0");
    EXPECT_TRUE(!missing.has_value() && missing.error() == std::errc::no_such_file_or_directory);
    EXPECT_FALSE(interface_mtu("no-such-if0").has_value());
    EXPECT_FALSE(tx_queue_count("../etc").has_value());  // not a path
}

}  // namespace

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_qdisc_test)
