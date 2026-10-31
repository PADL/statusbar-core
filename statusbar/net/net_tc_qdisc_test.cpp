// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The rtnetlink qdisc request builders, against bytes checked by hand from
// linux/rtnetlink.h (nlmsghdr, tcmsg, rtattr) and linux/pkt_sched.h
// (tc_mqprio_qopt, tc_cbs_qopt, TCA_CBS_PARMS, tc_etf_qopt, TCA_ETF_PARMS), framed as
// iproute2's q_mqprio.c, q_cbs.c and q_etf.c frame them, and the parser against replies framed as
// the kernel's tc_fill_qdisc writes them. Netlink is host byte order: the
// expected bytes are little-endian. Nothing is changed (that needs
// CAP_NET_ADMIN); the interface helpers and a qdisc read are exercised on
// loopback only.

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

// The same port with PTP event traffic on a queue of its own: TC3 on queue 2 takes PTP_PRIORITY,
// TC0 legacy keeps queue 3 alone.
// `tc qdisc replace dev <if3> root handle 9000: mqprio num_tc 4
//  map 0 0 1 2 0 0 0 3 0 0 0 0 0 0 0 0 queues 1@3 1@1 1@0 1@2 hw 0`
TEST(tc_qdisc, mqprio_four_traffic_classes_with_ptp_on_its_own_queue)
{
    if (!LITTLE) {
        return;
    }
    MqprioQdisc q{.major = 0x9000, .num_tc = 4};
    q.prio_tc_map[2] = 1;
    q.prio_tc_map[3] = 2;
    q.prio_tc_map[PTP_PRIORITY] = 3;
    q.count = {1, 1, 1, 1};
    q.offset = {3, 1, 0, 2};

    // clang-format off
    std::array<uint8_t, 136> const want{
        0x88, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x07, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x90,  0xff, 0xff, 0xff, 0xff,  0x00, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x01, 0x00,  'm', 'q', 'p', 'r', 'i', 'o', 0x00,  0x00,
        0x56, 0x00, 0x02, 0x00,
        // num_tc 4
        0x04,
        // prio_tc_map[16]: 2 -> 1, 3 -> 2, 7 -> 3
        0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x03,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
        // count[16]: 1, 1, 1, 1
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // offset[16]: 3, 1, 0, 2
        0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    };
    // clang-format on

    RequestBuffer out{};
    auto const length = build_replace_mqprio(out, 3, q, 7);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
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

// `tc qdisc replace dev <if3> parent 8001:1 etf clockid CLOCK_TAI delta 150000 offload skip_sock_check`
TEST(tc_qdisc, an_etf_request_is_framed_as_q_etf_does)
{
    if (!LITTLE) {
        return;
    }
    EtfQdisc const q{.parent = make_handle(0x8001, 1), .delta_ns = 150'000, .offload = true, .skip_sock_check = true};
    // clang-format off
    std::array<uint8_t, 64> const want{
        // nlmsghdr: len 64, RTM_NEWQDISC, REQUEST|ACK|REPLACE|CREATE, seq 8, pid 0
        0x40, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x08, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: ifindex 3, handle 0 (kernel assigns), parent 8001:1
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x01, 0x80,  0x00, 0x00, 0x00, 0x00,
        // TCA_KIND, len 4 + 4: "etf\0"
        0x08, 0x00, 0x01, 0x00,  'e', 't', 'f', 0x00,
        // TCA_OPTIONS (nest), len 4 + 16 > TCA_ETF_PARMS (1), len 4 + 12
        0x14, 0x00, 0x02, 0x00,  0x10, 0x00, 0x01, 0x00,
        // struct tc_etf_qopt: delta 150000 = 0x000249f0, clockid 11 (CLOCK_TAI),
        // flags OFFLOAD_ON (2) | SKIP_SOCK_CHECK (4)
        0xf0, 0x49, 0x02, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x06, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_replace_etf(out, 3, q, 8);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
    auto const deadline = build_replace_etf(out, 3, EtfQdisc{.parent = q.parent, .offload = false, .deadline_mode = true}, 8);
    EXPECT_TRUE(deadline.has_value() && out[60] == 0x01 && out[52] == 0x00);  // DEADLINE_MODE_ON alone, delta 0
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

// `tc qdisc show`: RTM_GETQDISC dump (the kernel dumps every device's qdiscs).
TEST(tc_qdisc, dump_qdiscs)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 36> const want{
        // nlmsghdr: len 36, RTM_GETQDISC (38), REQUEST|DUMP (0x0301), seq 11, pid 0
        0x24, 0x00, 0x00, 0x00,  0x26, 0x00,  0x01, 0x03,  0x0b, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: family 0, pad, ifindex 3 (for the record), handle 0, parent 0, info 0
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length = build_dump(out, 3, 11);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(same_bytes(std::span{out}.first(*length), want));
}

// The igb AVB root above in the kernel's dump: mqprio_dump puts the flat
// tc_mqprio_qopt (82 bytes, padded to 84) and then nested attributes (here
// TCA_MQPRIO_MODE) inside one TCA_OPTIONS; tc_fill_qdisc adds TCA_HW_OFFLOAD.
TEST(tc_qdisc, parse_mqprio_reply)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 152> const reply{
        // nlmsghdr: len 152, RTM_NEWQDISC (36), flags 0, seq 11, pid 0 (as parse_qdisc sees it)
        0x98, 0x00, 0x00, 0x00,  0x24, 0x00,  0x00, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: ifindex 3, handle 9000:0, parent ROOT, info (refcnt) 1
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x90,  0xff, 0xff, 0xff, 0xff,  0x01, 0x00, 0x00, 0x00,
        // TCA_KIND, len 11: "mqprio\0", pad 1
        0x0b, 0x00, 0x01, 0x00,  'm', 'q', 'p', 'r', 'i', 'o', 0x00,  0x00,
        // TCA_OPTIONS, len 96: num_tc 3, map 0 0 1 2 0..., hw 0
        0x60, 0x00, 0x02, 0x00,
        0x03,  0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00,
        //   count: 2 1 1, 0...
        0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //   offset: 2 1 0, 0...; then the struct's pad to 84
        0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00,
        //   TCA_MQPRIO_MODE (1), len 6: u16 0 (dcb), pad 2
        0x06, 0x00, 0x01, 0x00,  0x00, 0x00,  0x00, 0x00,
        // TCA_HW_OFFLOAD (12), len 5: 0, pad 3
        0x05, 0x00, 0x0c, 0x00,  0x00,  0x00, 0x00, 0x00,
    };
    // clang-format on
    auto const info = parse_qdisc(reply);
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->ifindex, 3);
    EXPECT_EQ(info->handle, make_handle(0x9000, 0));
    EXPECT_EQ(info->parent, ROOT);
    EXPECT_TRUE(info->kind == "mqprio");
    EXPECT_FALSE(info->cbs.has_value());
    MqprioQdisc want{};
    want.major = 0x9000;
    want.num_tc = 3;
    want.prio_tc_map[2] = 1;
    want.prio_tc_map[3] = 2;
    want.count[0] = 2;
    want.offset[0] = 2;
    want.count[1] = 1;
    want.offset[1] = 1;
    want.count[2] = 1;
    want.offset[2] = 0;
    EXPECT_TRUE(info->mqprio.has_value() && *info->mqprio == want);

    // A truncated message, a short struct, another message type.
    EXPECT_FALSE(parse_qdisc(std::span{reply}.first(100)).has_value());
    auto short_options = reply;
    short_options[48] = 0x40;  // TCA_OPTIONS len 64: under sizeof(tc_mqprio_qopt)
    EXPECT_FALSE(parse_qdisc(short_options).has_value());
    auto other_type = reply;
    other_type[4] = 0x2c;  // RTM_NEWTCLASS
    EXPECT_FALSE(parse_qdisc(other_type).has_value());
}

// A cbs child as `tc qdisc show` prints it: "qdisc cbs 8008: parent 9000:1
// hicredit 25 locredit -254 sendslope -983424 idleslope 16576 offload 1":
// its own handle 8008:0 (the kernel numbered it), its parent the mqprio class
// of queue 0, 9000:(0 + 1); cbs_dump nests TCA_CBS_PARMS in TCA_OPTIONS.
TEST(tc_qdisc, parse_cbs_reply)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 80> const reply{
        0x50, 0x00, 0x00, 0x00,  0x24, 0x00,  0x00, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: handle 8008:0, parent 9000:1
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x08, 0x80,  0x01, 0x00, 0x00, 0x90,  0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00,  'c', 'b', 's', 0x00,
        // TCA_OPTIONS, len 28 > TCA_CBS_PARMS (1), len 24: offload 1, pad 3,
        // hicredit 25, locredit -254, idleslope 16576, sendslope -983424
        0x1c, 0x00, 0x02, 0x00,  0x18, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,  0x19, 0x00, 0x00, 0x00,  0x02, 0xff, 0xff, 0xff,  0xc0, 0x40, 0x00, 0x00,  0x80, 0xfe, 0xf0, 0xff,
        0x05, 0x00, 0x0c, 0x00,  0x01,  0x00, 0x00, 0x00,
    };
    // clang-format on
    auto const info = parse_qdisc(reply);
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->handle, make_handle(0x8008, 0));
    EXPECT_TRUE(info->kind == "cbs");
    EXPECT_FALSE(info->mqprio.has_value());
    CbsQdisc const want{
        .parent = make_handle(0x9000, 1),
        .offload = true,
        .hicredit = 25,
        .locredit = -254,
        .idleslope_kbps = 16576,
        .sendslope_kbps = -983424,
    };
    EXPECT_TRUE(info->cbs.has_value() && *info->cbs == want);

    auto no_parms = reply;
    no_parms[50] = 0x02;  // the nested attribute is TCA_CBS_MAXSDU, not TCA_CBS_PARMS
    EXPECT_FALSE(parse_qdisc(no_parms).has_value());
}

// An offloaded etf under a cbs (8001:1), as tc_fill_qdisc and etf_dump write it.
TEST(tc_qdisc, an_etf_reply_parses_to_its_parameters)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 72> const reply{
        0x48, 0x00, 0x00, 0x00,  0x24, 0x00,  0x00, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        // tcmsg: handle 8003:0, parent 8001:1
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x03, 0x80,  0x01, 0x00, 0x01, 0x80,  0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00,  'e', 't', 'f', 0x00,
        // TCA_OPTIONS, len 20 > TCA_ETF_PARMS (1), len 16: delta 150000, clockid 11, flags OFFLOAD_ON
        0x14, 0x00, 0x02, 0x00,  0x10, 0x00, 0x01, 0x00,
        0xf0, 0x49, 0x02, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x02, 0x00, 0x00, 0x00,
        // TCA_HW_OFFLOAD 1
        0x05, 0x00, 0x0c, 0x00,  0x01,  0x00, 0x00, 0x00,
    };
    // clang-format on
    auto const info = parse_qdisc(reply);
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->handle, make_handle(0x8003, 0));
    EXPECT_TRUE(info->kind == "etf");
    EXPECT_FALSE(info->cbs.has_value());
    EtfQdisc const want{.parent = make_handle(0x8001, 1), .delta_ns = 150'000, .offload = true};
    EXPECT_TRUE(info->etf.has_value() && *info->etf == want);

    auto short_parms = reply;
    short_parms[48] = 0x0c;  // TCA_ETF_PARMS of 8 octets: shorter than tc_etf_qopt
    EXPECT_FALSE(parse_qdisc(short_parms).has_value());
}

// Any other kind (the default fq_codel the kernel put on legacy queue 2,
// class 9000:3) parses to its kind, handle 0 and parent, its options skipped.
TEST(tc_qdisc, parse_other_kind_reply)
{
    if (!LITTLE) {
        return;
    }
    // clang-format off
    std::array<uint8_t, 64> const reply{
        0x40, 0x00, 0x00, 0x00,  0x24, 0x00,  0x00, 0x00,  0x0b, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x90,  0x01, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x01, 0x00,  'f', 'q', '_', 'c', 'o', 'd', 'e', 'l', 0x00,  0x00, 0x00, 0x00,
        // TCA_OPTIONS, len 12 > a u32 attribute
        0x0c, 0x00, 0x02, 0x00,  0x08, 0x00, 0x02, 0x00,  0x00, 0x28, 0x00, 0x00,
    };
    // clang-format on
    auto const info = parse_qdisc(reply);
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->handle, uint32_t{0});
    EXPECT_EQ(info->parent, make_handle(0x9000, 3));
    EXPECT_TRUE(info->kind == "fq_codel");
    EXPECT_FALSE(info->mqprio.has_value() || info->cbs.has_value());
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

// Reading qdiscs needs no privilege: loopback's root, found in the dump of
// every device's, is the default noqueue.
TEST(tc_qdisc, get_loopback_root)
{
    auto const index = interface_index("lo");
    TcClient client{};
    if (!index || !client.open()) {
        std::println("  no NETLINK_ROUTE socket here: skipped");
        return;
    }
    auto const root = client.get(*index, ROOT);
    EXPECT_TRUE(root.has_value());
    if (root) {
        EXPECT_TRUE(root->kind == "noqueue");
        EXPECT_FALSE(root->mqprio.has_value() || root->cbs.has_value());
    }
    // Nothing under a class of a qdisc that does not exist.
    EXPECT_FALSE(client.get(*index, make_handle(0x9123, 1)).has_value());
}

}  // namespace

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_qdisc_test)
