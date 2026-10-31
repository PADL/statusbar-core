// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the rtnetlink traffic-control message builders and parser.
///
/// Every test here runs in CI: no socket, no root, no NIC. That is the
/// point of splitting the builders out from the client — the bytes we
/// send to the kernel are the part most likely to be wrong, and they are
/// checkable without the kernel.
///
/// Two styles of check, deliberately:
///
///   * The small messages (delete, dump, replace_kind) and the cbs
///     request are compared against a complete hand-written byte array.
///   * mqprio is checked field by field at named offsets, with every
///     padding byte asserted zero and the total length asserted. A
///     136-byte hex wall would catch the same errors while documenting
///     none of them.
///
/// Offsets and sizes come from <linux/netlink.h>, <linux/rtnetlink.h> and
/// <linux/pkt_sched.h>: nlmsghdr is 16 bytes, tcmsg 20, rtattr 4,
/// tc_mqprio_qopt 82 and tc_cbs_qopt 20, with every attribute payload
/// padded up to a multiple of 4.

#include "statusbar/net/net_tc_qdisc.hpp"

#include "statusbar/net/net_tc_qdisc_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include <unistd.h>

#    include <net/if.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

#if defined(__linux__)

namespace {

constexpr std::uint32_t SEQ = 0x11223344U;
constexpr int IFINDEX = 7;

/// Byte offsets into a qdisc request, from the three struct layouts.
constexpr std::size_t NLMSGHDR_SIZE = 16;
constexpr std::size_t TCMSG_SIZE = 20;
constexpr std::size_t RTATTR_SIZE = 4;
constexpr std::size_t PAYLOAD_START = NLMSGHDR_SIZE + TCMSG_SIZE;  // 36

[[nodiscard]] auto read_u16(std::span<std::uint8_t const> message, std::size_t at) -> std::uint16_t
{
    return static_cast<std::uint16_t>(message[at] | (static_cast<std::uint16_t>(message[at + 1]) << 8));
}

[[nodiscard]] auto read_u32(std::span<std::uint8_t const> message, std::size_t at) -> std::uint32_t
{
    return static_cast<std::uint32_t>(message[at]) | (static_cast<std::uint32_t>(message[at + 1]) << 8) |
        (static_cast<std::uint32_t>(message[at + 2]) << 16) | (static_cast<std::uint32_t>(message[at + 3]) << 24);
}

[[nodiscard]] auto read_i32(std::span<std::uint8_t const> message, std::size_t at) -> std::int32_t
{
    return static_cast<std::int32_t>(read_u32(message, at));
}

/// A valid three-class mqprio request, used by several tests.
[[nodiscard]] auto sample_mqprio() -> tc::MqprioQdisc
{
    tc::MqprioQdisc qdisc;
    qdisc.major = 0x8001;
    qdisc.num_tc = 3;
    qdisc.prio_tc_map = {0, 0, 0, 1, 1, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0};
    qdisc.count = {1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    qdisc.offset = {0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    qdisc.offload = true;
    return qdisc;
}

/// A Class A cbs hanging off the sample mqprio's second class.
[[nodiscard]] auto sample_cbs() -> tc::CbsQdisc
{
    tc::CbsQdisc qdisc;
    qdisc.parent = tc::make_handle(0x8001, 1);
    qdisc.handle_major = 0x8002;
    qdisc.idleslope_kbps = 7808;     // kbit/s
    qdisc.sendslope_kbps = -992192;  // kbit/s
    qdisc.hicredit = 2;              // bytes
    qdisc.locredit = -249;           // bytes
    qdisc.offload = true;
    return qdisc;
}

}  // namespace

TEST(tc_qdisc, delete_request_is_byte_for_byte_as_expected)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_delete(out, IFINDEX, tc::make_handle(0x8001, 0), tc::ROOT, SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // 16 + 20, no attributes: a delete names the qdisc and says nothing else.
    std::array<std::uint8_t, 36> const expected{
        // nlmsghdr
        0x24,
        0x00,
        0x00,
        0x00,  // nlmsg_len = 36
        0x25,
        0x00,  // nlmsg_type = RTM_DELQDISC (37)
        0x05,
        0x00,  // nlmsg_flags = REQUEST|ACK
        0x44,
        0x33,
        0x22,
        0x11,  // nlmsg_seq
        0x00,
        0x00,
        0x00,
        0x00,  // nlmsg_pid = 0, the kernel fills it in
        // tcmsg
        0x00,
        0x00,
        0x00,
        0x00,  // tcm_family = AF_UNSPEC + pad1 + pad2
        0x07,
        0x00,
        0x00,
        0x00,  // tcm_ifindex = 7
        0x00,
        0x00,
        0x01,
        0x80,  // tcm_handle = 0x80010000
        0xFF,
        0xFF,
        0xFF,
        0xFF,  // tcm_parent = TC_H_ROOT
        0x00,
        0x00,
        0x00,
        0x00,  // tcm_info = 0
    };

    EXPECT_EQ(*length, expected.size());
    if (*length != expected.size()) {
        return;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(out[i], expected[i]);
    }
}

TEST(tc_qdisc, dump_request_is_byte_for_byte_as_expected)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_dump(out, IFINDEX, SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    std::array<std::uint8_t, 36> const expected{
        0x24, 0x00, 0x00, 0x00,  // nlmsg_len = 36
        0x26, 0x00,              // nlmsg_type = RTM_GETQDISC (38)
        0x01, 0x03,              // nlmsg_flags = REQUEST|DUMP (0x301)
        0x44, 0x33, 0x22, 0x11,  // nlmsg_seq
        0x00, 0x00, 0x00, 0x00,  // nlmsg_pid
        0x00, 0x00, 0x00, 0x00,  // tcm_family + pads
        0x07, 0x00, 0x00, 0x00,  // tcm_ifindex = 7
        0x00, 0x00, 0x00, 0x00,  // tcm_handle = 0
        0x00, 0x00, 0x00, 0x00,  // tcm_parent = TC_H_UNSPEC
        0x00, 0x00, 0x00, 0x00,  // tcm_info = 0
    };

    EXPECT_EQ(*length, expected.size());
    if (*length != expected.size()) {
        return;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(out[i], expected[i]);
    }
}

TEST(tc_qdisc, a_dump_is_requested_not_a_single_qdisc_get)
{
    // Trap worth encoding. RTM_GETQDISC for one qdisc is answered through
    // rtnetlink_send, which also notifies every RTNLGRP_TC listener — so a
    // *read* shows up in anyone's `tc monitor` as a change. Dumping the
    // namespace and filtering locally has no such side effect, so the DUMP
    // flag is part of the contract, not an optimisation.
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_dump(out, IFINDEX, SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    constexpr std::uint16_t NLM_F_DUMP_EXPECTED = 0x0300;
    constexpr std::uint16_t NLM_F_ECHO_EXPECTED = 0x0008;
    auto const flags = read_u16(out, 6);
    EXPECT_EQ(flags & NLM_F_DUMP_EXPECTED, NLM_F_DUMP_EXPECTED);
    EXPECT_EQ(flags & NLM_F_ECHO_EXPECTED, 0);
}

TEST(tc_qdisc, replace_kind_request_is_byte_for_byte_as_expected)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_kind(out, IFINDEX, tc::make_handle(0x8001, 1), "pfifo_fast", SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // 16 + 20 + TCA_KIND("pfifo_fast\0" = 11 bytes, padded to 12) = 52.
    std::array<std::uint8_t, 52> const expected{
        0x34, 0x00, 0x00, 0x00,  // nlmsg_len = 52
        0x24, 0x00,              // nlmsg_type = RTM_NEWQDISC (36)
        0x05, 0x05,              // nlmsg_flags = REQUEST|ACK|REPLACE|CREATE
        0x44, 0x33, 0x22, 0x11,  // nlmsg_seq
        0x00, 0x00, 0x00, 0x00,  // nlmsg_pid
        0x00, 0x00, 0x00, 0x00,  // tcm_family + pads
        0x07, 0x00, 0x00, 0x00,  // tcm_ifindex = 7
        0x00, 0x00, 0x00, 0x00,  // tcm_handle = 0 (let the kernel choose)
        0x01, 0x00, 0x01, 0x80,  // tcm_parent = 0x80010001
        0x00, 0x00, 0x00, 0x00,  // tcm_info = 0
        0x0F, 0x00,              // rta_len = 15
        0x01, 0x00,              // rta_type = TCA_KIND
        'p',  'f',  'i',  'f',  'o', '_', 'f', 'a', 's', 't', 0x00,
        0x00,  // pad to 4
    };

    EXPECT_EQ(*length, expected.size());
    if (*length != expected.size()) {
        return;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(out[i], expected[i]);
    }
}

TEST(tc_qdisc, cbs_request_is_byte_for_byte_as_expected)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // 16 + 20 + TCA_KIND("cbs\0" = 8) + TCA_OPTIONS(4 + TCA_CBS_PARMS(4 + 20)) = 72.
    std::array<std::uint8_t, 72> const expected{
        0x48, 0x00, 0x00, 0x00,  // nlmsg_len = 72
        0x24, 0x00,              // nlmsg_type = RTM_NEWQDISC
        0x05, 0x05,              // nlmsg_flags = REQUEST|ACK|REPLACE|CREATE
        0x44, 0x33, 0x22, 0x11,  // nlmsg_seq
        0x00, 0x00, 0x00, 0x00,  // nlmsg_pid
        0x00, 0x00, 0x00, 0x00,  // tcm_family + pads
        0x07, 0x00, 0x00, 0x00,  // tcm_ifindex = 7
        0x00, 0x00, 0x02, 0x80,  // tcm_handle = 0x80020000
        0x01, 0x00, 0x01, 0x80,  // tcm_parent = 0x80010001 (mqprio class 1)
        0x00, 0x00, 0x00, 0x00,  // tcm_info = 0
        0x08, 0x00,              // rta_len = 8
        0x01, 0x00,              // rta_type = TCA_KIND
        'c',  'b',  's',  0x00,  // "cbs\0", already a multiple of 4
        0x1C, 0x00,              // rta_len = 28
        0x02, 0x00,              // rta_type = TCA_OPTIONS
        0x18, 0x00,              // rta_len = 24
        0x01, 0x00,              // rta_type = TCA_CBS_PARMS
        0x01,                    // offload = 1
        0x00, 0x00, 0x00,        // _pad[3]
        0x02, 0x00, 0x00, 0x00,  // hicredit = 2
        0x07, 0xFF, 0xFF, 0xFF,  // locredit = -249
        0x80, 0x1E, 0x00, 0x00,  // idleslope = 7808
        0x40, 0xDC, 0xF0, 0xFF,  // sendslope = -992192
    };

    EXPECT_EQ(*length, expected.size());
    if (*length != expected.size()) {
        return;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(out[i], expected[i]);
    }
}

TEST(tc_qdisc, mqprio_request_has_the_expected_header_and_attributes)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, sample_mqprio(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // 16 + 20 + TCA_KIND("mqprio\0" = 11 -> 12) + TCA_OPTIONS(4 + 82 = 86 -> 88).
    EXPECT_EQ(*length, 136u);
    if (*length != 136u) {
        return;
    }

    EXPECT_EQ(read_u32(out, 0), 136u);     // nlmsg_len
    EXPECT_EQ(read_u16(out, 4), 36u);      // RTM_NEWQDISC
    EXPECT_EQ(read_u16(out, 6), 0x0505u);  // REQUEST|ACK|REPLACE|CREATE
    EXPECT_EQ(read_u32(out, 8), SEQ);      // nlmsg_seq
    EXPECT_EQ(read_u32(out, 12), 0u);      // nlmsg_pid

    EXPECT_EQ(out[16], 0u);                     // tcm_family = AF_UNSPEC
    EXPECT_EQ(read_u32(out, 20), 7u);           // tcm_ifindex
    EXPECT_EQ(read_u32(out, 24), 0x80010000u);  // tcm_handle
    EXPECT_EQ(read_u32(out, 28), tc::ROOT);     // tcm_parent
    EXPECT_EQ(read_u32(out, 32), 0u);           // tcm_info

    // TCA_KIND at 36
    EXPECT_EQ(read_u16(out, PAYLOAD_START), 11u);     // rta_len
    EXPECT_EQ(read_u16(out, PAYLOAD_START + 2), 1u);  // TCA_KIND
    EXPECT_EQ(std::string_view(reinterpret_cast<char const*>(&out[PAYLOAD_START + RTATTR_SIZE]), 6), "mqprio");
    EXPECT_EQ(out[PAYLOAD_START + RTATTR_SIZE + 6], 0u);  // terminator
    EXPECT_EQ(out[PAYLOAD_START + 11], 0u);               // pad byte must be zero

    // TCA_OPTIONS at 48
    constexpr std::size_t OPTIONS = 48;
    EXPECT_EQ(read_u16(out, OPTIONS), 86u);     // rta_len = 4 + sizeof(tc_mqprio_qopt)
    EXPECT_EQ(read_u16(out, OPTIONS + 2), 2u);  // TCA_OPTIONS

    // tc_mqprio_qopt at 52: num_tc@0, prio_tc_map@1, hw@17, count@18, offset@50
    constexpr std::size_t QOPT = OPTIONS + RTATTR_SIZE;
    EXPECT_EQ(out[QOPT], 3u);       // num_tc
    EXPECT_EQ(out[QOPT + 17], 1u);  // hw = offload requested

    std::array<std::uint8_t, 16> const expected_map{0, 0, 0, 1, 1, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0};
    for (std::size_t i = 0; i < expected_map.size(); ++i) {
        EXPECT_EQ(out[QOPT + 1 + i], expected_map[i]);
    }

    std::array<std::uint16_t, 16> const expected_count{1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::array<std::uint16_t, 16> const expected_offset{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(read_u16(out, QOPT + 18 + (i * 2)), expected_count[i]);
        EXPECT_EQ(read_u16(out, QOPT + 50 + (i * 2)), expected_offset[i]);
    }

    // The two trailing pad bytes that bring 86 up to 88.
    EXPECT_EQ(out[134], 0u);
    EXPECT_EQ(out[135], 0u);
}

TEST(tc_qdisc, mqprio_without_offload_clears_the_hw_byte)
{
    auto qdisc = sample_mqprio();
    qdisc.offload = false;

    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, qdisc, SEQ);
    EXPECT_TRUE(length.has_value());
    if (length) {
        // 48 TCA_OPTIONS header -> 52 tc_mqprio_qopt, whose `hw` is at
        // offset 17 (num_tc, then the 16-entry priority map).
        constexpr std::size_t MQPRIO_HW_BYTE = 52 + 17;
        EXPECT_EQ(out[MQPRIO_HW_BYTE], 0u);
    }
}

TEST(tc_qdisc, cbs_without_offload_clears_the_offload_byte)
{
    // A software cbs sits in the qdisc layer. That still shapes our default
    // AF_PACKET traffic (we do not set PACKET_QDISC_BYPASS by default), but
    // never an AF_XDP or bypass frame, which skip the qdisc layer entirely.
    auto qdisc = sample_cbs();
    qdisc.offload = false;

    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, qdisc, SEQ);
    EXPECT_TRUE(length.has_value());
    if (length) {
        // 36 TCA_KIND("cbs\0" = 8) -> 44 TCA_OPTIONS header -> 48
        // TCA_CBS_PARMS header -> 52, the first byte of tc_cbs_qopt.
        constexpr std::size_t CBS_OFFLOAD_BYTE = 52;
        EXPECT_EQ(out[CBS_OFFLOAD_BYTE], 0u);
    }
}

TEST(tc_qdisc, every_request_fits_in_max_request_size)
{
    // The bound that lets a request live on the stack with no allocation.
    // mqprio is the largest at 136.
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const mqprio = tc::build_replace_mqprio(out, IFINDEX, sample_mqprio(), SEQ);
    auto const cbs = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    auto const kind = tc::build_replace_kind(out, IFINDEX, tc::ROOT, "pfifo_fast", SEQ);
    auto const removed = tc::build_delete(out, IFINDEX, 0x80010000U, tc::ROOT, SEQ);
    auto const dump = tc::build_dump(out, IFINDEX, SEQ);

    EXPECT_TRUE(mqprio.has_value());
    EXPECT_TRUE(cbs.has_value());
    EXPECT_TRUE(kind.has_value());
    EXPECT_TRUE(removed.has_value());
    EXPECT_TRUE(dump.has_value());
    if (mqprio) {
        EXPECT_TRUE(*mqprio <= tc::MAX_REQUEST_SIZE);
    }
}

TEST(tc_qdisc, a_buffer_one_byte_short_is_refused_rather_than_truncated)
{
    std::array<std::uint8_t, 135> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, sample_mqprio(), SEQ);
    EXPECT_FALSE(length.has_value());
    if (!length) {
        EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, a_handle_major_of_zero_is_refused)
{
    // The kernel's own diagnosis of this is poor, so validate first.
    auto qdisc = sample_mqprio();
    qdisc.major = 0;

    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, qdisc, SEQ);
    EXPECT_FALSE(length.has_value());
    if (!length) {
        EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, a_num_tc_of_zero_or_above_the_maximum_is_refused)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};

    auto none = sample_mqprio();
    none.num_tc = 0;
    EXPECT_FALSE(tc::build_replace_mqprio(out, IFINDEX, none, SEQ).has_value());

    auto too_many = sample_mqprio();
    too_many.num_tc = static_cast<std::uint8_t>(tc::MAX_TRAFFIC_CLASSES + 1);
    EXPECT_FALSE(tc::build_replace_mqprio(out, IFINDEX, too_many, SEQ).has_value());

    // The boundary is accepted: exactly MAX_TRAFFIC_CLASSES classes, with a
    // priority map that stays in range.
    auto at_limit = sample_mqprio();
    at_limit.num_tc = static_cast<std::uint8_t>(tc::MAX_TRAFFIC_CLASSES);
    at_limit.prio_tc_map = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    EXPECT_TRUE(tc::build_replace_mqprio(out, IFINDEX, at_limit, SEQ).has_value());
}

TEST(tc_qdisc, a_priority_map_entry_not_below_num_tc_is_refused)
{
    // The failure this prevents is the quiet one: the kernel may accept a
    // map whose class index has no queues behind it, and frames at that
    // priority then go to a queue that is never serviced.
    auto qdisc = sample_mqprio();
    qdisc.prio_tc_map[5] = 3;  // num_tc is 3, so classes are 0..2

    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, qdisc, SEQ);
    EXPECT_FALSE(length.has_value());
    if (!length) {
        EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, a_cbs_handle_major_of_zero_is_refused)
{
    auto qdisc = sample_cbs();
    qdisc.handle_major = 0;

    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    EXPECT_FALSE(tc::build_replace_cbs(out, IFINDEX, qdisc, SEQ).has_value());
}

TEST(tc_qdisc, an_empty_or_oversized_kind_is_refused)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};

    EXPECT_FALSE(tc::build_replace_kind(out, IFINDEX, tc::ROOT, "", SEQ).has_value());

    std::string const too_long(tc::MAX_KIND_LENGTH + 1, 'x');
    EXPECT_FALSE(tc::build_replace_kind(out, IFINDEX, tc::ROOT, too_long, SEQ).has_value());

    std::string const longest(tc::MAX_KIND_LENGTH, 'x');
    EXPECT_TRUE(tc::build_replace_kind(out, IFINDEX, tc::ROOT, longest, SEQ).has_value());
}

TEST(tc_qdisc, make_handle_packs_major_and_minor)
{
    EXPECT_EQ(tc::make_handle(0x8001, 0), 0x80010000U);
    EXPECT_EQ(tc::make_handle(0x8001, 1), 0x80010001U);
    EXPECT_EQ(tc::make_handle(1, 0xFFFF), 0x0001FFFFU);
}

TEST(tc_qdisc, parse_qdisc_round_trips_the_mqprio_builder)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_mqprio(out, IFINDEX, sample_mqprio(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    auto const info = tc::parse_qdisc({out.data(), *length});
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->ifindex, IFINDEX);
    EXPECT_EQ(info->handle, 0x80010000U);
    EXPECT_EQ(info->parent, tc::ROOT);
    EXPECT_EQ(info->kind_name(), "mqprio");
    EXPECT_FALSE(info->has_cbs_params);
}

TEST(tc_qdisc, parse_qdisc_round_trips_the_cbs_builder_including_its_slopes)
{
    // This is what the shaper reads back to find out a driver silently
    // clamped a slope, so the numbers have to survive the round trip
    // exactly — including the negative ones.
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    auto const info = tc::parse_qdisc({out.data(), *length});
    EXPECT_TRUE(info.has_value());
    if (!info) {
        return;
    }
    EXPECT_EQ(info->kind_name(), "cbs");
    EXPECT_EQ(info->handle, 0x80020000U);
    EXPECT_EQ(info->parent, tc::make_handle(0x8001, 1));
    EXPECT_TRUE(info->has_cbs_params);
    EXPECT_EQ(info->cbs.idleslope_kbps, 7808);
    EXPECT_EQ(info->cbs.sendslope_kbps, -992192);
    EXPECT_EQ(info->cbs.hicredit, 2);
    EXPECT_EQ(info->cbs.locredit, -249);
    EXPECT_TRUE(info->cbs.offload);
}

TEST(tc_qdisc, parse_qdisc_round_trips_the_kind_builder)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_kind(out, IFINDEX, tc::make_handle(0x8001, 2), "pfifo_fast", SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    auto const info = tc::parse_qdisc({out.data(), *length});
    EXPECT_TRUE(info.has_value());
    if (info) {
        EXPECT_EQ(info->kind_name(), "pfifo_fast");
        EXPECT_EQ(info->parent, tc::make_handle(0x8001, 2));
    }
}

TEST(tc_qdisc, parse_qdisc_rejects_a_truncated_message_distinguishably)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // Shorter than an nlmsghdr.
    auto const no_header = tc::parse_qdisc({out.data(), 8});
    EXPECT_FALSE(no_header.has_value());
    if (!no_header) {
        EXPECT_EQ(no_header.error(), make_error_code(NetError::invalid_argument));
    }

    // A header whose nlmsg_len claims more than we were handed.
    auto const short_body = tc::parse_qdisc({out.data(), *length - 1});
    EXPECT_FALSE(short_body.has_value());
    if (!short_body) {
        EXPECT_EQ(short_body.error(), make_error_code(NetError::invalid_argument));
    }

    // Long enough for the header but not for the tcmsg behind it.
    std::array<std::uint8_t, 20> stub{};
    stub[0] = 20;
    stub[4] = 36;  // RTM_NEWQDISC
    auto const no_tcmsg = tc::parse_qdisc(stub);
    EXPECT_FALSE(no_tcmsg.has_value());
    if (!no_tcmsg) {
        EXPECT_EQ(no_tcmsg.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, parse_qdisc_rejects_a_wrong_message_type_distinguishably)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // RTM_NEWLINK (16) where a qdisc message belongs. Distinguishable from
    // a truncation, because a dump reply stream contains other message
    // types and the client must skip rather than fail.
    out[4] = 16;
    out[5] = 0;
    auto const wrong = tc::parse_qdisc({out.data(), *length});
    EXPECT_FALSE(wrong.has_value());
    if (!wrong) {
        EXPECT_EQ(wrong.error(), make_error_code(NetError::not_supported));
    }
}

TEST(tc_qdisc, parse_qdisc_rejects_a_short_options_blob_distinguishably)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // Shrink TCA_CBS_PARMS so its payload is smaller than tc_cbs_qopt, and
    // shrink everything above it to match so the message stays well-formed
    // as a netlink message. The parse must notice the blob cannot hold the
    // struct rather than read past it.
    constexpr std::size_t OPTIONS = 44;  // after 36 + TCA_KIND("cbs\0" = 8)
    out[OPTIONS] = 4 + 4 + 8;            // TCA_OPTIONS rta_len
    out[OPTIONS + 4] = 4 + 8;            // TCA_CBS_PARMS rta_len: 8 bytes of payload
    auto const truncated_length = OPTIONS + 4 + 4 + 8;
    out[0] = static_cast<std::uint8_t>(truncated_length);

    auto const short_blob = tc::parse_qdisc({out.data(), truncated_length});
    EXPECT_TRUE(short_blob.has_value());
    if (short_blob) {
        // The qdisc itself is still reportable — we know its kind, handle
        // and parent. What must NOT happen is a confident set of slopes
        // read out of a blob too small to hold them.
        EXPECT_EQ(short_blob->kind_name(), "cbs");
        EXPECT_FALSE(short_blob->has_cbs_params);
    }
}

TEST(tc_qdisc, parse_qdisc_ignores_an_attribute_whose_rta_len_runs_past_the_message)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // A hostile or corrupt rta_len. The walk must stop, not read on.
    out[44] = 0xFF;
    out[45] = 0xFF;
    auto const info = tc::parse_qdisc({out.data(), *length});
    EXPECT_TRUE(info.has_value());
    if (info) {
        EXPECT_EQ(info->kind_name(), "cbs");
        EXPECT_FALSE(info->has_cbs_params);
    }
}

TEST(tc_qdisc, parse_qdisc_tolerates_an_rta_len_below_the_header_size)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_replace_cbs(out, IFINDEX, sample_cbs(), SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    // rta_len of 0 would make a naive walk loop forever.
    out[36] = 0;
    out[37] = 0;
    auto const info = tc::parse_qdisc({out.data(), *length});
    EXPECT_TRUE(info.has_value());
    if (info) {
        EXPECT_TRUE(info->kind_name().empty());
    }
}

namespace {

/// Append a little-endian value of `width` bytes.
auto push(std::vector<std::uint8_t>& out, std::uint64_t value, std::size_t width) -> void
{
    for (std::size_t i = 0; i < width; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFU));
    }
}

/// Build an NLMSG_ERROR the way the kernel does, so parse_ack's offset
/// arithmetic is exercised against both shapes.
///
/// @param errno_value Positive errno; the kernel carries it negated.
/// @param capped Whether NLM_F_CAPPED is set. When it is not, the whole
///        offending request is appended and the TLVs sit after it — which
///        is the case that is easy to get wrong.
/// @param text Extended-ack text, or empty for none.
auto make_error_reply(int errno_value, bool capped, std::string_view text) -> std::vector<std::uint8_t>
{
    constexpr std::uint16_t NLMSG_ERROR_TYPE = 2;
    constexpr std::uint16_t NLM_F_CAPPED_FLAG = 0x0100;
    constexpr std::size_t ORIGINAL_REQUEST_LENGTH = 36;  // a delete: 16 + 20
    constexpr std::uint16_t NLMSGERR_ATTR_MSG_TYPE = 1;

    std::vector<std::uint8_t> body;
    push(body, static_cast<std::uint64_t>(static_cast<std::uint32_t>(-errno_value)), 4);  // nlmsgerr.error

    // nlmsgerr.msg: a copy of the offending request's header.
    push(body, ORIGINAL_REQUEST_LENGTH, 4);  // nlmsg_len
    push(body, 37, 2);                       // RTM_DELQDISC
    push(body, 0x0005, 2);                   // REQUEST|ACK
    push(body, SEQ, 4);                      // nlmsg_seq
    push(body, 0, 4);                        // nlmsg_pid

    if (!capped) {
        // The rest of the original request, which the TLVs come after.
        for (std::size_t i = 0; i < ORIGINAL_REQUEST_LENGTH - NLMSGHDR_SIZE; ++i) {
            body.push_back(0xAB);  // recognisable filler, not valid attributes
        }
    }
    if (!text.empty()) {
        push(body, RTATTR_SIZE + text.size() + 1, 2);  // rta_len
        push(body, NLMSGERR_ATTR_MSG_TYPE, 2);         // rta_type
        for (char const character : text) {
            body.push_back(static_cast<std::uint8_t>(character));
        }
        body.push_back(0);  // the kernel NUL-terminates the text
    }

    std::vector<std::uint8_t> message;
    push(message, NLMSGHDR_SIZE + body.size(), 4);
    push(message, NLMSG_ERROR_TYPE, 2);
    push(message, capped ? NLM_F_CAPPED_FLAG : 0U, 2);
    push(message, SEQ, 4);
    push(message, 0, 4);
    message.insert(message.end(), body.begin(), body.end());
    return message;
}

}  // namespace

TEST(tc_qdisc, parse_ack_reads_an_uncapped_error_and_its_extended_ack_text)
{
    // The case the offset arithmetic exists for: the whole offending
    // request is echoed back, and the TLVs sit *after* it. Computing the
    // offset as sizeof(nlmsgerr) alone reads the echoed request's own
    // bytes as attributes -- here, 0xAB filler.
    auto const reply = make_error_reply(EINVAL, /*capped=*/false, "Specified qdisc kind is unknown");

    auto const ack = tc::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EINVAL);
        EXPECT_EQ(ack->message, "Specified qdisc kind is unknown");
    }
}

TEST(tc_qdisc, parse_ack_reads_a_capped_error_and_its_extended_ack_text)
{
    // With NLM_F_CAPPED the request is not echoed, so the TLVs start right
    // after the nlmsgerr. The same code must handle both.
    auto const reply = make_error_reply(EOPNOTSUPP, /*capped=*/true, "Offload not supported");

    auto const ack = tc::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EOPNOTSUPP);
        EXPECT_EQ(ack->message, "Offload not supported");
    }
}

TEST(tc_qdisc, parse_ack_reports_an_eperm_with_no_text_as_exactly_that)
{
    // What the kernel actually sends an unprivileged writer: the
    // permission check fires before any ext-ack is set, so there is no
    // text. An empty message must not be mistaken for a parse failure.
    auto const reply = make_error_reply(EPERM, /*capped=*/false, "");

    auto const ack = tc::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EPERM);
        EXPECT_TRUE(ack->message.empty());
    }
}

TEST(tc_qdisc, parse_ack_reads_a_plain_acknowledgement_as_success)
{
    auto const reply = make_error_reply(0, /*capped=*/false, "");

    auto const ack = tc::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, 0);
        EXPECT_TRUE(ack->message.empty());
    }
}

TEST(tc_qdisc, parse_ack_refuses_a_message_that_is_not_an_error)
{
    std::array<std::uint8_t, tc::MAX_REQUEST_SIZE> out{};
    auto const length = tc::build_dump(out, IFINDEX, SEQ);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }

    auto const ack = tc::parse_ack({out.data(), *length});
    EXPECT_FALSE(ack.has_value());
    if (!ack) {
        EXPECT_EQ(ack.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, parse_ack_refuses_a_truncated_error)
{
    auto reply = make_error_reply(EPERM, /*capped=*/true, "");

    // Short of nlmsghdr + nlmsgerr.
    auto const too_short = tc::parse_ack({reply.data(), 20});
    EXPECT_FALSE(too_short.has_value());
    if (!too_short) {
        EXPECT_EQ(too_short.error(), make_error_code(NetError::invalid_argument));
    }

    // A header claiming more than we hold.
    auto const over_claimed = tc::parse_ack({reply.data(), reply.size() - 1});
    EXPECT_FALSE(over_claimed.has_value());
    if (!over_claimed) {
        EXPECT_EQ(over_claimed.error(), make_error_code(NetError::invalid_argument));
    }
}

TEST(tc_qdisc, parse_ack_ignores_a_tlv_whose_rta_len_runs_past_the_message)
{
    auto reply = make_error_reply(EINVAL, /*capped=*/true, "Offload not supported");

    // Corrupt the TLV's rta_len. The walk must stop and leave the errno
    // intact rather than read on.
    constexpr std::size_t TLV_START = NLMSGHDR_SIZE + 20;  // after nlmsgerr
    reply[TLV_START] = 0xFF;
    reply[TLV_START + 1] = 0xFF;

    auto const ack = tc::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EINVAL);
        EXPECT_TRUE(ack->message.empty());
    }
}

TEST(tc_qdisc, client_opens_a_netlink_socket_without_privilege)
{
    // NETLINK_ROUTE needs no capability to open, bind or read -- only
    // writes do. That is what makes the dump path testable in CI.
    tc::TcClient client;
    auto const opened = client.open();
    EXPECT_TRUE(opened.has_value());
    if (opened) {
        EXPECT_TRUE(client.valid());
    }
}

TEST(tc_qdisc, opening_a_client_twice_is_refused)
{
    tc::TcClient client;
    EXPECT_TRUE(client.open().has_value());

    auto const again = client.open();
    EXPECT_FALSE(again.has_value());
    if (!again) {
        EXPECT_EQ(again.error(), make_error_code(NetError::already_connected));
    }
}

TEST(tc_qdisc, a_closed_client_refuses_every_operation)
{
    tc::TcClient client;
    EXPECT_FALSE(client.valid());

    auto const read_back = client.get(1, tc::ROOT);
    EXPECT_FALSE(read_back.has_value());
    if (!read_back) {
        EXPECT_EQ(read_back.error(), make_error_code(NetError::not_connected));
    }

    auto const removed = client.remove(1, 0x80010000U, tc::ROOT);
    EXPECT_FALSE(removed.has_value());
    if (!removed) {
        EXPECT_EQ(removed.error(), make_error_code(NetError::not_connected));
    }
}

TEST(tc_qdisc, get_reads_back_the_root_qdisc_of_loopback)
{
    // A real dump against a real kernel, unprivileged: this exercises the
    // whole send/drain/filter/parse path including the port-id filter.
    tc::TcClient client;
    if (!client.open()) {
        return;
    }
    auto const lo = ::if_nametoindex("lo");
    EXPECT_TRUE(lo > 0);
    if (lo == 0) {
        return;
    }

    auto const root = client.get(static_cast<int>(lo), tc::ROOT);
    EXPECT_TRUE(root.has_value());
    if (root) {
        // Loopback's root is normally `noqueue`; the assertion is only
        // that we found *a* qdisc on the interface we asked about.
        EXPECT_EQ(root->ifindex, static_cast<int>(lo));
        EXPECT_EQ(root->parent, tc::ROOT);
        EXPECT_FALSE(root->kind_name().empty());
    }
}

TEST(tc_qdisc, get_reports_a_qdisc_that_is_not_there_as_a_bad_handle)
{
    tc::TcClient client;
    if (!client.open()) {
        return;
    }
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }

    // No qdisc hangs off this class on loopback.
    auto const missing = client.get(static_cast<int>(lo), tc::make_handle(0x7FFF, 9));
    EXPECT_FALSE(missing.has_value());
    if (!missing) {
        EXPECT_EQ(missing.error(), make_error_code(NetError::invalid_handle));
    }
}

TEST(tc_qdisc, two_dumps_in_a_row_both_succeed)
{
    // The bug this pins: a dump reply stream must be read to NLMSG_DONE.
    // Leaving replies in the socket is not harmless -- the next request
    // reads a leftover NLMSG_DONE as its own acknowledgement, which looks
    // like success. The second get() here fails if the first left anything.
    tc::TcClient client;
    if (!client.open()) {
        return;
    }
    auto const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        return;
    }

    EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
    EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
}

TEST(tc_qdisc, an_unprivileged_write_fails_and_the_client_survives_it)
{
    tc::TcClient client;
    if (!client.open()) {
        return;
    }

    // An ifindex no interface has, so this cannot disturb the host even
    // when the suite is run as root. Unprivileged the kernel refuses on
    // the capability check, which happens before the ifindex lookup; as
    // root it refuses on the lookup. Either way it must fail cleanly and
    // leave the client usable.
    constexpr int NO_SUCH_IFINDEX = 0x7FFFFFF0;
    auto const removed = client.remove(NO_SUCH_IFINDEX, tc::make_handle(0x8001, 0), tc::ROOT);
    EXPECT_FALSE(removed.has_value());
    if (!removed) {
        auto const expected = (::geteuid() == 0) ? std::make_error_code(std::errc::no_such_device)
                                                 : std::make_error_code(std::errc::operation_not_permitted);
        EXPECT_EQ(removed.error(), expected);
    }

    // And the socket is still good for the next transaction.
    auto const lo = ::if_nametoindex("lo");
    if (lo > 0) {
        EXPECT_TRUE(client.get(static_cast<int>(lo), tc::ROOT).has_value());
    }
}

TEST(tc_recorder, records_the_full_request_sequence)
{
    // The capability criterion 3 asks for: a caller's tests can assert the
    // whole sequence a shaper makes, with no kernel. This stands in for
    // those tests until a shaper exists.
    tc::TcRecorder recorder;

    EXPECT_TRUE(recorder.replace_mqprio(IFINDEX, sample_mqprio()).has_value());
    EXPECT_TRUE(recorder.replace_cbs(IFINDEX, sample_cbs()).has_value());
    EXPECT_TRUE(recorder.replace_kind(IFINDEX, tc::make_handle(0x8001, 2), "pfifo_fast").has_value());
    EXPECT_TRUE(recorder.remove(IFINDEX, tc::make_handle(0x8001, 0), tc::ROOT).has_value());

    auto const requests = recorder.requests();
    EXPECT_EQ(requests.size(), 4u);
    if (requests.size() != 4) {
        return;
    }
    EXPECT_TRUE(requests[0].operation == tc::TcRecorder::Operation::replace_mqprio);
    EXPECT_EQ(requests[0].mqprio.num_tc, 3u);
    EXPECT_EQ(requests[0].parent, tc::ROOT);
    EXPECT_TRUE(requests[1].operation == tc::TcRecorder::Operation::replace_cbs);
    EXPECT_EQ(requests[1].cbs.idleslope_kbps, 7808);
    EXPECT_EQ(requests[1].parent, tc::make_handle(0x8001, 1));
    EXPECT_TRUE(requests[2].operation == tc::TcRecorder::Operation::replace_kind);
    EXPECT_EQ(requests[2].kind, "pfifo_fast");
    EXPECT_TRUE(requests[3].operation == tc::TcRecorder::Operation::remove);
    EXPECT_EQ(requests[3].handle, tc::make_handle(0x8001, 0));
}

TEST(tc_recorder, a_programmed_failure_affects_one_call_and_carries_its_message)
{
    // So a caller's "the driver refused the offload" path is reachable
    // without a driver that refuses offload.
    tc::TcRecorder recorder;
    recorder.fail_next_write(std::make_error_code(std::errc::operation_not_supported), "Offload not supported");

    auto const refused = recorder.replace_cbs(IFINDEX, sample_cbs());
    EXPECT_FALSE(refused.has_value());
    if (!refused) {
        EXPECT_EQ(refused.error(), std::make_error_code(std::errc::operation_not_supported));
    }
    EXPECT_EQ(recorder.last_message(), "Offload not supported");

    // The next call succeeds: one programmed failure, not a sticky mode.
    EXPECT_TRUE(recorder.replace_cbs(IFINDEX, sample_cbs()).has_value());
    EXPECT_TRUE(recorder.last_message().empty());

    // And the refused attempt was still recorded -- what a caller tried is
    // usually the thing to assert.
    EXPECT_EQ(recorder.requests().size(), 2u);
}

TEST(tc_recorder, get_answers_nothing_installed_until_a_result_is_set)
{
    tc::TcRecorder recorder;

    auto const empty = recorder.get(IFINDEX, tc::ROOT);
    EXPECT_FALSE(empty.has_value());
    if (!empty) {
        EXPECT_EQ(empty.error(), make_error_code(NetError::invalid_handle));
    }

    // A read-back that reports a clamped idleslope, which is what the
    // shaper uses get() to discover.
    tc::QdiscInfo installed{};
    installed.ifindex = IFINDEX;
    installed.handle = tc::make_handle(0x8002, 0);
    installed.parent = tc::make_handle(0x8001, 1);
    installed.kind = {'c', 'b', 's', '\0'};
    installed.has_cbs_params = true;
    installed.cbs = sample_cbs();
    installed.cbs.idleslope_kbps = 5000;  // the driver gave us less than we asked
    recorder.set_get_result(installed);

    auto const read_back = recorder.get(IFINDEX, tc::make_handle(0x8001, 1));
    EXPECT_TRUE(read_back.has_value());
    if (read_back) {
        EXPECT_EQ(read_back->kind_name(), "cbs");
        EXPECT_EQ(read_back->cbs.idleslope_kbps, 5000);
    }
    EXPECT_EQ(recorder.requests().size(), 2u);
}

TEST(tc_recorder, clear_forgets_the_history_so_one_test_can_assert_phases)
{
    tc::TcRecorder recorder;
    EXPECT_TRUE(recorder.replace_mqprio(IFINDEX, sample_mqprio()).has_value());
    EXPECT_EQ(recorder.requests().size(), 1u);

    recorder.clear();
    EXPECT_TRUE(recorder.requests().empty());

    EXPECT_TRUE(recorder.remove(IFINDEX, tc::make_handle(0x8001, 0), tc::ROOT).has_value());
    EXPECT_EQ(recorder.requests().size(), 1u);
}

TEST(tc_recorder, is_usable_through_the_tccontrol_interface)
{
    // The substitution has to work through the interface, because that is
    // how a caller holds it.
    tc::TcRecorder recorder;
    tc::TcControl& control = recorder;

    EXPECT_TRUE(control.replace_mqprio(IFINDEX, sample_mqprio()).has_value());
    EXPECT_EQ(recorder.requests().size(), 1u);
    EXPECT_TRUE(control.last_message().empty());
}

TEST(tc_qdisc, the_client_installs_a_receive_timeout)
{
    // Without this the client can block forever: a read bound does not
    // help when the kernel sends nothing at all, which happens if a reply
    // never carries NLMSG_DONE or is dropped under memory pressure. A
    // mutation that drops NLM_F_DUMP from the dump request turns the whole
    // test binary into a hang without it, and into a clean failure with it.
    tc::TcClient client;
    if (!client.open()) {
        return;
    }

    timeval timeout{};
    socklen_t length = sizeof(timeout);
    EXPECT_EQ(::getsockopt(client.fd(), SOL_SOCKET, SO_RCVTIMEO, &timeout, &length), 0);
    EXPECT_TRUE(timeout.tv_sec > 0 || timeout.tv_usec > 0);
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_qdisc_test)
