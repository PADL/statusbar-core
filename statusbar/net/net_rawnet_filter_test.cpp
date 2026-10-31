// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the AF_PACKET subtype filter programs.
///
/// Two kinds of assertion, and both matter:
///
/// 1. **Byte-for-byte.** The emitted instruction sequence is compared
///    against a hand-checked expected program. This catches a changed
///    jump offset that the behavioural tests might still accept by
///    luck, and documents the program for a reader.
/// 2. **Behavioural.** Every program is executed by the software cBPF
///    interpreter against crafted frames. A filter that assembles into
///    plausible bytecode but admits the wrong frames fails here.
///
/// Neither needs a socket, a privilege or a NIC.

#include "statusbar/net/net_rawnet_filter.hpp"

#include "statusbar/ieee/ieee_protocols.hpp"
#include "statusbar/net/net_cbpf_emit.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr std::uint16_t AVTP = ieee::protocols::ETHERTYPE_AVTP;  // 0x22F0
constexpr std::uint8_t SUBTYPE_AAF = 0x02;
constexpr std::uint8_t SUBTYPE_CRF = 0x04;
constexpr std::uint8_t SUBTYPE_ADP = 0x7A;  // not in the admitted set

/// An untagged frame of `ethertype` whose first payload byte is `subtype`.
auto untagged_frame(std::uint16_t ethertype, std::uint8_t subtype) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> frame(64, 0);
    frame[12] = static_cast<std::uint8_t>(ethertype >> 8);
    frame[13] = static_cast<std::uint8_t>(ethertype & 0xFF);
    frame[14] = subtype;
    return frame;
}

/// The same frame under one 802.1Q tag: the subtype moves from 14 to 18.
auto tagged_frame(std::uint16_t ethertype, std::uint8_t subtype, std::uint8_t pcp) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> frame(64, 0);
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[14] = static_cast<std::uint8_t>(pcp << 5);  // PCP in the top 3 bits of the TCI
    frame[15] = 0x02;                                 // VID 2
    frame[16] = static_cast<std::uint8_t>(ethertype >> 8);
    frame[17] = static_cast<std::uint8_t>(ethertype & 0xFF);
    frame[18] = subtype;
    return frame;
}

}  // namespace

TEST(rawnet_filter, subtype_filter_emits_the_expected_program)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    EXPECT_EQ(*length, 12u);  // 10 fixed + one compare per subtype

    // Hand-checked. Jump targets are relative to the following instruction.
    // Index 11 accepts, index 10 rejects.
    std::array<cbpf::Instruction, 12> const expected{
        cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = 12},        // 0: outer ethertype
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 5, .jf = 0, .k = AVTP},     // 1: untagged? -> 7
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 0, .jf = 7, .k = 0x8100},   // 2: tagged? else -> 10
        cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = 16},        // 3: inner ethertype
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 0, .jf = 5, .k = AVTP},     // 4: ours? else -> 10
        cbpf::Instruction{.code = cbpf::op::LD_B_ABS, .jt = 0, .jf = 0, .k = 18},        // 5: tagged subtype
        cbpf::Instruction{.code = cbpf::op::JMP_JA, .jt = 0, .jf = 0, .k = 1},           // 6: -> 8
        cbpf::Instruction{.code = cbpf::op::LD_B_ABS, .jt = 0, .jf = 0, .k = 14},        // 7: untagged subtype
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 2, .jf = 0, .k = 0x02},     // 8: -> 11
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 1, .jf = 0, .k = 0x04},     // 9: -> 11
        cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = 0},            // 10: reject
        cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = 0xFFFFFFFFU},  // 11: accept
    };

    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(out[i].code, expected[i].code);
        EXPECT_EQ(out[i].jt, expected[i].jt);
        EXPECT_EQ(out[i].jf, expected[i].jf);
        EXPECT_EQ(out[i].k, expected[i].k);
    }
}

TEST(rawnet_filter, admits_untagged_in_set_subtypes)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};
    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_AAF)), 0xFFFFFFFFU);
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_CRF)), 0xFFFFFFFFU);
}

TEST(rawnet_filter, admits_tagged_in_set_subtypes)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};
    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // An AVB stream frame is always tagged, so this is the common case.
    EXPECT_EQ(cbpf::interpret(program, tagged_frame(AVTP, SUBTYPE_AAF, 3)), 0xFFFFFFFFU);
    EXPECT_EQ(cbpf::interpret(program, tagged_frame(AVTP, SUBTYPE_CRF, 3)), 0xFFFFFFFFU);
}

TEST(rawnet_filter, rejects_out_of_set_subtype_tagged_and_untagged)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};
    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // ADP is AVTP, so the ethertype check passes and only the subtype
    // comparison rejects it. That is the branch this test pins.
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_ADP)), 0u);
    EXPECT_EQ(cbpf::interpret(program, tagged_frame(AVTP, SUBTYPE_ADP, 3)), 0u);
}

TEST(rawnet_filter, rejects_non_avtp_even_with_an_in_set_first_payload_byte)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};
    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // 0x0800 (IPv4) whose first payload byte happens to be 0x02. If the
    // ethertype branch were dropped this frame would be admitted.
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(0x0800, SUBTYPE_AAF)), 0u);
    EXPECT_EQ(cbpf::interpret(program, tagged_frame(0x0800, SUBTYPE_AAF, 3)), 0u);
}

TEST(rawnet_filter, rejects_frame_truncated_mid_header)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 1> const subtypes{SUBTYPE_AAF};
    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // 13 bytes: the ethertype halfword itself does not fit.
    std::vector<std::uint8_t> const no_ethertype(13, 0);
    EXPECT_EQ(cbpf::interpret(program, no_ethertype), 0u);

    // 14 bytes: the ethertype is readable and says AVTP, but the subtype
    // byte at 14 is past the end.
    auto truncated = untagged_frame(AVTP, SUBTYPE_AAF);
    truncated.resize(14);
    EXPECT_EQ(cbpf::interpret(program, truncated), 0u);

    // A tagged frame cut off before the inner ethertype.
    auto tagged_short = tagged_frame(AVTP, SUBTYPE_AAF, 3);
    tagged_short.resize(17);
    EXPECT_EQ(cbpf::interpret(program, tagged_short), 0u);
}

TEST(rawnet_filter, subtype_count_of_zero_is_refused)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::span<std::uint8_t const> const none{};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, none, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_FALSE(length.has_value());
    if (length) {
        return;
    }
    EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
}

TEST(rawnet_filter, more_than_max_subtypes_is_refused)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, rawnet_filter::MAX_SUBTYPES + 1> const too_many{0, 1, 2, 3, 4, 5, 6, 7, 8};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, too_many, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_FALSE(length.has_value());
    if (length) {
        return;
    }
    EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
}

TEST(rawnet_filter, exactly_max_subtypes_is_accepted_and_all_of_them_match)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, rawnet_filter::MAX_SUBTYPES> const subtypes{0x00, 0x02, 0x03, 0x04, 0x05, 0x6F, 0x7A, 0xFF};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    EXPECT_EQ(*length, rawnet_filter::MAX_PROGRAM_LENGTH);
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // Every subtype must match from both offsets. The last entry is the
    // one whose jump offset is shortest, so an off-by-one in the chain
    // shows up here.
    for (auto const subtype : subtypes) {
        EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, subtype)), 0xFFFFFFFFU);
        EXPECT_EQ(cbpf::interpret(program, tagged_frame(AVTP, subtype, 3)), 0xFFFFFFFFU);
    }

    // And a subtype outside the full set is still rejected.
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, 0x01)), 0u);
}

TEST(rawnet_filter, an_output_buffer_too_small_is_refused)
{
    // One instruction short of what two subtypes need.
    std::array<cbpf::Instruction, 11> out{};
    std::array<std::uint8_t const, 2> const subtypes{SUBTYPE_AAF, SUBTYPE_CRF};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, rawnet_filter::PASS_WHOLE_FRAME);
    EXPECT_FALSE(length.has_value());
    if (length) {
        return;
    }
    EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
}

TEST(rawnet_filter, pass_length_is_the_returned_snap_length)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};
    std::array<std::uint8_t const, 1> const subtypes{SUBTYPE_AAF};

    auto const length = rawnet_filter::build_subtype_filter(out, AVTP, subtypes, /*pass_length=*/128);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    std::span<cbpf::Instruction const> const program{out.data(), *length};

    // A filter may truncate rather than pass the whole frame; the accept
    // RET carries the snap length the kernel then applies.
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_AAF)), 128u);
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_ADP)), 0u);
}

TEST(rawnet_filter, drop_all_admits_nothing)
{
    std::array<cbpf::Instruction, rawnet_filter::MAX_PROGRAM_LENGTH> out{};

    auto const length = rawnet_filter::build_drop_all(out);
    EXPECT_TRUE(length.has_value());
    if (!length) {
        return;
    }
    EXPECT_EQ(*length, 1u);
    EXPECT_EQ(out[0].code, cbpf::op::RET_K);
    EXPECT_EQ(out[0].k, 0u);

    std::span<cbpf::Instruction const> const program{out.data(), *length};
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(AVTP, SUBTYPE_AAF)), 0u);
    EXPECT_EQ(cbpf::interpret(program, tagged_frame(AVTP, SUBTYPE_AAF, 3)), 0u);
    EXPECT_EQ(cbpf::interpret(program, untagged_frame(0x0800, 0x45)), 0u);
}

TEST(rawnet_filter, drop_all_refuses_an_empty_buffer)
{
    std::span<cbpf::Instruction> const empty{};
    auto const length = rawnet_filter::build_drop_all(empty);
    EXPECT_FALSE(length.has_value());
    if (length) {
        return;
    }
    EXPECT_EQ(length.error(), make_error_code(NetError::invalid_argument));
}

TEST_MAIN(statusbar_net, net_rawnet_filter_test)
