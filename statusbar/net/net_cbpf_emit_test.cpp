// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the CompiledRule -> cBPF emitter and the companion
/// interpreter. The interpreter runs on any platform so we can prove
/// the emitted bytecode classifies correctly without needing a
/// kernel to load it.

#include "statusbar/net/net_cbpf_emit.hpp"

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/ieee/ieee_protocols.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_tcam_classifier.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstring>

using namespace statusbar;
using namespace statusbar::net;

TEST(cbpf_emit, empty_rule_set_returns_default)
{
    std::array<CompiledRule<>, 0> rules{};
    auto program = cbpf::compile<32>({rules.data(), 0}, /*default_return=*/0x1234U);
    EXPECT_EQ(program.size(), 1u);  // just the fall-through RET
    EXPECT_EQ(program[0].code, cbpf::op::RET_K);
    EXPECT_EQ(program[0].k, 0x1234u);

    std::array<std::uint8_t, 64> frame{};
    EXPECT_EQ(cbpf::interpret(program, frame), 0x1234u);
}

TEST(cbpf_emit, ethertype_match_returns_result_flags_low32)
{
    auto rules = ClassifierRuleBuilder<>{}.ethertype(ieee::protocols::ETHERTYPE_AVTP).vlan_untagged().result(0xDEADBEEFU).build();
    auto program = cbpf::compile<32>(rules, /*default_return=*/0U);

    // Frame 1: matching untagged AVTP.
    std::array<std::uint8_t, 32> match_frame{};
    match_frame[12] = 0x22;
    match_frame[13] = 0xF0;
    EXPECT_EQ(cbpf::interpret(program, match_frame), 0xDEADBEEFU);

    // Frame 2: different EtherType.
    std::array<std::uint8_t, 32> miss_frame{};
    miss_frame[12] = 0x08;
    miss_frame[13] = 0x00;
    EXPECT_EQ(cbpf::interpret(program, miss_frame), 0u);
}

TEST(cbpf_emit, first_rule_match_wins)
{
    auto r1 = ClassifierRuleBuilder<>{}
                  .ethertype(ieee::protocols::ETHERTYPE_AVTP)
                  .vlan_untagged()
                  .avtp_subtype(0x02)
                  .result(0x1111U)
                  .build();
    auto r2 = ClassifierRuleBuilder<>{}.ethertype(ieee::protocols::ETHERTYPE_AVTP).vlan_untagged().result(0x2222U).build();
    std::array<CompiledRule<>, 2> rules{r1[0], r2[0]};
    auto program = cbpf::compile<32>(rules, 0U);

    // Frame matches BOTH rules; first (more specific) should win.
    std::array<std::uint8_t, 32> f{};
    f[12] = 0x22;
    f[13] = 0xF0;
    f[14] = 0x02;
    EXPECT_EQ(cbpf::interpret(program, f), 0x1111U);

    // Frame matches only the second rule.
    f[14] = 0x00;
    EXPECT_EQ(cbpf::interpret(program, f), 0x2222U);
}

TEST(cbpf_emit, result_policy_rule_index_returns_1_based_index)
{
    auto r1 = ClassifierRuleBuilder<>{}.ethertype(0x88F7).vlan_untagged().result(flag::rx_gptp).build();
    auto r2 = ClassifierRuleBuilder<>{}.ethertype(0x22F0).vlan_untagged().result(flag::rx_avtp_stream).build();
    std::array<CompiledRule<>, 2> rules{r1[0], r2[0]};
    auto program = cbpf::compile<32>(rules, 0U, cbpf::ResultPolicy::use_rule_index);

    std::array<std::uint8_t, 32> gptp{};
    gptp[12] = 0x88;
    gptp[13] = 0xF7;
    EXPECT_EQ(cbpf::interpret(program, gptp), 1u);  // rule 0 -> index 1

    std::array<std::uint8_t, 32> avtp{};
    avtp[12] = 0x22;
    avtp[13] = 0xF0;
    EXPECT_EQ(cbpf::interpret(program, avtp), 2u);  // rule 1 -> index 2

    std::array<std::uint8_t, 32> arp{};
    arp[12] = 0x08;
    arp[13] = 0x06;
    EXPECT_EQ(cbpf::interpret(program, arp), 0u);  // default
}

TEST(cbpf_emit, agrees_with_tcam_classifier_on_multi_rule_set)
{
    // Build the same rule set both engines will see.
    auto append = [](std::vector<CompiledRule<>>& out, auto built) { out.insert(out.end(), built.begin(), built.end()); };
    std::vector<CompiledRule<>> rules;
    append(
        rules, ClassifierRuleBuilder<>{}.ethertype(ieee::protocols::ETHERTYPE_GPTP).vlan_untagged().result(flag::rx_gptp).build());
    append(
        rules,
        ClassifierRuleBuilder<>{}
            .ethertype(ieee::protocols::ETHERTYPE_AVTP)
            .vlan_tagged_exact(2)
            .avtp_subtype(0x02)
            .result(flag::rx_avtp_stream | flag::process)
            .build());
    append(
        rules,
        ClassifierRuleBuilder<>{}
            .ethertype(ieee::protocols::ETHERTYPE_AVTP)
            .vlan_untagged()
            .avtp_subtype(0xFA)
            .result(0xAAU)
            .build());

    // Low-32 bits go into the cBPF program.
    auto program = cbpf::compile<32>(rules, /*default_return=*/0xFFU);

    // Feed the SAME frames to both engines and verify the
    // low-32-bit result agrees.
    TcamClassifier<32, 16> tc;
    tc.set_rules(rules, /*default_flags=*/0xFFU);

    auto check = [&](std::array<std::uint8_t, 32> const& f) {
        auto const tcam = static_cast<std::uint32_t>(tc.classify_first(f));
        auto const cbpf = cbpf::interpret(program, f);
        EXPECT_EQ(cbpf, tcam);
    };

    std::array<std::uint8_t, 32> gptp{};
    gptp[12] = 0x88;
    gptp[13] = 0xF7;
    check(gptp);

    std::array<std::uint8_t, 32> avtp_tagged{};
    avtp_tagged[12] = 0x81;
    avtp_tagged[13] = 0x00;
    avtp_tagged[14] = 0x00;
    avtp_tagged[15] = 0x02;  // VID = 2
    avtp_tagged[16] = 0x22;
    avtp_tagged[17] = 0xF0;
    avtp_tagged[18] = 0x02;  // AAF
    check(avtp_tagged);

    std::array<std::uint8_t, 32> adp{};
    adp[12] = 0x22;
    adp[13] = 0xF0;
    adp[14] = 0xFA;  // ADP
    check(adp);

    std::array<std::uint8_t, 32> miss{};
    miss[12] = 0x08;
    miss[13] = 0x06;  // ARP
    check(miss);
}

TEST(cbpf_emit, ld_h_abs_loads_big_endian_halfword)
{
    // The ethertype at offset 12 is the reason this opcode exists: a
    // halfword load is how a socket filter reads it in one instruction
    // instead of two byte loads and a shift.
    std::array<cbpf::Instruction, 3> const program{
        cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = 12},
        cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = 0, .jf = 1, .k = 0x22F0},
        cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = 0xFFFF},
    };

    std::array<std::uint8_t, 16> frame{};
    frame[12] = 0x22;
    frame[13] = 0xF0;
    EXPECT_EQ(cbpf::interpret(program, frame), 0xFFFFu);

    // Byte-swapped ethertype must not match: the load is network order.
    frame[12] = 0xF0;
    frame[13] = 0x22;
    EXPECT_EQ(cbpf::interpret(program, frame), 0u);
}

TEST(cbpf_emit, ld_h_abs_refuses_read_past_end)
{
    // Offset 13 needs bytes 13 and 14; a 14-byte frame has only 13.
    std::array<cbpf::Instruction, 2> const program{
        cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = 13},
        cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = 0xFFFF},
    };

    std::array<std::uint8_t, 15> const long_enough{};
    EXPECT_EQ(cbpf::interpret(program, long_enough), 0xFFFFu);

    std::array<std::uint8_t, 14> const one_byte_short{};
    EXPECT_EQ(cbpf::interpret(program, one_byte_short), 0u);
}

TEST(cbpf_emit, ld_h_abs_bound_check_does_not_wrap)
{
    // k + 2 computed in uint32 arithmetic wraps to 1 here and would pass
    // a naive `k + 2 <= size` check, then read at offset 0xFFFFFFFF.
    std::array<cbpf::Instruction, 2> const program{
        cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = 0xFFFFFFFFU},
        cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = 0xFFFF},
    };

    std::array<std::uint8_t, 64> const frame{};
    EXPECT_EQ(cbpf::interpret(program, frame), 0u);
}

TEST_MAIN(statusbar_net, net_cbpf_emit_test)
