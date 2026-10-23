#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Emit classic-BPF bytecode from a set of CompiledRule<N> entries.
///
/// The emitter consumes the same CompiledRule<N> that TcamClassifier
/// runs in userspace and produces an equivalent cBPF program suitable
/// for setsockopt(SO_ATTACH_FILTER), tc classifier, or any other
/// cBPF-accepting sink. A small companion `interpret()` runs cBPF
/// programs in software so the emitter can be tested on any platform
/// — no kernel required.
///
/// Semantics mirror TcamClassifier::classify_first: rules are walked
/// in order, the first matching rule returns its result_flags (low
/// 32 bits — cBPF RET values are 32 bits wide), and the emitted
/// program falls through to a final `return default_flags` if no
/// rule matches.
///
/// cBPF can't carry the user bits of the 64-bit flag space if they
/// exceed bit 31. For socket-filter use the common pattern is to
/// emit a RULE INDEX as the return value and have userspace map the
/// index back to the full 64-bit flags via the original rule vector.
/// The emitter exposes that policy via a caller-supplied lambda.

#include "statusbar/net/net_compiled_rule.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace statusbar::net::cbpf {

/// Portable mirror of Linux's `struct sock_filter` / BSD's `struct
/// bpf_insn`. Same 8-byte layout; users on Linux can
/// `reinterpret_cast` or `memcpy` this to `struct sock_filter`.
struct Instruction
{
    std::uint16_t code;
    std::uint8_t jt;
    std::uint8_t jf;
    std::uint32_t k;

    friend constexpr auto operator==(Instruction const&, Instruction const&) noexcept -> bool = default;
};
static_assert(sizeof(Instruction) == 8, "Instruction must match Linux struct sock_filter");

// cBPF opcode constants, matching Linux <linux/filter.h>.
namespace op {
inline constexpr std::uint16_t LD_B_ABS = 0x30;   // BPF_LD | BPF_B | BPF_ABS
inline constexpr std::uint16_t LD_W_ABS = 0x20;   // BPF_LD | BPF_W | BPF_ABS
inline constexpr std::uint16_t LD_H_ABS = 0x28;   // BPF_LD | BPF_H | BPF_ABS
inline constexpr std::uint16_t ALU_AND_K = 0x54;  // BPF_ALU | BPF_AND | BPF_K
inline constexpr std::uint16_t JMP_JEQ_K = 0x15;  // BPF_JMP | BPF_JEQ | BPF_K
inline constexpr std::uint16_t JMP_JA = 0x05;     // BPF_JMP | BPF_JA
inline constexpr std::uint16_t RET_K = 0x06;      // BPF_RET | BPF_K
}  // namespace op

/// Policy: what RET value does a matching rule emit?
/// - `use_result_flags` returns the low 32 bits of the rule's
///   result_flags verbatim. Loses user bits >= bit 32.
/// - `use_rule_index` returns (index + 1); 0 means "no rule
///   matched" (the default). Pairs with a userspace lookup table.
enum class ResultPolicy
{
    use_result_flags,
    use_rule_index,
};

/// Compile a CompiledRule<N> span to a cBPF program.
/// Returns an empty vector if the rule set needs jump distances
/// larger than 255 bytes (cBPF's jt/jf are 8-bit offsets); split
/// the rule set in that case.
template <std::size_t N>
auto compile(
    std::span<CompiledRule<N> const> rules, std::uint32_t default_return = 0U, ResultPolicy policy = ResultPolicy::use_result_flags)
    -> std::vector<Instruction>
{
    std::vector<Instruction> program;

    for (std::size_t rule_index = 0; rule_index < rules.size(); ++rule_index) {
        auto const& rule = rules[rule_index];
        std::size_t const rule_start = program.size();

        for (std::size_t i = 0; i < N; ++i) {
            if (rule.mask[i] == 0) {
                continue;  // "don't care" byte.
            }
            program.push_back({op::LD_B_ABS, 0, 0, static_cast<std::uint32_t>(i)});
            if (rule.mask[i] != 0xFF) {
                program.push_back({op::ALU_AND_K, 0, 0, rule.mask[i]});
            }
            // match[i] is already pre-ANDed with mask[i] by the builder,
            // so a direct JEQ against match[i] is correct.
            program.push_back({op::JMP_JEQ_K, 0, 0, static_cast<std::uint32_t>(rule.match[i])});
        }

        std::uint32_t const ret_value = (policy == ResultPolicy::use_result_flags)
            ? static_cast<std::uint32_t>(rule.result_flags & 0xFFFFFFFFULL)
            : static_cast<std::uint32_t>(rule_index + 1);
        program.push_back({op::RET_K, 0, 0, ret_value});

        // Patch each JEQ's jf to skip past this rule's RET_K on mismatch.
        std::size_t const rule_end = program.size();
        for (std::size_t p = rule_start; p < rule_end; ++p) {
            if (program[p].code != op::JMP_JEQ_K) {
                continue;
            }
            std::size_t const skip = rule_end - p - 1;
            if (skip > 255) {
                // Would need a JA chain; punt for now.
                return {};
            }
            program[p].jf = static_cast<std::uint8_t>(skip);
        }
    }

    // Fall-through: no rule matched.
    program.push_back({op::RET_K, 0, 0, default_return});
    return program;
}

/// Minimal cBPF interpreter supporting the opcodes `compile` emits.
/// Returns the RET_K value the program produces on `packet`, or 0
/// if execution terminated abnormally (invalid opcode, branch out
/// of bounds, packet read past end).
[[nodiscard]] inline auto interpret(std::span<Instruction const> program, std::span<std::uint8_t const> packet) noexcept
    -> std::uint32_t
{
    std::uint32_t acc = 0;
    std::size_t pc = 0;
    while (pc < program.size()) {
        auto const& ins = program[pc];
        switch (ins.code) {
            case op::LD_B_ABS: {
                // ins.k is uint32_t; promote to size_t before comparing against
                // packet.size() so the bound check is well-defined even when
                // ins.k is near UINT32_MAX.
                std::size_t const k = ins.k;
                if (k >= packet.size()) {
                    return 0;
                }
                acc = packet[k];
                ++pc;
                break;
            }
            case op::LD_W_ABS: {
                // The original check `ins.k + 4 > packet.size()` performed the
                // addition in uint32 arithmetic, which wraps when ins.k is near
                // UINT32_MAX and bypasses the bound — then packet[ins.k] reads
                // out of bounds. Compare against packet.size() in size_t
                // arithmetic that cannot wrap.
                std::size_t const k = ins.k;
                if (k > packet.size() || packet.size() - k < 4) {
                    return 0;
                }
                acc = (static_cast<std::uint32_t>(packet[k]) << 24) | (static_cast<std::uint32_t>(packet[k + 1]) << 16) |
                    (static_cast<std::uint32_t>(packet[k + 2]) << 8) | static_cast<std::uint32_t>(packet[k + 3]);
                ++pc;
                break;
            }
            case op::LD_H_ABS: {
                std::size_t const k = ins.k;
                if (k > packet.size() || packet.size() - k < 2) {
                    return 0;
                }
                acc = (static_cast<std::uint32_t>(packet[k]) << 8) | static_cast<std::uint32_t>(packet[k + 1]);
                ++pc;
                break;
            }
            case op::ALU_AND_K: {
                acc &= ins.k;
                ++pc;
                break;
            }
            case op::JMP_JEQ_K: {
                pc += 1 + ((acc == ins.k) ? ins.jt : ins.jf);
                break;
            }
            case op::JMP_JA: {
                pc += 1 + ins.k;
                break;
            }
            case op::RET_K: {
                return ins.k;
            }
            default: {
                return 0;  // unsupported opcode
            }
        }
    }
    return 0;  // ran past end without RET
}

}  // namespace statusbar::net::cbpf
