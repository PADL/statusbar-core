#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Classic-BPF filter programs for the AF_PACKET talker/listener path.
///
/// An `ETH_P_ALL` raw socket wakes our process for every frame on the
/// wire; on a busy link that is tens of thousands of wakeups per second,
/// nearly all of them for frames we discard in user space after a
/// syscall and a copy. A kernel-side filter that admits only our
/// ethertype with a subtype in a small set drops the rest before the
/// socket queue.
///
/// This header is deliberately **platform-independent**: it only builds
/// instruction sequences into a caller-supplied buffer. Attaching one
/// (`SO_ATTACH_FILTER`) is the only part that is platform code, and it
/// lives in net_rawnet.cpp. The split is what lets every program here be
/// asserted byte-for-byte and executed through `cbpf::interpret()` in a
/// unit test with no socket, no privilege and no NIC.

#include "statusbar/net/net_cbpf_emit.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/status/status.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::net::rawnet_filter {

/// Most subtypes one filter may admit. Enough for AAF + CRF + CVF and
/// room to spare; the cap keeps the program a fixed small sequence with
/// a bounded worst case rather than something that grows with caller
/// appetite.
inline constexpr std::size_t MAX_SUBTYPES = 8;

/// Instructions in the fixed part of a subtype filter: two ethertype
/// reads, the 802.1Q branch, both subtype loads, and the two returns.
inline constexpr std::size_t SUBTYPE_FILTER_FIXED_LENGTH = 10;

/// Longest program `build_subtype_filter` can emit.
inline constexpr std::size_t MAX_PROGRAM_LENGTH = SUBTYPE_FILTER_FIXED_LENGTH + MAX_SUBTYPES;

/// Accept RET value meaning "pass the whole frame" — cBPF treats the
/// return as a snap length, and anything at or above the frame size
/// passes it entire.
inline constexpr std::uint32_t PASS_WHOLE_FRAME = 0xFFFFFFFFU;

/// TPID of a single 802.1Q customer VLAN tag.
inline constexpr std::uint16_t TPID_8021Q = 0x8100;

namespace detail {

inline constexpr std::uint32_t ETHERTYPE_OFFSET = 12;
inline constexpr std::uint32_t TAGGED_ETHERTYPE_OFFSET = 16;
inline constexpr std::uint32_t UNTAGGED_PAYLOAD_OFFSET = 14;
inline constexpr std::uint32_t TAGGED_PAYLOAD_OFFSET = 18;

[[nodiscard]] inline constexpr auto load_halfword(std::uint32_t offset) noexcept -> cbpf::Instruction
{
    return cbpf::Instruction{.code = cbpf::op::LD_H_ABS, .jt = 0, .jf = 0, .k = offset};
}

[[nodiscard]] inline constexpr auto load_byte(std::uint32_t offset) noexcept -> cbpf::Instruction
{
    return cbpf::Instruction{.code = cbpf::op::LD_B_ABS, .jt = 0, .jf = 0, .k = offset};
}

[[nodiscard]] inline constexpr auto jump_if_equal(std::uint32_t value, std::uint8_t jt, std::uint8_t jf) noexcept
    -> cbpf::Instruction
{
    return cbpf::Instruction{.code = cbpf::op::JMP_JEQ_K, .jt = jt, .jf = jf, .k = value};
}

[[nodiscard]] inline constexpr auto jump_always(std::uint32_t offset) noexcept -> cbpf::Instruction
{
    return cbpf::Instruction{.code = cbpf::op::JMP_JA, .jt = 0, .jf = 0, .k = offset};
}

[[nodiscard]] inline constexpr auto ret(std::uint32_t value) noexcept -> cbpf::Instruction
{
    return cbpf::Instruction{.code = cbpf::op::RET_K, .jt = 0, .jf = 0, .k = value};
}

/// Where each landmark of a subtype-filter program sits, given how many
/// subtypes it admits. Computed once so the emitter and the jump offsets
/// cannot disagree.
struct Layout
{
    std::size_t untagged_load;  ///< loads the subtype from an untagged frame
    std::size_t compare_chain;  ///< first of the per-subtype comparisons
    std::size_t reject;         ///< `return 0`
    std::size_t accept;         ///< `return pass_length`
    std::size_t length;         ///< total instruction count
};

[[nodiscard]] inline constexpr auto layout_for(std::size_t subtype_count) noexcept -> Layout
{
    constexpr std::size_t UNTAGGED_LOAD = 7;
    constexpr std::size_t COMPARE_CHAIN = 8;
    return Layout{
        .untagged_load = UNTAGGED_LOAD,
        .compare_chain = COMPARE_CHAIN,
        .reject = COMPARE_CHAIN + subtype_count,
        .accept = COMPARE_CHAIN + subtype_count + 1,
        .length = SUBTYPE_FILTER_FIXED_LENGTH + subtype_count,
    };
}

/// Write the program described in build_subtype_filter()'s listing.
/// `out` is known to be large enough and `subtypes` known to be in range.
inline auto emit_subtype_filter(
    std::span<cbpf::Instruction> out,
    std::uint16_t ethertype,
    std::span<std::uint8_t const> subtypes,
    Layout const& at,
    std::uint32_t pass_length) noexcept -> void
{
    // The fixed head, in one initializer so the twelve-line listing in the
    // caller's comment and the code below read in the same order. A cBPF
    // jump is relative to the instruction *after* the jump, hence each -N.
    std::array<cbpf::Instruction, 8> const prologue{
        load_halfword(ETHERTYPE_OFFSET),
        jump_if_equal(ethertype, static_cast<std::uint8_t>(at.untagged_load - 2), 0),
        jump_if_equal(TPID_8021Q, 0, static_cast<std::uint8_t>(at.reject - 3)),
        load_halfword(TAGGED_ETHERTYPE_OFFSET),
        jump_if_equal(ethertype, 0, static_cast<std::uint8_t>(at.reject - 5)),
        load_byte(TAGGED_PAYLOAD_OFFSET),
        jump_always(static_cast<std::uint32_t>(at.compare_chain - 7)),
        load_byte(UNTAGGED_PAYLOAD_OFFSET),
    };
    std::ranges::copy(prologue, out.begin());

    for (std::size_t i = 0; i < subtypes.size(); ++i) {
        std::size_t const here = at.compare_chain + i;
        // jf is 0 throughout: a miss falls through to the next comparison,
        // and the last one falls through to `reject`.
        out[here] = jump_if_equal(subtypes[i], static_cast<std::uint8_t>(at.accept - here - 1), 0);
    }

    out[at.reject] = ret(0);
    out[at.accept] = ret(pass_length);
}

}  // namespace detail

/// Build a filter admitting frames of `ethertype` whose first payload
/// byte is in `subtypes`, both untagged and under one 802.1Q tag.
///
/// The tagged/untagged duplication is the part that is easy to get
/// wrong, and the reason this is written once here: the subtype byte
/// sits at offset 14 in an untagged frame and 18 under a tag, so the
/// ethertype has to be branched on *before* the subtype can be read at
/// all. The emitted program loads the subtype into A from whichever
/// offset applies and then shares a single comparison chain:
///
/// ```text
///  0  A = halfword @12                 ; outer ethertype
///  1  if A == ethertype goto 7         ; untagged: subtype at 14
///  2  if A != 0x8100    goto reject
///  3  A = halfword @16                 ; inner ethertype
///  4  if A != ethertype goto reject
///  5  A = byte @18                     ; tagged subtype
///  6  goto 8                           ; skip the untagged load
///  7  A = byte @14                     ; untagged subtype
///  8  if A == subtypes[0] goto accept
///  …  one comparison per subtype, falling through to reject
///     reject: return 0
///     accept: return pass_length
/// ```
///
/// A read past the end of a short frame terminates the program with 0,
/// so a frame truncated mid-header is rejected rather than misread.
///
/// @param out Buffer to write into; must hold at least
///        `SUBTYPE_FILTER_FIXED_LENGTH + subtypes.size()` instructions.
/// @param ethertype Ethertype to admit, host byte order (e.g. 0x22F0).
/// @param subtypes 1 to `MAX_SUBTYPES` first-payload-byte values.
/// @param pass_length RET value for an admitted frame, which the kernel
///        reads as a snap length. `PASS_WHOLE_FRAME` passes it entire.
/// @return The number of instructions written, or
///         `NetError::invalid_argument` for an empty or oversized
///         subtype set or an output buffer too small to hold the result.
[[nodiscard]] inline auto build_subtype_filter(
    std::span<cbpf::Instruction> out,
    std::uint16_t ethertype,
    std::span<std::uint8_t const> subtypes,
    std::uint32_t pass_length = PASS_WHOLE_FRAME) noexcept -> StatusValue<std::size_t>
{
    if (subtypes.empty() || subtypes.size() > MAX_SUBTYPES) {
        return failure(NetError::invalid_argument);
    }

    auto const at = detail::layout_for(subtypes.size());
    if (out.size() < at.length) {
        return failure(NetError::invalid_argument);
    }

    detail::emit_subtype_filter(out, ethertype, subtypes, at, pass_length);
    return success(at.length);
}

/// Build a program that admits nothing.
///
/// This exists for the window between `socket()` and attaching the real
/// filter: frames that arrive in it are queued unfiltered, and a caller
/// that then attaches a subtype filter would still read pre-filter
/// frames out of the queue. The remedy is to attach this first, drain,
/// then attach the real program.
///
/// @param out Buffer to write into; must hold at least one instruction.
/// @return The number of instructions written (1), or
///         `NetError::invalid_argument` if `out` is empty.
[[nodiscard]] inline auto build_drop_all(std::span<cbpf::Instruction> out) noexcept -> StatusValue<std::size_t>
{
    if (out.empty()) {
        return failure(NetError::invalid_argument);
    }
    out[0] = detail::ret(0);
    return success(std::size_t{1});
}

}  // namespace statusbar::net::rawnet_filter
