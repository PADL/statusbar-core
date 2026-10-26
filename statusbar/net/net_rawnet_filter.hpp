#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The classic-BPF receive filters a RawnetContext attaches to its socket.
///
/// Platform independent so the exact bytecode is unit tested (and run through
/// cbpf::interpret) on any host. Each program accepts a frame whose ethertype
/// is the socket's, untagged (ethertype at L2 offset 12) or under one 802.1Q
/// tag (0x8100 at 12, the inner ethertype at 16). Frames whose tag the NIC
/// stripped into packet metadata (RX VLAN offload) are seen untagged; a frame
/// this host sends with a software tag reaches the egress tap tagged. The
/// subtype variant also requires the first byte after the L2 header (14, or
/// 18 when tagged), the AVTP subtype for ethertype 0x22F0, to be one of a set.

#include "statusbar/net/net_cbpf_emit.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::net::rawnet_filter {

/// Most subtypes one filter can match.
inline constexpr std::size_t MAX_SUBTYPES = 8;

/// A cBPF program in a fixed buffer (no allocation).
struct Program
{
    std::array<cbpf::Instruction, 10 + MAX_SUBTYPES> code{};
    std::size_t length{0};

    [[nodiscard]] constexpr auto instructions() const noexcept -> std::span<cbpf::Instruction const>
    {
        return std::span<cbpf::Instruction const>{code}.first(length);
    }
};

inline constexpr std::uint32_t ACCEPT = 0xFFFFFFFFU;
inline constexpr std::uint32_t DROP = 0U;
inline constexpr std::uint16_t TPID_8021Q = 0x8100U;

/// Accept every frame of @p ethertype, untagged or under one 802.1Q tag.
[[nodiscard]] constexpr auto ethertype_filter(std::uint16_t const ethertype) noexcept -> Program
{
    Program p{};
    p.code = {{
        {cbpf::op::LD_H_ABS, 0, 0, 12},           // 0: A = ethertype @12
        {cbpf::op::JMP_JEQ_K, 4, 0, ethertype},   // 1: == type -> accept (6)
        {cbpf::op::JMP_JEQ_K, 0, 2, TPID_8021Q},  // 2: == 0x8100 -> 3, else drop (5)
        {cbpf::op::LD_H_ABS, 0, 0, 16},           // 3: A = inner ethertype @16
        {cbpf::op::JMP_JEQ_K, 1, 0, ethertype},   // 4: == type -> accept (6), else drop (5)
        {cbpf::op::RET_K, 0, 0, DROP},            // 5
        {cbpf::op::RET_K, 0, 0, ACCEPT},          // 6
    }};
    p.length = 7;
    return p;
}

/// Accept a frame of @p ethertype only if its first payload byte (the AVTP
/// subtype) is one of @p subtypes. An empty set, or more than MAX_SUBTYPES,
/// gives ethertype_filter(): wider, never narrower, than asked.
///
///   0: ldh [12]
///   1: jeq #type      jt 7 (untagged)
///   2: jeq #0x8100    jf drop
///   3: ldh [16]
///   4: jeq #type      jf drop
///   5: ldb [18]       (tagged subtype)
///   6: ja 8
///   7: ldb [14]       (untagged subtype)
///   8+i: jeq #subtype[i] jt accept    (i < n; the last falls through to drop)
///   8+n: ret #0
///   9+n: ret #-1
[[nodiscard]] constexpr auto subtype_filter(std::uint16_t const ethertype, std::span<std::uint8_t const> const subtypes) noexcept
    -> Program
{
    std::size_t const n = subtypes.size();
    if (n == 0 || n > MAX_SUBTYPES) {
        return ethertype_filter(ethertype);
    }
    auto const u8 = [](std::size_t const v) noexcept -> std::uint8_t { return static_cast<std::uint8_t>(v); };
    Program p{};
    std::size_t const drop = 8 + n;
    p.code[0] = {cbpf::op::LD_H_ABS, 0, 0, 12};
    p.code[1] = {cbpf::op::JMP_JEQ_K, 5, 0, ethertype};
    p.code[2] = {cbpf::op::JMP_JEQ_K, 0, u8(drop - 3), TPID_8021Q};
    p.code[3] = {cbpf::op::LD_H_ABS, 0, 0, 16};
    p.code[4] = {cbpf::op::JMP_JEQ_K, 0, u8(drop - 5), ethertype};
    p.code[5] = {cbpf::op::LD_B_ABS, 0, 0, 18};
    p.code[6] = {cbpf::op::JMP_JA, 0, 0, 1};
    p.code[7] = {cbpf::op::LD_B_ABS, 0, 0, 14};
    for (std::size_t i = 0; i < n; ++i) {
        p.code[8 + i] = {cbpf::op::JMP_JEQ_K, u8(n - i), 0, subtypes[i]};
    }
    p.code[drop] = {cbpf::op::RET_K, 0, 0, DROP};
    p.code[drop + 1] = {cbpf::op::RET_K, 0, 0, ACCEPT};
    p.length = drop + 2;
    return p;
}

}  // namespace statusbar::net::rawnet_filter
