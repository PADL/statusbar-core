#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// XDP filter rules for AVTP stream data (IEC 61883/IIDC, AAF, CRF; untagged
/// and 802.1Q-tagged, for NICs with and without rx-vlan-offload), and where an
/// AVTP frame's PDU starts. ATDECC, MAAP and the rest stay with the kernel.

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee_base.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_tcam_bpf_abi.h"
#include "statusbar/sg14/inplace_vector.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::net {

inline constexpr std::uint16_t ETHERTYPE_AVTP = 0x22F0;
inline constexpr std::uint16_t ETHERTYPE_VLAN = 0x8100;

/// The AVTP stream subtypes (IEEE 1722-2016 Table 6): IEC 61883/IIDC, AAF, CRF.
inline constexpr std::array<std::uint8_t, 3> AVTP_STREAM_SUBTYPES = {0x00, 0x02, 0x04};

/// As many rules as the program's table holds.
using XdpRules = sg14::inplace_vector<CompiledRule<32>, TCAM_MAX_RULES>;

/// A rule per subtype for untagged AVTP frames and, with `tagged_form_too`,
/// one per subtype for tagged ones (any VID), each with `flags`; nullopt when
/// they do not fit the table.
[[nodiscard]] inline auto avtp_subtype_rules(
    std::span<std::uint8_t const> const subtypes, bool const tagged_form_too = true, std::uint64_t const flags = flag::process)
    -> std::optional<XdpRules>
{
    std::size_t const forms = tagged_form_too ? 2 : 1;
    if (subtypes.size() * forms > TCAM_MAX_RULES) {
        return std::nullopt;
    }
    XdpRules rules;
    for (std::size_t form = 0; form < forms; ++form) {
        for (auto const subtype : subtypes) {
            ClassifierRuleBuilder<32> builder{};
            builder.ethertype(ETHERTYPE_AVTP).avtp_subtype(subtype).result(flags);
            if (form == 0) {
                builder.vlan_untagged();
            } else {
                builder.vlan_tagged_any();
            }
            rules.push_back(builder.build()[0]);
        }
    }
    return rules;
}

/// The six rules for the AVTP stream subtypes, untagged and tagged.
[[nodiscard]] inline auto avtp_stream_rules() -> XdpRules
{
    return *avtp_subtype_rules(AVTP_STREAM_SUBTYPES);
}

namespace detail {

/// The network-order doublet at `offset` of `frame`, which holds it.
[[nodiscard]] inline auto doublet_at(std::span<std::uint8_t const> const frame, std::size_t const offset) noexcept -> std::uint16_t
{
    ieee::doublet_t value{};
    span_load(value, frame.subspan(offset, sizeof(value)));
    return value.get();
}

/// 14 or 18: where the payload after an AVTP ethertype starts, untagged or
/// under one 802.1Q tag; nullopt when the frame is not AVTP.
[[nodiscard]] inline auto avtp_ethertype_end(std::span<std::uint8_t const> const frame) noexcept -> std::optional<std::size_t>
{
    if (frame.size() < 14) {
        return std::nullopt;
    }
    if (doublet_at(frame, 12) == ETHERTYPE_AVTP) {
        return 14;
    }
    if (doublet_at(frame, 12) == ETHERTYPE_VLAN && frame.size() >= 18 && doublet_at(frame, 16) == ETHERTYPE_AVTP) {
        return 18;
    }
    return std::nullopt;
}

}  // namespace detail

/// Where the AVTP PDU starts in an Ethernet frame: 14 untagged, 18 after one
/// 802.1Q tag; nullopt if not AVTP or too short for the 12-byte AVTP header.
[[nodiscard]] inline auto avtp_payload_offset(std::span<std::uint8_t const> const frame) noexcept -> std::optional<std::size_t>
{
    constexpr std::size_t AVTP_HEADER = 12;
    auto const offset = detail::avtp_ethertype_end(frame);
    if (!offset || frame.size() < *offset + AVTP_HEADER) {
        return std::nullopt;
    }
    return offset;
}

}  // namespace statusbar::net
