#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The AVTP stream rule set for the TCAM classifier, and where the AVTPDU
/// starts in a received frame.
///
/// A rule recipe, not a rule engine: everything here is built out of
/// ClassifierRuleBuilder and CompiledRule from net_compiled_rule.hpp.
///
/// It exists because the rule set is easy to get subtly wrong in two ways,
/// and both ways work in a lab and fail on a real network:
///
///   - The stream subtypes are three separate values, not a range. 0x01
///     (MMA) and 0x03 (CVF) sit between them and are not in the set, so a
///     rule written as "subtype <= 0x04" admits traffic it should not.
///   - Each subtype needs *two* rules, because an 802.1Q tag shifts the
///     ethertype and the subtype byte four bytes to the right. A rule set
///     with only the untagged variant passes every test on a veth pair -
///     veth carries untagged frames - and then drops every frame on a
///     switched AVB network, where the traffic is tagged by definition:
///     the stream reservation it is travelling under is a VLAN.
///
/// avtp_payload_offset() is the same problem from the receiving end. Code
/// reading an AVTPDU out of a frame has to know whether it is looking past
/// a tag, and the answer is in the frame rather than in the configuration.
///
/// Header-only and free of any dependency on an XDP program or a NIC, so a
/// test can compile the rules and inspect their bytes with no hardware.

#include "statusbar/ieee/ieee_protocols.hpp"
#include "statusbar/net/net_compiled_rule.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::net {

/// Spelled here as well as in ieee::protocols so building a rule set needs
/// one header rather than two. Aliases rather than fresh literals: one
/// definition of each value, and it is the one the rest of the tree uses.
inline constexpr std::uint16_t ETHERTYPE_AVTP = ieee::protocols::ETHERTYPE_AVTP;
inline constexpr std::uint16_t ETHERTYPE_VLAN = ieee::protocols::ETHERTYPE_VLAN;

/// The AVTP subtypes an audio endpoint streams: IEC 61883/IIDC (0x00),
/// AAF (0x02) and CRF (0x04).
///
/// Narrower than "every continuous format in IEEE 1722" - that would also
/// take in MMA (0x01), CVF (0x03), TSCF (0x05), SVF (0x06) and RVF (0x07).
/// These three are what an AVB audio talker or listener plus its media
/// clock needs: the two audio encapsulations, old and current, and the
/// clock reference that carries their presentation time. A caller that
/// wants video or MIDI steered as well adds its own rule rather than
/// widening this set, because widening it costs every other caller two
/// more rules out of the sixteen the BPF program evaluates per frame.
inline constexpr std::array<std::uint8_t, 3> AVTP_STREAM_SUBTYPES = {0x00, 0x02, 0x04};

/// Two rules per subtype: untagged and 802.1Q-tagged.
inline constexpr std::size_t avtp_stream_rule_count = AVTP_STREAM_SUBTYPES.size() * 2;

/// The whole set, sized at compile time so it needs no allocation and
/// converts straight to the std::span that TcamClassifier::set_rules and
/// XdpContext's rule installer take.
using AvtpStreamRules = std::array<CompiledRule<tcam_default_window_bytes>, avtp_stream_rule_count>;

/// Every rule needed to admit the AVTP stream subtypes, tagged and
/// untagged, in the order (subtype 0x00 untagged, 0x00 tagged, 0x02
/// untagged, 0x02 tagged, ...). Order is worth knowing because the
/// classifier is first-match-wins over the slots as installed; within this
/// set it does not matter, as no frame matches two of these rules.
///
/// `result_flags` defaults to what a stream port wants - steer the frame
/// into the AF_XDP socket and tag it as an AVTP stream frame. It is a
/// parameter because the action is the caller's to choose: the same six
/// rules with flag::forward_tap divert the streams to a TAP device, and
/// with flag::drop they are a blocklist.
///
/// Each rule carries min_frame_size = 32, inherited from the TCAM window,
/// so none of them matches a frame shorter than the window. That is not a
/// limitation in practice - the shortest real AVTP stream frame is far
/// longer - and it matches the BPF program, which passes a frame shorter
/// than the window up the stack before consulting any rule.
[[nodiscard]] constexpr auto avtp_stream_rules(std::uint64_t result_flags = flag::process | flag::rx_avtp_stream) -> AvtpStreamRules
{
    AvtpStreamRules out{};
    std::size_t next = 0;
    for (auto const subtype : AVTP_STREAM_SUBTYPES) {
        // vlan_any() is the fan-out that produces the untagged and the
        // tagged form of one rule; it is the reason this is six rules and
        // not three.
        auto const both = ClassifierRuleBuilder<tcam_default_window_bytes>{}
                              .ethertype(ETHERTYPE_AVTP)
                              .avtp_subtype(subtype)
                              .vlan_any()
                              .result(result_flags)
                              .build();
        for (auto const& rule : both) {
            out[next] = rule;
            ++next;
        }
    }
    return out;
}

/// Where the AVTPDU starts in `frame`: 14 for an untagged AVTP frame, 18
/// for one under a single 802.1Q tag, and nullopt when the frame is not
/// AVTP or is too short to say.
///
/// Only one level of tagging is in scope. A QinQ frame - 0x8100 twice -
/// reports nullopt rather than being mis-parsed as a single-tagged frame
/// whose payload begins inside the inner tag, and an 802.1ad S-TAG
/// (0x88A8) is not recognised at all. Both refuse rather than guess; add
/// them here if something needs them.
///
/// The offset says where the AVTPDU begins, not that any of it is present:
/// a 14-byte AVTP frame reports 14, and `frame.subspan(14)` is then empty
/// but valid. Keeping that distinct from nullopt matters, because nullopt
/// means "not an AVTP frame" and a caller may well want to treat a runt
/// AVTP frame differently from an IPv4 one. The caller still has to check
/// the length of what it reads out of the subspan.
///
/// Every read is bounds-checked against `frame.size()` first. This runs on
/// whatever arrives on a shared LAN, which is to say on input chosen by
/// someone else.
///
/// ieee::can_load(frame, EthernetFrame const*) answers the same question
/// for any ethertype, with the same 14-or-18 result and the same refusal
/// of a frame too short for the tag it claims. Prefer it when the next
/// thing you want is the parsed header. This exists alongside it because
/// it is constexpr and that one is not - it is declared in a header and
/// defined in a .cpp - which is what lets the offsets here be asserted at
/// compile time against frames that are themselves compile-time data. If
/// can_load ever becomes constexpr, this should be a call to it.
[[nodiscard]] constexpr auto avtp_payload_offset(std::span<std::uint8_t const> frame) noexcept -> std::optional<std::size_t>
{
    constexpr std::size_t ethertype_offset = 12;
    constexpr std::size_t untagged_payload_offset = 14;
    constexpr std::size_t tagged_ethertype_offset = 16;
    constexpr std::size_t tagged_payload_offset = 18;

    auto const ethertype_at = [frame](std::size_t offset) constexpr noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(frame[offset]) << 8U) | frame[offset + 1]);
    };

    // Reading the outer ethertype needs the first 14 bytes, which is also
    // the untagged payload offset: a frame that can be classified at all
    // can hold the offset this returns.
    if (frame.size() < untagged_payload_offset) {
        return std::nullopt;
    }
    auto const outer = ethertype_at(ethertype_offset);
    if (outer == ETHERTYPE_AVTP) {
        return untagged_payload_offset;
    }
    if (outer != ETHERTYPE_VLAN) {
        return std::nullopt;
    }
    // Same again for the tag: 18 bytes both to read the inner ethertype
    // and to be a valid offset.
    if (frame.size() < tagged_payload_offset) {
        return std::nullopt;
    }
    if (ethertype_at(tagged_ethertype_offset) != ETHERTYPE_AVTP) {
        return std::nullopt;
    }
    return tagged_payload_offset;
}

}  // namespace statusbar::net
