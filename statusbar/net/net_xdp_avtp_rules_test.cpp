// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the AVTP stream rule recipe and the AVTPDU payload offset.
///
/// The rule bytes are checked against offsets written out here from the
/// IEEE 802.3, 802.1Q and 1722 field positions, not taken from the
/// builder's own offset table. A rule set that agrees with itself about a
/// wrong offset is exactly the failure this file is here to catch.

#include "statusbar/net/net_xdp_avtp_rules.hpp"

#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_tcam_classifier.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr std::size_t window = tcam_default_window_bytes;
constexpr std::uint64_t stream_flags = flag::process | flag::rx_avtp_stream;

struct Expected
{
    std::array<std::uint8_t, window> mask{};
    std::array<std::uint8_t, window> match{};
};

/// An untagged AVTP frame: ethertype at 12, AVTP common header at 14, so
/// the subtype - its first byte - is at 14.
constexpr auto expected_untagged(std::uint8_t subtype) -> Expected
{
    Expected e{};
    e.mask[12] = 0xFF;
    e.mask[13] = 0xFF;
    e.match[12] = 0x22;
    e.match[13] = 0xF0;
    e.mask[14] = 0xFF;
    e.match[14] = subtype;
    return e;
}

/// Under one 802.1Q tag everything after the addresses moves right by
/// four: TPID at 12, TCI at 14 (unmatched - any VID, any priority), the
/// real ethertype at 16, and the subtype at 18.
constexpr auto expected_tagged(std::uint8_t subtype) -> Expected
{
    Expected e{};
    e.mask[12] = 0xFF;
    e.mask[13] = 0xFF;
    e.match[12] = 0x81;
    e.match[13] = 0x00;
    e.mask[16] = 0xFF;
    e.mask[17] = 0xFF;
    e.match[16] = 0x22;
    e.match[17] = 0xF0;
    e.mask[18] = 0xFF;
    e.match[18] = subtype;
    return e;
}

constexpr auto expected_for(std::size_t index) -> Expected
{
    auto const subtype = AVTP_STREAM_SUBTYPES[index / 2];
    return (index % 2 == 0) ? expected_untagged(subtype) : expected_tagged(subtype);
}

/// The whole set, byte for byte, at compile time. Spelled as a predicate
/// so the static_assert below needs no frame source and no NIC.
constexpr auto rule_bytes_are_as_expected() -> bool
{
    auto const rules = avtp_stream_rules();
    for (std::size_t i = 0; i < rules.size(); ++i) {
        auto const want = expected_for(i);
        if (rules[i].mask != want.mask || rules[i].match != want.match) {
            return false;
        }
        if (rules[i].result_flags != stream_flags) {
            return false;
        }
        if (rules[i].min_frame_size != window || rules[i].priority != 0) {
            return false;
        }
    }
    return true;
}

static_assert(avtp_stream_rule_count == 6, "three stream subtypes, two framings each");
static_assert(avtp_stream_rules().size() == avtp_stream_rule_count, "the set is the size it says it is");
static_assert(rule_bytes_are_as_expected(), "a compiled AVTP stream rule does not have the bytes it should");

// The subtypes are three separate values with gaps, not a range. If this
// ever becomes contiguous the comment in the header is wrong.
static_assert(AVTP_STREAM_SUBTYPES == std::array<std::uint8_t, 3>{0x00, 0x02, 0x04}, "AVTP stream subtype set changed");
static_assert(AVTP_STREAM_SUBTYPES[1] - AVTP_STREAM_SUBTYPES[0] == 2, "0x01 (MMA) is not in the set");
static_assert(AVTP_STREAM_SUBTYPES[2] - AVTP_STREAM_SUBTYPES[1] == 2, "0x03 (CVF) is not in the set");

//
// Frames, for the coverage tests.
//

auto make_frame(bool tagged, std::uint16_t ethertype, std::uint8_t subtype) -> std::array<std::uint8_t, 64>
{
    std::array<std::uint8_t, 64> f{};
    for (std::size_t i = 0; i < 6; ++i) {
        f[i] = static_cast<std::uint8_t>(0x91 + i);      // some destination
        f[6 + i] = static_cast<std::uint8_t>(0x02 + i);  // some source
    }
    std::size_t at = 12;
    if (tagged) {
        f[at] = 0x81;
        f[at + 1] = 0x00;
        f[at + 2] = 0x60;  // priority 3, VID 2
        f[at + 3] = 0x02;
        at += 4;
    }
    f[at] = static_cast<std::uint8_t>(ethertype >> 8U);
    f[at + 1] = static_cast<std::uint8_t>(ethertype & 0xFFU);
    f[at + 2] = subtype;
    return f;
}

//
// Frames for the payload-offset assertions, which are compile-time and so
// have to be constexpr data rather than the function above.
//

/// A frame of `Size` bytes: twelve bytes of addresses, then `tail` - the
/// ethertype onwards. The addresses are arbitrary because none of this
/// matches on them; what matters is that they occupy the right twelve
/// bytes, so the ethertype lands where a real frame puts it.
template <std::size_t Size, std::size_t Tail>
constexpr auto frame_with(std::array<std::uint8_t, Tail> const& tail) -> std::array<std::uint8_t, Size>
{
    std::array<std::uint8_t, Size> f{};
    for (std::size_t i = 0; i < 12 && i < Size; ++i) {
        f[i] = static_cast<std::uint8_t>(0x91 + (i % 6));
    }
    for (std::size_t i = 0; i < Tail && (12 + i) < Size; ++i) {
        f[12 + i] = tail[i];
    }
    return f;
}

constexpr auto untagged_avtp = frame_with<14>(std::array<std::uint8_t, 2>{0x22, 0xF0});
constexpr auto tagged_avtp = frame_with<18>(std::array<std::uint8_t, 6>{0x81, 0x00, 0x60, 0x02, 0x22, 0xF0});
constexpr auto untagged_ipv4 = frame_with<14>(std::array<std::uint8_t, 2>{0x08, 0x00});

// Thirteen bytes: one short of being able to read the ethertype at all.
constexpr auto runt = frame_with<13>(std::array<std::uint8_t, 1>{0x22});

// Tagged, and cut off inside the inner ethertype.
constexpr auto tagged_truncated = frame_with<17>(std::array<std::uint8_t, 5>{0x81, 0x00, 0x60, 0x02, 0x22});

// Two tags. Out of scope, and refused rather than read as single-tagged -
// which would put the payload offset inside the inner tag.
constexpr auto qinq_avtp = frame_with<22>(std::array<std::uint8_t, 10>{0x81, 0x00, 0x60, 0x02, 0x81, 0x00, 0x60, 0x03, 0x22, 0xF0});

static_assert(avtp_payload_offset(untagged_avtp) == 14, "an untagged AVTPDU starts at 14");
static_assert(avtp_payload_offset(tagged_avtp) == 18, "a tagged AVTPDU starts at 18");
static_assert(!avtp_payload_offset(untagged_ipv4).has_value(), "IPv4 is not AVTP");
static_assert(!avtp_payload_offset(runt).has_value(), "a frame too short to hold an ethertype has no answer");
static_assert(!avtp_payload_offset(tagged_truncated).has_value(), "a tag with no readable inner ethertype has no answer");
static_assert(!avtp_payload_offset(qinq_avtp).has_value(), "QinQ is out of scope and must not be mis-parsed as one tag");
static_assert(!avtp_payload_offset(std::span<std::uint8_t const>{}).has_value(), "an empty frame has no answer");

// The returned offset is always one the caller can subspan at.
static_assert(*avtp_payload_offset(untagged_avtp) <= untagged_avtp.size(), "offset must be within the frame");
static_assert(*avtp_payload_offset(tagged_avtp) <= tagged_avtp.size(), "offset must be within the frame");

}  // namespace

TEST(xdp_avtp_rules, the_set_is_two_rules_for_each_of_three_subtypes)
{
    auto const rules = avtp_stream_rules();
    EXPECT_EQ(rules.size(), std::size_t{6});
    EXPECT_EQ(AVTP_STREAM_SUBTYPES.size(), std::size_t{3});
}

TEST(xdp_avtp_rules, every_rule_has_the_bytes_it_should)
{
    // Same check as the static_assert above, run again so a failure names
    // the rule and the byte instead of only the line.
    auto const rules = avtp_stream_rules();
    for (std::size_t i = 0; i < rules.size(); ++i) {
        auto const want = expected_for(i);
        for (std::size_t b = 0; b < window; ++b) {
            EXPECT_EQ(static_cast<int>(rules[i].mask[b]), static_cast<int>(want.mask[b]));
            EXPECT_EQ(static_cast<int>(rules[i].match[b]), static_cast<int>(want.match[b]));
        }
        EXPECT_EQ(rules[i].result_flags, stream_flags);
        EXPECT_EQ(rules[i].min_frame_size, static_cast<std::uint16_t>(window));
        EXPECT_EQ(static_cast<int>(rules[i].priority), 0);
    }
}

TEST(xdp_avtp_rules, every_stream_subtype_is_admitted_tagged_and_untagged)
{
    TcamClassifier<> tc;
    auto const rules = avtp_stream_rules();
    tc.set_rules(rules, flag::forward_tap);

    for (auto const subtype : AVTP_STREAM_SUBTYPES) {
        auto const untagged = make_frame(false, ETHERTYPE_AVTP, subtype);
        auto const tagged = make_frame(true, ETHERTYPE_AVTP, subtype);
        EXPECT_EQ(tc.classify_first(untagged), stream_flags);
        EXPECT_EQ(tc.classify_first(tagged), stream_flags);
    }
}

TEST(xdp_avtp_rules, a_subtype_outside_the_set_is_not_admitted)
{
    TcamClassifier<> tc;
    auto const rules = avtp_stream_rules();
    tc.set_rules(rules, flag::forward_tap);

    // 0x01 MMA and 0x03 CVF are the two that sit inside the numeric span
    // of the set without being in it; 0x05 TSCF is just past the end, and
    // 0xFB AECP is control traffic that must not be steered as a stream.
    for (std::uint8_t const subtype : {std::uint8_t{0x01}, std::uint8_t{0x03}, std::uint8_t{0x05}, std::uint8_t{0xFB}}) {
        auto const untagged = make_frame(false, ETHERTYPE_AVTP, subtype);
        auto const tagged = make_frame(true, ETHERTYPE_AVTP, subtype);
        EXPECT_EQ(tc.classify_first(untagged), flag::forward_tap);
        EXPECT_EQ(tc.classify_first(tagged), flag::forward_tap);
    }
}

TEST(xdp_avtp_rules, a_frame_that_is_not_avtp_is_not_admitted)
{
    TcamClassifier<> tc;
    auto const rules = avtp_stream_rules();
    tc.set_rules(rules, flag::forward_tap);

    // IPv4, and gPTP - which shares the AVB network and whose subtype byte
    // would otherwise look like a 61883/IIDC stream.
    for (std::uint16_t const ethertype : {std::uint16_t{0x0800}, std::uint16_t{0x88F7}}) {
        auto const untagged = make_frame(false, ethertype, 0x00);
        auto const tagged = make_frame(true, ethertype, 0x00);
        EXPECT_EQ(tc.classify_first(untagged), flag::forward_tap);
        EXPECT_EQ(tc.classify_first(tagged), flag::forward_tap);
    }
}

TEST(xdp_avtp_rules, the_untagged_halves_alone_would_miss_every_tagged_frame)
{
    // The failure this rule set exists to prevent, demonstrated: a set
    // with only the untagged rule for each subtype passes on a veth pair,
    // which carries untagged frames, and admits nothing at all on a
    // switched AVB network, where stream traffic is tagged by definition.
    auto const full = avtp_stream_rules();
    std::array<CompiledRule<window>, 3> untagged_only{full[0], full[2], full[4]};

    TcamClassifier<> partial;
    partial.set_rules(untagged_only, flag::forward_tap);
    TcamClassifier<> complete;
    complete.set_rules(full, flag::forward_tap);

    for (auto const subtype : AVTP_STREAM_SUBTYPES) {
        auto const tagged = make_frame(true, ETHERTYPE_AVTP, subtype);
        EXPECT_EQ(partial.classify_first(tagged), flag::forward_tap);
        EXPECT_EQ(complete.classify_first(tagged), stream_flags);

        // ...and both agree on the untagged frame, which is why the gap
        // survives a test that only ever sees a veth.
        auto const untagged = make_frame(false, ETHERTYPE_AVTP, subtype);
        EXPECT_EQ(partial.classify_first(untagged), stream_flags);
        EXPECT_EQ(complete.classify_first(untagged), stream_flags);
    }
}

TEST(xdp_avtp_rules, the_action_is_the_callers_to_choose)
{
    TcamClassifier<> tc;
    auto const rules = avtp_stream_rules(flag::drop);
    tc.set_rules(rules, flag::process);
    auto const tagged = make_frame(true, ETHERTYPE_AVTP, 0x02);
    EXPECT_EQ(tc.classify_first(tagged), flag::drop);
}

TEST(xdp_avtp_rules, the_rule_set_fits_the_bpf_programs_table)
{
    // The BPF program evaluates tcam_default_capacity rules per frame.
    // Six of them being this set is only interesting if it leaves room.
    EXPECT_TRUE(avtp_stream_rule_count < tcam_default_capacity);
}

TEST(xdp_avtp_rules, the_payload_offset_steps_over_a_tag)
{
    EXPECT_TRUE(avtp_payload_offset(untagged_avtp).has_value());
    EXPECT_EQ(*avtp_payload_offset(untagged_avtp), std::size_t{14});
    EXPECT_EQ(*avtp_payload_offset(tagged_avtp), std::size_t{18});
    EXPECT_FALSE(avtp_payload_offset(untagged_ipv4).has_value());
    EXPECT_FALSE(avtp_payload_offset(runt).has_value());
    EXPECT_FALSE(avtp_payload_offset(tagged_truncated).has_value());
    EXPECT_FALSE(avtp_payload_offset(qinq_avtp).has_value());
}

TEST(xdp_avtp_rules, the_payload_offset_agrees_with_the_frames_the_rules_match)
{
    // The two halves of this header have to agree: a frame the rule set
    // admits is one whose AVTPDU the offset can find, and the subtype the
    // rule matched is the byte the offset points at.
    for (auto const subtype : AVTP_STREAM_SUBTYPES) {
        for (bool const tagged : {false, true}) {
            auto const frame = make_frame(tagged, ETHERTYPE_AVTP, subtype);
            auto const offset = avtp_payload_offset(frame);
            EXPECT_TRUE(offset.has_value());
            EXPECT_EQ(*offset, tagged ? std::size_t{18} : std::size_t{14});
            EXPECT_EQ(static_cast<int>(frame[*offset]), static_cast<int>(subtype));
        }
    }
}

TEST_MAIN(statusbar_net, net_xdp_avtp_rules_test)
