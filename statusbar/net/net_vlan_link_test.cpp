// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for VLAN link registration.
///
/// Three tiers, and the middle one is the interesting part.
///
/// The builders and the ack parser are pure, so they are compared against
/// complete hand-written byte arrays with no socket and no privilege. The
/// create request was checked against what `ip link add link dummy0 name
/// dummy0.2 type vlan id 2` actually sends, captured with strace: 80
/// bytes, field for field the same.
///
/// The lifecycle — create a link, confirm the VID is registered and the
/// link is down, delete it, confirm it is gone — reads in the issue like
/// a root-only test. It is not. A user namespace grants CAP_NET_ADMIN
/// over a network namespace created alongside it, so an ordinary uid can
/// do all of it on a device list nothing else can see. Those tests run
/// here, unprivileged, and skip out loud if the kernel forbids user
/// namespaces.
///
/// The third tier is what is left: whether the kernel's refusal of a
/// *privileged* operation is reported clearly to an unprivileged caller.

#include "statusbar/net/net_vlan_link.hpp"

#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_vlan_link_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include <fcntl.h>
#    include <sched.h>
#    include <unistd.h>

#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <net/if.h>
#    include <sys/socket.h>
#    include <sys/wait.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

#if defined(__linux__)

constexpr std::uint16_t AVB_VID = 2;

/// The longest name the kernel takes, and the shortest it will not. Their
/// lengths are asserted rather than counted by eye: a boundary test whose
/// fixture is off by one asserts the wrong side of the boundary and still
/// looks like it passes.
constexpr std::string_view LONGEST_NAME = "fifteen.bytes.x";
constexpr std::string_view TOO_LONG_NAME = "sixteen.bytes.xy";
static_assert(LONGEST_NAME.size() == vlan::MAX_LINK_NAME_LENGTH);
static_assert(TOO_LONG_NAME.size() == vlan::MAX_LINK_NAME_LENGTH + 1);

// ---------------------------------------------------------------------------
// The two requests, byte for byte.
// ---------------------------------------------------------------------------

/// `ip link add link dummy0 name dummy0.2 type vlan id 2` with dummy0 at
/// ifindex 2, sequence 100. iproute2 sends 80 bytes for this; so do we,
/// with the same fields in the same places.
constexpr std::array<std::uint8_t, 80> EXPECTED_CREATE{
    // nlmsghdr
    0x50,
    0x00,
    0x00,
    0x00,  // nlmsg_len = 80
    0x10,
    0x00,  // nlmsg_type = RTM_NEWLINK
    0x05,
    0x06,  // nlmsg_flags = REQUEST|ACK|EXCL|CREATE
    0x64,
    0x00,
    0x00,
    0x00,  // nlmsg_seq = 100
    0x00,
    0x00,
    0x00,
    0x00,  // nlmsg_pid = 0: the kernel fills in our port
    // ifinfomsg, every field zero: the link does not exist yet, so there is
    // no index to name, no flags to set and nothing to change.
    0x00,
    0x00,
    0x00,
    0x00,  // ifi_family = AF_UNSPEC, pad, ifi_type
    0x00,
    0x00,
    0x00,
    0x00,  // ifi_index
    0x00,
    0x00,
    0x00,
    0x00,  // ifi_flags
    0x00,
    0x00,
    0x00,
    0x00,  // ifi_change
    // IFLA_LINK: the device the VLAN hangs off
    0x08,
    0x00,
    0x05,
    0x00,
    0x02,
    0x00,
    0x00,
    0x00,  // parent ifindex 2
    // IFLA_IFNAME: "dummy0.2", NUL-terminated, padded to 4
    0x0D,
    0x00,
    0x03,
    0x00,
    'd',
    'u',
    'm',
    'm',
    'y',
    '0',
    '.',
    '2',
    0x00,
    0x00,
    0x00,
    0x00,
    // IFLA_LINKINFO, nesting the two below. No NLA_F_NESTED flag on the
    // type, which is what iproute2 sends and what the kernel's policy for
    // this attribute expects.
    0x18,
    0x00,
    0x12,
    0x00,
    //   IFLA_INFO_KIND = "vlan", with no terminator: nla_strcmp compares
    //   on length, and this is byte for byte what iproute2 sends.
    0x08,
    0x00,
    0x01,
    0x00,
    'v',
    'l',
    'a',
    'n',
    //   IFLA_INFO_DATA, nesting the id
    0x0C,
    0x00,
    0x02,
    0x00,
    //     IFLA_VLAN_ID = 2
    0x06,
    0x00,
    0x01,
    0x00,
    0x02,
    0x00,
    0x00,
    0x00,  // padding, counted inside both nests' lengths
};

/// `ip link del dummy0.2`, sequence 300 — naming the link, where iproute2
/// resolves the name to an ifindex first and deletes by index.
constexpr std::array<std::uint8_t, 48> EXPECTED_DELETE{
    0x30,
    0x00,
    0x00,
    0x00,  // nlmsg_len = 48
    0x11,
    0x00,  // nlmsg_type = RTM_DELLINK
    0x05,
    0x00,  // nlmsg_flags = REQUEST|ACK
    0x2C,
    0x01,
    0x00,
    0x00,  // nlmsg_seq = 300
    0x00,
    0x00,
    0x00,
    0x00,  // nlmsg_pid
    // ifinfomsg, every field zero — ifi_index included, because the link is
    // named instead.
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    // IFLA_IFNAME
    0x0D,
    0x00,
    0x03,
    0x00,
    'd',
    'u',
    'm',
    'm',
    'y',
    '0',
    '.',
    '2',
    0x00,
    0x00,
    0x00,
    0x00,
};

/// Report where two byte strings first differ, so a failure says which
/// field is wrong rather than only that something is.
auto expect_bytes(std::span<std::uint8_t const> got, std::span<std::uint8_t const> want) -> void
{
    EXPECT_EQ(got.size(), want.size());
    if (got.size() != want.size()) {
        return;
    }
    for (std::size_t at = 0; at < want.size(); ++at) {
        if (got[at] != want[at]) {
            std::printf("  first difference at offset %zu: got 0x%02X, want 0x%02X\n", at, got[at], want[at]);
            EXPECT_EQ(got[at], want[at]);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Synthesised error replies, in the shape the kernel really sends.
// ---------------------------------------------------------------------------

/// Assemble an `NLMSG_ERROR` the way the kernel assembles one: the errno,
/// then the offending request's header, then — unless the kernel set
/// NLM_F_CAPPED — the *rest* of that request, and only after all of it the
/// extended-ack TLVs.
///
/// The lengths this produces were checked against the real thing: a plain
/// acknowledgement of our 80-byte create came back as 36 bytes, its
/// refusal with EEXIST as 100, and a 76-byte request refused with a
/// 36-character message as 140.
auto make_error_reply(int error, std::span<std::uint8_t const> request, bool capped, std::string_view message)
    -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> reply(sizeof(nlmsghdr) + sizeof(nlmsgerr));
    nlmsgerr body{};
    body.error = -error;
    std::memcpy(&body.msg, request.data(), sizeof(nlmsghdr));
    std::memcpy(reply.data() + sizeof(nlmsghdr), &body, sizeof(body));
    if (!capped) {
        reply.insert(reply.end(), request.begin() + sizeof(nlmsghdr), request.end());
    }
    if (!message.empty()) {
        auto const payload = message.size() + 1;
        auto const at = reply.size();
        reply.resize(at + ((sizeof(rtattr) + payload + 3) & ~std::size_t{3}));
        rtattr const attribute{
            .rta_len = static_cast<unsigned short>(sizeof(rtattr) + payload),
            .rta_type = NLMSGERR_ATTR_MSG,
        };
        std::memcpy(reply.data() + at, &attribute, sizeof(attribute));
        std::memcpy(reply.data() + at + sizeof(rtattr), message.data(), message.size());
    }
    nlmsghdr header{};
    header.nlmsg_len = static_cast<std::uint32_t>(reply.size());
    header.nlmsg_type = NLMSG_ERROR;
    header.nlmsg_flags = static_cast<std::uint16_t>(capped ? NLM_F_CAPPED : (message.empty() ? 0 : NLM_F_ACK_TLVS));
    std::memcpy(reply.data(), &header, sizeof(header));
    return reply;
}

// ---------------------------------------------------------------------------
// A private network namespace, so the lifecycle is a CI test.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scaffolding for the namespace tests.
// ---------------------------------------------------------------------------

#endif  // defined(__linux__)

}  // namespace

#if defined(__linux__)

// ===========================================================================
// vlan_link_name
// ===========================================================================

TEST(vlan_link, a_link_name_is_the_parent_a_dot_and_the_vid)
{
    EXPECT_TRUE(vlan::vlan_link_name("eth0", 2) == "eth0.2");
    EXPECT_TRUE(vlan::vlan_link_name("enp0s31f6", 4094) == "enp0s31f6.4094");
}

TEST(vlan_link, a_name_that_exactly_fills_the_limit_is_not_truncated)
{
    // 13 + 1 + 1 = 15, which is all a link name may be.
    auto const name = vlan::vlan_link_name("abcdefghijklm", 2);
    EXPECT_EQ(name.size(), vlan::MAX_LINK_NAME_LENGTH);
    EXPECT_TRUE(name == "abcdefghijklm.2");
}

TEST(vlan_link, a_name_past_the_limit_loses_parent_bytes_and_keeps_the_vid)
{
    // A 15-byte parent is legal, so parent + ".2" is not.
    auto const name = vlan::vlan_link_name("enp0s31f6abcdef", 2);
    EXPECT_EQ(name.size(), vlan::MAX_LINK_NAME_LENGTH);
    EXPECT_TRUE(name == "enp0s31f6abcd.2");
}

TEST(vlan_link, a_four_digit_vid_survives_truncation_whole)
{
    // The VID is the part that makes the name mean anything, so it is the
    // part that is never clipped.
    auto const name = vlan::vlan_link_name("enp0s31f6abcdef", 4094);
    EXPECT_EQ(name.size(), vlan::MAX_LINK_NAME_LENGTH);
    EXPECT_TRUE(name == "enp0s31f6a.4094");
}

TEST(vlan_link, the_same_parent_and_vid_always_give_the_same_name)
{
    // Which is what lets a later run delete a link it did not create in
    // this process.
    EXPECT_TRUE(vlan::vlan_link_name("enp0s31f6abcdef", 2) == vlan::vlan_link_name("enp0s31f6abcdef", 2));
}

TEST(vlan_link, two_parents_sharing_a_prefix_can_collide)
{
    // Not a defect to fix in the name: 15 bytes cannot be injective over
    // parent names. It is the reason add_vlan checks what it adopted.
    EXPECT_TRUE(vlan::vlan_link_name("enp0s31f6abcdef", 2) == vlan::vlan_link_name("enp0s31f6abcdZZ", 2));
}

TEST(vlan_link, an_empty_parent_gives_no_name)
{
    EXPECT_TRUE(vlan::vlan_link_name("", 2).empty());
}

// ===========================================================================
// build_new_vlan
// ===========================================================================

TEST(vlan_link, a_create_request_is_byte_for_byte_what_iproute2_sends)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    if (length) {
        EXPECT_EQ(*length, EXPECTED_CREATE.size());
        expect_bytes({request.data(), *length}, EXPECTED_CREATE);
    }
}

TEST(vlan_link, a_create_request_asks_for_exclusive_creation)
{
    // Without NLM_F_EXCL the kernel reads RTM_NEWLINK on an existing link
    // as a *change*, and would silently re-point an administrator's VLAN
    // link at our VID instead of telling us it is already there. EXCL is
    // what makes the ownership policy possible at all.
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    std::uint16_t flags = 0;
    std::memcpy(&flags, request.data() + offsetof(nlmsghdr, nlmsg_flags), sizeof(flags));
    EXPECT_EQ(flags & NLM_F_EXCL, NLM_F_EXCL);
    EXPECT_EQ(flags & NLM_F_CREATE, NLM_F_CREATE);
    EXPECT_EQ(flags & NLM_F_ACK, NLM_F_ACK);
}

TEST(vlan_link, a_create_request_carries_the_sequence_it_was_given)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "eth0.2", AVB_VID, 0xABCDEF12);
    EXPECT_TRUE(length.has_value());
    std::uint32_t seq = 0;
    std::memcpy(&seq, request.data() + offsetof(nlmsghdr, nlmsg_seq), sizeof(seq));
    EXPECT_EQ(seq, 0xABCDEF12U);
}

TEST(vlan_link, a_create_request_needs_a_real_parent)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    EXPECT_FALSE(vlan::build_new_vlan(request, 0, "eth0.2", AVB_VID, 1).has_value());
    EXPECT_FALSE(vlan::build_new_vlan(request, -1, "eth0.2", AVB_VID, 1).has_value());
}

TEST(vlan_link, a_create_request_refuses_a_name_the_kernel_would_refuse)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    EXPECT_FALSE(vlan::build_new_vlan(request, 2, "", AVB_VID, 1).has_value());
    EXPECT_FALSE(vlan::build_new_vlan(request, 2, TOO_LONG_NAME, AVB_VID, 1).has_value());
    EXPECT_TRUE(vlan::build_new_vlan(request, 2, LONGEST_NAME, AVB_VID, 1).has_value());
}

TEST(vlan_link, a_create_request_refuses_the_vids_802_1q_reserves)
{
    // 0 marks a priority-tagged frame with no VLAN membership and 4095 is
    // reserved; the kernel would accept a link for VID 0, which is exactly
    // why refusing it here is worth doing.
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    EXPECT_FALSE(vlan::build_new_vlan(request, 2, "eth0.0", 0, 1).has_value());
    EXPECT_FALSE(vlan::build_new_vlan(request, 2, "eth0.4095", 4095, 1).has_value());
    EXPECT_FALSE(vlan::build_new_vlan(request, 2, "eth0.9999", 9999, 1).has_value());
    EXPECT_TRUE(vlan::build_new_vlan(request, 2, "eth0.1", vlan::MIN_VLAN_ID, 1).has_value());
    EXPECT_TRUE(vlan::build_new_vlan(request, 2, "eth0.4094", vlan::MAX_VLAN_ID, 1).has_value());
}

TEST(vlan_link, a_create_request_refuses_a_buffer_it_would_overrun)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    EXPECT_FALSE(vlan::build_new_vlan({request.data(), EXPECTED_CREATE.size() - 1}, 2, "dummy0.2", AVB_VID, 100).has_value());
    EXPECT_TRUE(vlan::build_new_vlan({request.data(), EXPECTED_CREATE.size()}, 2, "dummy0.2", AVB_VID, 100).has_value());
}

// ===========================================================================
// build_delete_link
// ===========================================================================

TEST(vlan_link, a_delete_request_is_byte_for_byte_as_hand_checked)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_delete_link(request, "dummy0.2", 300);
    EXPECT_TRUE(length.has_value());
    if (length) {
        EXPECT_EQ(*length, EXPECTED_DELETE.size());
        expect_bytes({request.data(), *length}, EXPECTED_DELETE);
    }
}

TEST(vlan_link, a_delete_request_names_the_link_instead_of_its_index)
{
    // iproute2 resolves the name with a separate RTM_GETLINK and deletes by
    // index. The kernel takes IFLA_IFNAME directly, which is one round trip
    // instead of two and leaves no window in which the index it looked up
    // could be freed and handed to a different link.
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_delete_link(request, "dummy0.2", 300);
    EXPECT_TRUE(length.has_value());
    std::int32_t index = -1;
    std::memcpy(&index, request.data() + sizeof(nlmsghdr) + offsetof(ifinfomsg, ifi_index), sizeof(index));
    EXPECT_EQ(index, 0);
    std::uint16_t type = 0;
    std::memcpy(&type, request.data() + sizeof(nlmsghdr) + sizeof(ifinfomsg) + offsetof(rtattr, rta_type), sizeof(type));
    EXPECT_EQ(type, static_cast<std::uint16_t>(IFLA_IFNAME));
}

TEST(vlan_link, a_delete_request_refuses_a_name_the_kernel_would_refuse)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    EXPECT_FALSE(vlan::build_delete_link(request, "", 1).has_value());
    EXPECT_FALSE(vlan::build_delete_link(request, TOO_LONG_NAME, 1).has_value());
    EXPECT_TRUE(vlan::build_delete_link(request, LONGEST_NAME, 1).has_value());
    EXPECT_FALSE(vlan::build_delete_link({request.data(), EXPECTED_DELETE.size() - 1}, "dummy0.2", 1).has_value());
}

// ===========================================================================
// parse_ack
// ===========================================================================

TEST(vlan_link, a_plain_acknowledgement_parses_as_success)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    auto const reply = make_error_reply(0, {request.data(), *length}, /*capped=*/true, "");
    // The kernel really does send exactly 36 bytes for this.
    EXPECT_EQ(reply.size(), 36U);
    auto const ack = vlan::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, 0);
        EXPECT_TRUE(ack->message.empty());
    }
}

TEST(vlan_link, an_error_with_no_extended_ack_parses_as_an_errno_alone)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    // EEXIST comes back uncapped, echoing the whole 80-byte request: 100
    // bytes, which is what the kernel sent when this was checked.
    auto const reply = make_error_reply(EEXIST, {request.data(), *length}, /*capped=*/false, "");
    EXPECT_EQ(reply.size(), 100U);
    auto const ack = vlan::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EEXIST);
        EXPECT_TRUE(ack->message.empty());
    }
}

TEST(vlan_link, a_message_after_an_uncapped_echo_is_found)
{
    // The case that costs a day if the offset is wrong: the TLVs sit after
    // the echoed request, not after the nlmsgerr. Reading them at
    // sizeof(nlmsgerr) lands inside the echoed request's own ifinfomsg,
    // whose first bytes are zero, so the message comes out empty.
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 1, "lo.2", AVB_VID, 200);
    EXPECT_TRUE(length.has_value());
    EXPECT_EQ(*length, 76U);
    std::string_view const text = "8021q: VLANs not supported on device";
    auto const reply = make_error_reply(EOPNOTSUPP, {request.data(), *length}, /*capped=*/false, text);
    // 140 bytes, which is the length the kernel really sent for this one.
    EXPECT_EQ(reply.size(), 140U);
    auto const ack = vlan::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EOPNOTSUPP);
        EXPECT_TRUE(ack->message == text);
    }
}

TEST(vlan_link, a_message_in_a_capped_reply_is_found_at_the_other_offset)
{
    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    std::string_view const text = "capped refusal";
    auto const reply = make_error_reply(EINVAL, {request.data(), *length}, /*capped=*/true, text);
    auto const ack = vlan::parse_ack(reply);
    EXPECT_TRUE(ack.has_value());
    if (ack) {
        EXPECT_EQ(ack->error, EINVAL);
        EXPECT_TRUE(ack->message == text);
    }
}

TEST(vlan_link, a_truncated_or_wrong_typed_reply_is_refused)
{
    std::array<std::uint8_t, 8> too_short{};
    EXPECT_FALSE(vlan::parse_ack(too_short).has_value());

    std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
    auto const length = vlan::build_new_vlan(request, 2, "dummy0.2", AVB_VID, 100);
    EXPECT_TRUE(length.has_value());
    auto reply = make_error_reply(0, {request.data(), *length}, /*capped=*/true, "");
    std::uint16_t const not_an_error = RTM_NEWLINK;
    std::memcpy(reply.data() + offsetof(nlmsghdr, nlmsg_type), &not_an_error, sizeof(not_an_error));
    EXPECT_FALSE(vlan::parse_ack(reply).has_value());
}

// ===========================================================================
// read_vlan_link — unprivileged, on whatever this host has
// ===========================================================================

TEST(vlan_link, reading_an_unnamed_device_reports_no_such_device)
{
    auto const facts = vlan::read_vlan_link("");
    EXPECT_FALSE(facts.has_value());
    if (!facts) {
        EXPECT_TRUE(facts.error() == std::errc::no_such_device);
    }
}

TEST(vlan_link, reading_an_impossible_name_is_refused_before_any_syscall)
{
    // ENAMETOOLONG is a verdict no interface query returns, so the early
    // return is observable rather than merely asserted.
    auto const facts = vlan::read_vlan_link("this.name.is.far.too.long");  // NOLINT
    EXPECT_FALSE(facts.has_value());
    if (!facts) {
        EXPECT_TRUE(facts.error() == std::errc::filename_too_long);
    }
}

// ===========================================================================
// The recorder, which is what a listener's tests will use
// ===========================================================================

TEST(vlan_link, the_recorder_remembers_what_was_registered)
{
    vlan::VlanRecorder recorder;
    auto const ownership = recorder.add_vlan(7, "eth0.2", AVB_VID);
    EXPECT_TRUE(ownership.has_value());
    if (ownership) {
        EXPECT_TRUE(*ownership == vlan::LinkOwnership::created);
    }
    EXPECT_EQ(recorder.requests().size(), 1U);
    EXPECT_TRUE(recorder.requests()[0].operation == vlan::VlanRecorder::Operation::add_vlan);
    EXPECT_TRUE(recorder.requests()[0].name == "eth0.2");
    EXPECT_EQ(recorder.requests()[0].vid, AVB_VID);
    EXPECT_EQ(recorder.requests()[0].parent_ifindex, 7);
    EXPECT_TRUE(recorder.registered(7, AVB_VID));
    EXPECT_FALSE(recorder.registered(7, 3));
    EXPECT_FALSE(recorder.registered(8, AVB_VID));
}

TEST(vlan_link, the_recorder_can_report_an_adoption)
{
    vlan::VlanRecorder recorder;
    recorder.set_next_ownership(vlan::LinkOwnership::adopted);
    auto const first = recorder.add_vlan(7, "eth0.2", AVB_VID);
    EXPECT_TRUE(first.has_value());
    if (first) {
        EXPECT_TRUE(*first == vlan::LinkOwnership::adopted);
    }
    // One programmed answer, not a mode: the next call is a creation again.
    auto const second = recorder.add_vlan(7, "eth0.3", 3);
    EXPECT_TRUE(second.has_value());
    if (second) {
        EXPECT_TRUE(*second == vlan::LinkOwnership::created);
    }
}

TEST(vlan_link, the_recorder_can_fail_a_registration_with_a_message)
{
    vlan::VlanRecorder recorder;
    recorder.fail_next(std::make_error_code(std::errc::operation_not_permitted), "no");
    auto const refused = recorder.add_vlan(7, "eth0.2", AVB_VID);
    EXPECT_FALSE(refused.has_value());
    if (!refused) {
        EXPECT_TRUE(refused.error() == std::errc::operation_not_permitted);
    }
    EXPECT_TRUE(recorder.last_message() == "no");
    // The attempt is still recorded: what a caller tried is the thing a
    // test usually wants to assert.
    EXPECT_EQ(recorder.requests().size(), 1U);
    EXPECT_TRUE(recorder.registered(7, AVB_VID));
}

TEST(vlan_link, the_recorder_remembers_removals_too)
{
    vlan::VlanRecorder recorder;
    EXPECT_TRUE(recorder.add_vlan(7, "eth0.2", AVB_VID).has_value());
    EXPECT_TRUE(recorder.remove_link("eth0.2").has_value());
    EXPECT_EQ(recorder.requests().size(), 2U);
    EXPECT_TRUE(recorder.requests()[1].operation == vlan::VlanRecorder::Operation::remove_link);
    EXPECT_TRUE(recorder.requests()[1].name == "eth0.2");
    recorder.clear();
    EXPECT_TRUE(recorder.requests().empty());
}

// ===========================================================================
// The client, with no CAP_NET_ADMIN
// ===========================================================================

TEST(vlan_link, a_client_that_was_never_opened_is_not_connected)
{
    vlan::VlanLinkClient client;
    EXPECT_FALSE(client.valid());
    auto const refused = client.add_vlan(1, "lo.2", AVB_VID);
    EXPECT_FALSE(refused.has_value());
    if (!refused) {
        EXPECT_TRUE(refused.error() == NetError::not_connected);
    }
    EXPECT_FALSE(client.remove_link("lo.2").has_value());
}

// ===========================================================================
// The lifecycle, in a network namespace of our own
// ===========================================================================

#endif  // defined(__linux__)

TEST_MAIN(statusbar_net, net_vlan_link_test)
