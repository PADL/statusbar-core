// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// LinkReadiness and reset_wait_state against rtnetlink messages framed as the kernel writes them (linux/rtnetlink.h,
// linux/if_addr.h: RTM_NEWADDR 20, RTM_DELADDR 21, RTM_NEWQDISC 36, IFA_ADDRESS 1, IFA_LOCAL 2, IFA_LABEL 3) and a
// fake clock: an adapter reset is a carrier loss, the address going and both coming back. The bytes are little-endian.

#include "statusbar/test/test.hpp"

#if defined(__linux__)

#    include "statusbar/net/net_link_readiness.hpp"
#    include "statusbar/net/net_message_reactor.hpp"

#    include <array>
#    include <bit>
#    include <cstddef>
#    include <cstdint>
#    include <span>
#    include <system_error>

#    include <sys/socket.h>

namespace {

using namespace statusbar::net;

constexpr bool LITTLE = std::endian::native == std::endian::little;
constexpr int64_t MS = 1'000'000;

// clang-format off
/// RTM_NEWLINK for ifindex 3 with LOWER_UP: carrier 1, carrier_down_count 7, ifname "eth0".
constexpr std::array<uint8_t, 60> NEWLINK{
    0x3c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x30, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x03, 0x00, 'e', 't', 'h', '0', 0x00, 0x00, 0x00, 0x00,
};

/// RTM_NEWADDR for ifindex 3: 192.0.2.5/24 (IFA_ADDRESS and IFA_LOCAL), label "eth0".
constexpr std::array<uint8_t, 52> NEWADDR{
    0x34, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x18, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xc0, 0x00, 0x02, 0x05,
    0x08, 0x00, 0x02, 0x00, 0xc0, 0x00, 0x02, 0x05,
    0x09, 0x00, 0x03, 0x00, 'e', 't', 'h', '0', 0x00, 0x00, 0x00, 0x00,
};

/// RTM_NEWQDISC for ifindex 3: an etf (TCA_KIND) under 8001:1.
constexpr std::array<uint8_t, 44> NEWQDISC{
    0x2c, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x01, 0x80,
    0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 'e', 't', 'f', 0x00,
};
// clang-format on

constexpr Ipv4Octets ADDRESS{192, 0, 2, 5};

/// `message` with the octet at `at` replaced by `value`.
template <size_t N>
auto patched(std::array<uint8_t, N> message, size_t const at, uint8_t const value) -> std::array<uint8_t, N>
{
    message[at] = value;
    return message;
}

/// NEWLINK reporting `carrier` and the down count `down`.
auto link_report(bool const carrier, uint8_t const down) -> std::array<uint8_t, 60>
{
    return patched(patched(NEWLINK, 36, carrier ? 1 : 0), 44, down);
}

/// NEWADDR as an RTM_DELADDR.
auto removed_address() -> std::array<uint8_t, 52>
{
    return patched(NEWADDR, 4, 0x15);
}

/// A readiness of ifindex 3 that applied each of `messages`; false in `applied` if one was refused.
template <typename... Messages>
auto readiness_after(bool& applied, Messages const&... messages) -> LinkReadiness
{
    LinkReadiness link{3};
    applied = (link.apply(messages, 0).has_value() && ...);
    return link;
}

}  // namespace

TEST(net_link_readiness, a_newaddr_reports_its_local_address)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const added = parse_ipv4_address(NEWADDR, 3);
    EXPECT_TRUE(added && *added && **added == (Ipv4AddressChange{.added = true, .address = ADDRESS}));
    auto const removed = parse_ipv4_address(removed_address(), 3);
    EXPECT_TRUE(removed && *removed && **removed == (Ipv4AddressChange{.added = false, .address = ADDRESS}));
    auto const peer = parse_ipv4_address(patched(NEWADDR, 31, 0x09), 3);  // IFA_ADDRESS a point-to-point peer's
    EXPECT_TRUE(peer && *peer && (*peer)->address == ADDRESS);
}

TEST(net_link_readiness, other_interfaces_families_and_messages_are_none)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    auto const other = parse_ipv4_address(NEWADDR, 4);
    EXPECT_TRUE(other && !*other);
    auto const inet6 = parse_ipv4_address(patched(NEWADDR, 16, AF_INET6), 3);
    EXPECT_TRUE(inet6 && !*inet6);
    auto const link = parse_ipv4_address(NEWLINK, 3);
    EXPECT_TRUE(link && !*link);
    auto const no_address = parse_ipv4_address(patched(patched(NEWADDR, 26, 0x08), 34, 0x08), 3);  // both retyped
    EXPECT_TRUE(no_address && !*no_address);
}

TEST(net_link_readiness, a_malformed_address_message_is_refused)
{
    EXPECT_FALSE(parse_ipv4_address(patched(NEWADDR, 32, 0x06), 3).has_value());    // IFA_LOCAL of 2 octets
    EXPECT_FALSE(parse_ipv4_address(patched(NEWADDR, 40, 0x20), 3).has_value());    // overruns
    EXPECT_FALSE(parse_ipv4_address(std::span{NEWADDR}.first(36), 3).has_value());  // truncated
    EXPECT_FALSE(parse_ipv4_address(patched(NEWADDR, 0, 0x14), 3).has_value());     // shorter than ifaddrmsg
}

TEST(net_link_readiness, a_get_addresses_dumps_every_ipv4_address)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    // clang-format off
    constexpr std::array<uint8_t, 24> EXPECTED{
        0x18, 0x00, 0x00, 0x00, 0x16, 0x00, 0x01, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    std::array<uint8_t, 24> out{};
    auto const length = build_get_ipv4_addresses(out, 2);
    EXPECT_TRUE(length && *length == out.size());
    EXPECT_TRUE(out == EXPECTED);
    EXPECT_FALSE(build_get_ipv4_addresses(std::span{out}.first(16), 2).has_value());
}

TEST(net_link_readiness, a_qdisc_change_is_its_interfaces_alone)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    EXPECT_TRUE(is_qdisc_change(NEWQDISC, 3));
    EXPECT_TRUE(is_qdisc_change(patched(NEWQDISC, 4, 0x25), 3));  // RTM_DELQDISC
    EXPECT_FALSE(is_qdisc_change(NEWQDISC, 4));
    EXPECT_FALSE(is_qdisc_change(patched(NEWQDISC, 4, 0x28), 3));  // RTM_NEWTCLASS
    EXPECT_FALSE(is_qdisc_change(std::span{NEWQDISC}.first(30), 3));
}

TEST(net_link_readiness, an_adapter_reset_is_a_carrier_lost_and_regained)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto before = readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC);
    EXPECT_TRUE(applied && before.reported() && before.carrier() && before.has_ipv4() && before.last_qdisc_change_ns() == 0);
    EXPECT_FALSE(before.carrier_lost());
    auto const down = readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), removed_address());
    EXPECT_TRUE(applied && down.carrier_lost() && !down.carrier() && !down.has_ipv4());
    auto const back = readiness_after(
        applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), removed_address(), link_report(true, 8), NEWADDR);
    EXPECT_TRUE(applied && back.carrier_lost() && back.carrier() && back.has_ipv4());
}

TEST(net_link_readiness, a_loss_between_two_reports_shows_in_the_down_count)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto const cycled = readiness_after(applied, link_report(true, 7), link_report(true, 9));
    EXPECT_TRUE(applied && cycled.carrier_lost() && cycled.carrier());
    auto const never_up = readiness_after(applied, link_report(false, 7), link_report(false, 7));
    EXPECT_TRUE(applied && !never_up.carrier_lost());
}

TEST(net_link_readiness, an_address_counts_until_its_removal)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto const twice = readiness_after(applied, NEWADDR, NEWADDR, removed_address());
    EXPECT_TRUE(applied && !twice.has_ipv4());  // an update of the same address, then its removal
    auto const other = readiness_after(applied, NEWADDR, patched(removed_address(), 39, 0x06));
    EXPECT_TRUE(applied && other.has_ipv4());  // another address's removal
    auto const malformed = readiness_after(applied, NEWADDR, patched(removed_address(), 32, 0x06));
    EXPECT_TRUE(!applied && malformed.has_ipv4());
}

TEST(net_link_readiness, without_a_qdisc_change_there_is_nothing_to_wait_for)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto const link = readiness_after(applied, link_report(false, 7));
    EXPECT_TRUE(applied && reset_wait_state(link, ResetWaitPolicy{}, 0) == ResetWaitState::unchanged);
}

TEST(net_link_readiness, no_carrier_loss_within_the_settle_time_is_no_reset)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto const link = readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC);
    ResetWaitPolicy const policy{.ipv4 = true};
    EXPECT_TRUE(applied && reset_wait_state(link, policy, 0) == ResetWaitState::waiting);
    EXPECT_EQ(reset_wait_state(link, policy, 1999 * MS), ResetWaitState::waiting);
    EXPECT_EQ(reset_wait_state(link, policy, 2000 * MS), ResetWaitState::no_reset);
}

TEST(net_link_readiness, after_a_loss_the_wait_ends_with_carrier_and_address)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    ResetWaitPolicy const policy{.ipv4 = true};
    auto const down = readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), removed_address());
    EXPECT_EQ(reset_wait_state(down, policy, 5000 * MS), ResetWaitState::waiting);  // past the settle time: lost
    auto const up = readiness_after(
        applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), removed_address(), link_report(true, 8));
    EXPECT_EQ(reset_wait_state(up, policy, 5000 * MS), ResetWaitState::waiting);  // no address yet
    EXPECT_EQ(reset_wait_state(up, ResetWaitPolicy{.ipv4 = false}, 5000 * MS), ResetWaitState::ready);
    auto const back = readiness_after(
        applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), removed_address(), link_report(true, 8), NEWADDR);
    EXPECT_TRUE(applied && reset_wait_state(back, policy, 100 * MS) == ResetWaitState::ready);
}

TEST(net_link_readiness, a_link_not_back_in_time_times_out)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    ResetWaitPolicy const policy{.ipv4 = true};
    auto const down = readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8));
    EXPECT_TRUE(applied && reset_wait_state(down, policy, 29'999 * MS) == ResetWaitState::waiting);
    EXPECT_EQ(reset_wait_state(down, policy, 30'000 * MS), ResetWaitState::timed_out);
}

TEST(net_link_readiness, a_loss_before_the_last_change_does_not_count)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    auto const link =
        readiness_after(applied, link_report(true, 7), NEWADDR, NEWQDISC, link_report(false, 8), link_report(true, 8), NEWQDISC);
    ResetWaitPolicy const policy{.ipv4 = true};
    EXPECT_TRUE(applied && !link.carrier_lost());
    EXPECT_EQ(reset_wait_state(link, policy, 1000 * MS), ResetWaitState::waiting);
    EXPECT_EQ(reset_wait_state(link, policy, 2000 * MS), ResetWaitState::no_reset);
}

TEST(net_link_readiness, no_carrier_at_a_change_is_a_reset_under_way)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    bool applied = false;
    ResetWaitPolicy const policy{.ipv4 = true};
    auto const down = readiness_after(applied, link_report(true, 7), link_report(false, 8), NEWQDISC);
    EXPECT_TRUE(applied && down.carrier_lost());
    EXPECT_EQ(reset_wait_state(down, policy, 5000 * MS), ResetWaitState::waiting);
    auto const back =
        readiness_after(applied, link_report(true, 7), link_report(false, 8), NEWQDISC, link_report(true, 8), NEWADDR);
    EXPECT_TRUE(applied && reset_wait_state(back, policy, 5000 * MS) == ResetWaitState::ready);
}

TEST(net_link_readiness, the_settle_time_runs_from_the_change_as_read)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    LinkReadiness link{3};
    ResetWaitPolicy const policy{.ipv4 = true};
    EXPECT_TRUE(link.apply(link_report(true, 7), 0).has_value() && link.apply(NEWQDISC, 5000 * MS).has_value());
    EXPECT_EQ(reset_wait_state(link, policy, 6999 * MS), ResetWaitState::waiting);
    EXPECT_EQ(reset_wait_state(link, policy, 7000 * MS), ResetWaitState::no_reset);
    link.notifications_lost(8000 * MS);  // a change already seen keeps its time
    EXPECT_EQ(reset_wait_state(link, policy, 9000 * MS), ResetWaitState::no_reset);
}

TEST(net_link_readiness, lost_notifications_assume_a_change_and_keep_a_loss)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    ResetWaitPolicy const policy{.ipv4 = true};
    LinkReadiness quiet{3};
    EXPECT_TRUE(quiet.apply(link_report(true, 7), 0).has_value());
    quiet.notifications_lost(8000 * MS);  // an overrun may have hidden a change
    EXPECT_EQ(reset_wait_state(quiet, policy, 9000 * MS), ResetWaitState::waiting);
    bool applied = false;
    auto cycled = readiness_after(applied, link_report(true, 7), NEWQDISC, link_report(false, 8), link_report(true, 8));
    cycled.notifications_lost(3000 * MS);
    EXPECT_TRUE(applied && cycled.carrier_lost());
    EXPECT_EQ(reset_wait_state(cycled, policy, 4000 * MS), ResetWaitState::waiting);  // the address not back
}

TEST(net_link_readiness, apply_says_which_message_was_the_link_report)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    LinkReadiness link{3};
    auto const reported = link.apply(link_report(true, 7), 0);
    EXPECT_TRUE(reported && *reported);
    auto const address = link.apply(NEWADDR, 0);
    EXPECT_TRUE(address && !*address);
    auto const qdisc = link.apply(NEWQDISC, 0);
    EXPECT_TRUE(qdisc && !*qdisc);
    auto const other = link.apply(patched(NEWLINK, 20, 4), 0);  // ifindex 4's
    EXPECT_TRUE(other && !*other);
}

TEST(net_link_readiness, the_interface_removed_is_refused)
{
    if (!LITTLE) {
        SKIP("the messages are little-endian bytes");
    }
    LinkReadiness link{3};
    auto const removed = link.apply(patched(NEWLINK, 4, 0x11), 0);  // RTM_DELLINK
    EXPECT_TRUE(!removed && removed.error() == std::make_error_code(std::errc::no_such_device));
}

TEST(net_link_readiness, the_watch_reads_loopback_and_finds_nothing_to_wait_for)
{
    // Host-dependent: skipped where NETLINK_ROUTE is unavailable. Loopback (ifindex 1) has a carrier and 127.0.0.1.
    LinkWatch watch{1};
    if (!watch.open().has_value()) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    EXPECT_TRUE(watch.read(monotonic_ns()).has_value());
    if (!watch.readiness().carrier() || !watch.readiness().has_ipv4()) {
        SKIP("loopback is down here (a fresh network namespace)");
    }
    EXPECT_TRUE(watch.readiness().reported());
    auto const state = await_reset(watch, ResetWaitPolicy{});
    EXPECT_TRUE(state && *state == ResetWaitState::unchanged);
}

TEST(net_link_readiness, a_link_the_kernel_does_not_know_is_refused)
{
    LinkWatch watch{0x7FFFFFF0};
    if (!watch.open().has_value()) {
        SKIP("NETLINK_ROUTE is not available here");
    }
    EXPECT_FALSE(watch.read(0).has_value());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_link_readiness_test)
