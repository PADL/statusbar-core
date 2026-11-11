// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Launch time on an AF_XDP socket: the UMEM's TX metadata, and the per-frame
/// time written into it.
///
/// What cannot be tested here is the only thing that finally matters: whether
/// a NIC honours the time. That needs an igc (or another driver with
/// launch-time offload) and root, and no machine in this tree has one. What is
/// testable without hardware is everything that silently does nothing when it
/// is wrong — the metadata length the UMEM is registered with, the flag in the
/// descriptor, and the bytes of the metadata itself.

#include "statusbar/net/net_linux_xdp.hpp"
#include "statusbar/test/test.hpp"

#if defined(__linux__) && defined(HAVE_XDP)
#    include <array>
#    include <cstring>

#    include <linux/genetlink.h>
#    include <linux/netlink.h>
#    include <net/if.h>
#endif

#include <cstdint>

using namespace statusbar;
using namespace statusbar::net;

TEST(xdp_launch_time, a_config_does_not_ask_for_launch_time_unless_told_to)
{
    XdpConfig config{};
    EXPECT_FALSE(config.tx_launch_time);
}

TEST(xdp_launch_time, the_error_for_a_kernel_without_tx_metadata_is_its_own)
{
    auto const error = make_error_code(XdpError::tx_metadata_not_supported);
    EXPECT_TRUE(error != make_error_code(XdpError::not_supported_on_platform));
    EXPECT_FALSE(error.message().empty());
    EXPECT_TRUE(error.message() != std::string{"Unknown XDP error"});
}

// A closed context has no socket to time frames on, and the checked form
// must say so rather than write into a UMEM that is not there.
TEST(xdp_launch_time, a_closed_context_refuses_to_set_a_launch_time)
{
    XdpContext context;
    EXPECT_FALSE(context.tx_launch_time());
    auto const set = context.try_tx_set_launch_time(0, 1'000);
    EXPECT_FALSE(set.has_value());
    if (!set) {
#if defined(__linux__) && defined(HAVE_XDP)
        EXPECT_EQ(set.error(), make_error_code(XdpError::not_open));
#else
        // The stub has no socket to be closed; it says so in its own words.
        EXPECT_EQ(set.error(), make_error_code(XdpError::not_supported_on_platform));
#endif
    }
}

// The silent form is a statement on a commit path: it takes the same refusal
// without an answer to drop, and the context is as closed afterwards as before.
TEST(xdp_launch_time, the_silent_form_swallows_the_refusal_of_a_closed_context)
{
    XdpContext context;
    context.tx_set_launch_time(0, 1'000);
    EXPECT_FALSE(context.valid());
    EXPECT_FALSE(context.tx_launch_time());
}

// The probe is what open() consults, so it must give a definite answer on
// this host rather than throw or hang: either support, or a reason.
TEST(xdp_launch_time, the_tx_metadata_probe_answers_one_way_or_the_other)
{
    auto const probed = probe_tx_metadata();
    if (!probed) {
        // Unprivileged, or a kernel or libxdp without it. All are reasons.
        EXPECT_FALSE(probed.error().message().empty());
    }
}

// Counters are a soak readout; a run that has been going for days needs them
// zeroed without losing the socket.
TEST(xdp_launch_time, stats_can_be_reset_on_a_closed_context)
{
    XdpContext context;
    context.reset_stats();
    EXPECT_EQ(context.socket_stats().tx_count, uint64_t{0});
}

// Loopback never times a frame, on any kernel: the probe says so, and says it
// as the launch-time refusal rather than as a transport error. A kernel with
// no netdev family to ask (before 6.6) gives the same answer.
TEST(xdp_launch_time, loopback_has_no_launch_time_and_the_probe_says_so)
{
#if defined(__linux__) && defined(HAVE_XDP)
    auto const lo = ::if_nametoindex("lo");
    EXPECT_TRUE(lo > 0);
    auto const probed = probe_tx_launch_time(lo);
    EXPECT_FALSE(probed.has_value());
    if (!probed) {
        EXPECT_EQ(probed.error(), make_error_code(XdpError::launch_time_not_supported));
    }
#else
    auto const probed = probe_tx_launch_time(1);
    EXPECT_FALSE(probed.has_value());
    if (!probed) {
        EXPECT_EQ(probed.error(), make_error_code(XdpError::not_supported_on_platform));
    }
#endif
}

#if defined(__linux__) && defined(HAVE_XDP)

namespace {

/// A one-message generic-netlink reply holding one attribute of `value`.
template <typename Value>
[[nodiscard]] auto genl_reply(std::uint16_t const type, std::uint8_t const cmd, std::uint16_t const attribute, Value const value)
    -> std::array<std::uint8_t, 64>
{
    std::array<std::uint8_t, 64> bytes{};
    nlattr const attr{.nla_len = static_cast<std::uint16_t>(NLA_HDRLEN + sizeof(value)), .nla_type = attribute};
    nlmsghdr const nlh{
        .nlmsg_len = static_cast<std::uint32_t>(NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(attr.nla_len)),
        .nlmsg_type = type,
        .nlmsg_flags = 0,
        .nlmsg_seq = 1,
        .nlmsg_pid = 0};
    genlmsghdr const genl{.cmd = cmd, .version = 1, .reserved = 0};
    std::memcpy(bytes.data(), &nlh, sizeof(nlh));
    std::memcpy(bytes.data() + NLMSG_HDRLEN, &genl, sizeof(genl));
    std::memcpy(bytes.data() + NLMSG_HDRLEN + GENL_HDRLEN, &attr, sizeof(attr));
    std::memcpy(bytes.data() + NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN, &value, sizeof(value));
    return bytes;
}

}  // namespace

// The two replies the probe reads, built as the kernel lays them out.
TEST(xdp_launch_time, the_genetlink_replies_are_read_as_the_kernel_lays_them_out)
{
    auto const family = genl_reply(GENL_ID_CTRL, CTRL_CMD_NEWFAMILY, CTRL_ATTR_FAMILY_ID, std::uint16_t{0x1c});
    EXPECT_EQ(detail::genl_family_id_in(family), std::optional<std::uint16_t>{0x1c});
    // Wrong attribute, and a reply cut short of its own length.
    EXPECT_EQ(detail::xsk_features_in(family), std::nullopt);
    EXPECT_EQ(detail::genl_family_id_in(std::span<std::uint8_t const>{family.data(), 20}), std::nullopt);

    constexpr std::uint16_t NETDEV_FAMILY = 0x1c;
    constexpr std::uint8_t NETDEV_CMD_DEV_GET_REPLY = 1;
    constexpr std::uint16_t NETDEV_A_DEV_XSK_FEATURES_ATTR = 6;
    auto const features = genl_reply(NETDEV_FAMILY, NETDEV_CMD_DEV_GET_REPLY, NETDEV_A_DEV_XSK_FEATURES_ATTR, std::uint64_t{7});
    EXPECT_EQ(detail::xsk_features_in(features), std::optional<std::uint64_t>{7});
    EXPECT_EQ(detail::genl_family_id_in(features), std::nullopt);
    // A refusal carries no attributes at all.
    std::array<std::uint8_t, 64> refusal{};
    nlmsghdr const nlh{.nlmsg_len = NLMSG_HDRLEN + 20, .nlmsg_type = NLMSG_ERROR, .nlmsg_flags = 0, .nlmsg_seq = 1, .nlmsg_pid = 0};
    std::memcpy(refusal.data(), &nlh, sizeof(nlh));
    EXPECT_EQ(detail::xsk_features_in(refusal), std::nullopt);
}

#endif  // __linux__ && HAVE_XDP

TEST_MAIN(statusbar_net, net_xdp_launch_time_test)
