// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for the RawnetContext receive filters: the exact cBPF bytecode, run
/// through cbpf::interpret on untagged and 802.1Q-tagged frames, and (on
/// Linux, with CAP_NET_RAW) the kernel's view on the loopback interface.

#include "statusbar/net/net_rawnet_filter.hpp"

#include "statusbar/net/net_cbpf_emit.hpp"
#include "statusbar/net/net_rawnet.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#if defined(__linux__)
#    include <poll.h>

#    include <sys/ioctl.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr std::uint16_t AVTP = 0x22F0;
constexpr std::array<std::uint8_t, 3> ATDECC_SUBTYPES{0xFA, 0xFB, 0xFC};
constexpr std::array<std::uint8_t, 3> STREAM_SUBTYPES{0x00, 0x02, 0x04};

/// A frame of @p ethertype whose payload starts with @p subtype, optionally
/// under one 802.1Q tag; padded to the Ethernet minimum.
auto make_frame(std::uint16_t const ethertype, std::uint8_t const subtype, bool const tagged) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> f(12, 0x11);
    if (tagged) {
        f.insert(f.end(), {0x81, 0x00, 0x60, 0x02});  // PCP 3, VID 2
    }
    f.push_back(static_cast<std::uint8_t>(ethertype >> 8));
    f.push_back(static_cast<std::uint8_t>(ethertype & 0xFF));
    f.push_back(subtype);
    f.resize(60, 0);
    return f;
}

auto run(rawnet_filter::Program const& p, std::vector<std::uint8_t> const& frame) -> std::uint32_t
{
    return cbpf::interpret(p.instructions(), frame);
}

}  // namespace

TEST(rawnet_filter, ethertype_filter_bytecode)
{
    // Byte for byte the program RawnetContext::open has always attached.
    std::array<cbpf::Instruction, 7> const expected{{
        {0x28, 0, 0, 12},
        {0x15, 4, 0, AVTP},
        {0x15, 0, 2, 0x8100},
        {0x28, 0, 0, 16},
        {0x15, 1, 0, AVTP},
        {0x06, 0, 0, 0},
        {0x06, 0, 0, 0xFFFFFFFFU},
    }};
    auto const p = rawnet_filter::ethertype_filter(AVTP);
    EXPECT_EQ(p.length, expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_TRUE(p.code[i] == expected[i]);
    }
}

TEST(rawnet_filter, subtype_filter_bytecode)
{
    std::array<cbpf::Instruction, 13> const expected{{
        {0x28, 0, 0, 12},           // 0: ldh [12]
        {0x15, 5, 0, AVTP},         // 1: untagged -> 7
        {0x15, 0, 8, 0x8100},       // 2: tagged -> 3, else drop (11)
        {0x28, 0, 0, 16},           // 3: ldh [16]
        {0x15, 0, 6, AVTP},         // 4: else drop (11)
        {0x30, 0, 0, 18},           // 5: ldb [18]
        {0x05, 0, 0, 1},            // 6: ja 8
        {0x30, 0, 0, 14},           // 7: ldb [14]
        {0x15, 3, 0, 0xFA},         // 8: -> accept (12)
        {0x15, 2, 0, 0xFB},         // 9: -> accept (12)
        {0x15, 1, 0, 0xFC},         // 10: -> accept (12), else drop (11)
        {0x06, 0, 0, 0},            // 11: drop
        {0x06, 0, 0, 0xFFFFFFFFU},  // 12: accept
    }};
    auto const p = rawnet_filter::subtype_filter(AVTP, ATDECC_SUBTYPES);
    EXPECT_EQ(p.length, expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_TRUE(p.code[i] == expected[i]);
    }
}

TEST(rawnet_filter, single_subtype_bytecode)
{
    std::array<std::uint8_t, 1> const maap{0xFE};
    auto const p = rawnet_filter::subtype_filter(AVTP, maap);
    EXPECT_EQ(p.length, 11u);
    EXPECT_TRUE(p.code[2] == (cbpf::Instruction{0x15, 0, 6, 0x8100}));
    EXPECT_TRUE(p.code[4] == (cbpf::Instruction{0x15, 0, 4, AVTP}));
    EXPECT_TRUE(p.code[8] == (cbpf::Instruction{0x15, 1, 0, 0xFE}));
    EXPECT_TRUE(p.code[9] == (cbpf::Instruction{0x06, 0, 0, 0}));
    EXPECT_TRUE(p.code[10] == (cbpf::Instruction{0x06, 0, 0, 0xFFFFFFFFU}));
}

TEST(rawnet_filter, empty_or_oversized_set_is_the_ethertype_filter)
{
    auto const plain = rawnet_filter::ethertype_filter(AVTP);
    std::array<std::uint8_t, rawnet_filter::MAX_SUBTYPES + 1> too_many{};
    for (auto const& p : {rawnet_filter::subtype_filter(AVTP, {}), rawnet_filter::subtype_filter(AVTP, too_many)}) {
        EXPECT_EQ(p.length, plain.length);
        for (std::size_t i = 0; i < plain.length; ++i) {
            EXPECT_TRUE(p.code[i] == plain.code[i]);
        }
    }
    std::array<std::uint8_t, rawnet_filter::MAX_SUBTYPES> most{};
    EXPECT_EQ(rawnet_filter::subtype_filter(AVTP, most).length, 10 + rawnet_filter::MAX_SUBTYPES);
}

TEST(rawnet_filter, control_filter_accepts_only_atdecc)
{
    auto const p = rawnet_filter::subtype_filter(AVTP, ATDECC_SUBTYPES);
    for (bool const tagged : {false, true}) {
        for (std::uint8_t const s : ATDECC_SUBTYPES) {
            EXPECT_EQ(run(p, make_frame(AVTP, s, tagged)), rawnet_filter::ACCEPT);
        }
        for (std::uint8_t const s : {0x00, 0x02, 0x04, 0xFE, 0xFD, 0x7A}) {
            EXPECT_EQ(run(p, make_frame(AVTP, static_cast<std::uint8_t>(s), tagged)), rawnet_filter::DROP);
        }
        EXPECT_EQ(run(p, make_frame(0x88F7, 0xFA, tagged)), rawnet_filter::DROP);
    }
}

TEST(rawnet_filter, stream_filter_accepts_only_streams)
{
    auto const p = rawnet_filter::subtype_filter(AVTP, STREAM_SUBTYPES);
    for (bool const tagged : {false, true}) {
        for (std::uint8_t const s : STREAM_SUBTYPES) {
            EXPECT_EQ(run(p, make_frame(AVTP, s, tagged)), rawnet_filter::ACCEPT);
        }
        for (std::uint8_t const s : {0xFA, 0xFB, 0xFC, 0xFE, 0x03}) {
            EXPECT_EQ(run(p, make_frame(AVTP, static_cast<std::uint8_t>(s), tagged)), rawnet_filter::DROP);
        }
    }
    // The tag's own bytes are not mistaken for the subtype: a tagged frame
    // whose TCI low byte is a stream subtype but whose subtype is ADP.
    auto f = make_frame(AVTP, 0xFA, true);
    f[15] = 0x02;
    EXPECT_EQ(run(p, f), rawnet_filter::DROP);
}

TEST(rawnet_filter, ethertype_filter_ignores_subtype)
{
    auto const p = rawnet_filter::ethertype_filter(AVTP);
    for (bool const tagged : {false, true}) {
        EXPECT_EQ(run(p, make_frame(AVTP, 0x02, tagged)), rawnet_filter::ACCEPT);
        EXPECT_EQ(run(p, make_frame(AVTP, 0xFA, tagged)), rawnet_filter::ACCEPT);
        EXPECT_EQ(run(p, make_frame(0x0800, 0xFA, tagged)), rawnet_filter::DROP);
    }
}

TEST(rawnet_filter, truncated_frame_is_dropped)
{
    auto const p = rawnet_filter::subtype_filter(AVTP, ATDECC_SUBTYPES);
    auto f = make_frame(AVTP, 0xFA, false);
    f.resize(14);  // no subtype byte
    EXPECT_EQ(run(p, f), rawnet_filter::DROP);
}

#if defined(__linux__)

namespace {

auto queued_bytes(int const fd) -> int
{
    int n = -1;
    (void)::ioctl(fd, FIONREAD, &n);
    return n;
}

/// Drain @p ctx, waiting up to 200 ms for the first frame; @return the
/// subtype of each frame received.
auto drain(RawnetContext& ctx) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> subtypes;
    std::array<std::uint8_t, 1600> buf{};
    pollfd pfd{.fd = ctx.fd(), .events = POLLIN, .revents = 0};
    (void)::poll(&pfd, 1, 200);
    while (true) {
        auto const r = ctx.recv(nullptr, nullptr, buf);
        if (!r || *r <= 0) {
            break;
        }
        subtypes.push_back(buf[0]);
    }
    return subtypes;
}

}  // namespace

// Needs CAP_NET_RAW (e.g. `unshare -r -n` with lo up); without it the
// sockets cannot be opened and the test has nothing to check.
TEST(rawnet_filter, loopback_transmit_only_and_subtype_filter)
{
    RawnetContext tx;
    if (!tx.open("lo", AVTP, nullptr, false, /*transmit_only=*/true)) {
        std::println("  (skipped: no CAP_NET_RAW or no lo)");
        return;
    }
    // A transmit-only socket refuses what would hook it into delivery.
    ieee::Eui48 const dest{0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00};
    EXPECT_FALSE(tx.join_multicast(dest).has_value());
    EXPECT_FALSE(tx.set_subtype_filter(ATDECC_SUBTYPES).has_value());

    // Joining binds the receivers to lo: they hear no other interface.
    RawnetContext all;
    RawnetContext control;
    EXPECT_TRUE(all.open("lo", AVTP, &dest).has_value());
    EXPECT_TRUE(control.open("lo", AVTP, &dest).has_value());
    EXPECT_TRUE(control.set_subtype_filter(ATDECC_SUBTYPES).has_value());
    (void)drain(all);  // anything queued before the subtype filter
    (void)drain(control);

    std::array<std::uint8_t, 46> aaf{0x02};
    std::array<std::uint8_t, 46> adp{0xFA};
    EXPECT_TRUE(tx.send(&dest, aaf).has_value());
    EXPECT_TRUE(tx.send(&dest, adp).has_value());
    EXPECT_TRUE(tx.send_vlan(&dest, aaf, 2, 3).has_value());
    EXPECT_TRUE(tx.send_vlan(&dest, adp, 2, 3).has_value());

    auto const seen_all = drain(all);
    auto const seen_control = drain(control);
    // The unfiltered socket hears every frame (lo delivers each twice: the
    // egress tap and the receive path).
    EXPECT_TRUE(seen_all.size() >= 4);
    std::size_t adp_count = 0;
    for (auto const s : seen_control) {
        EXPECT_EQ(s, 0xFA);
        adp_count += s == 0xFA ? 1U : 0U;
    }
    EXPECT_TRUE(adp_count >= 2);

    // The transmit-only socket was handed none of them.
    EXPECT_EQ(queued_bytes(tx.fd()), 0);
    std::array<std::uint8_t, 1600> buf{};
    auto const r = tx.recv(nullptr, nullptr, buf);
    EXPECT_FALSE(r.has_value());

    // An empty set restores the ethertype-only filter.
    EXPECT_TRUE(control.set_subtype_filter({}).has_value());
    EXPECT_TRUE(tx.send(&dest, aaf).has_value());
    auto const after = drain(control);
    EXPECT_TRUE(!after.empty());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_rawnet_filter_test)
