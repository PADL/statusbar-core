// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The netlink framing against bytes laid out by hand from linux/netlink.h
// (host byte order: the vectors are little-endian), and netlink::Socket
// against the kernel's RTM_GETLINK, which needs no privilege.

#include "statusbar/net/net_netlink.hpp"

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#if defined(__linux__)
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>
#endif

using namespace statusbar;
using namespace statusbar::net;

namespace {

constexpr bool LITTLE = std::endian::native == std::endian::little;

auto same_bytes(std::span<uint8_t const> const got, std::span<uint8_t const> const want) -> bool
{
    if (got.size() != want.size()) {
        return false;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            return false;
        }
    }
    return true;
}

// clang-format off
/// NLMSG_ERROR for a 20-octet request (seq 5), -EINVAL, capped, with the extended
/// ack "bad attr" (NLMSGERR_ATTR_MSG): 16 header + 20 nlmsgerr + 16 attribute.
constexpr std::array<uint8_t, 52> REFUSAL_CAPPED{
    0x34, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0xea, 0xff, 0xff, 0xff,                                                                          // -EINVAL
    0x14, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // the request's header
    0x0d, 0x00, 0x01, 0x00, 'b', 'a', 'd', ' ', 'a', 't', 't', 'r', 0x00, 0x00, 0x00, 0x00,          // NLMSGERR_ATTR_MSG
};
/// The same refusal with the 20-octet request echoed in full (not capped): the
/// attribute follows the request's 4 payload octets.
constexpr std::array<uint8_t, 56> REFUSAL_ECHOED{
    0x38, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0xea, 0xff, 0xff, 0xff,
    0x14, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd,                                                                          // the request's payload
    0x0d, 0x00, 0x01, 0x00, 'b', 'a', 'd', ' ', 'a', 't', 't', 'r', 0x00, 0x00, 0x00, 0x00,
};
/// A plain acknowledgement: error 0, the request's header, nothing else.
constexpr std::array<uint8_t, 36> ACK{
    0x24, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
/// NLMSG_DONE ending a dump: complete (0), then one carrying -ENOSPC.
constexpr std::array<uint8_t, 20> DONE{
    0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
constexpr std::array<uint8_t, 20> DONE_ENOSPC{
    0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0xe4, 0xff, 0xff, 0xff,
};
/// Three attributes: a u32 (type 1), a string "lo" (type 3, padded), a nested
/// one (type 2 | NLA_F_NESTED) holding a u16.
constexpr std::array<uint8_t, 28> ATTRIBUTES{
    0x08, 0x00, 0x01, 0x00, 0x2a, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x03, 0x00, 'l', 'o', 0x00, 0x00,
    0x0a, 0x00, 0x02, 0x80, 0x06, 0x00, 0x09, 0x00, 0x07, 0x00, 0x00, 0x00,
};
// clang-format on

}  // namespace

TEST(netlink_framing, alignment_and_sizes)
{
    EXPECT_EQ(netlink::align4(0), size_t{0});
    EXPECT_EQ(netlink::align4(1), size_t{4});
    EXPECT_EQ(netlink::align4(4), size_t{4});
    EXPECT_EQ(netlink::align4(5), size_t{8});
    EXPECT_EQ(netlink::attribute_size(0), size_t{4});
    EXPECT_EQ(netlink::attribute_size(2), size_t{8});
    EXPECT_EQ(netlink::attribute_size(4), size_t{8});
    EXPECT_EQ(netlink::attribute_size(5), size_t{12});
    EXPECT_TRUE(netlink::transient_error(EAGAIN) && netlink::transient_error(ENOBUFS) && netlink::transient_error(EINTR));
    EXPECT_FALSE(netlink::transient_error(ENOENT) || netlink::transient_error(0));
}

TEST(netlink_framing, a_header_and_attributes_written_read_back)
{
    if (!LITTLE) {
        SKIP("the expected bytes are little-endian");
    }
    // clang-format off
    constexpr std::array<uint8_t, 32> want{
        0x20, 0x00, 0x00, 0x00, 0x12, 0x00, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x2a, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x03, 0x00, 'l', 'o', 0x00, 0x00,
    };
    // clang-format on
    std::array<uint8_t, 64> out{};
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    constexpr size_t LENGTH = netlink::MESSAGE_HEADER + netlink::attribute_size(4) + netlink::attribute_size(3);
    netlink::put_header(b, LENGTH, 0x12, netlink::FLAG_REQUEST | netlink::FLAG_ACK, 9);
    uint32_t const answer = 42;
    netlink::put_attribute(b, 1, make_const_span(answer));
    netlink::put_attribute(b, 3, make_const_span(std::string_view{"lo\0", 3}));
    auto const length = netlink::finish(b, LENGTH);
    EXPECT_TRUE(length.has_value());
    EXPECT_TRUE(length && same_bytes(std::span{out}.first(*length), want));
    EXPECT_EQ(netlink::load<uint32_t>(want, netlink::OFFSET_LENGTH), uint32_t{32});
    EXPECT_EQ(netlink::load<uint16_t>(want, netlink::OFFSET_TYPE), uint16_t{0x12});
    EXPECT_EQ(netlink::load<uint32_t>(want, netlink::OFFSET_SEQUENCE), uint32_t{9});
}

TEST(netlink_framing, finish_refuses_a_short_buffer_and_a_wrong_length)
{
    std::array<uint8_t, 8> out{};
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, netlink::MESSAGE_HEADER, 0x12, netlink::FLAG_REQUEST, 1);
    EXPECT_FALSE(netlink::finish(b, netlink::MESSAGE_HEADER).has_value());
    std::array<uint8_t, 64> room{};
    MutableBuffer buffer2{room};
    BufferSerializerBuilder b2{buffer2};
    netlink::put_header(b2, netlink::MESSAGE_HEADER + 4, 0x12, netlink::FLAG_REQUEST, 1);
    auto const wrong = netlink::finish(b2, netlink::MESSAGE_HEADER + 4);
    EXPECT_TRUE(!wrong && wrong.error() == std::errc::message_size);
    EXPECT_TRUE(netlink::finish(b2, netlink::MESSAGE_HEADER).has_value());
}

TEST(netlink_framing, attributes_are_walked_found_and_masked)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    std::vector<uint16_t> types;
    std::vector<size_t> sizes;
    auto const walked = netlink::walk_attributes(ATTRIBUTES, [&](uint16_t const type, std::span<uint8_t const> const payload) {
        types.push_back(type);
        sizes.push_back(payload.size());
        return success();
    });
    EXPECT_TRUE(walked.has_value());
    EXPECT_EQ(types.size(), size_t{3});
    EXPECT_TRUE(types.size() == 3 && types[0] == 1 && types[1] == 3 && types[2] == 0x8002);
    EXPECT_TRUE(sizes.size() == 3 && sizes[0] == 4 && sizes[1] == 3 && sizes[2] == 6);
    auto const name = netlink::find_attribute(ATTRIBUTES, 3);
    EXPECT_TRUE(name && *name && (**name).size() == 3);
    EXPECT_TRUE(name && *name && netlink::without_trailing_nuls(**name).size() == 2);
    auto const nested = netlink::find_attribute(ATTRIBUTES, 2);  // found through NLA_F_NESTED
    EXPECT_TRUE(nested && *nested && (**nested).size() == 6);
    auto const inner = netlink::find_attribute(**nested, 9);
    EXPECT_TRUE(inner && *inner && netlink::load<uint16_t>(**inner, 0) == 7);
    auto const absent = netlink::find_attribute(ATTRIBUTES, 4);
    EXPECT_TRUE(absent && !*absent);
}

TEST(netlink_framing, a_malformed_attribute_stops_the_walk_and_a_refusal_is_the_result)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    auto overrun = ATTRIBUTES;
    overrun[8] = 0x20;  // the string claims 32 octets
    auto const walked = netlink::walk_attributes(overrun, [](uint16_t, std::span<uint8_t const>) { return success(); });
    EXPECT_TRUE(!walked && walked.error() == std::errc::bad_message);
    EXPECT_FALSE(netlink::find_attribute(overrun, 2).has_value());  // the bad one lies before it
    EXPECT_TRUE(netlink::find_attribute(overrun, 1).has_value());   // the first is before the bad one
    auto tiny = ATTRIBUTES;
    tiny[0] = 0x02;  // shorter than its header
    EXPECT_FALSE(netlink::find_attribute(tiny, 1).has_value());
    int visited = 0;
    auto const refused = netlink::walk_attributes(ATTRIBUTES, [&](uint16_t, std::span<uint8_t const>) -> Status {
        ++visited;
        return failure(std::make_error_code(std::errc::invalid_argument));
    });
    EXPECT_TRUE(!refused && refused.error() == std::errc::invalid_argument);
    EXPECT_EQ(visited, 1);
    EXPECT_TRUE(netlink::walk_attributes(std::span<uint8_t const>{}, [](uint16_t, std::span<uint8_t const>) {
                    return success();
                }).has_value());
}

TEST(netlink_framing, messages_are_walked_each_cut_to_its_length)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    std::vector<uint8_t> datagram(DONE.begin(), DONE.end());
    datagram.insert(datagram.end(), ACK.begin(), ACK.end());
    std::vector<size_t> lengths;
    auto const result = netlink::walk_messages(datagram, [&](std::span<uint8_t const> const message) -> std::optional<Status> {
        lengths.push_back(message.size());
        return std::nullopt;
    });
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(lengths.size() == 2 && lengths[0] == 20 && lengths[1] == 36);
    auto const first = netlink::walk_messages(datagram, [](std::span<uint8_t const>) -> std::optional<Status> {
        return failure(std::make_error_code(std::errc::operation_canceled));
    });
    EXPECT_TRUE(first && !*first && first->error() == std::errc::operation_canceled);
    auto cut = datagram;
    cut[0] = 0x40;  // the first message claims 64 octets of 56
    auto const overrun =
        netlink::walk_messages(cut, [](std::span<uint8_t const>) -> std::optional<Status> { return std::nullopt; });
    EXPECT_TRUE(overrun && !*overrun && overrun->error() == std::errc::bad_message);
    cut[0] = 0x08;  // shorter than a header
    auto const tiny = netlink::walk_messages(cut, [](std::span<uint8_t const>) -> std::optional<Status> { return std::nullopt; });
    EXPECT_TRUE(tiny && !*tiny);
    std::array<uint8_t, 10> trailing{};  // less than a header: nothing to visit, nothing wrong
    EXPECT_FALSE(
        netlink::walk_messages(trailing, [](std::span<uint8_t const>) -> std::optional<Status> { return success(); }).has_value());
}

TEST(netlink_framing, an_ack_is_success_and_a_refusal_carries_its_errno_and_reason)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    std::string text;
    auto const acked = netlink::ack_status(ACK, netlink::FLAG_CAPPED, 20, text);
    EXPECT_TRUE(acked.has_value());
    EXPECT_TRUE(text.empty());
    auto const capped = netlink::ack_status(REFUSAL_CAPPED, netlink::FLAG_CAPPED | netlink::FLAG_ACK_TLVS, 20, text);
    EXPECT_TRUE(!capped && capped.error() == std::errc::invalid_argument);
    EXPECT_EQ(text, std::string{"bad attr"});
    text.clear();
    auto const echoed = netlink::ack_status(REFUSAL_ECHOED, netlink::FLAG_ACK_TLVS, 20, text);
    EXPECT_TRUE(!echoed && echoed.error() == std::errc::invalid_argument);
    EXPECT_EQ(text, std::string{"bad attr"});
    text.clear();
    // Without FLAG_ACK_TLVS the kernel gave no attributes: nothing is read past the nlmsgerr.
    auto const plain = netlink::ack_status(REFUSAL_CAPPED, netlink::FLAG_CAPPED, 20, text);
    EXPECT_TRUE(!plain && plain.error() == std::errc::invalid_argument);
    EXPECT_TRUE(text.empty());
    // Echoed but read as capped: the attribute search starts inside the echoed payload and finds nothing sensible.
    auto const misread = netlink::ack_status(REFUSAL_ECHOED, netlink::FLAG_ACK_TLVS | netlink::FLAG_CAPPED, 20, text);
    EXPECT_TRUE(!misread && misread.error() == std::errc::invalid_argument);
    EXPECT_TRUE(text.empty());
}

TEST(netlink_framing, a_truncated_ack_a_done_and_the_end_of_a_request)
{
    if (!LITTLE) {
        SKIP("the vectors are little-endian");
    }
    std::string text;
    auto const truncated = netlink::ack_status(std::span{ACK}.first(30), 0, 20, text);
    EXPECT_TRUE(!truncated && truncated.error() == std::errc::bad_message);
    auto cut_reason = REFUSAL_CAPPED;
    cut_reason[36] = 0x40;  // the reason claims more than is there: ignored, the errno still counts
    auto const no_reason = netlink::ack_status(cut_reason, netlink::FLAG_CAPPED | netlink::FLAG_ACK_TLVS, 20, text);
    EXPECT_TRUE(!no_reason && no_reason.error() == std::errc::invalid_argument);
    EXPECT_TRUE(text.empty());
    EXPECT_TRUE(netlink::dump_status(DONE).has_value());
    EXPECT_TRUE(netlink::dump_status(std::span{DONE}.first(16)).has_value());  // a bare NLMSG_DONE
    auto const enospc = netlink::dump_status(DONE_ENOSPC);
    EXPECT_TRUE(!enospc && enospc.error() == std::errc::no_space_on_device);
    auto const end = netlink::end_status(ACK, netlink::TYPE_ERROR, netlink::FLAG_CAPPED, 20, text);
    EXPECT_TRUE(end && end->has_value());
    auto const done = netlink::end_status(DONE_ENOSPC, netlink::TYPE_DONE, netlink::FLAG_MULTI, 20, text);
    EXPECT_TRUE(done && !*done);
    EXPECT_FALSE(netlink::end_status(ACK, netlink::TYPE_MIN_FAMILY, 0, 20, text).has_value());
}

TEST(netlink_framing, trailing_nuls_are_dropped_and_only_those)
{
    constexpr std::array<uint8_t, 6> padded{'l', 'o', 0x00, 0x00, 0x00, 0x00};
    constexpr std::array<uint8_t, 4> inner{'a', 0x00, 'b', 0x00};
    constexpr std::array<uint8_t, 3> nuls{0x00, 0x00, 0x00};
    EXPECT_EQ(netlink::without_trailing_nuls(padded).size(), size_t{2});
    EXPECT_EQ(netlink::without_trailing_nuls(inner).size(), size_t{3});
    EXPECT_EQ(netlink::without_trailing_nuls(nuls).size(), size_t{0});
    EXPECT_EQ(netlink::without_trailing_nuls(std::span<uint8_t const>{}).size(), size_t{0});
}

#if defined(__linux__)

#endif  // __linux__

TEST_MAIN(statusbar_net, net_netlink_test)
