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

auto write_small_file(char const* path, char const* text) -> bool
{
    int const fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    auto const written = ::write(fd, text, std::strlen(text));
    ::close(fd);
    return written == static_cast<ssize_t>(std::strlen(text));
}

/// Move into a new user namespace and a new network namespace.
///
/// The user namespace is what supplies CAP_NET_ADMIN, and it only grants
/// it over namespaces created with or after it — hence both at once. The
/// uid and gid mappings are not needed for the capability, only to keep
/// the child's own identity sane, so a failure to write them is ignored.
[[nodiscard]] auto enter_private_namespaces() -> bool
{
    auto const uid = ::getuid();
    auto const gid = ::getgid();
    if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return false;
    }
    std::array<char, 32> mapping{};
    (void)write_small_file("/proc/self/setgroups", "deny");
    (void)std::snprintf(mapping.data(), mapping.size(), "0 %u 1", uid);
    (void)write_small_file("/proc/self/uid_map", mapping.data());
    (void)std::snprintf(mapping.data(), mapping.size(), "0 %u 1", gid);
    (void)write_small_file("/proc/self/gid_map", mapping.data());
    return true;
}

template <typename Report>
struct Envelope
{
    bool entered{false};
    Report report{};
};

auto read_fully(int fd, void* into, std::size_t size) -> bool
{
    std::size_t have = 0;
    while (have < size) {
        auto const got = ::read(fd, static_cast<std::uint8_t*>(into) + have, size - have);
        if (got <= 0) {
            return false;
        }
        have += static_cast<std::size_t>(got);
    }
    return true;
}

/// Run `fill` in a child with its own user and network namespace, and
/// bring back what it saw.
///
/// `unshare(CLONE_NEWUSER)` requires a single-threaded process, and a
/// child of `fork()` is single-threaded however many threads the parent
/// has — so the fork is not only for isolation.
///
/// nullopt means namespaces are unavailable, which is a skip and not a
/// failure: a kernel built without user namespaces, or a sysctl that
/// forbids them, is a legitimate place to run the suite.
template <typename Report>
[[nodiscard]] auto in_private_netns(void (*fill)(Report&)) -> std::optional<Report>
{
    std::array<int, 2> ends{-1, -1};
    if (::pipe(ends.data()) != 0) {
        return std::nullopt;
    }
    pid_t const child = ::fork();
    if (child < 0) {
        ::close(ends[0]);
        ::close(ends[1]);
        return std::nullopt;
    }
    if (child == 0) {
        ::close(ends[0]);
        Envelope<Report> envelope{};
        envelope.entered = enter_private_namespaces();
        if (envelope.entered) {
            fill(envelope.report);
        }
        (void)::write(ends[1], &envelope, sizeof(envelope));
        ::_exit(0);
    }
    ::close(ends[1]);
    Envelope<Report> envelope{};
    bool const whole = read_fully(ends[0], &envelope, sizeof(envelope));
    ::close(ends[0]);
    int status = 0;
    (void)::waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        std::printf("  the namespace child died on signal %d\n", WTERMSIG(status));
    }
    if (!whole || !envelope.entered) {
        return std::nullopt;
    }
    return envelope.report;
}

/// Say out loud that a namespace test could not run. A silent skip reads
/// exactly like a pass in the runner's output, which is how a test that
/// needs something stops being run at all.
auto skip_no_namespaces(char const* test_name) -> void
{
    std::printf("  SKIP: %s needs user namespaces (unshare(CLONE_NEWUSER|CLONE_NEWNET) refused)\n", test_name);
}

// ---------------------------------------------------------------------------
// Scaffolding for the namespace tests.
// ---------------------------------------------------------------------------

auto append_attribute(std::span<std::uint8_t> out, std::size_t at, std::uint16_t type, std::span<std::uint8_t const> payload)
    -> std::size_t
{
    rtattr const header{
        .rta_len = static_cast<unsigned short>(sizeof(rtattr) + payload.size()),
        .rta_type = type,
    };
    std::memcpy(out.data() + at, &header, sizeof(header));
    std::memcpy(out.data() + at + sizeof(rtattr), payload.data(), payload.size());
    return at + ((sizeof(rtattr) + payload.size() + 3) & ~std::size_t{3});
}

auto as_bytes(std::string_view text) -> std::span<std::uint8_t const>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

/// A netlink socket of the test's own, for the two things a namespace test
/// needs that this module does not do: an Ethernet-like parent device to
/// hang a VLAN on, and a VLAN link created *out of band*, the way an
/// administrator's would be, so the client under test can meet one it did
/// not create.
class Scaffold
{
  public:
    Scaffold()
        : fd_{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)}
    {
        if (fd_ < 0) {
            return;
        }
        sockaddr_nl address{};
        address.nl_family = AF_NETLINK;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (::bind(fd_, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) < 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    ~Scaffold()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    Scaffold(Scaffold const&) = delete;
    auto operator=(Scaffold const&) -> Scaffold& = delete;
    Scaffold(Scaffold&&) = delete;
    auto operator=(Scaffold&&) -> Scaffold& = delete;

    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// Create a `dummy` device: an Ethernet-like link that supports VLANs
    /// and needs no peer. Hand-built, because building links of arbitrary
    /// kinds is test scaffolding and does not belong in the module.
    [[nodiscard]] auto create_dummy(std::string_view name) -> int
    {
        std::array<std::uint8_t, 128> request{};
        nlmsghdr header{};
        header.nlmsg_type = RTM_NEWLINK;
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        header.nlmsg_seq = ++seq_;
        std::size_t at = sizeof(nlmsghdr) + sizeof(ifinfomsg);
        std::string const terminated{name};
        at = append_attribute(request, at, IFLA_IFNAME, as_bytes({terminated.c_str(), terminated.size() + 1}));
        auto const nest_at = at;
        at = append_attribute(request, at + sizeof(rtattr), IFLA_INFO_KIND, as_bytes("dummy"));
        rtattr const nest{
            .rta_len = static_cast<unsigned short>(at - nest_at),
            .rta_type = IFLA_LINKINFO,
        };
        std::memcpy(request.data() + nest_at, &nest, sizeof(nest));
        header.nlmsg_len = static_cast<std::uint32_t>(at);
        std::memcpy(request.data(), &header, sizeof(header));
        return transact({request.data(), at});
    }

    /// Create a VLAN link without the client under test, using the module's
    /// own builder on this socket.
    [[nodiscard]] auto create_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid) -> int
    {
        std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
        auto const length = vlan::build_new_vlan(request, parent_ifindex, name, vid, ++seq_);
        if (!length) {
            return EINVAL;
        }
        return transact({request.data(), *length});
    }

    /// Delete a link behind the client's back, so a test can arrange for
    /// one the client believes it owns to be gone.
    [[nodiscard]] auto remove_link(std::string_view name) -> int
    {
        std::array<std::uint8_t, vlan::MAX_REQUEST_SIZE> request{};
        auto const length = vlan::build_delete_link(request, name, ++seq_);
        if (!length) {
            return EINVAL;
        }
        return transact({request.data(), *length});
    }

  private:
    /// Send one request and return the kernel's errno, 0 for success.
    [[nodiscard]] auto transact(std::span<std::uint8_t const> request) -> int
    {
        if (::send(fd_, request.data(), request.size(), 0) < 0) {
            return errno;
        }
        std::array<std::uint8_t, 4096> reply{};
        auto const got = ::recv(fd_, reply.data(), reply.size(), 0);
        if (got < 0) {
            return errno;
        }
        auto const ack = vlan::parse_ack({reply.data(), static_cast<std::size_t>(got)});
        if (!ack) {
            return EPROTO;
        }
        return ack->error;
    }

    int fd_{-1};
    std::uint32_t seq_{9000};
};

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

TEST(vlan_link, reading_a_device_that_is_not_a_vlan_says_so)
{
    auto const facts = vlan::read_vlan_link("lo");
    EXPECT_FALSE(facts.has_value());
    if (!facts) {
        EXPECT_TRUE(facts.error() == std::errc::invalid_argument);
    }
}

TEST(vlan_link, reading_a_device_nobody_has_reports_no_such_device)
{
    auto const facts = vlan::read_vlan_link("statusbar.nope");
    EXPECT_FALSE(facts.has_value());
    if (!facts) {
        EXPECT_TRUE(facts.error() == std::errc::no_such_device);
    }
}

TEST(vlan_link, errno_reaches_the_caller_in_the_generic_category)
{
    // Pinning the category, which comparing against a std::errc does not
    // do: that comparison goes through default_error_condition and holds
    // for a system-category code of the same value too. error_code
    // equality is the category-sensitive one, so this is the form that
    // tells the two apart — and a caller may well write it.
    auto const facts = vlan::read_vlan_link("statusbar.nope");
    EXPECT_FALSE(facts.has_value());
    if (!facts) {
        EXPECT_TRUE(facts.error() == std::make_error_code(std::errc::no_such_device));
        EXPECT_TRUE(facts.error().category() == std::generic_category());
    }
}

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

TEST(vlan_link, opening_a_netlink_socket_needs_no_privilege)
{
    vlan::VlanLinkClient client;
    EXPECT_TRUE(client.open().has_value());
    EXPECT_TRUE(client.valid());
    EXPECT_TRUE(client.fd() >= 0);
    // Opening twice is a caller's mistake, not a silent re-open.
    EXPECT_FALSE(client.open().has_value());
    EXPECT_TRUE(client.created_links().empty());
}

TEST(vlan_link, a_registration_without_cap_net_admin_is_refused_clearly)
{
    // Loopback is the parent on purpose: it cannot carry a VLAN, so this
    // test creates nothing even when the suite is run as root. Which of
    // the two refusals arrives depends on the privilege we have, and both
    // are worth asserting.
    vlan::VlanLinkClient client;
    EXPECT_TRUE(client.open().has_value());
    auto const refused = client.add_vlan(1, "lo.2", AVB_VID);
    EXPECT_FALSE(refused.has_value());
    if (refused) {
        return;
    }
    if (refused.error() == std::errc::operation_not_permitted) {
        // The permission check fires before any extended ack is set, so
        // there is no kernel text to surface here and the errno is the
        // whole diagnostic.
        EXPECT_TRUE(client.last_message().empty());
        return;
    }
    EXPECT_TRUE(refused.error() == std::errc::operation_not_supported);
    EXPECT_FALSE(client.last_message().empty());
}

// ===========================================================================
// The lifecycle, in a network namespace of our own
// ===========================================================================

namespace {

struct LifecycleReport
{
    int setup_errno{-1};
    int parent_ifindex{0};
    int add_error{-1};
    int ownership{-1};
    int vid_read_back{-1};
    int parent_read_back{-1};
    int up_after_add{-1};
    int created_count{-1};
    int re_add_ownership{-1};
    int created_count_after_re_add{-1};
    int remove_error{-1};
    int index_after_remove{-1};
    int created_count_after{-1};
};

void run_lifecycle(LifecycleReport& report)
{
    Scaffold scaffold;
    report.setup_errno = scaffold.valid() ? scaffold.create_dummy("dummy0") : ENOTSUP;
    report.parent_ifindex = static_cast<int>(::if_nametoindex("dummy0"));

    vlan::VlanLinkClient client;
    if (!client.open()) {
        return;
    }
    auto const ownership = client.add_vlan(report.parent_ifindex, "dummy0.2", AVB_VID);
    report.add_error = ownership ? 0 : ownership.error().value();
    if (!ownership) {
        return;
    }
    report.ownership = static_cast<int>(*ownership);
    report.created_count = static_cast<int>(client.created_links().size());

    if (auto const facts = vlan::read_vlan_link("dummy0.2")) {
        report.vid_read_back = facts->vid;
        report.parent_read_back = facts->parent_ifindex;
        report.up_after_add = facts->up ? 1 : 0;
    }

    // Registering our own link a second time comes back from the kernel as
    // EEXIST like anyone else's would. It is still ours, and a caller told
    // "adopted" would leave it behind at shutdown.
    auto const again = client.add_vlan(report.parent_ifindex, "dummy0.2", AVB_VID);
    report.re_add_ownership = again ? static_cast<int>(*again) : -2;
    report.created_count_after_re_add = static_cast<int>(client.created_links().size());

    auto const removed = client.remove_link("dummy0.2");
    report.remove_error = removed ? 0 : removed.error().value();
    report.index_after_remove = static_cast<int>(::if_nametoindex("dummy0.2"));
    report.created_count_after = static_cast<int>(client.created_links().size());
}

}  // namespace

TEST(vlan_link, the_whole_lifecycle_against_a_real_kernel)
{
    auto const report = in_private_netns<LifecycleReport>(run_lifecycle);
    if (!report) {
        skip_no_namespaces("the_whole_lifecycle_against_a_real_kernel");
        return;
    }
    EXPECT_EQ(report->setup_errno, 0);
    EXPECT_TRUE(report->parent_ifindex > 0);
    EXPECT_EQ(report->add_error, 0);
    EXPECT_EQ(report->ownership, static_cast<int>(vlan::LinkOwnership::created));
    // The VID is registered with the parent's hardware: this is the whole
    // point of the module, read back from the 8021q module itself.
    EXPECT_EQ(report->vid_read_back, static_cast<int>(AVB_VID));
    EXPECT_EQ(report->parent_read_back, report->parent_ifindex);
    // And the link is down, which is deliberate: an interface that comes up
    // may pick up an address or start answering ARP.
    EXPECT_EQ(report->up_after_add, 0);
    EXPECT_EQ(report->created_count, 1);
    EXPECT_EQ(report->re_add_ownership, static_cast<int>(vlan::LinkOwnership::created));
    EXPECT_EQ(report->created_count_after_re_add, 1);
    EXPECT_EQ(report->remove_error, 0);
    EXPECT_EQ(report->index_after_remove, 0);
    EXPECT_EQ(report->created_count_after, 0);
}

namespace {

struct AdoptReport
{
    int setup_errno{-1};
    int out_of_band_errno{-1};
    int add_error{-1};
    int ownership{-1};
    int created_count{-1};
    int index_after_close{-1};
};

void run_adoption(AdoptReport& report)
{
    Scaffold scaffold;
    report.setup_errno = scaffold.valid() ? scaffold.create_dummy("dummy0") : ENOTSUP;
    auto const parent = static_cast<int>(::if_nametoindex("dummy0"));
    // Somebody else's link: same name, same VID, same parent, but not ours.
    report.out_of_band_errno = scaffold.create_vlan(parent, "dummy0.2", AVB_VID);
    {
        vlan::VlanLinkClient client;
        if (!client.open()) {
            return;
        }
        auto const ownership = client.add_vlan(parent, "dummy0.2", AVB_VID);
        report.add_error = ownership ? 0 : ownership.error().value();
        if (!ownership) {
            return;
        }
        report.ownership = static_cast<int>(*ownership);
        report.created_count = static_cast<int>(client.created_links().size());
    }
    report.index_after_close = static_cast<int>(::if_nametoindex("dummy0.2"));
}

}  // namespace

TEST(vlan_link, a_link_somebody_else_made_is_adopted_and_outlives_us)
{
    auto const report = in_private_netns<AdoptReport>(run_adoption);
    if (!report) {
        skip_no_namespaces("a_link_somebody_else_made_is_adopted_and_outlives_us");
        return;
    }
    EXPECT_EQ(report->setup_errno, 0);
    EXPECT_EQ(report->out_of_band_errno, 0);
    // The VID is registered, which is all the caller needed.
    EXPECT_EQ(report->add_error, 0);
    EXPECT_EQ(report->ownership, static_cast<int>(vlan::LinkOwnership::adopted));
    EXPECT_EQ(report->created_count, 0);
    // And destroying the client left it alone: deleting a link an
    // administrator made would break their configuration.
    EXPECT_TRUE(report->index_after_close > 0);
}

namespace {

struct ConflictReport
{
    int setup_errno{-1};
    int out_of_band_errno{-1};
    int wrong_vid_error{-1};
    std::array<char, 160> wrong_vid_message{};
    int wrong_parent_error{-1};
    int not_a_vlan_error{-1};
    std::array<char, 160> not_a_vlan_message{};
};

void run_conflicts(ConflictReport& report)
{
    Scaffold scaffold;
    report.setup_errno = scaffold.valid() ? scaffold.create_dummy("dummy0") : ENOTSUP;
    if (scaffold.create_dummy("dummy1") != 0) {
        return;
    }
    auto const parent = static_cast<int>(::if_nametoindex("dummy0"));
    auto const other = static_cast<int>(::if_nametoindex("dummy1"));
    report.out_of_band_errno = scaffold.create_vlan(parent, "dummy0.2", AVB_VID);

    vlan::VlanLinkClient client;
    if (!client.open()) {
        return;
    }
    // Same name, different VID: adopting this would leave us believing
    // VID 3 is registered when VID 2 is.
    auto const wrong_vid = client.add_vlan(parent, "dummy0.2", 3);
    report.wrong_vid_error = wrong_vid ? 0 : wrong_vid.error().value();
    std::snprintf(report.wrong_vid_message.data(), report.wrong_vid_message.size(), "%s", client.last_message().c_str());

    // Same name and VID, different parent: this is what name truncation
    // can produce, and the VID would be registered on the wrong NIC.
    auto const wrong_parent = client.add_vlan(other, "dummy0.2", AVB_VID);
    report.wrong_parent_error = wrong_parent ? 0 : wrong_parent.error().value();

    // A name already held by something that is not a VLAN at all.
    auto const not_a_vlan = client.add_vlan(parent, "dummy1", AVB_VID);
    report.not_a_vlan_error = not_a_vlan ? 0 : not_a_vlan.error().value();
    std::snprintf(report.not_a_vlan_message.data(), report.not_a_vlan_message.size(), "%s", client.last_message().c_str());
}

}  // namespace

TEST(vlan_link, a_name_held_by_a_different_link_is_a_conflict_not_an_adoption)
{
    auto const report = in_private_netns<ConflictReport>(run_conflicts);
    if (!report) {
        skip_no_namespaces("a_name_held_by_a_different_link_is_a_conflict_not_an_adoption");
        return;
    }
    EXPECT_EQ(report->setup_errno, 0);
    EXPECT_EQ(report->out_of_band_errno, 0);
    EXPECT_EQ(report->wrong_vid_error, EEXIST);
    // The message has to say what it collided with, or the caller is left
    // with a bare EEXIST on a name it computed itself.
    EXPECT_FALSE(std::string_view{report->wrong_vid_message.data()}.empty());
    EXPECT_EQ(report->wrong_parent_error, EEXIST);
    EXPECT_EQ(report->not_a_vlan_error, EEXIST);
    EXPECT_FALSE(std::string_view{report->not_a_vlan_message.data()}.empty());
}

namespace {

struct ExtAckReport
{
    int add_error{-1};
    std::array<char, 160> message{};
    int remove_absent_error{-1};
};

void run_ext_ack(ExtAckReport& report)
{
    vlan::VlanLinkClient client;
    if (!client.open()) {
        return;
    }
    // Loopback cannot carry a VLAN, and the 8021q driver says so in words.
    auto const refused = client.add_vlan(static_cast<int>(::if_nametoindex("lo")), "lo.2", AVB_VID);
    report.add_error = refused ? 0 : refused.error().value();
    std::snprintf(report.message.data(), report.message.size(), "%s", client.last_message().c_str());

    auto const removed = client.remove_link("statusbar.nope");
    report.remove_absent_error = removed ? 0 : removed.error().value();
}

}  // namespace

TEST(vlan_link, the_kernels_own_words_reach_last_message)
{
    auto const report = in_private_netns<ExtAckReport>(run_ext_ack);
    if (!report) {
        skip_no_namespaces("the_kernels_own_words_reach_last_message");
        return;
    }
    EXPECT_EQ(report->add_error, EOPNOTSUPP);
    // This is the criterion the issue asks for, met against a real kernel:
    // the refusal's own text, not a bare errno. It is reachable because we
    // have CAP_NET_ADMIN in here — the *unprivileged* refusal, EPERM,
    // carries no text at all, because the permission check fires before any
    // extended ack is set.
    EXPECT_TRUE(std::string_view{report->message.data()} == "8021q: VLANs not supported on device");
    EXPECT_EQ(report->remove_absent_error, ENODEV);
}

namespace {

struct CloseReport
{
    int setup_errno{-1};
    int add_error{-1};
    int index_in_scope{-1};
    int index_after_scope{-1};
    int removed_error{-1};
    int index_after_explicit{-1};
    int vanished_remove_error{-1};
    int created_after_vanished{-1};
    int vanished_still_owned{-1};
};

void run_close(CloseReport& report)
{
    Scaffold scaffold;
    report.setup_errno = scaffold.valid() ? scaffold.create_dummy("dummy0") : ENOTSUP;
    auto const parent = static_cast<int>(::if_nametoindex("dummy0"));
    {
        vlan::VlanLinkClient client;
        if (!client.open()) {
            return;
        }
        auto const ownership = client.add_vlan(parent, "dummy0.2", AVB_VID);
        report.add_error = ownership ? 0 : ownership.error().value();
        report.index_in_scope = static_cast<int>(::if_nametoindex("dummy0.2"));
    }
    report.index_after_scope = static_cast<int>(::if_nametoindex("dummy0.2"));

    // And again, explicitly, so the errors are visible to a caller who
    // wants them rather than swallowed by a destructor.
    vlan::VlanLinkClient client;
    if (!client.open()) {
        return;
    }
    EXPECT_TRUE(client.add_vlan(parent, "dummy0.3", 3).has_value());
    auto const removed = client.remove_created_links();
    report.removed_error = removed ? 0 : removed.error().value();
    report.index_after_explicit = static_cast<int>(::if_nametoindex("dummy0.3"));

    // A link we created that somebody else removes first. Our delete comes
    // back ENODEV, and after it we must not still be claiming to own it.
    if (!client.add_vlan(parent, "dummy0.4", 4)) {
        return;
    }
    if (scaffold.remove_link("dummy0.4") != 0) {
        return;
    }
    report.vanished_still_owned = client.created_links().empty() ? 0 : 1;
    auto const vanished = client.remove_link("dummy0.4");
    report.vanished_remove_error = vanished ? 0 : vanished.error().value();
    report.created_after_vanished = static_cast<int>(client.created_links().size());
}

}  // namespace

TEST(vlan_link, destroying_a_client_removes_only_what_it_created)
{
    auto const report = in_private_netns<CloseReport>(run_close);
    if (!report) {
        skip_no_namespaces("destroying_a_client_removes_only_what_it_created");
        return;
    }
    EXPECT_EQ(report->setup_errno, 0);
    EXPECT_EQ(report->add_error, 0);
    EXPECT_TRUE(report->index_in_scope > 0);
    EXPECT_EQ(report->index_after_scope, 0);
    EXPECT_EQ(report->removed_error, 0);
    EXPECT_EQ(report->index_after_explicit, 0);
    // It was ours right up to the moment it vanished,
    EXPECT_EQ(report->vanished_still_owned, 1);
    // the kernel says there is no such device,
    EXPECT_EQ(report->vanished_remove_error, ENODEV);
    // and we stop claiming it, rather than reporting a link we own that
    // does not exist and retrying its removal from the destructor.
    EXPECT_EQ(report->created_after_vanished, 0);
}

#endif  // defined(__linux__)

TEST_MAIN(statusbar_net, net_vlan_link_test)
