// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_vlan_link.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"

// <net/if.h> must precede the kernel headers: glibc's compatibility guards
// only suppress the duplicate IFF_* and ifreq definitions in <linux/if.h>,
// which <linux/if_vlan.h> pulls in, when they see this one first.
#    include <unistd.h>

#    include <algorithm>
#    include <array>
#    include <cerrno>
#    include <cstdio>
#    include <cstring>
#    include <utility>

#    include <linux/if_link.h>
#    include <linux/if_vlan.h>
#    include <linux/netlink.h>
#    include <linux/rtnetlink.h>
// SIOCGIFVLAN is kernel UAPI and belongs to this header. Fedora's
// glibc happens to reach it through <sys/ioctl.h>; Debian's does not,
// so leaving it implicit compiles here and fails on the target.
#    include <linux/sockios.h>
#    include <net/if.h>
#    include <sys/ioctl.h>
#    include <sys/socket.h>
#    include <sys/time.h>

namespace statusbar::net::vlan {

namespace {

constexpr std::size_t NLMSGHDR_SIZE = sizeof(nlmsghdr);
constexpr std::size_t IFINFOMSG_SIZE = sizeof(ifinfomsg);
constexpr std::size_t RTATTR_SIZE = sizeof(rtattr);

// The request sizes in the tests, and MAX_REQUEST_SIZE itself, are derived
// from these. A kernel that changed any of them would make every byte
// offset below wrong, so they are pinned rather than assumed.
static_assert(NLMSGHDR_SIZE == 16, "nlmsghdr is 16 bytes on every Linux ABI we build for");
static_assert(IFINFOMSG_SIZE == 16, "ifinfomsg is 16 bytes on every Linux ABI we build for");
static_assert(RTATTR_SIZE == 4, "rtattr is 4 bytes on every Linux ABI we build for");

/// NLM_F_EXCL is the load-bearing flag: without it the kernel reads
/// RTM_NEWLINK on an existing link as a change and would silently
/// re-point somebody else's VLAN link at our VID.
constexpr std::uint16_t CREATE_FLAGS = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
constexpr std::uint16_t DELETE_FLAGS = NLM_F_REQUEST | NLM_F_ACK;

/// Sent without a terminator, which is what iproute2 does and what the
/// kernel's `nla_strcmp` expects either way.
constexpr std::string_view VLAN_KIND = "vlan";

/// Long enough for either conflict description below.
constexpr std::size_t MAX_MESSAGE_LENGTH = 160;

[[nodiscard]] constexpr auto align4(std::size_t length) noexcept -> std::size_t
{
    return (length + 3U) & ~std::size_t{3U};
}

[[nodiscard]] auto as_bytes(std::string_view text) noexcept -> std::span<std::uint8_t const>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

/// Write an rtattr header at the start of `at`.
auto write_attribute_header(std::span<std::uint8_t> at, std::uint16_t type, std::size_t payload_length) noexcept -> void
{
    rtattr const header{
        .rta_len = static_cast<unsigned short>(RTATTR_SIZE + payload_length),
        .rta_type = type,
    };
    std::memcpy(at.data(), &header, RTATTR_SIZE);
}

/// A cursor that writes a request into a caller's buffer, refusing to run
/// past its end rather than truncating.
class Writer
{
  public:
    /// What `open_nest` returns when there was no room for the header.
    static constexpr std::size_t NO_NEST = static_cast<std::size_t>(-1);

    explicit Writer(std::span<std::uint8_t> out) noexcept
        : out_{out}
    {}

    /// Reserve `length` bytes, zeroed and 4-aligned, and return them.
    /// An empty span means the buffer is too small.
    [[nodiscard]] auto reserve(std::size_t length) noexcept -> std::span<std::uint8_t>
    {
        auto const padded = align4(length);
        if (overflowed_ || padded > out_.size() - used_) {
            overflowed_ = true;
            return {};
        }
        auto const slot = out_.subspan(used_, length);
        std::fill_n(out_.data() + used_, padded, std::uint8_t{0});
        used_ += padded;
        return slot;
    }

    /// Write an attribute header and its payload.
    [[nodiscard]] auto put_attribute(std::uint16_t type, std::span<std::uint8_t const> payload) noexcept -> bool
    {
        auto slot = reserve(RTATTR_SIZE + payload.size());
        if (slot.empty()) {
            return false;
        }
        write_attribute_header(slot, type, payload.size());
        std::memcpy(slot.data() + RTATTR_SIZE, payload.data(), payload.size());
        return true;
    }

    /// Reserve an attribute header whose length is not yet known, and
    /// return where it sits so `close_nest` can patch it.
    [[nodiscard]] auto open_nest(std::uint16_t type) noexcept -> std::size_t
    {
        auto const at = used_;
        auto const slot = reserve(RTATTR_SIZE);
        if (slot.empty()) {
            return NO_NEST;
        }
        write_attribute_header(slot, type, 0);
        return at;
    }

    /// Patch a nest's length to cover everything written since it opened,
    /// padding included — which is what the kernel's own nests count.
    auto close_nest(std::size_t at) noexcept -> void
    {
        if (at == NO_NEST || overflowed_) {
            return;
        }
        auto const length = static_cast<unsigned short>(used_ - at);
        std::memcpy(out_.data() + at + offsetof(rtattr, rta_len), &length, sizeof(length));
    }

    [[nodiscard]] auto used() const noexcept -> std::size_t { return used_; }
    [[nodiscard]] auto overflowed() const noexcept -> bool { return overflowed_; }
    [[nodiscard]] auto buffer() const noexcept -> std::span<std::uint8_t> { return out_; }

  private:
    std::span<std::uint8_t> out_;
    std::size_t used_{0};
    bool overflowed_{false};
};

/// nlmsg_len is left 0 and patched by finish(); nlmsg_pid is left 0, which
/// tells the kernel to use the socket's own port.
auto write_nlmsghdr(std::span<std::uint8_t> at, std::uint16_t type, std::uint16_t flags, std::uint32_t seq) noexcept -> void
{
    nlmsghdr const header{
        .nlmsg_len = 0,
        .nlmsg_type = type,
        .nlmsg_flags = flags,
        .nlmsg_seq = seq,
        .nlmsg_pid = 0,
    };
    std::memcpy(at.data(), &header, NLMSGHDR_SIZE);
}

/// Write the nlmsghdr and the ifinfomsg every link request starts with.
///
/// Every ifinfomsg field stays zero, and all of them deliberately:
/// AF_UNSPEC because a link is not per address family, index 0 because a
/// create has no link to name and a delete names it as an attribute
/// instead, and no flags because the link must come up only when somebody
/// asks for it.
[[nodiscard]] auto put_preamble(Writer& writer, std::uint16_t type, std::uint16_t flags, std::uint32_t seq) noexcept -> bool
{
    auto header_slot = writer.reserve(NLMSGHDR_SIZE);
    auto const body_slot = writer.reserve(IFINFOMSG_SIZE);
    if (header_slot.empty() || body_slot.empty()) {
        return false;
    }
    write_nlmsghdr(header_slot, type, flags, seq);
    return true;
}

/// Patch nlmsg_len and report the final length.
[[nodiscard]] auto finish(Writer const& writer) noexcept -> StatusValue<std::size_t>
{
    if (writer.overflowed()) {
        return failure(NetError::invalid_argument);
    }
    auto const length = static_cast<std::uint32_t>(writer.used());
    std::memcpy(writer.buffer().data(), &length, sizeof(length));
    return success(writer.used());
}

[[nodiscard]] auto put_u16(Writer& writer, std::uint16_t type, std::uint16_t value) noexcept -> bool
{
    std::array<std::uint8_t, sizeof(value)> payload{};
    std::memcpy(payload.data(), &value, sizeof(value));
    return writer.put_attribute(type, payload);
}

[[nodiscard]] auto put_u32(Writer& writer, std::uint16_t type, std::uint32_t value) noexcept -> bool
{
    std::array<std::uint8_t, sizeof(value)> payload{};
    std::memcpy(payload.data(), &value, sizeof(value));
    return writer.put_attribute(type, payload);
}

/// IFLA_IFNAME, NUL-terminated: the kernel's policy for this attribute is
/// a string, and iproute2 includes the terminator in the length.
[[nodiscard]] auto put_name(Writer& writer, std::string_view name) noexcept -> bool
{
    if (name.size() > MAX_LINK_NAME_LENGTH) {
        return false;
    }
    std::array<std::uint8_t, MAX_LINK_NAME_LENGTH + 1> payload{};
    std::memcpy(payload.data(), name.data(), name.size());
    return writer.put_attribute(IFLA_IFNAME, {payload.data(), name.size() + 1});
}

/// IFLA_INFO_DATA for a VLAN, which holds just the id. 802.1Q is the
/// default protocol, so IFLA_VLAN_PROTOCOL is left out exactly as
/// iproute2 leaves it out.
[[nodiscard]] auto put_vlan_data(Writer& writer, std::uint16_t vid) noexcept -> bool
{
    auto const data = writer.open_nest(IFLA_INFO_DATA);
    bool const ok = put_u16(writer, IFLA_VLAN_ID, vid);
    writer.close_nest(data);
    return ok;
}

/// IFLA_LINKINFO: which kind of link to make, and that kind's options.
[[nodiscard]] auto put_vlan_info(Writer& writer, std::uint16_t vid) noexcept -> bool
{
    auto const info = writer.open_nest(IFLA_LINKINFO);
    bool const kind = writer.put_attribute(IFLA_INFO_KIND, as_bytes(VLAN_KIND));
    bool const data = put_vlan_data(writer, vid);
    writer.close_nest(info);
    return kind && data;
}

[[nodiscard]] auto validate_name(std::string_view name) noexcept -> Status
{
    if (name.empty() || name.size() > MAX_LINK_NAME_LENGTH) {
        return failure(NetError::invalid_argument);
    }
    return success();
}

[[nodiscard]] auto validate_new_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid) noexcept -> Status
{
    if (parent_ifindex <= 0) {
        return failure(NetError::invalid_argument);
    }
    if (vid < MIN_VLAN_ID || vid > MAX_VLAN_ID) {
        return failure(NetError::invalid_argument);
    }
    return validate_name(name);
}

}  // namespace

auto vlan_link_name(std::string_view interface, std::uint16_t vid) -> std::string
{
    if (interface.empty()) {
        return {};
    }
    std::array<char, MAX_LINK_NAME_LENGTH + 1> suffix{};
    auto const suffix_length = std::snprintf(suffix.data(), suffix.size(), ".%u", vid);
    if (suffix_length <= 0 || static_cast<std::size_t>(suffix_length) >= MAX_LINK_NAME_LENGTH) {
        return {};
    }
    auto const room = MAX_LINK_NAME_LENGTH - static_cast<std::size_t>(suffix_length);
    return std::string{interface.substr(0, std::min(room, interface.size()))} + suffix.data();
}

auto build_new_vlan(std::span<std::uint8_t> out, int parent_ifindex, std::string_view name, std::uint16_t vid, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    if (auto status = validate_new_vlan(parent_ifindex, name, vid); !status) {
        return forward_failure(status);
    }
    Writer writer{out};
    bool const written = put_preamble(writer, RTM_NEWLINK, CREATE_FLAGS, seq) &&
        put_u32(writer, IFLA_LINK, static_cast<std::uint32_t>(parent_ifindex)) && put_name(writer, name) &&
        put_vlan_info(writer, vid);
    if (!written) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_delete_link(std::span<std::uint8_t> out, std::string_view name, std::uint32_t seq) -> StatusValue<std::size_t>
{
    if (auto status = validate_name(name); !status) {
        return forward_failure(status);
    }
    Writer writer{out};
    bool const written = put_preamble(writer, RTM_DELLINK, DELETE_FLAGS, seq) && put_name(writer, name);
    if (!written) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

namespace {

/// Where an NLMSG_ERROR's extended-ack TLVs begin, measured from the end
/// of its own netlink header.
///
/// The payload starts with the errno and the offending request's netlink
/// header. Unless the kernel set NLM_F_CAPPED it also appends the rest of
/// that request, and the TLVs come after all of it. Getting this wrong
/// reads the original request's bytes as attributes — and every error
/// reply this module provokes in practice is uncapped.
[[nodiscard]] auto ack_tlv_offset(nlmsghdr const& header, nlmsgerr const& error) noexcept -> std::size_t
{
    auto offset = sizeof(nlmsgerr);
    if ((header.nlmsg_flags & NLM_F_CAPPED) == 0) {
        offset += error.msg.nlmsg_len - sizeof(error.msg);
    }
    return offset;
}

/// The TLV bytes of an NLMSG_ERROR, or an empty span if there are none.
[[nodiscard]] auto ack_payload(std::span<std::uint8_t const> message, nlmsghdr const& header, nlmsgerr const& error) noexcept
    -> std::span<std::uint8_t const>
{
    auto const offset = NLMSGHDR_SIZE + ack_tlv_offset(header, error);
    if (offset >= header.nlmsg_len || header.nlmsg_len > message.size()) {
        return {};
    }
    return message.subspan(offset, header.nlmsg_len - offset);
}

auto extract_ack_message(std::span<std::uint8_t const> payload, AckResult& result) noexcept -> void
{
    std::size_t at = 0;
    while (at + RTATTR_SIZE <= payload.size()) {
        rtattr attribute{};
        std::memcpy(&attribute, payload.data() + at, RTATTR_SIZE);
        if (attribute.rta_len < RTATTR_SIZE || at + attribute.rta_len > payload.size()) {
            return;
        }
        if (attribute.rta_type == NLMSGERR_ATTR_MSG) {
            auto const text = payload.subspan(at + RTATTR_SIZE, attribute.rta_len - RTATTR_SIZE);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto const view = std::string_view{reinterpret_cast<char const*>(text.data()), text.size()};
            result.message = std::string{view.substr(0, view.find('\0'))};
        }
        at += align4(attribute.rta_len);
    }
}

struct ErrorReply
{
    nlmsghdr header{};
    nlmsgerr error{};
};

[[nodiscard]] auto read_error_reply(std::span<std::uint8_t const> message) noexcept -> StatusValue<ErrorReply>
{
    if (message.size() < NLMSGHDR_SIZE + sizeof(nlmsgerr)) {
        return failure(NetError::invalid_argument);
    }
    ErrorReply reply{};
    std::memcpy(&reply.header, message.data(), NLMSGHDR_SIZE);
    std::memcpy(&reply.error, message.data() + NLMSGHDR_SIZE, sizeof(reply.error));
    if (reply.header.nlmsg_type != NLMSG_ERROR || reply.header.nlmsg_len > message.size() ||
        reply.header.nlmsg_len < NLMSGHDR_SIZE + sizeof(nlmsgerr)) {
        return failure(NetError::invalid_argument);
    }
    return success(reply);
}

}  // namespace

auto parse_ack(std::span<std::uint8_t const> message) -> StatusValue<AckResult>
{
    auto const reply = read_error_reply(message);
    if (!reply) {
        return forward_failure(reply);
    }
    // The kernel reports a negative errno, and 0 for a plain acknowledgement.
    AckResult result{.error = -reply->error.error, .message = {}};
    extract_ack_message(ack_payload(message, reply->header, reply->error), result);
    return success(result);
}

namespace {

/// errno in the generic category.
///
/// Which category this is matters for one comparison and not the other,
/// and the difference is easy to state backwards. Against a `std::errc`,
/// either category compares equal: `ec == std::errc::no_such_device` goes
/// through the category's `default_error_condition`, and the system
/// category maps a POSIX errno straight onto the generic one. Against
/// another `error_code` it does not: `error_code` equality compares the
/// category identity too, so a caller writing
/// `== std::make_error_code(std::errc::no_such_device)` sees false for a
/// system-category code of the very same value. Both forms are things a
/// caller writes, so the category is pinned here and asserted in the
/// tests rather than left to whichever form a test happened to use.
[[nodiscard]] auto errno_error() noexcept -> std::error_code
{
    return {errno, std::generic_category()};
}

[[nodiscard]] auto generic_error(int value) noexcept -> std::error_code
{
    return {value, std::generic_category()};
}

/// A `vlan_ioctl_args` carrying one query and the device to ask about.
[[nodiscard]] auto vlan_args(std::string_view name, int command) noexcept -> vlan_ioctl_args
{
    vlan_ioctl_args args{};
    args.cmd = command;
    // Clamped rather than trusting the caller to have validated: this
    // takes a string_view, and the copy's bound should not depend on
    // which path reached it.
    std::memcpy(args.device1, name.data(), std::min(name.size(), sizeof(args.device1) - 1));
    return args;
}

/// Ask the 8021q module one question about a device.
///
/// These queries need no privilege — only the ADD, DEL and SET commands
/// want CAP_NET_ADMIN — which is what lets a caller check what is already
/// registered before trying to register anything.
[[nodiscard]] auto vlan_query(vlan_ioctl_args& args) noexcept -> Status
{
    FileDescriptor const probe{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (!probe.valid()) {
        return failure(NetError::socket_creation_failed);
    }
    if (::ioctl(probe.get(), SIOCGIFVLAN, &args) < 0) {
        return failure(errno_error());
    }
    return success();
}

[[nodiscard]] auto read_vid(std::string_view name) -> StatusValue<std::uint16_t>
{
    auto args = vlan_args(name, GET_VLAN_VID_CMD);
    if (auto status = vlan_query(args); !status) {
        return forward_failure(status);
    }
    return success(static_cast<std::uint16_t>(args.u.VID));
}

/// The parent's ifindex, or 0 if the kernel will not say. Resolved from
/// the name the 8021q module reports, so a parent renamed or removed
/// since reads as absent rather than as some other device.
[[nodiscard]] auto read_parent_ifindex(std::string_view name) -> int
{
    auto args = vlan_args(name, GET_VLAN_REALDEV_NAME_CMD);
    if (!vlan_query(args)) {
        return 0;
    }
    // Belt and braces: the kernel terminates the name it writes here and
    // the buffer started zeroed, so no test can reach a case where this
    // matters. It stays because the alternative is handing a 24-byte
    // window to if_nametoindex and trusting a driver.
    args.u.device2[sizeof(args.u.device2) - 1] = '\0';
    return static_cast<int>(::if_nametoindex(args.u.device2));
}

/// Whether the link is administratively up. We create links down and
/// leave them down, so a link that is up is one somebody else is using.
[[nodiscard]] auto read_link_up(std::string_view name) -> bool
{
    FileDescriptor const probe{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    ifreq request{};
    std::memcpy(request.ifr_name, name.data(), std::min(name.size(), sizeof(request.ifr_name) - 1));
    if (!probe.valid() || ::ioctl(probe.get(), SIOCGIFFLAGS, &request) < 0) {
        return false;
    }
    return (static_cast<unsigned>(request.ifr_flags) & IFF_UP) != 0;
}

/// An over-long name cannot be any device, and reporting it as
/// ENAMETOOLONG — a verdict no interface query returns — makes the early
/// return observable rather than merely asserted.
[[nodiscard]] auto validate_queryable_name(std::string_view name) noexcept -> Status
{
    if (name.empty()) {
        return failure(generic_error(ENODEV));
    }
    if (name.size() > MAX_LINK_NAME_LENGTH) {
        return failure(generic_error(ENAMETOOLONG));
    }
    return success();
}

}  // namespace

auto read_vlan_link(std::string_view name) -> StatusValue<VlanLinkFacts>
{
    if (auto status = validate_queryable_name(name); !status) {
        return forward_failure(status);
    }
    auto const vid = read_vid(name);
    if (!vid) {
        return forward_failure(vid);
    }
    return success(VlanLinkFacts{
        .vid = *vid,
        .parent_ifindex = read_parent_ifindex(name),
        .up = read_link_up(name),
    });
}

namespace {

/// NLMSG_GOODSIZE: what the kernel assumes a reader's buffer holds.
constexpr std::size_t REPLY_BUFFER_SIZE = 8192;

/// A reply that never arrives would otherwise block a caller forever: a
/// read bound does not help when the kernel sends nothing at all. Two
/// seconds is generous, and a daemon that reports a timeout is strictly
/// better than one that stops.
constexpr time_t REPLY_TIMEOUT_SECONDS = 2;

/// Translate a failed recv(). A timeout is reported distinguishably so a
/// caller can tell "the kernel did not answer" from "the socket broke".
[[nodiscard]] auto recv_failure() noexcept -> std::error_code
{
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return std::make_error_code(std::errc::timed_out);
    }
    return make_error_code(NetError::receive_failed);
}

[[nodiscard]] auto sequence_of(std::span<std::uint8_t const> request) noexcept -> std::uint32_t
{
    std::uint32_t seq = 0;
    std::memcpy(&seq, request.data() + offsetof(nlmsghdr, nlmsg_seq), sizeof(seq));
    return seq;
}

[[nodiscard]] auto bind_netlink(int fd) noexcept -> Status
{
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    // nl_pid left 0: the kernel assigns a unique port id, which we then
    // read back.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(fd, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) < 0) {
        return failure(NetError::bind_failed);
    }
    return success();
}

/// Both options are advisory: an old kernel without NETLINK_EXT_ACK still
/// answers, just less helpfully, and a socket without SO_RCVTIMEO still
/// works until a reply goes missing. Neither failing is worth refusing to
/// open, so neither is checked.
auto configure_netlink(int fd) noexcept -> void
{
    // Without NETLINK_EXT_ACK the kernel sends only an errno, and
    // last_message() can never be anything but empty — which would lose
    // the 8021q driver's own account of why it refused.
    int const enable = 1;
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &enable, sizeof(enable));
    // No test reaches this: provoking it needs a reply the kernel never
    // sends. It is here because the failure it prevents is a daemon that
    // stops rather than one that reports, which is the worst way to find
    // out. Removing it fails nothing and costs everything.
    timeval const timeout{.tv_sec = REPLY_TIMEOUT_SECONDS, .tv_usec = 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

/// The socket's own port id is deliberately not kept. This client makes
/// one request at a time and joins no multicast group, so the only
/// messages it can read are answers to its own; a port-id filter here
/// would be state nothing reads.
[[nodiscard]] auto open_netlink_socket() noexcept -> StatusValue<FileDescriptor>
{
    FileDescriptor socket_fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (!socket_fd.valid()) {
        return failure(NetError::socket_creation_failed);
    }
    configure_netlink(socket_fd.get());
    if (auto status = bind_netlink(socket_fd.get()); !status) {
        return forward_failure(status);
    }
    return success(std::move(socket_fd));
}

/// Say what a name collided with. A bare EEXIST on a name the caller
/// computed itself is not a diagnostic.
[[nodiscard]] auto describe_conflict(std::string_view name, VlanLinkFacts const& facts, int parent_ifindex, std::uint16_t vid)
    -> std::string
{
    std::array<char, MAX_MESSAGE_LENGTH> text{};
    (void)std::snprintf(
        text.data(),
        text.size(),
        "%.*s already registers VLAN %u on ifindex %d, not VLAN %u on ifindex %d",
        static_cast<int>(name.size()),
        name.data(),
        facts.vid,
        facts.parent_ifindex,
        vid,
        parent_ifindex);
    return std::string{text.data()};
}

/// The name exists but is not a VLAN link we can inspect: either it is
/// some other kind of device, or it went away between the kernel's
/// refusal and our question about it.
[[nodiscard]] auto describe_unreadable(std::string_view name, std::error_code error) -> std::string
{
    char const* why = (error == std::errc::invalid_argument) ? "is not a VLAN link" : "could not be read back";
    std::array<char, MAX_MESSAGE_LENGTH> text{};
    (void)std::snprintf(text.data(), text.size(), "%.*s exists but %s", static_cast<int>(name.size()), name.data(), why);
    return std::string{text.data()};
}

}  // namespace

VlanLinkClient::~VlanLinkClient()
{
    (void)remove_created_links();
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

auto VlanLinkClient::open() -> Status
{
    if (fd_ >= 0) {
        return failure(NetError::already_connected);
    }
    auto opened = open_netlink_socket();
    if (!opened) {
        return forward_failure(opened);
    }
    fd_ = opened->release();
    return success();
}

auto VlanLinkClient::record_ack(std::span<std::uint8_t const> message) -> Status
{
    auto const ack = parse_ack(message);
    if (!ack) {
        return forward_failure(ack);
    }
    last_message_ = ack->message;
    if (ack->error != 0) {
        return failure(generic_error(ack->error));
    }
    return success();
}

auto VlanLinkClient::apply_ack(std::span<std::uint8_t const> reply, std::uint32_t seq) -> Status
{
    std::size_t at = 0;
    while (at + NLMSGHDR_SIZE <= reply.size()) {
        nlmsghdr header{};
        std::memcpy(&header, reply.data() + at, NLMSGHDR_SIZE);
        if (header.nlmsg_len < NLMSGHDR_SIZE || at + header.nlmsg_len > reply.size()) {
            return failure(NetError::receive_failed);
        }
        // One reply buffer can hold several messages, so the sequence is
        // how our acknowledgement is told from any other. With one
        // request outstanding at a time nothing else can be in here, but
        // walking a buffer and taking the first NLMSG_ERROR found is the
        // habit that breaks the day something else can be.
        if (header.nlmsg_seq == seq && header.nlmsg_type == NLMSG_ERROR) {
            return record_ack(reply.subspan(at, header.nlmsg_len));
        }
        at += align4(header.nlmsg_len);
    }
    return failure(NetError::receive_failed);
}

auto VlanLinkClient::read_ack(std::uint32_t seq) -> Status
{
    std::array<std::uint8_t, REPLY_BUFFER_SIZE> buffer{};
    ssize_t const received = ::recv(fd_, buffer.data(), buffer.size(), 0);
    if (received < 0) {
        return failure(recv_failure());
    }
    return apply_ack({buffer.data(), static_cast<std::size_t>(received)}, seq);
}

auto VlanLinkClient::transact(std::span<std::uint8_t const> request) -> Status
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }
    last_message_.clear();
    if (::send(fd_, request.data(), request.size(), 0) < 0) {
        return failure(NetError::send_failed);
    }
    return read_ack(sequence_of(request));
}

auto VlanLinkClient::holds(std::string_view name) const noexcept -> bool
{
    return std::ranges::find(created_, name) != created_.end();
}

auto VlanLinkClient::adopt_existing(std::string_view name, int parent_ifindex, std::uint16_t vid) -> StatusValue<LinkOwnership>
{
    auto const facts = read_vlan_link(name);
    if (!facts) {
        last_message_ = describe_unreadable(name, facts.error());
        return failure(std::make_error_code(std::errc::file_exists));
    }
    if (facts->vid != vid || facts->parent_ifindex != parent_ifindex) {
        last_message_ = describe_conflict(name, *facts, parent_ifindex, vid);
        return failure(std::make_error_code(std::errc::file_exists));
    }
    // It is the link we wanted. Whether we may remove it later is a
    // different question from whether the VID is registered.
    return success(holds(name) ? LinkOwnership::created : LinkOwnership::adopted);
}

auto VlanLinkClient::finish_add(Status const& status, std::string_view name, int parent_ifindex, std::uint16_t vid)
    -> StatusValue<LinkOwnership>
{
    if (status) {
        created_.emplace_back(name);
        return success(LinkOwnership::created);
    }
    if (status.error() != std::errc::file_exists) {
        return forward_failure(status);
    }
    return adopt_existing(name, parent_ifindex, vid);
}

auto VlanLinkClient::add_vlan(int parent_ifindex, std::string_view name, std::uint16_t vid) -> StatusValue<LinkOwnership>
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_new_vlan(request, parent_ifindex, name, vid, ++sequence_);
    if (!length) {
        return forward_failure(length);
    }
    return finish_add(transact({request.data(), *length}), name, parent_ifindex, vid);
}

auto VlanLinkClient::remove_link(std::string_view name) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_delete_link(request, name, ++sequence_);
    if (!length) {
        return forward_failure(length);
    }
    auto status = transact({request.data(), *length});
    if (status || status.error() == std::errc::no_such_device) {
        // Forgotten when it is gone, which includes the case where
        // somebody else removed it first: ENODEV means the link is not
        // there, so claiming to own it would be a lie and retrying from
        // the destructor would be noise. Any other failure leaves it
        // standing, and leaves it ours — a case no test can arrange,
        // since a client that could create the link can remove it.
        std::erase(created_, std::string{name});
    }
    return status;
}

auto VlanLinkClient::remove_created_links() -> Status
{
    Status result = success();
    while (!created_.empty()) {
        auto const name = created_.back();
        created_.pop_back();
        if (auto status = remove_link(name); !status) {
            result = status;
        }
    }
    return result;
}

}  // namespace statusbar::net::vlan

#endif  // defined(__linux__)
