// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_qdisc.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"

#    include <unistd.h>

#    include <algorithm>
#    include <cerrno>
#    include <cstddef>
#    include <cstring>
#    include <utility>

#    include <linux/netlink.h>
#    include <linux/pkt_sched.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>
#    include <sys/time.h>

namespace statusbar::net::tc {

namespace {

constexpr std::size_t NLMSGHDR_SIZE = sizeof(nlmsghdr);
constexpr std::size_t TCMSG_SIZE = sizeof(tcmsg);
constexpr std::size_t RTATTR_SIZE = sizeof(rtattr);
constexpr std::size_t PAYLOAD_START = NLMSGHDR_SIZE + TCMSG_SIZE;

static_assert(NLMSGHDR_SIZE == 16, "nlmsghdr layout changed");
static_assert(TCMSG_SIZE == 20, "tcmsg layout changed");
static_assert(RTATTR_SIZE == 4, "rtattr layout changed");
static_assert(sizeof(tc_mqprio_qopt) == 82, "tc_mqprio_qopt layout changed");
static_assert(sizeof(tc_cbs_qopt) == 20, "tc_cbs_qopt layout changed");
static_assert(sizeof(tc_etf_qopt) == 12, "tc_etf_qopt layout changed");
static_assert(TC_QOPT_MAX_QUEUE == static_cast<int>(MAX_TRAFFIC_CLASSES), "TC_QOPT_MAX_QUEUE changed");
static_assert(TC_QOPT_BITMASK + 1 == static_cast<int>(PRIO_MAP_SIZE), "TC_QOPT_BITMASK changed");

/// Flags on a request that installs or replaces: create if absent,
/// replace if present, and ask for an ack so a refusal is reportable
/// along with its extended-ack text.
constexpr std::uint16_t REPLACE_FLAGS = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
constexpr std::uint16_t DELETE_FLAGS = NLM_F_REQUEST | NLM_F_ACK;
constexpr std::uint16_t DUMP_FLAGS = NLM_F_REQUEST | NLM_F_DUMP;

/// Netlink pads every message and attribute up to a multiple of 4.
[[nodiscard]] constexpr auto align4(std::size_t length) noexcept -> std::size_t
{
    return (length + 3U) & ~std::size_t{3U};
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

/// A cursor that writes a request into a caller's buffer, refusing to
/// run past its end rather than truncating.
class Writer
{
  public:
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

/// tcm_family stays AF_UNSPEC: a qdisc is not per address family.
auto write_tcmsg(std::span<std::uint8_t> at, int ifindex, std::uint32_t handle, std::uint32_t parent) noexcept -> void
{
    tcmsg const message{
        .tcm_family = 0,
        .tcm__pad1 = 0,
        .tcm__pad2 = 0,
        .tcm_ifindex = ifindex,
        .tcm_handle = handle,
        .tcm_parent = parent,
        .tcm_info = 0,
    };
    std::memcpy(at.data(), &message, TCMSG_SIZE);
}

/// Write the nlmsghdr and tcmsg that every qdisc request starts with.
/// `nlmsg_len` is patched by `finish()` once the attributes are known.
[[nodiscard]] auto put_preamble(
    Writer& writer,
    std::uint16_t type,
    std::uint16_t flags,
    std::uint32_t seq,
    int ifindex,
    std::uint32_t handle,
    std::uint32_t parent) noexcept -> bool
{
    auto header_slot = writer.reserve(NLMSGHDR_SIZE);
    auto tc_slot = writer.reserve(TCMSG_SIZE);
    if (header_slot.empty() || tc_slot.empty()) {
        return false;
    }
    write_nlmsghdr(header_slot, type, flags, seq);
    write_tcmsg(tc_slot, ifindex, handle, parent);
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

/// The kind name as a NUL-terminated payload, which is how the kernel
/// expects TCA_KIND.
[[nodiscard]] auto put_kind(Writer& writer, std::string_view kind) noexcept -> bool
{
    std::array<std::uint8_t, MAX_KIND_LENGTH + 1> payload{};
    std::copy(kind.begin(), kind.end(), payload.begin());
    return writer.put_attribute(TCA_KIND, {payload.data(), kind.size() + 1});
}

[[nodiscard]] auto validate_kind(std::string_view kind) noexcept -> Status
{
    if (kind.empty() || kind.size() > MAX_KIND_LENGTH) {
        return failure(NetError::invalid_argument);
    }
    return success();
}

[[nodiscard]] auto validate_mqprio(MqprioQdisc const& qdisc) noexcept -> Status
{
    // The kernel's own diagnosis of each of these is poor, and the third
    // one it may simply accept.
    if (qdisc.major == 0) {
        return failure(NetError::invalid_argument);
    }
    if (qdisc.num_tc == 0 || qdisc.num_tc > MAX_TRAFFIC_CLASSES) {
        return failure(NetError::invalid_argument);
    }
    auto const out_of_range = [&](std::uint8_t entry) { return entry >= qdisc.num_tc; };
    if (std::ranges::any_of(qdisc.prio_tc_map, out_of_range)) {
        return failure(NetError::invalid_argument);
    }
    return success();
}

/// Copy the three fixed-size arrays. Separate from to_qopt only because
/// the kernel struct's arrays cannot be written as an initializer.
auto copy_mqprio_queues(MqprioQdisc const& qdisc, tc_mqprio_qopt& qopt) noexcept -> void
{
    std::ranges::copy(qdisc.prio_tc_map, std::begin(qopt.prio_tc_map));
    std::ranges::copy(qdisc.count, std::begin(qopt.count));
    std::ranges::copy(qdisc.offset, std::begin(qopt.offset));
}

/// Fill a tc_mqprio_qopt from our typed struct.
[[nodiscard]] auto to_qopt(MqprioQdisc const& qdisc) noexcept -> tc_mqprio_qopt
{
    tc_mqprio_qopt qopt{};
    qopt.num_tc = qdisc.num_tc;
    qopt.hw = qdisc.offload ? 1 : 0;
    copy_mqprio_queues(qdisc, qopt);
    return qopt;
}

/// Fill a tc_cbs_qopt from our typed struct.
[[nodiscard]] auto to_qopt(CbsQdisc const& qdisc) noexcept -> tc_cbs_qopt
{
    return tc_cbs_qopt{
        .offload = static_cast<__u8>(qdisc.offload ? 1 : 0),
        ._pad = {},
        .hicredit = qdisc.hicredit,
        .locredit = qdisc.locredit,
        .idleslope = qdisc.idleslope_kbps,
        .sendslope = qdisc.sendslope_kbps,
    };
}

/// TCA_OPTIONS for a cbs is a nest holding one TCA_CBS_PARMS, so it is
/// written by hand rather than through put_attribute.
[[nodiscard]] auto put_cbs_options(Writer& writer, tc_cbs_qopt const& qopt) noexcept -> bool
{
    auto slot = writer.reserve((2 * RTATTR_SIZE) + sizeof(qopt));
    if (slot.empty()) {
        return false;
    }
    write_attribute_header(slot, TCA_OPTIONS, RTATTR_SIZE + sizeof(qopt));
    write_attribute_header(slot.subspan(RTATTR_SIZE), TCA_CBS_PARMS, sizeof(qopt));
    std::memcpy(slot.data() + (2 * RTATTR_SIZE), &qopt, sizeof(qopt));
    return true;
}

/// Fill a tc_etf_qopt from our typed struct. Each flag is a separate bit, so
/// a caller that asked for one never gets another.
[[nodiscard]] auto to_qopt(EtfQdisc const& qdisc) noexcept -> tc_etf_qopt
{
    std::uint32_t flags = 0;
    if (qdisc.deadline_mode) {
        flags |= TC_ETF_DEADLINE_MODE_ON;
    }
    if (qdisc.offload) {
        flags |= TC_ETF_OFFLOAD_ON;
    }
    if (qdisc.skip_sock_check) {
        flags |= TC_ETF_SKIP_SOCK_CHECK;
    }
    return tc_etf_qopt{.delta = qdisc.delta_ns, .clockid = qdisc.clockid, .flags = flags};
}

/// TCA_OPTIONS for an etf is a nest holding one TCA_ETF_PARMS.
[[nodiscard]] auto put_etf_options(Writer& writer, tc_etf_qopt const& qopt) noexcept -> bool
{
    auto slot = writer.reserve((2 * RTATTR_SIZE) + sizeof(qopt));
    if (slot.empty()) {
        return false;
    }
    write_attribute_header(slot, TCA_OPTIONS, RTATTR_SIZE + sizeof(qopt));
    write_attribute_header(slot.subspan(RTATTR_SIZE), TCA_ETF_PARMS, sizeof(qopt));
    std::memcpy(slot.data() + (2 * RTATTR_SIZE), &qopt, sizeof(qopt));
    return true;
}

[[nodiscard]] auto as_bytes(auto const& value) noexcept -> std::span<std::uint8_t const>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(&value), sizeof(value)};
}

}  // namespace

auto build_replace_mqprio(std::span<std::uint8_t> out, int ifindex, MqprioQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    if (auto status = validate_mqprio(qdisc); !status) {
        return forward_failure(status);
    }
    Writer writer{out};
    if (!put_preamble(writer, RTM_NEWQDISC, REPLACE_FLAGS, seq, ifindex, make_handle(qdisc.major, 0), ROOT) ||
        !put_kind(writer, "mqprio")) {
        return failure(NetError::invalid_argument);
    }
    auto const qopt = to_qopt(qdisc);
    if (!writer.put_attribute(TCA_OPTIONS, as_bytes(qopt))) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_replace_cbs(std::span<std::uint8_t> out, int ifindex, CbsQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    if (qdisc.handle_major == 0) {
        return failure(NetError::invalid_argument);
    }
    Writer writer{out};
    if (!put_preamble(writer, RTM_NEWQDISC, REPLACE_FLAGS, seq, ifindex, make_handle(qdisc.handle_major, 0), qdisc.parent) ||
        !put_kind(writer, "cbs")) {
        return failure(NetError::invalid_argument);
    }
    // TCA_OPTIONS is a nest holding one TCA_CBS_PARMS, so it is built by
    // hand rather than through put_attribute.
    auto const qopt = to_qopt(qdisc);
    if (!put_cbs_options(writer, qopt)) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_replace_etf(std::span<std::uint8_t> out, int ifindex, EtfQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    // TC_H_UNSPEC names no class, and sch_etf refuses a negative delta in
    // validate_input_params. Both are caught here rather than in a syscall.
    if (qdisc.parent == UNSPEC || qdisc.delta_ns < 0) {
        return failure(NetError::invalid_argument);
    }
    Writer writer{out};
    // Handle 0: nothing hangs off an etf, so the kernel may pick one.
    if (!put_preamble(writer, RTM_NEWQDISC, REPLACE_FLAGS, seq, ifindex, 0, qdisc.parent) || !put_kind(writer, "etf")) {
        return failure(NetError::invalid_argument);
    }
    auto const qopt = to_qopt(qdisc);
    if (!put_etf_options(writer, qopt)) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_replace_kind(std::span<std::uint8_t> out, int ifindex, std::uint32_t parent, std::string_view kind, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    if (auto status = validate_kind(kind); !status) {
        return forward_failure(status);
    }
    Writer writer{out};
    // Handle 0: let the kernel pick one, since nothing hangs off this.
    if (!put_preamble(writer, RTM_NEWQDISC, REPLACE_FLAGS, seq, ifindex, 0, parent) || !put_kind(writer, kind)) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_delete(std::span<std::uint8_t> out, int ifindex, std::uint32_t handle, std::uint32_t parent, std::uint32_t seq)
    -> StatusValue<std::size_t>
{
    Writer writer{out};
    if (!put_preamble(writer, RTM_DELQDISC, DELETE_FLAGS, seq, ifindex, handle, parent)) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

auto build_dump(std::span<std::uint8_t> out, int ifindex, std::uint32_t seq) -> StatusValue<std::size_t>
{
    Writer writer{out};
    // No NLM_F_ECHO, and a dump rather than a single-qdisc get: see the
    // first trap in the header. Handle and parent are left unspecified so
    // the kernel reports everything and we filter locally.
    if (!put_preamble(writer, RTM_GETQDISC, DUMP_FLAGS, seq, ifindex, 0, UNSPEC)) {
        return failure(NetError::invalid_argument);
    }
    return finish(writer);
}

namespace {

/// Validate the netlink header of a reply we intend to read as a qdisc.
[[nodiscard]] auto read_header(std::span<std::uint8_t const> message) noexcept -> StatusValue<nlmsghdr>
{
    if (message.size() < NLMSGHDR_SIZE) {
        return failure(NetError::invalid_argument);
    }
    nlmsghdr header{};
    std::memcpy(&header, message.data(), NLMSGHDR_SIZE);
    if (header.nlmsg_len < NLMSGHDR_SIZE + TCMSG_SIZE || header.nlmsg_len > message.size()) {
        return failure(NetError::invalid_argument);
    }
    // A dump reply stream carries other message types; a reader must skip
    // them, so a well-formed non-qdisc message is reported distinguishably
    // from a malformed one.
    if (header.nlmsg_type != RTM_NEWQDISC && header.nlmsg_type != RTM_DELQDISC) {
        return failure(NetError::not_supported);
    }
    return success(header);
}

[[nodiscard]] auto read_tcmsg(std::span<std::uint8_t const> message) noexcept -> tcmsg
{
    tcmsg body{};
    std::memcpy(&body, message.data() + NLMSGHDR_SIZE, TCMSG_SIZE);
    return body;
}

auto copy_kind(std::span<std::uint8_t const> payload, QdiscInfo& info) noexcept -> void
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const text = std::string_view{reinterpret_cast<char const*>(payload.data()), payload.size()};
    auto const name = text.substr(0, std::min(text.find('\0'), MAX_KIND_LENGTH));
    std::ranges::copy(name, info.kind.begin());
    info.kind[name.size()] = '\0';
}

auto store_cbs_params(std::span<std::uint8_t const> payload, QdiscInfo& info) noexcept -> void
{
    tc_cbs_qopt qopt{};
    std::memcpy(&qopt, payload.data(), sizeof(qopt));
    info.cbs = CbsQdisc{
        .parent = info.parent,
        .offload = qopt.offload != 0,
        .hicredit = qopt.hicredit,
        .locredit = qopt.locredit,
        .idleslope_kbps = qopt.idleslope,
        .sendslope_kbps = qopt.sendslope,
        .handle_major = handle_major(info.handle),
    };
    info.has_cbs_params = true;
}

/// Walk a nest of attributes looking for TCA_CBS_PARMS.
auto parse_cbs_options(std::span<std::uint8_t const> nest, QdiscInfo& info) noexcept -> void
{
    std::size_t at = 0;
    while (at + RTATTR_SIZE <= nest.size()) {
        rtattr attribute{};
        std::memcpy(&attribute, nest.data() + at, RTATTR_SIZE);
        if (attribute.rta_len < RTATTR_SIZE || at + attribute.rta_len > nest.size()) {
            return;
        }
        auto const payload = nest.subspan(at + RTATTR_SIZE, attribute.rta_len - RTATTR_SIZE);
        // A payload too small to hold the struct must not produce a
        // confident set of slopes: the shaper reads these back precisely to
        // learn what a driver clamped, so a guess is worse than nothing.
        if (attribute.rta_type == TCA_CBS_PARMS && payload.size() >= sizeof(tc_cbs_qopt)) {
            store_cbs_params(payload, info);
        }
        at += align4(attribute.rta_len);
    }
}

auto apply_attribute(std::uint16_t type, std::span<std::uint8_t const> payload, QdiscInfo& info) noexcept -> void
{
    if (type == TCA_KIND) {
        copy_kind(payload, info);
        return;
    }
    if (type == TCA_OPTIONS && info.kind_name() == "cbs") {
        parse_cbs_options(payload, info);
    }
}

/// Walk the attributes behind a tcmsg. A malformed rta_len stops the walk
/// rather than failing the parse: the handle, parent and kind already read
/// are still worth reporting, and an rta_len of 0 would otherwise make a
/// naive walk loop forever.
auto parse_attributes(std::span<std::uint8_t const> attributes, QdiscInfo& info) noexcept -> void
{
    std::size_t at = 0;
    while (at + RTATTR_SIZE <= attributes.size()) {
        rtattr attribute{};
        std::memcpy(&attribute, attributes.data() + at, RTATTR_SIZE);
        if (attribute.rta_len < RTATTR_SIZE || at + attribute.rta_len > attributes.size()) {
            return;
        }
        apply_attribute(attribute.rta_type, attributes.subspan(at + RTATTR_SIZE, attribute.rta_len - RTATTR_SIZE), info);
        at += align4(attribute.rta_len);
    }
}

/// Where the extended-ack TLVs begin inside an NLMSG_ERROR payload.
///
/// `nlmsgerr` is an int followed by a copy of the offending request's
/// header. Unless the kernel set NLM_F_CAPPED it also appends the rest of
/// the original request, and the TLVs come after all of it. Getting this
/// wrong reads the original request's bytes as attributes.
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

}  // namespace

auto parse_qdisc(std::span<std::uint8_t const> message) -> StatusValue<QdiscInfo>
{
    auto const header = read_header(message);
    if (!header) {
        return forward_failure(header);
    }
    auto const body = read_tcmsg(message);
    QdiscInfo info{.ifindex = body.tcm_ifindex, .handle = body.tcm_handle, .parent = body.tcm_parent};
    parse_attributes(message.subspan(PAYLOAD_START, header->nlmsg_len - PAYLOAD_START), info);
    return success(info);
}

namespace {

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

/// NLMSG_GOODSIZE: what the kernel assumes a reader's buffer holds.
constexpr std::size_t REPLY_BUFFER_SIZE = 8192;

/// A bound on how many reads one dump may take, so a stream that keeps
/// producing replies without ever reaching NLMSG_DONE cannot spin forever.
constexpr int MAX_DUMP_READS = 256;

/// How long a reply may take before we give up.
///
/// This bound is not theoretical. A read bound alone does not help when
/// the kernel sends *nothing*: recv() blocks, and the caller hangs. That
/// happens whenever a reply never arrives — a request the kernel answers
/// without a terminating NLMSG_DONE, a reply dropped under memory
/// pressure (netlink gives ENOBUFS and moves on), or a bug of our own in
/// the request flags. Netlink replies are local and immediate, so two
/// seconds is generous; a daemon that reports a timeout is strictly
/// better than one that stops.
constexpr time_t REPLY_TIMEOUT_SECONDS = 2;

/// A bound on how many datagrams read_ack() drains looking for its own
/// acknowledgement, so a socket somebody keeps feeding cannot hold it.
constexpr int MAX_ACK_READS = 16;

/// What NLMSG_DONE says about the dump. Its payload is the dump's own
/// return value, so a dump the kernel abandoned part way (-ENOBUFS, say)
/// is the failure it names, not a success with the qdisc "not found".
/// @param message The NLMSG_DONE, header included
[[nodiscard]] auto dump_outcome(std::span<std::uint8_t const> message) noexcept -> StatusValue<bool>
{
    int value = 0;
    if (message.size() < NLMSGHDR_SIZE + sizeof(value)) {
        return true;  // a bare NLMSG_DONE, as older kernels send
    }
    std::memcpy(&value, message.data() + NLMSGHDR_SIZE, sizeof(value));
    if (value < 0) {
        return failure(std::error_code{-value, std::generic_category()});
    }
    return true;
}

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
    // nl_pid left 0: the kernel assigns a unique port id, which is what we
    // then read back and filter replies against.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(fd, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) < 0) {
        return failure(NetError::bind_failed);
    }
    return success();
}

struct OpenedSocket
{
    FileDescriptor fd;
    std::uint32_t port_id{0};
};

[[nodiscard]] auto learn_port(FileDescriptor socket_fd) noexcept -> StatusValue<OpenedSocket>
{
    sockaddr_nl address{};
    socklen_t length = sizeof(address);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getsockname(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), &length) < 0) {
        return failure(NetError::socket_option_failed);
    }
    return success(OpenedSocket{.fd = std::move(socket_fd), .port_id = address.nl_pid});
}

/// Both options are advisory: an old kernel without NETLINK_EXT_ACK still
/// answers, just less helpfully, and a socket without SO_RCVTIMEO still
/// works until a reply goes missing. Neither failing is worth refusing to
/// open, so neither is checked.
auto configure_netlink(int fd) noexcept -> void
{
    // Without NETLINK_EXT_ACK the kernel sends only an errno and
    // last_message() can never be anything but empty.
    int const enable = 1;
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &enable, sizeof(enable));
    timeval const timeout{.tv_sec = REPLY_TIMEOUT_SECONDS, .tv_usec = 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

[[nodiscard]] auto open_netlink_socket() noexcept -> StatusValue<OpenedSocket>
{
    FileDescriptor socket_fd{::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)};
    if (!socket_fd.valid()) {
        return failure(NetError::socket_creation_failed);
    }
    configure_netlink(socket_fd.get());
    if (auto status = bind_netlink(socket_fd.get()); !status) {
        return forward_failure(status);
    }
    return learn_port(std::move(socket_fd));
}

}  // namespace

TcClient::~TcClient()
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

auto TcClient::open() -> Status
{
    if (fd_ >= 0) {
        return failure(NetError::already_connected);
    }
    auto opened = open_netlink_socket();
    if (!opened) {
        return forward_failure(opened);
    }
    fd_ = opened->fd.release();
    port_id_ = opened->port_id;
    return success();
}

auto TcClient::record_ack(std::span<std::uint8_t const> message) -> Status
{
    auto const ack = parse_ack(message);
    if (!ack) {
        return forward_failure(ack);
    }
    last_message_ = ack->message;
    if (ack->error != 0) {
        return failure(std::error_code{ack->error, std::generic_category()});
    }
    return success();
}

auto TcClient::find_ack(std::span<std::uint8_t const> reply, std::uint32_t seq) noexcept
    -> std::optional<std::span<std::uint8_t const>>
{
    std::size_t at = 0;
    while (at + NLMSGHDR_SIZE <= reply.size()) {
        nlmsghdr header{};
        std::memcpy(&header, reply.data() + at, NLMSGHDR_SIZE);
        if (header.nlmsg_len < NLMSGHDR_SIZE || at + header.nlmsg_len > reply.size()) {
            return std::nullopt;
        }
        if (header.nlmsg_seq == seq && header.nlmsg_type == NLMSG_ERROR) {
            return reply.subspan(at, header.nlmsg_len);
        }
        at += align4(header.nlmsg_len);
    }
    return std::nullopt;
}

auto TcClient::read_ack(std::uint32_t seq) -> Status
{
    std::array<std::uint8_t, REPLY_BUFFER_SIZE> buffer{};
    for (int reads = 0; reads < MAX_ACK_READS; ++reads) {
        ssize_t const received = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (received < 0) {
            return failure(recv_failure());
        }
        if (auto const ack = find_ack({buffer.data(), static_cast<std::size_t>(received)}, seq); ack) {
            return record_ack(*ack);
        }
        // Not ours: the late answer to a request that already timed out,
        // which taken as this one's would have put every call after it
        // one acknowledgement behind.
    }
    return failure(NetError::receive_failed);
}

auto TcClient::transact(std::span<std::uint8_t const> request) -> Status
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

auto TcClient::replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_replace_mqprio(request, ifindex, qdisc, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return transact({request.data(), *length});
}

auto TcClient::replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_replace_cbs(request, ifindex, qdisc, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return transact({request.data(), *length});
}

auto TcClient::replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_replace_etf(request, ifindex, qdisc, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return transact({request.data(), *length});
}

auto TcClient::replace_kind(int ifindex, std::uint32_t parent, std::string_view kind) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_replace_kind(request, ifindex, parent, kind, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return transact({request.data(), *length});
}

auto TcClient::remove(int ifindex, std::uint32_t handle, std::uint32_t parent) -> Status
{
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_delete(request, ifindex, handle, parent, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return transact({request.data(), *length});
}

auto TcClient::consider_reply(std::span<std::uint8_t const> message, DumpFilter const& filter, DumpMatch& match) noexcept -> void
{
    nlmsghdr header{};
    std::memcpy(&header, message.data(), NLMSGHDR_SIZE);
    // The port id check is trap 1's other half: a netlink socket can be
    // sent unsolicited multicast traffic, so a reply not addressed to our
    // own port is somebody else's business.
    //
    // Defensive today, and honestly so: this client never joins an
    // RTNLGRP_TC group, so nothing but our own replies reaches the socket
    // and removing the check fails no test. It stays because joining a
    // group is a one-line change somebody will make, and because the
    // consequence of getting it wrong -- reading another listener's qdisc
    // as our own read-back -- is silent.
    if (header.nlmsg_seq != filter.seq || header.nlmsg_pid != filter.port_id) {
        return;
    }
    auto const info = parse_qdisc(message);
    // A dump stream carries other message types; skipping them is correct.
    if (!info || info->ifindex != filter.ifindex || info->parent != filter.parent) {
        return;
    }
    match = DumpMatch{.info = *info, .matched = true};
}

auto TcClient::scan_dump_message(std::span<std::uint8_t const> message, DumpFilter const& filter, DumpMatch& match)
    -> StatusValue<bool>
{
    nlmsghdr header{};
    std::memcpy(&header, message.data(), NLMSGHDR_SIZE);
    if (header.nlmsg_seq == filter.seq && header.nlmsg_type == NLMSG_ERROR) {
        // The kernel refused the dump. Skipped as "another message type"
        // this would leave the read waiting out SO_RCVTIMEO for an
        // NLMSG_DONE that never comes, and the caller told timed_out for
        // what was an errno with a message attached.
        if (auto status = record_ack(message); !status) {
            return forward_failure(status);
        }
        return true;
    }
    if (header.nlmsg_type == NLMSG_DONE) {
        return dump_outcome(message);
    }
    consider_reply(message, filter, match);
    return false;
}

auto TcClient::scan_dump_chunk(std::span<std::uint8_t const> chunk, DumpFilter const& filter, DumpMatch& match) -> StatusValue<bool>
{
    std::size_t at = 0;
    while (at + NLMSGHDR_SIZE <= chunk.size()) {
        nlmsghdr header{};
        std::memcpy(&header, chunk.data() + at, NLMSGHDR_SIZE);
        if (header.nlmsg_len < NLMSGHDR_SIZE || at + header.nlmsg_len > chunk.size()) {
            return false;
        }
        auto const done = scan_dump_message(chunk.subspan(at, header.nlmsg_len), filter, match);
        if (!done || *done) {
            return done;
        }
        at += align4(header.nlmsg_len);
    }
    return false;
}

auto TcClient::read_dump_stream(DumpFilter const& filter, DumpMatch& match) -> Status
{
    std::array<std::uint8_t, REPLY_BUFFER_SIZE> buffer{};
    for (int reads = 0; reads < MAX_DUMP_READS; ++reads) {
        ssize_t const received = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (received < 0) {
            return failure(recv_failure());
        }
        auto const done = scan_dump_chunk({buffer.data(), static_cast<std::size_t>(received)}, filter, match);
        if (!done) {
            return forward_failure(done);
        }
        if (*done) {
            return success();
        }
    }
    return failure(NetError::receive_failed);
}

auto TcClient::dump_and_find(std::span<std::uint8_t const> request, int ifindex, std::uint32_t parent) -> StatusValue<QdiscInfo>
{
    if (::send(fd_, request.data(), request.size(), 0) < 0) {
        return failure(NetError::send_failed);
    }
    // The stream is read to NLMSG_DONE even once a match is found. Leaving
    // replies in the socket is not harmless: the next request's read picks
    // them up and reads a leftover NLMSG_DONE as that request's
    // acknowledgement, which looks like success.
    DumpFilter const filter{.seq = sequence_of(request), .port_id = port_id_, .ifindex = ifindex, .parent = parent};
    DumpMatch match{};
    if (auto status = read_dump_stream(filter, match); !status) {
        return forward_failure(status);
    }
    if (!match.matched) {
        return failure(NetError::invalid_handle);
    }
    return success(match.info);
}

auto TcClient::get(int ifindex, std::uint32_t parent) -> StatusValue<QdiscInfo>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }
    last_message_.clear();
    std::array<std::uint8_t, MAX_REQUEST_SIZE> request{};
    auto const length = build_dump(request, ifindex, next_sequence());
    if (!length) {
        return forward_failure(length);
    }
    return dump_and_find({request.data(), *length}, ifindex, parent);
}

}  // namespace statusbar::net::tc

#endif  // __linux__
