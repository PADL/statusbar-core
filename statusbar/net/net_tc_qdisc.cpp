// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_qdisc.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/net/net_posix_util.hpp"

#    include <cerrno>
#    include <cstddef>
#    include <cstring>
#    include <system_error>
#    include <utility>

#    include <linux/netlink.h>
#    include <linux/pkt_sched.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>
#    include <sys/time.h>

namespace statusbar::net::tc {

// The layouts the builders write field by field.
static_assert(sizeof(nlmsghdr) == 16);
static_assert(sizeof(tcmsg) == 20);
static_assert(offsetof(tcmsg, tcm_ifindex) == 4 && offsetof(tcmsg, tcm_handle) == 8 && offsetof(tcmsg, tcm_parent) == 12);
static_assert(sizeof(rtattr) == 4);
static_assert(sizeof(tc_mqprio_qopt) == 82);
static_assert(offsetof(tc_mqprio_qopt, prio_tc_map) == 1 && offsetof(tc_mqprio_qopt, hw) == 17);
static_assert(offsetof(tc_mqprio_qopt, count) == 18 && offsetof(tc_mqprio_qopt, offset) == 50);
static_assert(sizeof(tc_cbs_qopt) == 20);
static_assert(offsetof(tc_cbs_qopt, hicredit) == 4 && offsetof(tc_cbs_qopt, sendslope) == 16);
static_assert(PRIORITY_COUNT == TC_QOPT_BITMASK + 1 && MAX_TRAFFIC_CLASSES == TC_QOPT_MAX_QUEUE);
static_assert(ROOT == TC_H_ROOT);

namespace {

constexpr size_t NLMSG_HEADER = sizeof(nlmsghdr);
constexpr size_t TCMSG_SIZE = sizeof(tcmsg);
constexpr size_t RTA_HEADER = sizeof(rtattr);
constexpr uint16_t REPLACE_FLAGS = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
constexpr uint16_t DELETE_FLAGS = NLM_F_REQUEST | NLM_F_ACK;
/// A dump ends with NLMSG_DONE; NLM_F_ACK would add nothing.
constexpr uint16_t DUMP_FLAGS = NLM_F_REQUEST | NLM_F_DUMP;
/// The receive buffer: a dump part is at most the larger of a page and the
/// buffer we read with (netlink_dump's alloc_min_size).
constexpr size_t REPLY_SIZE = 32768;
/// IFNAMSIZ-style bound on a qdisc kind (TCA_KIND is a string of at most 15 bytes + NUL in practice).
constexpr size_t MAX_KIND = 15;

/// RTA_ALIGN / NLMSG_ALIGN (both 4) as a constexpr function, for the sizes.
[[nodiscard]] constexpr auto align4(size_t const n) noexcept -> size_t
{
    return RTA_ALIGN(n);
}
static_assert(RTA_ALIGN(1) == NLMSG_ALIGN(1) && RTA_ALIGN(5) == 8 && NLMSG_ALIGN(86) == 88);

void put_nlmsghdr(BufferSerializerBuilder& b, size_t const length, uint16_t const type, uint16_t const flags, uint32_t const seq)
{
    b.append(static_cast<uint32_t>(length)).append(type).append(flags).append(seq).append(uint32_t{0});  // nlmsg_pid: the kernel
}

void put_tcmsg(BufferSerializerBuilder& b, int const ifindex, uint32_t const handle, uint32_t const parent)
{
    b.append(uint8_t{AF_UNSPEC})  // tcm_family
        .append(uint8_t{0})       // tcm__pad1
        .append(uint16_t{0})      // tcm__pad2
        .append(static_cast<int32_t>(ifindex))
        .append(handle)
        .append(parent)
        .append(uint32_t{0});  // tcm_info
}

void put_rta(BufferSerializerBuilder& b, size_t const payload, uint16_t const type)
{
    b.append(static_cast<uint16_t>(RTA_HEADER + payload)).append(type);
}

void put_pad(BufferSerializerBuilder& b, size_t const count)
{
    for (size_t i = 0; i < count; ++i) {
        b.append(uint8_t{0});
    }
}

/// TCA_KIND: the NUL-terminated name, padded to 4.
void put_kind(BufferSerializerBuilder& b, std::string_view const kind)
{
    put_rta(b, kind.size() + 1, TCA_KIND);
    for (char const c : kind) {
        b.append(static_cast<uint8_t>(c));
    }
    b.append(uint8_t{0});
    put_pad(b, align4(RTA_HEADER + kind.size() + 1) - (RTA_HEADER + kind.size() + 1));
}

[[nodiscard]] constexpr auto kind_size(std::string_view const kind) noexcept -> size_t
{
    return align4(RTA_HEADER + kind.size() + 1);
}

[[nodiscard]] auto finish(BufferSerializerBuilder const& b, size_t const expected) -> StatusValue<size_t>
{
    if (b.error()) {
        return failure(b.error());
    }
    if (b.position() != expected) {  // a builder's length arithmetic is wrong
        return failure(std::make_error_code(std::errc::message_size));
    }
    return expected;
}

/// Usable mqprio settings: major 0 would give the per-queue classes ids
/// 0:1..N, which do not exist; every priority maps to one of num_tc classes.
[[nodiscard]] auto valid_mqprio(MqprioQdisc const& qdisc) noexcept -> bool
{
    if (qdisc.major == 0 || qdisc.num_tc == 0 || qdisc.num_tc > MAX_TRAFFIC_CLASSES) {
        return false;
    }
    for (uint8_t const tc : qdisc.prio_tc_map) {
        if (tc >= qdisc.num_tc) {
            return false;
        }
    }
    return true;
}

}  // namespace

auto build_replace_mqprio(std::span<uint8_t> const out, int const ifindex, MqprioQdisc const& qdisc, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the mqprio request, field by field
    if (!valid_mqprio(qdisc)) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    constexpr std::string_view KIND = "mqprio";
    constexpr size_t QOPT = sizeof(tc_mqprio_qopt);
    size_t const length = NLMSG_HEADER + TCMSG_SIZE + kind_size(KIND) + align4(RTA_HEADER + QOPT);

    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_nlmsghdr(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, make_handle(qdisc.major, 0), ROOT);
    put_kind(b, KIND);
    // TCA_OPTIONS is the flat struct tc_mqprio_qopt (q_mqprio.c: addattr_l(TCA_OPTIONS, &opt)).
    put_rta(b, QOPT, TCA_OPTIONS);
    b.append(qdisc.num_tc);
    for (uint8_t const tc : qdisc.prio_tc_map) {
        b.append(tc);
    }
    b.append(static_cast<uint8_t>(qdisc.hw ? TC_MQPRIO_HW_OFFLOAD_TCS : TC_MQPRIO_HW_OFFLOAD_NONE));
    for (uint16_t const count : qdisc.count) {
        b.append(count);
    }
    for (uint16_t const offset : qdisc.offset) {
        b.append(offset);
    }
    put_pad(b, align4(RTA_HEADER + QOPT) - (RTA_HEADER + QOPT));
    return finish(b, length);
}

auto build_replace_cbs(std::span<uint8_t> const out, int const ifindex, CbsQdisc const& qdisc, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the cbs request, field by field
    constexpr std::string_view KIND = "cbs";
    constexpr size_t QOPT = sizeof(tc_cbs_qopt);
    constexpr size_t PARMS = RTA_HEADER + QOPT;  // 24: already aligned
    size_t const length = NLMSG_HEADER + TCMSG_SIZE + kind_size(KIND) + RTA_HEADER + PARMS;

    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_nlmsghdr(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, qdisc.parent);
    put_kind(b, KIND);
    // TCA_OPTIONS nests TCA_CBS_PARMS (q_cbs.c: addattr_nest + addattr_l(TCA_CBS_PARMS, &opt)).
    put_rta(b, PARMS, TCA_OPTIONS);
    put_rta(b, QOPT, TCA_CBS_PARMS);
    b.append(static_cast<uint8_t>(qdisc.offload ? 1 : 0));
    put_pad(b, 3);
    b.append(qdisc.hicredit).append(qdisc.locredit).append(qdisc.idleslope_kbps).append(qdisc.sendslope_kbps);
    return finish(b, length);
}

auto build_replace_kind(
    std::span<uint8_t> const out, int const ifindex, uint32_t const parent, std::string_view const kind, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    if (kind.empty() || kind.size() > MAX_KIND) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    size_t const length = NLMSG_HEADER + TCMSG_SIZE + kind_size(kind);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_nlmsghdr(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, parent);
    put_kind(b, kind);
    return finish(b, length);
}

auto build_delete(std::span<uint8_t> const out, int const ifindex, uint32_t const handle, uint32_t const parent, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t length = NLMSG_HEADER + TCMSG_SIZE;
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_nlmsghdr(b, length, RTM_DELQDISC, DELETE_FLAGS, seq);
    put_tcmsg(b, ifindex, handle, parent);
    return finish(b, length);
}

auto build_dump(std::span<uint8_t> const out, int const ifindex, uint32_t const seq) -> StatusValue<size_t>
{
    constexpr size_t length = NLMSG_HEADER + TCMSG_SIZE;
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_nlmsghdr(b, length, RTM_GETQDISC, DUMP_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, 0);
    return finish(b, length);
}

namespace {

template <typename T>
[[nodiscard]] auto read_at(std::span<uint8_t const> const bytes, size_t const at) noexcept -> T
{
    T value{};
    std::memcpy(&value, bytes.data() + at, sizeof(T));
    return value;
}

[[nodiscard]] auto bad_message() noexcept -> std::error_code
{
    return std::make_error_code(std::errc::bad_message);
}

/// The flat tc_mqprio_qopt at the head of mqprio's TCA_OPTIONS.
[[nodiscard]] auto parse_mqprio(std::span<uint8_t const> const options, uint32_t const handle) -> StatusValue<MqprioQdisc>
{  // NOLINT(statusbar-block-statements): tc_mqprio_qopt, field by field
    if (options.size() < sizeof(tc_mqprio_qopt)) {
        return failure(bad_message());
    }
    MqprioQdisc q{};
    q.major = static_cast<uint16_t>(handle >> 16U);
    q.num_tc = options[offsetof(tc_mqprio_qopt, num_tc)];
    for (size_t i = 0; i < PRIORITY_COUNT; ++i) {
        q.prio_tc_map[i] = options[offsetof(tc_mqprio_qopt, prio_tc_map) + i];
    }
    q.hw = options[offsetof(tc_mqprio_qopt, hw)] != TC_MQPRIO_HW_OFFLOAD_NONE;
    for (size_t i = 0; i < MAX_TRAFFIC_CLASSES; ++i) {
        q.count[i] = read_at<uint16_t>(options, offsetof(tc_mqprio_qopt, count) + (i * sizeof(uint16_t)));
        q.offset[i] = read_at<uint16_t>(options, offsetof(tc_mqprio_qopt, offset) + (i * sizeof(uint16_t)));
    }
    return q;
}

/// TCA_CBS_PARMS inside cbs's nested TCA_OPTIONS.
[[nodiscard]] auto parse_cbs(std::span<uint8_t const> const options, uint32_t const parent) -> StatusValue<CbsQdisc>
{
    size_t at = 0;
    while (at + RTA_HEADER <= options.size()) {
        auto const len = read_at<uint16_t>(options, at);
        auto const type = read_at<uint16_t>(options, at + 2);
        if (len < RTA_HEADER || at + len > options.size()) {
            return failure(bad_message());
        }
        if ((type & NLA_TYPE_MASK) == TCA_CBS_PARMS) {
            if (len < RTA_HEADER + sizeof(tc_cbs_qopt)) {
                return failure(bad_message());
            }
            auto const parms = options.subspan(at + RTA_HEADER, sizeof(tc_cbs_qopt));
            return CbsQdisc{
                .parent = parent,
                .offload = parms[offsetof(tc_cbs_qopt, offload)] != 0,
                .hicredit = read_at<int32_t>(parms, offsetof(tc_cbs_qopt, hicredit)),
                .locredit = read_at<int32_t>(parms, offsetof(tc_cbs_qopt, locredit)),
                .idleslope_kbps = read_at<int32_t>(parms, offsetof(tc_cbs_qopt, idleslope)),
                .sendslope_kbps = read_at<int32_t>(parms, offsetof(tc_cbs_qopt, sendslope)),
            };
        }
        at += align4(len);
    }
    return failure(bad_message());
}

/// @p bytes without its trailing NULs.
[[nodiscard]] auto without_trailing_nuls(std::span<uint8_t const> const bytes) noexcept -> std::span<uint8_t const>
{
    size_t n = bytes.size();
    while (n > 0 && bytes[n - 1] == 0) {
        --n;
    }
    return bytes.first(n);
}

/// The tcmsg fields of a qdisc message at least NLMSG_HEADER + TCMSG_SIZE long.
[[nodiscard]] auto read_tcmsg(std::span<uint8_t const> const message) -> QdiscInfo
{
    QdiscInfo info{};
    info.ifindex = read_at<int32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_ifindex));
    info.handle = read_at<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_handle));
    info.parent = read_at<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_parent));
    return info;
}

/// Decode the TCA_OPTIONS of a kind we know (mqprio, cbs) into @p info;
/// bad_message when that kind has none.
[[nodiscard]] auto parse_options(QdiscInfo& info, std::optional<std::span<uint8_t const>> const options) -> Status
{
    if (info.kind == "mqprio") {
        if (!options) {
            return failure(bad_message());
        }
        auto mqprio = parse_mqprio(*options, info.handle);
        if (!mqprio) {
            return failure(mqprio.error());
        }
        info.mqprio = *mqprio;
    } else if (info.kind == "cbs") {
        if (!options) {
            return failure(bad_message());
        }
        auto cbs = parse_cbs(*options, info.parent);
        if (!cbs) {
            return failure(cbs.error());
        }
        info.cbs = *cbs;
    }
    return success();
}

/// Walk the attributes after the tcmsg of @p body: TCA_KIND names
/// info.kind, then the kind's TCA_OPTIONS are decoded (parse_options).
[[nodiscard]] auto parse_attributes(std::span<uint8_t const> const body, QdiscInfo& info) -> Status
{
    std::optional<std::span<uint8_t const>> options;
    size_t at = NLMSG_HEADER + TCMSG_SIZE;
    while (at + RTA_HEADER <= body.size()) {
        auto const len = read_at<uint16_t>(body, at);
        auto const type = read_at<uint16_t>(body, at + 2);
        if (len < RTA_HEADER || at + len > body.size()) {
            return failure(bad_message());
        }
        auto const payload = body.subspan(at + RTA_HEADER, len - RTA_HEADER);
        if (type == TCA_KIND) {
            auto const kind = without_trailing_nuls(payload);
            info.kind.assign(kind.begin(), kind.end());
        } else if ((type & NLA_TYPE_MASK) == TCA_OPTIONS) {
            options = payload;
        }
        at += align4(len);
    }
    return parse_options(info, options);
}

/// A dump's NLMSG_DONE: its payload is the dump's error (0 when complete).
[[nodiscard]] auto dump_status(std::span<uint8_t const> const message) -> Status
{
    int error = 0;
    if (message.size() >= NLMSG_HEADER + sizeof(error)) {
        error = read_at<int>(message, NLMSG_HEADER);
    }
    return error == 0 ? success() : failure(std::error_code{-error, std::system_category()});
}

/// Copy the extended ack's NLMSGERR_ATTR_MSG, if any, into @p text.
void read_ext_ack_message(
    std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text)
{
    size_t const skip = (flags & NLM_F_CAPPED) != 0 ? sizeof(nlmsgerr) : sizeof(nlmsgerr) + request_size - NLMSG_HEADER;
    size_t at = NLMSG_HEADER + align4(skip);
    while (at + RTA_HEADER <= message.size()) {
        auto const len = read_at<uint16_t>(message, at);
        auto const type = read_at<uint16_t>(message, at + 2);
        if (len < RTA_HEADER || at + len > message.size()) {
            return;
        }
        if ((type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG) {
            auto const found = without_trailing_nuls(message.subspan(at + RTA_HEADER, len - RTA_HEADER));
            text.assign(found.begin(), found.end());
            return;
        }
        at += align4(len);
    }
}

/// An NLMSG_ERROR: struct nlmsgerr (int error, then the request's header,
/// capped), then extended-ack TLVs, whose message goes to @p text.
[[nodiscard]] auto ack_status(
    std::span<uint8_t const> const message, uint16_t const flags, size_t const request_size, std::string& text) -> Status
{
    if (message.size() < NLMSG_HEADER + sizeof(nlmsgerr)) {
        return failure(std::make_error_code(std::errc::bad_message));
    }
    auto const error = read_at<int>(message, NLMSG_HEADER);
    if (error == 0) {
        return success();
    }
    if ((flags & NLM_F_ACK_TLVS) != 0) {
        read_ext_ack_message(message, flags, request_size, text);
    }
    return failure(std::error_code{-error, std::system_category()});
}

/// Bind netlink socket @p fd to a port id the kernel assigns: that id.
[[nodiscard]] auto bind_port_id(int const fd) -> StatusValue<uint32_t>
{
    sockaddr_nl const local{.nl_family = AF_NETLINK, .nl_pad = 0, .nl_pid = 0, .nl_groups = 0};
    if (::bind(fd, sockaddr_cast(local), sizeof(local)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    sockaddr_nl bound{};
    socklen_t bound_size = sizeof(bound);
    if (::getsockname(fd, sockaddr_cast(bound), &bound_size) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    return bound.nl_pid;
}

/// Set up route socket @p fd (acks, a 1 s receive timeout) and bind it: its port id.
[[nodiscard]] auto configure_route_socket(int const fd) -> StatusValue<uint32_t>
{
    // Extended acks carry the kernel's reason ("Change operation not
    // supported", "Specified device does not support offload"); capped acks
    // keep our request out of the reply. Both are best effort.
    int const on = 1;
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &on, sizeof(on));
    (void)::setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof(on));
    timeval const timeout{.tv_sec = 1, .tv_usec = 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    return bind_port_id(fd);
}

}  // namespace

auto parse_qdisc(std::span<uint8_t const> const message) -> StatusValue<QdiscInfo>
{
    if (message.size() < NLMSG_HEADER + TCMSG_SIZE) {
        return failure(bad_message());
    }
    auto const length = read_at<uint32_t>(message, offsetof(nlmsghdr, nlmsg_len));
    if (length < NLMSG_HEADER + TCMSG_SIZE || length > message.size() ||
        read_at<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) != RTM_NEWQDISC) {
        return failure(bad_message());
    }
    auto info = read_tcmsg(message);
    if (auto status = parse_attributes(message.first(length), info); !status) {
        return failure(status.error());
    }
    return info;
}

//
// TcClient
//

auto TcClient::open() noexcept -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (!fd.valid()) {
        return failure(std::error_code{errno, std::system_category()});
    }
    return configure_route_socket(fd.get()).transform([&](uint32_t const portid) {
        portid_ = portid;
        reply_.assign(REPLY_SIZE, 0);
        fd_ = std::move(fd);
    });
}

auto TcClient::replace_mqprio(int const ifindex, MqprioQdisc const& qdisc) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_mqprio(out, ifindex, qdisc, seq); });
}

auto TcClient::replace_cbs(int const ifindex, CbsQdisc const& qdisc) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_cbs(out, ifindex, qdisc, seq); });
}

auto TcClient::replace_kind(int const ifindex, uint32_t const parent, std::string_view const kind) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_kind(out, ifindex, parent, kind, seq); });
}

auto TcClient::remove(int const ifindex, uint32_t const handle, uint32_t const parent) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_delete(out, ifindex, handle, parent, seq); });
}

auto TcClient::get(int const ifindex, uint32_t const parent) -> StatusValue<QdiscInfo>
{
    QdiscInfo info{};
    Wanted wanted{.ifindex = ifindex, .parent = parent, .found = &info};
    if (auto status = send([&](std::span<uint8_t> out, uint32_t seq) { return build_dump(out, ifindex, seq); }, &wanted); !status) {
        return failure(status.error());
    }
    if (!wanted.came) {
        return failure(std::make_error_code(std::errc::no_such_file_or_directory));
    }
    return info;
}

auto TcClient::transact(std::span<uint8_t const> const request, uint32_t const seq, Wanted* const wanted) -> Status
{
    last_message_.clear();
    if (!fd_.valid()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(fd_.get(), request.data(), request.size(), 0, sockaddr_cast(kernel), sizeof(kernel)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    for (;;) {
        // MSG_TRUNC: the length of the datagram even when it did not fit.
        ssize_t const received = ::recv(fd_.get(), reply_.data(), reply_.size(), MSG_TRUNC);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return failure(std::make_error_code(std::errc::timed_out));
            }
            return failure(std::error_code{errno, std::system_category()});
        }
        if (static_cast<size_t>(received) > reply_.size()) {
            return failure(std::make_error_code(std::errc::message_size));
        }
        if (auto done = read_replies(static_cast<size_t>(received), request.size(), seq, wanted)) {
            return *done;
        }
    }
}

auto TcClient::read_replies(size_t const received, size_t const request_size, uint32_t const seq, Wanted* const wanted)
    -> std::optional<Status>
{
    std::span<uint8_t const> const reply{reply_.data(), received};
    for (size_t offset = 0; offset + NLMSG_HEADER <= reply.size();) {
        auto const header = read_at<nlmsghdr>(reply, offset);
        if (header.nlmsg_len < NLMSG_HEADER || header.nlmsg_len > reply.size() - offset) {
            return failure(std::make_error_code(std::errc::bad_message));
        }
        if (header.nlmsg_seq == seq && header.nlmsg_pid == portid_) {
            if (auto done = read_reply(reply.subspan(offset, header.nlmsg_len), request_size, wanted)) {
                return done;
            }
        }
        offset += align4(header.nlmsg_len);
    }
    return std::nullopt;
}

auto TcClient::read_reply(std::span<uint8_t const> const message, size_t const request_size, Wanted* const wanted)
    -> std::optional<Status>
{
    auto const header = read_at<nlmsghdr>(message, 0);
    if (header.nlmsg_type == NLMSG_DONE && wanted != nullptr) {
        return dump_status(message);
    }
    if (header.nlmsg_type == RTM_NEWQDISC && wanted != nullptr && !wanted->came && message.size() >= NLMSG_HEADER + TCMSG_SIZE) {
        return take_qdisc(message, *wanted);
    }
    if (header.nlmsg_type == NLMSG_ERROR) {
        return ack_status(message, header.nlmsg_flags, request_size, last_message_);
    }
    return std::nullopt;
}

auto TcClient::take_qdisc(std::span<uint8_t const> const message, Wanted& wanted) -> std::optional<Status>
{
    auto const ifindex = read_at<int32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_ifindex));
    auto const parent = read_at<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_parent));
    if (ifindex == wanted.ifindex && parent == wanted.parent) {
        auto parsed = parse_qdisc(message);
        if (!parsed) {
            return failure(parsed.error());
        }
        *wanted.found = std::move(*parsed);
        wanted.came = true;
    }
    return std::nullopt;
}

}  // namespace statusbar::net::tc

#endif  // __linux__
