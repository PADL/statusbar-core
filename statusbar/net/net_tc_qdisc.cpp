// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_qdisc.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"

#    include <cstddef>
#    include <ctime>
#    include <optional>
#    include <system_error>
#    include <utility>

#    include <linux/netlink.h>
#    include <linux/pkt_sched.h>
#    include <linux/rtnetlink.h>
#    include <sys/socket.h>

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
static_assert(sizeof(tc_etf_qopt) == 12);
static_assert(offsetof(tc_etf_qopt, clockid) == 4 && offsetof(tc_etf_qopt, flags) == 8);
static_assert(ETF_CLOCK_TAI == CLOCK_TAI);
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
/// IFNAMSIZ-style bound on a qdisc kind (TCA_KIND is a string of at most 15 bytes + NUL in practice).
constexpr size_t MAX_KIND = 15;

using netlink::align4;
static_assert(align4(5) == RTA_ALIGN(5) && align4(86) == NLMSG_ALIGN(86));

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
    netlink::put_header(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
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
    return netlink::finish(b, length);
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
    netlink::put_header(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, qdisc.parent);
    put_kind(b, KIND);
    // TCA_OPTIONS nests TCA_CBS_PARMS (q_cbs.c: addattr_nest + addattr_l(TCA_CBS_PARMS, &opt)).
    put_rta(b, PARMS, TCA_OPTIONS);
    put_rta(b, QOPT, TCA_CBS_PARMS);
    b.append(static_cast<uint8_t>(qdisc.offload ? 1 : 0));
    put_pad(b, 3);
    b.append(qdisc.hicredit).append(qdisc.locredit).append(qdisc.idleslope_kbps).append(qdisc.sendslope_kbps);
    return netlink::finish(b, length);
}

auto build_replace_etf(std::span<uint8_t> const out, int const ifindex, EtfQdisc const& qdisc, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the etf request, field by field
    constexpr std::string_view KIND = "etf";
    constexpr size_t QOPT = sizeof(tc_etf_qopt);
    constexpr size_t PARMS = RTA_HEADER + QOPT;  // 16: already aligned
    size_t const length = NLMSG_HEADER + TCMSG_SIZE + kind_size(KIND) + RTA_HEADER + PARMS;
    uint32_t const flags = (qdisc.deadline_mode ? TC_ETF_DEADLINE_MODE_ON : 0U) | (qdisc.offload ? TC_ETF_OFFLOAD_ON : 0U) |
        (qdisc.skip_sock_check ? TC_ETF_SKIP_SOCK_CHECK : 0U);

    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, qdisc.parent);
    put_kind(b, KIND);
    // TCA_OPTIONS nests TCA_ETF_PARMS (q_etf.c: addattr_nest + addattr_l(TCA_ETF_PARMS, &opt)).
    put_rta(b, PARMS, TCA_OPTIONS);
    put_rta(b, QOPT, TCA_ETF_PARMS);
    b.append(qdisc.delta_ns).append(qdisc.clockid).append(flags);
    return netlink::finish(b, length);
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
    netlink::put_header(b, length, RTM_NEWQDISC, REPLACE_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, parent);
    put_kind(b, kind);
    return netlink::finish(b, length);
}

auto build_delete(std::span<uint8_t> const out, int const ifindex, uint32_t const handle, uint32_t const parent, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t length = NLMSG_HEADER + TCMSG_SIZE;
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, length, RTM_DELQDISC, DELETE_FLAGS, seq);
    put_tcmsg(b, ifindex, handle, parent);
    return netlink::finish(b, length);
}

auto build_dump(std::span<uint8_t> const out, int const ifindex, uint32_t const seq) -> StatusValue<size_t>
{
    constexpr size_t length = NLMSG_HEADER + TCMSG_SIZE;
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    netlink::put_header(b, length, RTM_GETQDISC, DUMP_FLAGS, seq);
    put_tcmsg(b, ifindex, 0, 0);
    return netlink::finish(b, length);
}

namespace {

using netlink::bad_message;
using netlink::load;
using netlink::walk_attributes;
using netlink::without_trailing_nuls;

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
        q.count[i] = load<uint16_t>(options, offsetof(tc_mqprio_qopt, count) + (i * sizeof(uint16_t)));
        q.offset[i] = load<uint16_t>(options, offsetof(tc_mqprio_qopt, offset) + (i * sizeof(uint16_t)));
    }
    return q;
}

/// TCA_CBS_PARMS inside cbs's nested TCA_OPTIONS.
[[nodiscard]] auto parse_cbs(std::span<uint8_t const> const options, uint32_t const parent) -> StatusValue<CbsQdisc>
{
    auto const found = netlink::find_attribute(options, TCA_CBS_PARMS);
    if (!found || !*found || (*found)->size() < sizeof(tc_cbs_qopt)) {
        return failure(bad_message());
    }
    auto const parms = **found;
    return CbsQdisc{
        .parent = parent,
        .offload = parms[offsetof(tc_cbs_qopt, offload)] != 0,
        .hicredit = load<int32_t>(parms, offsetof(tc_cbs_qopt, hicredit)),
        .locredit = load<int32_t>(parms, offsetof(tc_cbs_qopt, locredit)),
        .idleslope_kbps = load<int32_t>(parms, offsetof(tc_cbs_qopt, idleslope)),
        .sendslope_kbps = load<int32_t>(parms, offsetof(tc_cbs_qopt, sendslope)),
    };
}

/// TCA_ETF_PARMS inside etf's nested TCA_OPTIONS.
[[nodiscard]] auto parse_etf(std::span<uint8_t const> const options, uint32_t const parent) -> StatusValue<EtfQdisc>
{
    auto const found = netlink::find_attribute(options, TCA_ETF_PARMS);
    if (!found || !*found || (*found)->size() < sizeof(tc_etf_qopt)) {
        return failure(bad_message());
    }
    auto const parms = **found;
    auto const flags = load<uint32_t>(parms, offsetof(tc_etf_qopt, flags));
    return EtfQdisc{
        .parent = parent,
        .clockid = load<int32_t>(parms, offsetof(tc_etf_qopt, clockid)),
        .delta_ns = load<int32_t>(parms, offsetof(tc_etf_qopt, delta)),
        .offload = (flags & TC_ETF_OFFLOAD_ON) != 0,
        .deadline_mode = (flags & TC_ETF_DEADLINE_MODE_ON) != 0,
        .skip_sock_check = (flags & TC_ETF_SKIP_SOCK_CHECK) != 0,
    };
}

/// The tcmsg fields of a qdisc message at least NLMSG_HEADER + TCMSG_SIZE long.
[[nodiscard]] auto read_tcmsg(std::span<uint8_t const> const message) noexcept -> QdiscInfo
{
    QdiscInfo info{};
    info.ifindex = load<int32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_ifindex));
    info.handle = load<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_handle));
    info.parent = load<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_parent));
    return info;
}

/// @p parse (options -> StatusValue<T>) applied to @p options, into @p out; bad_message when
/// the kind came without options.
template <typename T, typename Parse>
[[nodiscard]] auto decode_into(std::optional<std::span<uint8_t const>> const options, Parse const& parse, std::optional<T>& out)
    -> Status
{
    if (!options) {
        return failure(bad_message());
    }
    auto parsed = parse(*options);
    if (!parsed) {
        return failure(parsed.error());
    }
    out = *parsed;
    return success();
}

/// Decode the TCA_OPTIONS of a kind we know (mqprio, cbs, etf) into @p info;
/// bad_message when that kind has none.
[[nodiscard]] auto parse_options(QdiscInfo& info, std::optional<std::span<uint8_t const>> const options) -> Status
{
    using Options = std::span<uint8_t const>;
    if (info.kind == "mqprio") {
        return decode_into(options, [&](Options const o) { return parse_mqprio(o, info.handle); }, info.mqprio);
    }
    if (info.kind == "cbs") {
        return decode_into(options, [&](Options const o) { return parse_cbs(o, info.parent); }, info.cbs);
    }
    if (info.kind == "etf") {
        return decode_into(options, [&](Options const o) { return parse_etf(o, info.parent); }, info.etf);
    }
    return success();
}

/// Walk the attributes after the tcmsg of @p body: TCA_KIND names
/// info.kind, then the kind's TCA_OPTIONS are decoded (parse_options).
[[nodiscard]] auto parse_attributes(std::span<uint8_t const> const body, QdiscInfo& info) -> Status
{
    std::optional<std::span<uint8_t const>> options;
    auto const walked = walk_attributes(
        body.subspan(NLMSG_HEADER + TCMSG_SIZE), [&](uint16_t const type, std::span<uint8_t const> const payload) -> Status {
            if (type == TCA_KIND) {
                auto const kind = without_trailing_nuls(payload);
                info.kind.assign(kind.begin(), kind.end());
            } else if ((type & NLA_TYPE_MASK) == TCA_OPTIONS) {
                options = payload;
            }
            return success();
        });
    return walked ? parse_options(info, options) : walked;
}

}  // namespace

auto parse_qdisc(std::span<uint8_t const> const message) -> StatusValue<QdiscInfo>
{
    if (message.size() < NLMSG_HEADER + TCMSG_SIZE) {
        return failure(bad_message());
    }
    auto const length = load<uint32_t>(message, offsetof(nlmsghdr, nlmsg_len));
    if (length < NLMSG_HEADER + TCMSG_SIZE || length > message.size() ||
        load<uint16_t>(message, offsetof(nlmsghdr, nlmsg_type)) != RTM_NEWQDISC) {
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
    return socket_.open(NETLINK_ROUTE);
}

auto TcClient::replace_mqprio(int const ifindex, MqprioQdisc const& qdisc) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_mqprio(out, ifindex, qdisc, seq); });
}

auto TcClient::replace_cbs(int const ifindex, CbsQdisc const& qdisc) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_cbs(out, ifindex, qdisc, seq); });
}

auto TcClient::replace_etf(int const ifindex, EtfQdisc const& qdisc) -> Status
{
    return send([&](std::span<uint8_t> out, uint32_t seq) { return build_replace_etf(out, ifindex, qdisc, seq); });
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
    if (!socket_.is_open()) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
    return socket_.transact(
        request, seq, reply_, [&](std::span<uint8_t const> const message, uint16_t const type, uint16_t const flags) {
            return read_reply(message, type, flags, request.size(), wanted);
        });
}

auto TcClient::read_reply(
    std::span<uint8_t const> const message,
    uint16_t const type,
    uint16_t const flags,
    size_t const request_size,
    Wanted* const wanted) -> std::optional<Status>
{
    if (type == NLMSG_DONE && wanted != nullptr) {
        return netlink::dump_status(message);
    }
    if (type == RTM_NEWQDISC && wanted != nullptr && !wanted->came && message.size() >= NLMSG_HEADER + TCMSG_SIZE) {
        if (auto status = take_qdisc(message, *wanted); !status) {
            return status;
        }
        return std::nullopt;
    }
    if (type == NLMSG_ERROR) {
        return netlink::ack_status(message, flags, request_size, last_message_);
    }
    return std::nullopt;
}

auto TcClient::take_qdisc(std::span<uint8_t const> const message, Wanted& wanted) -> Status
{
    auto const ifindex = load<int32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_ifindex));
    auto const parent = load<uint32_t>(message, NLMSG_HEADER + offsetof(tcmsg, tcm_parent));
    if (ifindex == wanted.ifindex && parent == wanted.parent) {
        auto parsed = parse_qdisc(message);
        if (!parsed) {
            return failure(parsed.error());
        }
        *wanted.found = std::move(*parsed);
        wanted.came = true;
    }
    return success();
}

}  // namespace statusbar::net::tc

#endif  // __linux__
