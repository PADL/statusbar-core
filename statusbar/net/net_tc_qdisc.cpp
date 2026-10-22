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

}  // namespace

auto build_replace_mqprio(std::span<uint8_t> const out, int const ifindex, MqprioQdisc const& qdisc, uint32_t const seq)
    -> StatusValue<size_t>
{
    // major 0 would give the per-queue classes ids 0:1..N, which do not exist.
    if (qdisc.major == 0 || qdisc.num_tc == 0 || qdisc.num_tc > MAX_TRAFFIC_CLASSES) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    for (uint8_t const tc : qdisc.prio_tc_map) {
        if (tc >= qdisc.num_tc) {
            return failure(std::make_error_code(std::errc::invalid_argument));
        }
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
{
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
{
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

//
// TcClient
//

auto TcClient::open() noexcept -> Status
{
    FileDescriptor fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (!fd.valid()) {
        return failure(std::error_code{errno, std::system_category()});
    }
    // Extended acks carry the kernel's reason ("Change operation not
    // supported", "Specified device does not support offload"); capped acks
    // keep our request out of the reply. Both are best effort.
    int const on = 1;
    (void)::setsockopt(fd.get(), SOL_NETLINK, NETLINK_EXT_ACK, &on, sizeof(on));
    (void)::setsockopt(fd.get(), SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof(on));
    timeval const timeout{.tv_sec = 1, .tv_usec = 0};
    if (::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (::bind(fd.get(), sockaddr_cast(local), sizeof(local)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
    fd_ = std::move(fd);
    return success();
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

auto TcClient::transact(std::span<uint8_t const> const request, uint32_t const seq) -> Status
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
    alignas(nlmsghdr) std::array<uint8_t, 8192> reply{};
    for (;;) {
        ssize_t const received = ::recv(fd_.get(), reply.data(), reply.size(), 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return failure(std::make_error_code(std::errc::timed_out));
            }
            return failure(std::error_code{errno, std::system_category()});
        }
        size_t remaining = static_cast<size_t>(received);
        size_t offset = 0;
        while (remaining >= NLMSG_HEADER) {
            nlmsghdr header{};
            std::memcpy(&header, reply.data() + offset, NLMSG_HEADER);
            if (header.nlmsg_len < NLMSG_HEADER || header.nlmsg_len > remaining) {
                return failure(std::make_error_code(std::errc::bad_message));
            }
            if (header.nlmsg_seq == seq && header.nlmsg_type == NLMSG_ERROR) {
                // struct nlmsgerr: int error, then the request's header (capped).
                if (header.nlmsg_len < NLMSG_HEADER + sizeof(nlmsgerr)) {
                    return failure(std::make_error_code(std::errc::bad_message));
                }
                int error = 0;
                std::memcpy(&error, reply.data() + offset + NLMSG_HEADER, sizeof(error));
                if (error == 0) {
                    return success();
                }
                // Extended-ack TLVs after the (capped) nlmsgerr.
                if ((header.nlmsg_flags & NLM_F_ACK_TLVS) != 0) {
                    size_t const skip = (header.nlmsg_flags & NLM_F_CAPPED) != 0 ? sizeof(nlmsgerr)
                                                                                 : sizeof(nlmsgerr) + request.size() - NLMSG_HEADER;
                    size_t at = offset + NLMSG_HEADER + align4(skip);
                    size_t const end = offset + header.nlmsg_len;
                    while (at + RTA_HEADER <= end) {
                        uint16_t len = 0;
                        uint16_t type = 0;
                        std::memcpy(&len, reply.data() + at, sizeof(len));
                        std::memcpy(&type, reply.data() + at + 2, sizeof(type));
                        if (len < RTA_HEADER || at + len > end) {
                            break;
                        }
                        if ((type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG) {
                            auto const* text = reply.data() + at + RTA_HEADER;
                            size_t n = len - RTA_HEADER;
                            while (n > 0 && text[n - 1] == 0) {
                                --n;
                            }
                            last_message_.assign(text, text + n);
                            break;
                        }
                        at += align4(len);
                    }
                }
                return failure(std::error_code{-error, std::system_category()});
            }
            size_t const step = align4(header.nlmsg_len);
            if (step >= remaining) {
                break;
            }
            offset += step;
            remaining -= step;
        }
    }
}

}  // namespace statusbar::net::tc

#endif  // __linux__
