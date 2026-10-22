#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_tc_qdisc.hpp
/// @brief A small rtnetlink traffic-control client: install, replace and
/// delete queueing disciplines (mqprio, cbs, and option-less ones such as
/// pfifo_fast) the way `tc qdisc replace|del` does, without libnl or iproute2.
///
/// Two layers:
///   - pure message builders (build_*), which write one complete
///     RTM_NEWQDISC / RTM_DELQDISC request (nlmsghdr + tcmsg + TCA_KIND +
///     TCA_OPTIONS) into a caller buffer: socket-free, unit-tested against
///     hand-checked bytes. Netlink is host byte order; the layouts are
///     linux/rtnetlink.h's struct tcmsg and linux/pkt_sched.h's
///     struct tc_mqprio_qopt / struct tc_cbs_qopt, written field by field
///     (the .cpp static_asserts the kernel's sizes and offsets), with the
///     attribute framing iproute2's q_mqprio.c / q_cbs.c use: mqprio's
///     TCA_OPTIONS is the flat tc_mqprio_qopt, cbs's is a nest holding
///     TCA_CBS_PARMS.
///   - TcClient, a NETLINK_ROUTE socket that sends one request with
///     NLM_F_ACK and returns the kernel's answer as a Status (its errno),
///     keeping the kernel's extended-ack text for logs.
///
/// Changing qdiscs needs CAP_NET_ADMIN. Linux only.

#if defined(__linux__)

#    include "statusbar/buffer/file_descriptor.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <span>
#    include <string>
#    include <string_view>

namespace statusbar::net::tc {

/// TC_H_ROOT: the parent of a root qdisc.
inline constexpr uint32_t ROOT = 0xFFFF'FFFFU;

/// A tc handle or class id, `major:minor` (TC_H_MAKE).
[[nodiscard]] constexpr auto make_handle(uint16_t const major, uint16_t const minor) noexcept -> uint32_t
{
    return (static_cast<uint32_t>(major) << 16U) | minor;
}

/// The number of skb priorities mqprio maps to a traffic class (TC_QOPT_BITMASK + 1).
inline constexpr size_t PRIORITY_COUNT = 16;
/// The most traffic classes mqprio takes (TC_QOPT_MAX_QUEUE).
inline constexpr size_t MAX_TRAFFIC_CLASSES = 16;

/// An mqprio root qdisc: `tc qdisc replace dev <if> root handle <major>: mqprio
/// num_tc <n> map <prio_tc_map> queues <count@offset>... hw <0|1>`.
struct MqprioQdisc
{
    uint16_t major{0};                                   ///< the qdisc's handle is major:0; its per-queue classes are major:1..N
    uint8_t num_tc{0};                                   ///< traffic classes, 1..MAX_TRAFFIC_CLASSES
    std::array<uint8_t, PRIORITY_COUNT> prio_tc_map{};   ///< skb priority -> traffic class
    std::array<uint16_t, MAX_TRAFFIC_CLASSES> count{};   ///< TX queues of each traffic class
    std::array<uint16_t, MAX_TRAFFIC_CLASSES> offset{};  ///< first TX queue of each traffic class
    bool hw{false};                                      ///< ask the driver to offload the TC map (TC_MQPRIO_HW_OFFLOAD_TCS)
};

/// A credit-based shaper on one mqprio queue: `tc qdisc replace dev <if>
/// parent <parent> cbs idleslope .. sendslope .. hicredit .. locredit ..
/// offload <0|1>`. Slopes in kbit/s, credits in bytes (IEEE 802.1Q 8.6.8.2,
/// Annex L).
struct CbsQdisc
{
    uint32_t parent{0};  ///< mqprio_major:(queue + 1)
    bool offload{true};  ///< program the NIC's shaper (the software cbs never sees bypass frames)
    int32_t hicredit{0};
    int32_t locredit{0};
    int32_t idleslope_kbps{0};
    int32_t sendslope_kbps{0};
};

/// Room for any request the builders write (the largest, mqprio, is 136 bytes).
inline constexpr size_t MAX_REQUEST_SIZE = 256;
using RequestBuffer = std::array<uint8_t, MAX_REQUEST_SIZE>;

/// Build `tc qdisc replace ... root mqprio` (RTM_NEWQDISC, NLM_F_REQUEST |
/// NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE; tcm_handle major:0, tcm_parent
/// ROOT) into @p out. Returns the message length. Errors: invalid_argument for
/// major 0, num_tc 0 or over MAX_TRAFFIC_CLASSES, or a map entry not below num_tc;
/// BufferError::insufficient_space when @p out is too small.
[[nodiscard]] auto build_replace_mqprio(std::span<uint8_t> out, int ifindex, MqprioQdisc const& qdisc, uint32_t seq)
    -> StatusValue<size_t>;

/// Build `tc qdisc replace ... parent <parent> cbs ...` (RTM_NEWQDISC, CREATE |
/// REPLACE, tcm_handle 0: the kernel numbers it; a cbs already on that parent
/// is changed in place) into @p out. Returns the message length.
[[nodiscard]] auto build_replace_cbs(std::span<uint8_t> out, int ifindex, CbsQdisc const& qdisc, uint32_t seq)
    -> StatusValue<size_t>;

/// Build `tc qdisc replace ... parent <parent> <kind>` for a qdisc that takes
/// no options (e.g. "pfifo_fast"; no TCA_OPTIONS) into @p out. Returns the
/// message length. Errors: invalid_argument for an empty kind or one over 15 bytes.
[[nodiscard]] auto build_replace_kind(std::span<uint8_t> out, int ifindex, uint32_t parent, std::string_view kind, uint32_t seq)
    -> StatusValue<size_t>;

/// Build `tc qdisc del ... [parent <parent>] [handle <handle>]` (RTM_DELQDISC,
/// NLM_F_REQUEST | NLM_F_ACK, no attributes) into @p out. Deleting a root
/// mqprio (parent ROOT, its handle) takes its children with it. Returns the
/// message length.
[[nodiscard]] auto build_delete(std::span<uint8_t> out, int ifindex, uint32_t handle, uint32_t parent, uint32_t seq)
    -> StatusValue<size_t>;

/// A blocking NETLINK_ROUTE socket for qdisc requests. Each call sends one
/// request and waits (at most about a second) for its acknowledgement. Not
/// thread-safe; meant for the reactor thread, where a request is rare
/// (install, an admission change, shutdown).
class TcClient
{
  public:
    TcClient() noexcept = default;

    /// Open and bind the socket (extended acks requested). Errors: the socket's errno.
    [[nodiscard]] auto open() noexcept -> Status;
    [[nodiscard]] auto is_open() const noexcept -> bool { return fd_.valid(); }

    [[nodiscard]] auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status;
    [[nodiscard]] auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status;
    [[nodiscard]] auto replace_kind(int ifindex, uint32_t parent, std::string_view kind) -> Status;
    [[nodiscard]] auto remove(int ifindex, uint32_t handle, uint32_t parent) -> Status;

    /// The kernel's extended-ack message for the last failed request (empty:
    /// none was given, or the request succeeded).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return last_message_; }

  private:
    /// Build one request with @p build (out, seq) -> StatusValue<size_t> under
    /// the next sequence number and transact it.
    template <typename Build>
    [[nodiscard]] auto send(Build const& build) -> Status
    {
        RequestBuffer request{};
        uint32_t const seq = ++seq_;
        auto const length = build(std::span<uint8_t>{request}, seq);
        if (!length) {
            return failure(length.error());
        }
        return transact(std::span<uint8_t const>{request.data(), *length}, seq);
    }

    /// Send @p request (sequence number @p seq) and wait for its NLMSG_ERROR.
    [[nodiscard]] auto transact(std::span<uint8_t const> request, uint32_t seq) -> Status;

    FileDescriptor fd_{};
    uint32_t seq_{0};
    std::string last_message_{};
};

}  // namespace statusbar::net::tc

#endif  // __linux__
