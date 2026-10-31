#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_tc_qdisc.hpp
/// @brief A small rtnetlink traffic-control client: install, replace and
/// delete queueing disciplines (mqprio, cbs, etf, and option-less ones such as
/// pfifo_fast) the way `tc qdisc replace|del` does, without libnl or iproute2.
///
/// Two layers:
///   - pure message builders (build_*), which write one complete
///     RTM_NEWQDISC / RTM_DELQDISC / RTM_GETQDISC request (nlmsghdr + tcmsg +
///     TCA_KIND + TCA_OPTIONS) into a caller buffer, and parse_qdisc, which
///     reads one RTM_NEWQDISC of the kernel's qdisc dump: socket-free,
///     unit-tested against hand-checked bytes. Netlink is host byte order; the layouts are
///     linux/rtnetlink.h's struct tcmsg and linux/pkt_sched.h's
///     struct tc_mqprio_qopt / tc_cbs_qopt / tc_etf_qopt, written field by
///     field (the .cpp static_asserts the kernel's sizes and offsets), with the
///     attribute framing iproute2's q_mqprio.c / q_cbs.c / q_etf.c use:
///     mqprio's TCA_OPTIONS is the flat tc_mqprio_qopt, cbs's and etf's are
///     nests holding TCA_CBS_PARMS / TCA_ETF_PARMS.
///   - TcClient, a NETLINK_ROUTE socket that sends one request with
///     NLM_F_ACK and returns the kernel's answer as a Status (its errno),
///     keeping the kernel's extended-ack text for logs. It implements
///     TcControl, the interface a caller takes so tests can record requests.
///
/// Changing qdiscs needs CAP_NET_ADMIN; reading one does not. Linux only, PTP_PRIORITY aside.

#include <cstdint>

namespace statusbar::net::tc {

/// The skb priority (SO_PRIORITY; ptp4l's socket_priority) that steers PTP event traffic to a TX
/// queue of its own: TC_PRIO_CONTROL, which the kernel also gives IGMP and MLD reports.
inline constexpr uint8_t PTP_PRIORITY = 7;

}  // namespace statusbar::net::tc

#if defined(__linux__)

#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <optional>
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

    auto operator==(MqprioQdisc const&) const noexcept -> bool = default;
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

    auto operator==(CbsQdisc const&) const noexcept -> bool = default;
};

/// CLOCK_TAI, the only clock etf takes (sch_etf.c, validate_input_params).
inline constexpr int32_t ETF_CLOCK_TAI = 11;

/// An earliest-TxTime-first qdisc: `tc qdisc replace dev <if> parent <parent> etf clockid
/// CLOCK_TAI delta <ns> [offload] [deadline_mode] [skip_sock_check]` (tc-etf(8)). With offload the
/// driver puts the queue in launch-time mode and sends each frame at its txtime.
struct EtfQdisc
{
    uint32_t parent{0};              ///< the class it hangs on: a cbs's major:1, or mqprio_major:(queue + 1)
    int32_t clockid{ETF_CLOCK_TAI};  ///< the clock txtimes are read on
    int32_t delta_ns{0};             ///< how long before its txtime a queued frame goes to the driver (>= 0)
    bool offload{true};              ///< program the NIC's launch time (TC_ETF_OFFLOAD_ON)
    bool deadline_mode{false};       ///< txtime is a deadline: send at once (TC_ETF_DEADLINE_MODE_ON)
    bool skip_sock_check{false};     ///< take frames of sockets without SO_TXTIME (TC_ETF_SKIP_SOCK_CHECK)

    auto operator==(EtfQdisc const&) const noexcept -> bool = default;
};

/// One qdisc as the kernel reports it (`tc qdisc show`): its handle, parent
/// and kind, with the options of the kinds this client writes.
struct QdiscInfo
{
    int ifindex{0};
    /// The qdisc's own handle, major:0 ("8008:" for a cbs the kernel
    /// numbered); 0 for a default qdisc the kernel attached (the mq root, an
    /// mqprio queue's fq_codel).
    uint32_t handle{0};
    /// ROOT for the root; an mqprio child's is the class it hangs on,
    /// mqprio_major:(queue + 1).
    uint32_t parent{0};
    std::string kind{};
    std::optional<MqprioQdisc> mqprio{};  ///< kind "mqprio": its layout (major from the handle)
    std::optional<CbsQdisc> cbs{};        ///< kind "cbs": its parameters (parent as above)
    std::optional<EtfQdisc> etf{};        ///< kind "etf": its parameters (parent as above)
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

/// Build `tc qdisc replace ... parent <parent> etf ...` (RTM_NEWQDISC, CREATE | REPLACE, tcm_handle
/// 0: the kernel numbers it) into @p out. etf has no change operation: the kernel refuses (EINVAL) a
/// replace of an etf already on that parent. Returns the message length.
[[nodiscard]] auto build_replace_etf(std::span<uint8_t> out, int ifindex, EtfQdisc const& qdisc, uint32_t seq)
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

/// Build `tc qdisc show` (RTM_GETQDISC, NLM_F_REQUEST | NLM_F_DUMP, no
/// attributes) into @p out. The kernel dumps every qdisc of every device in
/// the namespace (tc_dump_qdisc ignores tcm_ifindex, which is set to @p
/// ifindex for the record); the caller filters. A dump rather than a single
/// get: tc_get_qdisc answers through rtnetlink_send, which with NLM_F_ECHO
/// also tells every RTNLGRP_TC listener (`tc monitor`) of a "new" qdisc.
/// Returns the message length.
[[nodiscard]] auto build_dump(std::span<uint8_t> out, int ifindex, uint32_t seq) -> StatusValue<size_t>;

/// Parse one RTM_NEWQDISC message (nlmsghdr + tcmsg + attributes), one part
/// of the kernel's answer to build_dump. mqprio's TCA_OPTIONS is the flat
/// tc_mqprio_qopt followed by optional attributes (ignored); cbs's nests
/// TCA_CBS_PARMS, etf's TCA_ETF_PARMS. Errors: bad_message for a truncated or malformed message,
/// another type, or a known kind whose options are short.
[[nodiscard]] auto parse_qdisc(std::span<uint8_t const> message) -> StatusValue<QdiscInfo>;

/// The qdisc requests a caller makes (TcClient in a host; a recorder in tests).
class TcControl
{
  public:
    virtual ~TcControl() = default;

    [[nodiscard]] virtual auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status = 0;
    [[nodiscard]] virtual auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status = 0;
    [[nodiscard]] virtual auto replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status = 0;
    [[nodiscard]] virtual auto replace_kind(int ifindex, uint32_t parent, std::string_view kind) -> Status = 0;
    [[nodiscard]] virtual auto remove(int ifindex, uint32_t handle, uint32_t parent) -> Status = 0;
    /// The qdisc on @p parent (ROOT: the root) of @p ifindex. Errors: ENOENT
    /// when there is none, or the request's.
    [[nodiscard]] virtual auto get(int ifindex, uint32_t parent) -> StatusValue<QdiscInfo> = 0;
    /// The kernel's extended-ack message for the last failed request (empty:
    /// none was given, or the request succeeded).
    [[nodiscard]] virtual auto last_message() const noexcept -> std::string const& = 0;

  protected:
    TcControl() noexcept = default;
};

/// Delete @p ifindex's root if it is an mqprio with handle @p major:0, which only its own user lays:
/// any other root is left alone. Its children go with it (on igb/igc, one adapter reset). Returns
/// whether it was deleted. Errors: the delete's netlink errno.
[[nodiscard]] auto remove_own_mqprio_root(TcControl& tc, int ifindex, uint16_t major) -> StatusValue<bool>;

/// Delete @p root, @p ifindex's root, if it is an mqprio or taprio under another handle than @p major:0, before
/// an mqprio of ours replaces it: replaced in place, its destroy would reset our TC map. Any other root stays.
[[nodiscard]] auto remove_other_tc_root(TcControl& tc, int ifindex, QdiscInfo const& root, uint16_t major) -> StatusValue<bool>;

/// A blocking NETLINK_ROUTE socket for qdisc requests. Each call sends one
/// request and waits (at most about a second) for its acknowledgement. Not
/// thread-safe; meant for the reactor thread, where a request is rare
/// (install, an admission change, shutdown).
class TcClient final : public TcControl
{
  public:
    TcClient() noexcept = default;

    /// Open and bind the socket (extended acks requested). Errors: the socket's errno.
    [[nodiscard]] auto open() noexcept -> Status;
    [[nodiscard]] auto is_open() const noexcept -> bool { return socket_.is_open(); }

    [[nodiscard]] auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status override;
    [[nodiscard]] auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status override;
    [[nodiscard]] auto replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status override;
    [[nodiscard]] auto replace_kind(int ifindex, uint32_t parent, std::string_view kind) -> Status override;
    [[nodiscard]] auto remove(int ifindex, uint32_t handle, uint32_t parent) -> Status override;
    [[nodiscard]] auto get(int ifindex, uint32_t parent) -> StatusValue<QdiscInfo> override;

    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return last_message_; }

    /// Send one other rtnetlink request that the kernel acknowledges (e.g.
    /// net_vlan_link's RTM_NEWLINK / RTM_DELLINK), built by @p build (out,
    /// seq) -> StatusValue<size_t> into a RequestBuffer under the next
    /// sequence number. Errors: the builder's, or the kernel's errno.
    template <typename Build>
    [[nodiscard]] auto request(Build const& build) -> Status
    {
        return send(build);
    }

  private:
    /// Build one request with @p build (out, seq) -> StatusValue<size_t> under
    /// the next sequence number and transact it.
    /// What a dump looks for: the qdisc of @p ifindex on @p parent.
    struct Wanted
    {
        int ifindex{0};
        uint32_t parent{0};
        QdiscInfo* found{nullptr};  ///< set when it came (parsed into it)
        bool came{false};
    };

    template <typename Build>
    [[nodiscard]] auto send(Build const& build, Wanted* wanted = nullptr) -> Status
    {
        RequestBuffer request{};
        uint32_t const seq = ++seq_;
        auto const length = build(std::span<uint8_t>{request}, seq);
        if (!length) {
            return failure(length.error());
        }
        return transact(std::span<uint8_t const>{request.data(), *length}, seq, wanted);
    }

    /// Send @p request (sequence number @p seq) and wait for its NLMSG_ERROR;
    /// with @p wanted, @p request is a dump: read its parts up to NLMSG_DONE,
    /// parsing the wanted qdisc. Only messages addressed to this socket
    /// (nlmsg_pid, our port id) under @p seq count.
    [[nodiscard]] auto transact(std::span<uint8_t const> request, uint32_t seq, Wanted* wanted) -> Status;
    /// One message addressed to this transaction, of nlmsg_type @p type and
    /// nlmsg_flags @p flags: its result if it ends the transaction, else nullopt.
    [[nodiscard]] auto read_reply(
        std::span<uint8_t const> message, uint16_t type, uint16_t flags, size_t request_size, Wanted* wanted)
        -> std::optional<Status>;
    /// Parse a dump's RTM_NEWQDISC into @p wanted when it is the qdisc wanted (else ignore it).
    [[nodiscard]] static auto take_qdisc(std::span<uint8_t const> message, Wanted& wanted) -> Status;

    netlink::Socket socket_{};
    uint32_t seq_{0};
    std::string last_message_{};
    /// A dump part is at most the larger of a page and the buffer read with (netlink_dump's
    /// alloc_min_size). 32 KiB in the object: hosts hold the client on the heap.
    std::array<uint8_t, 32768> reply_{};
};

}  // namespace statusbar::net::tc

#endif  // __linux__
