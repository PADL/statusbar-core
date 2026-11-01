#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// rtnetlink traffic-control client: mqprio and CBS qdiscs.
///
/// An AVB Class A talker must not burst. IEEE 802.1Q Annex L budgets a
/// class to a fixed slice of link bandwidth, and the way a Linux NIC
/// enforces that is a credit-based shaper (`cbs`) hanging off an `mqprio`
/// root qdisc, with the driver offloading both. Without it a talker that
/// is correct on the wire in every other respect still fails Class A
/// latency under load, because its frames queue behind ordinary traffic.
///
/// The alternative is shelling out to `tc`, which means a runtime
/// dependency on iproute2, parsing human-readable output to discover what
/// happened, no access to the kernel's extended-ack text when a request
/// is refused, and no way to test the logic without root.
///
/// The module is in two layers, and the split is the point:
///
///   1. **Pure message builders.** They write a complete netlink request
///      into a caller-supplied buffer and return its length. No socket,
///      no file descriptor, no privilege — so the bytes we send, which
///      are the part most likely to be wrong, are checkable in CI.
///   2. **A thin socket client behind an interface** (`TcControl`), so a
///      caller's tests can record the requests it makes instead of
///      touching the kernel.
///
/// Two traps are encoded here, both of which cost time to discover:
///
///   * **Read qdiscs with a dump, not a single-qdisc get.**
///     `RTM_GETQDISC` for one qdisc is answered by the kernel through
///     `rtnetlink_send`, which also notifies every `RTNLGRP_TC` listener
///     — so a *read* appears in anyone's `tc monitor` as a change. We
///     dump and filter on ifindex, parent and our own netlink port id.
///   * **`cbs` must be offloaded to shape an AF_XDP talker.** A software
///     cbs sits in the qdisc layer, which AF_XDP and `PACKET_QDISC_BYPASS`
///     frames never enter. It *does* shape our default AF_PACKET traffic,
///     because `ENABLE_PACKET_QDISC_BYPASS` is off by default in this
///     tree — but a bypass or XDP talker needs the offload, so `offload`
///     defaults on and a driver that refuses it is an error, not a
///     warning.
///
/// Linux only: the module does not exist elsewhere rather than stub out.

#include "statusbar/net/net_error.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace statusbar::net::tc {

#if defined(__linux__)

/// Covers every request this module builds. mqprio, the largest, is 136
/// bytes: 16 (nlmsghdr) + 20 (tcmsg) + 12 (TCA_KIND "mqprio") + 88
/// (TCA_OPTIONS holding an 82-byte tc_mqprio_qopt, padded). A request can
/// therefore live on the stack with no allocation.
inline constexpr std::size_t MAX_REQUEST_SIZE = 256;

/// A buffer big enough for any request this module builds. Named because
/// another implementation of this module names it, and a caller written
/// against that one should not have to spell the array out.
using RequestBuffer = std::array<std::uint8_t, MAX_REQUEST_SIZE>;

/// TC_H_ROOT: the parent of a root qdisc.
inline constexpr std::uint32_t ROOT = 0xFFFFFFFFU;

/// TC_H_UNSPEC: no parent named, which is what a dump asks about.
inline constexpr std::uint32_t UNSPEC = 0U;

/// TC_QOPT_MAX_QUEUE / TC_QOPT_BITMASK + 1 from <linux/pkt_sched.h>: the
/// priority map has one entry per skb priority 0..15, and there can be at
/// most 16 traffic classes.
inline constexpr std::size_t MAX_TRAFFIC_CLASSES = 16;
inline constexpr std::size_t PRIO_MAP_SIZE = 16;

/// The same count, under the name another implementation of this module
/// gives it, so a caller that spells the map type out compiles either way.
inline constexpr std::size_t PRIORITY_COUNT = PRIO_MAP_SIZE;

/// The skb priority PTP event traffic is sent at. IEEE 802.1Q Table 8-5 puts
/// network control at the top of the eight priorities, and the AVB profile
/// (IEEE 802.1BA-2021 Section 6.3) sends gPTP there. A host that gives PTP a
/// queue of its own maps this priority to it.
inline constexpr std::uint8_t PTP_PRIORITY = 7;

/// Longest qdisc kind name we build or store. The kernel's own limit
/// (IFNAMSIZ) is 16 including the terminator.
inline constexpr std::size_t MAX_KIND_LENGTH = 15;

/// Pack a tc handle from its major and minor parts, as `major:minor` in
/// `tc` syntax.
[[nodiscard]] constexpr auto make_handle(std::uint16_t major, std::uint16_t minor) noexcept -> std::uint32_t
{
    return (static_cast<std::uint32_t>(major) << 16) | static_cast<std::uint32_t>(minor);
}

/// The major part of a handle, i.e. which qdisc.
[[nodiscard]] constexpr auto handle_major(std::uint32_t handle) noexcept -> std::uint16_t
{
    return static_cast<std::uint16_t>(handle >> 16);
}

/// The minor part of a handle, i.e. which class within the qdisc.
[[nodiscard]] constexpr auto handle_minor(std::uint32_t handle) noexcept -> std::uint16_t
{
    return static_cast<std::uint16_t>(handle & 0xFFFFU);
}

/// An `mqprio` root qdisc: a map from skb priority to traffic class, and
/// a range of TX queues per class.
///
/// Typed rather than a `tc` command string, because the interesting
/// failures here are semantic. A priority mapped to a class with no
/// queues behind it is a request the kernel may *accept*, after which
/// frames at that priority go to a queue nothing services.
struct MqprioQdisc
{
    /// Handle major; the qdisc is installed as `major:0`. Must not be 0.
    std::uint16_t major{0};

    /// Number of traffic classes, 1..MAX_TRAFFIC_CLASSES.
    std::uint8_t num_tc{0};

    /// skb priority -> traffic class. Every entry must be < num_tc.
    std::array<std::uint8_t, PRIO_MAP_SIZE> prio_tc_map{};

    /// TX queues per traffic class, and where each class's range starts.
    /// Only the first `num_tc` entries are meaningful.
    std::array<std::uint16_t, MAX_TRAFFIC_CLASSES> count{};
    std::array<std::uint16_t, MAX_TRAFFIC_CLASSES> offset{};

    /// Ask the driver to offload the map to hardware. Defaults on.
    bool offload{true};

    auto operator==(MqprioQdisc const&) const noexcept -> bool = default;
};

/// A credit-based shaper hanging off one `mqprio` traffic class.
///
/// Slopes are in kbit/s and credits in bytes, matching the kernel's
/// `tc_cbs_qopt`. `sendslope` is normally negative (idleslope minus the
/// port transmit rate) and `locredit` is normally negative.
struct CbsQdisc
{
    // The first six fields are named and ordered as another implementation
    // of this module names and orders them, so that a positional
    // CbsQdisc{...} written against either one means the same thing. That
    // ordering is the reason to care: the names merely fail to compile when
    // they disagree, where a different order silently assigns a credit to a
    // slope. handle_major is ours alone and comes last for the same reason.
    //
    // `offload` keeps our name and our default. Both implementations call it
    // offload, but the other one's MqprioQdisc defaults its equivalent
    // (`hw`) to false; defaulting a shaper to software is the failure
    // FEAT-008 exists to prevent, so ours stays on.

    /// The mqprio class this shaper serves, e.g. make_handle(0x8001, 1).
    std::uint32_t parent{0};

    /// Offload to the driver's hardware shaper. Defaults on: see the
    /// second trap in this file's header comment.
    bool offload{true};

    std::int32_t hicredit{0};        ///< bytes, credit ceiling
    std::int32_t locredit{0};        ///< bytes, credit floor
    std::int32_t idleslope_kbps{0};  ///< kbit/s the class may accumulate at
    std::int32_t sendslope_kbps{0};  ///< kbit/s credit drains at while sending

    /// Handle major for the cbs itself; installed as `major:0`. Not 0.
    /// Ours only - the other implementation takes the major from the handle
    /// it is written with.
    std::uint16_t handle_major{0};

    auto operator==(CbsQdisc const&) const noexcept -> bool = default;
};

/// CLOCK_TAI's clockid. `sch_etf`'s validate_input_params takes no other
/// clock, because a launch time is only meaningful on a clock the NIC also
/// keeps, and that is TAI.
inline constexpr std::int32_t ETF_CLOCK_TAI = 11;

/// An `etf` (earliest TxTime first) qdisc hanging off one class.
///
/// Where `cbs` bounds how *much* a class may send, `etf` decides *when* each
/// frame goes: the frame carries a launch time and the qdisc releases it
/// `delta_ns` before that, or - offloaded - hands it to a NIC that holds it
/// until the time arrives. A talker that must put a frame on the wire inside
/// a window, rather than merely at an average rate, needs this and not a
/// shaper.
///
/// The three flags are each a trap of their own, which is why they are named
/// here rather than left to a flags word:
///
///   * `offload` puts the driver's queue in launch-time mode. Without it the
///     qdisc layer does the timing in software, and an AF_XDP or
///     `PACKET_QDISC_BYPASS` frame never enters the qdisc layer - so it is
///     sent immediately, untimed, with nothing reported. Defaults on for the
///     same reason `CbsQdisc::offload` does.
///   * `deadline_mode` changes what the time *means*: the frame is sent as
///     soon as possible and the launch time is only a deadline it must not
///     miss. A talker that wants frames spread out must leave this off.
///   * `skip_sock_check` takes frames from sockets that never set
///     `SO_TXTIME`. An AF_XDP socket sets its launch time in the UMEM's TX
///     metadata rather than through `SO_TXTIME`, so without this the qdisc
///     drops its frames.
struct EtfQdisc
{
    /// The class this hangs on: a cbs's `major:1`, or `make_handle(major,
    /// queue + 1)` of an mqprio root. TC_H_UNSPEC (0) names nothing and is
    /// refused; `ROOT` is a different value and is accepted.
    std::uint32_t parent{0};

    /// The clock launch times are read on. Only ETF_CLOCK_TAI works.
    std::int32_t clockid{ETF_CLOCK_TAI};

    /// How long before its launch time a queued frame is handed on, in
    /// nanoseconds. Must not be negative.
    std::int32_t delta_ns{0};

    bool offload{true};           ///< TC_ETF_OFFLOAD_ON
    bool deadline_mode{false};    ///< TC_ETF_DEADLINE_MODE_ON
    bool skip_sock_check{false};  ///< TC_ETF_SKIP_SOCK_CHECK

    auto operator==(EtfQdisc const&) const noexcept -> bool = default;
};

/// One qdisc as read back from the kernel.
struct QdiscInfo
{
    int ifindex{0};
    std::uint32_t handle{0};
    std::uint32_t parent{0};

    /// Kind name, NUL-terminated. Empty if the reply carried no TCA_KIND.
    std::array<char, MAX_KIND_LENGTH + 1> kind{};

    /// Whether `cbs` below was filled in. False for a kind that is not
    /// `cbs`, and false for a `cbs` whose options blob was too small to
    /// hold the parameters — a short blob must not yield a confident set
    /// of slopes.
    bool has_cbs_params{false};
    CbsQdisc cbs{};

    /// Set when the qdisc is an mqprio and the kernel's TCA_OPTIONS carried
    /// its tc_mqprio_qopt: the queue layout, which is what tells a root of
    /// ours from one that merely has our handle.
    bool has_mqprio_params{false};
    MqprioQdisc mqprio{};

    [[nodiscard]] auto kind_name() const noexcept -> std::string_view { return std::string_view{kind.data()}; }
};

/// Build an `RTM_NEWQDISC` request installing or replacing an mqprio root.
///
/// Deleting a root mqprio takes its `cbs` children with it, so a caller
/// tearing a configuration down does not need to remove children first.
///
/// @param out Buffer of at least the request's length; MAX_REQUEST_SIZE
///        always suffices.
/// @param ifindex Interface index, from `net::interface_index()`.
/// @param qdisc The map to install.
/// @param seq Netlink sequence number, echoed in the reply.
/// @return Bytes written, or `NetError::invalid_argument` for a handle
///         major of 0, a `num_tc` of 0 or above MAX_TRAFFIC_CLASSES, a
///         priority map entry not below `num_tc`, or a short buffer.
[[nodiscard]] auto build_replace_mqprio(std::span<std::uint8_t> out, int ifindex, MqprioQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build an `RTM_NEWQDISC` request installing or replacing a cbs.
/// @return Bytes written, or `NetError::invalid_argument`.
[[nodiscard]] auto build_replace_cbs(std::span<std::uint8_t> out, int ifindex, CbsQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build an `RTM_NEWQDISC` request installing or replacing an etf.
///
/// The request carries handle 0: nothing hangs off an etf, so the kernel may
/// pick its handle.
/// @return Bytes written, or `NetError::invalid_argument` for a parent of 0,
///         a negative `delta_ns`, or a short buffer.
[[nodiscard]] auto build_replace_etf(std::span<std::uint8_t> out, int ifindex, EtfQdisc const& qdisc, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build an `RTM_NEWQDISC` request installing a qdisc by kind name alone,
/// with no options — used to put something harmless (`pfifo_fast`) on a
/// class whose shaper is being removed.
/// @return Bytes written, or `NetError::invalid_argument` for an empty or
///         over-long kind, or a short buffer.
[[nodiscard]] auto build_replace_kind(
    std::span<std::uint8_t> out, int ifindex, std::uint32_t parent, std::string_view kind, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build an `RTM_DELQDISC` request.
/// @return Bytes written, or `NetError::invalid_argument`.
[[nodiscard]] auto build_delete(
    std::span<std::uint8_t> out, int ifindex, std::uint32_t handle, std::uint32_t parent, std::uint32_t seq)
    -> StatusValue<std::size_t>;

/// Build an `RTM_GETQDISC` **dump** request.
///
/// A dump, never a single-qdisc get: see the first trap in this file's
/// header comment. `ifindex` is carried so the kernel can narrow the dump
/// where it supports that, but the reply must still be filtered by the
/// caller.
/// @return Bytes written, or `NetError::invalid_argument`.
[[nodiscard]] auto build_dump(std::span<std::uint8_t> out, int ifindex, std::uint32_t seq) -> StatusValue<std::size_t>;

/// Parse one `RTM_NEWQDISC` message, as a dump reply or an echo of our
/// own request.
/// @param message Exactly one netlink message.
/// @return The qdisc, `NetError::invalid_argument` if the message is
///         truncated or internally inconsistent, or
///         `NetError::not_supported` if it is a well-formed message of
///         some other type — which a dump-reply reader must skip rather
///         than treat as a failure.
[[nodiscard]] auto parse_qdisc(std::span<std::uint8_t const> message) -> StatusValue<QdiscInfo>;

/// The outcome of a netlink acknowledgement.
struct AckResult
{
    /// 0 for a plain acknowledgement, otherwise a positive errno.
    int error{0};

    /// The kernel's extended-ack text, or empty. Not every refusal carries
    /// one: a permission check fires before the kernel sets any ext-ack,
    /// so an EPERM typically arrives with no text at all.
    std::string message;
};

/// Parse an `NLMSG_ERROR` reply.
///
/// Exposed because the offset arithmetic is the error-prone part and is
/// otherwise only reachable with a kernel: `nlmsgerr` is an int followed
/// by a copy of the offending request's header, and unless the kernel set
/// `NLM_F_CAPPED` it appends the rest of the original request too, with
/// the extended-ack TLVs after all of it. Computing that offset wrongly
/// reads the echoed request's own bytes as attributes.
///
/// @param message Exactly one netlink message.
/// @return The errno and any text, or `NetError::invalid_argument` if the
///         message is not a well-formed `NLMSG_ERROR`.
[[nodiscard]] auto parse_ack(std::span<std::uint8_t const> message) -> StatusValue<AckResult>;

/// What a caller needs of a traffic-control client.
///
/// An interface rather than a concrete class so a caller's own tests can
/// substitute a recorder and assert the full request sequence with no
/// kernel. `TcRecorder` in net_tc_qdisc_recorder.hpp is that recorder.
class TcControl
{
  public:
    TcControl() = default;
    virtual ~TcControl() = default;
    TcControl(TcControl const&) = delete;
    auto operator=(TcControl const&) -> TcControl& = delete;
    TcControl(TcControl&&) = delete;
    auto operator=(TcControl&&) -> TcControl& = delete;

    virtual auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status = 0;
    virtual auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status = 0;
    virtual auto replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status = 0;
    virtual auto replace_kind(int ifindex, std::uint32_t parent, std::string_view kind) -> Status = 0;
    virtual auto remove(int ifindex, std::uint32_t handle, std::uint32_t parent) -> Status = 0;

    /// Read one qdisc back. Implemented with a dump and a local filter.
    virtual auto get(int ifindex, std::uint32_t parent) -> StatusValue<QdiscInfo> = 0;

    /// The kernel's extended-ack text for the last refused request, or
    /// empty. This is the reason to speak netlink rather than shell out:
    /// the explanation exists, and `tc` discards it.
    [[nodiscard]] virtual auto last_message() const noexcept -> std::string const& = 0;
};

/// A `TcControl` over `NETLINK_ROUTE`.
class TcClient final : public TcControl
{
  public:
    TcClient() = default;
    ~TcClient() override;
    TcClient(TcClient const&) = delete;
    auto operator=(TcClient const&) -> TcClient& = delete;
    TcClient(TcClient&&) = delete;
    auto operator=(TcClient&&) -> TcClient& = delete;

    /// Open the netlink socket and request extended acks.
    ///
    /// Opening is separate from construction so the failure is reportable.
    /// `NETLINK_EXT_ACK` is requested here; without it the kernel sends
    /// only an errno and `last_message()` stays empty.
    [[nodiscard]] auto open() -> Status;

    /// Whether the socket is open.
    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// The same question as valid(), under the name another implementation
    /// of this module gives it, so a caller written against that one compiles
    /// against this one.
    [[nodiscard]] auto is_open() const noexcept -> bool { return valid(); }

    /// The netlink socket, for a caller that multiplexes it, and so a test
    /// can confirm the receive timeout is actually installed.
    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }

    auto replace_mqprio(int ifindex, MqprioQdisc const& qdisc) -> Status override;
    auto replace_cbs(int ifindex, CbsQdisc const& qdisc) -> Status override;
    auto replace_etf(int ifindex, EtfQdisc const& qdisc) -> Status override;
    auto replace_kind(int ifindex, std::uint32_t parent, std::string_view kind) -> Status override;
    auto remove(int ifindex, std::uint32_t handle, std::uint32_t parent) -> Status override;
    auto get(int ifindex, std::uint32_t parent) -> StatusValue<QdiscInfo> override;
    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return last_message_; }

  private:
    /// Which replies in a dump stream we are looking for. The port id is
    /// part of it deliberately: a netlink socket can be sent unsolicited
    /// multicast traffic, and a reply that is not addressed to our own
    /// port is somebody else's.
    struct DumpFilter
    {
        std::uint32_t seq{0};
        std::uint32_t port_id{0};
        int ifindex{0};
        std::uint32_t parent{0};
    };

    /// The qdisc a dump scan has found so far.
    struct DumpMatch
    {
        QdiscInfo info{};
        bool matched{false};
    };

    /// Take the next sequence number.
    [[nodiscard]] auto next_sequence() noexcept -> std::uint32_t { return next_seq_++; }

    /// Send a built request and read its acknowledgement.
    [[nodiscard]] auto transact(std::span<std::uint8_t const> request) -> Status;

    /// Read acknowledgements until the one for sequence `seq` arrives. The
    /// answer to an earlier request that timed out can still be queued, and
    /// reading exactly one datagram would take it for this request's and
    /// leave the real one to poison the next; anything with another
    /// sequence is drained and dropped instead.
    [[nodiscard]] auto read_ack(std::uint32_t seq) -> Status;

    /// The NLMSG_ERROR for `seq` inside one reply buffer, if it holds one.
    [[nodiscard]] static auto find_ack(std::span<std::uint8_t const> reply, std::uint32_t seq) noexcept
        -> std::optional<std::span<std::uint8_t const>>;

    /// Record an NLMSG_ERROR's text and turn its errno into a Status.
    [[nodiscard]] auto record_ack(std::span<std::uint8_t const> message) -> Status;

    /// Send a dump request and return the one qdisc that matches.
    [[nodiscard]] auto dump_and_find(std::span<std::uint8_t const> request, int ifindex, std::uint32_t parent)
        -> StatusValue<QdiscInfo>;

    /// Read the dump stream to NLMSG_DONE, keeping any match.
    [[nodiscard]] auto read_dump_stream(DumpFilter const& filter, DumpMatch& match) -> Status;

    /// Walk one recv()'s worth of dump replies. True when the stream is
    /// over; a dump the kernel refused or abandoned is the failure it names.
    [[nodiscard]] auto scan_dump_chunk(std::span<std::uint8_t const> chunk, DumpFilter const& filter, DumpMatch& match)
        -> StatusValue<bool>;

    /// One message of a dump stream. True when it ends the stream: an
    /// NLMSG_DONE, or the kernel's refusal of our dump (an NLMSG_ERROR for
    /// our sequence), the latter reported as the errno it carries.
    [[nodiscard]] auto scan_dump_message(std::span<std::uint8_t const> message, DumpFilter const& filter, DumpMatch& match)
        -> StatusValue<bool>;

    /// Keep one reply if it is ours and is the qdisc we asked about.
    static auto consider_reply(std::span<std::uint8_t const> message, DumpFilter const& filter, DumpMatch& match) noexcept -> void;

    int fd_{-1};
    std::uint32_t port_id_{0};
    std::uint32_t next_seq_{1};
    std::string last_message_;
};

#endif  // __linux__

}  // namespace statusbar::net::tc
