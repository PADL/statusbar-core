#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The netdev generic-netlink family's queue and NAPI commands (Documentation/netlink/specs/netdev.yaml):
/// the NAPI behind a device queue, its kthread, and its threaded mode (Documentation/networking/napi.rst),
/// as `ynl --family netdev` queue-get, napi-get and napi-set do them. Linux only.

#if defined(__linux__)

#    include "statusbar/net/net_netdev_features.hpp"
#    include "statusbar/net/net_netlink.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cstddef>
#    include <cstdint>
#    include <optional>
#    include <span>
#    include <string>

namespace statusbar::net::netdev {

//
// Wire constants - linux/netdev.h (Linux 7.1); defined here as the build host's headers may predate them
//

/// NETDEV_CMD_QUEUE_GET (6.9), NETDEV_CMD_NAPI_GET (6.9) and NETDEV_CMD_NAPI_SET (6.13).
inline constexpr uint8_t CMD_QUEUE_GET = 10;
inline constexpr uint8_t CMD_NAPI_GET = 11;
inline constexpr uint8_t CMD_NAPI_SET = 14;
/// NETDEV_A_QUEUE_*: a queue's id, device, type and NAPI.
inline constexpr uint16_t QUEUE_ID = 1;
inline constexpr uint16_t QUEUE_IFINDEX = 2;
inline constexpr uint16_t QUEUE_TYPE = 3;
inline constexpr uint16_t QUEUE_NAPI_ID = 4;
/// NETDEV_A_NAPI_*: a NAPI's device, id, IRQ, kthread and threaded mode (6.17).
inline constexpr uint16_t NAPI_IFINDEX = 1;
inline constexpr uint16_t NAPI_ID = 2;
inline constexpr uint16_t NAPI_IRQ = 3;
inline constexpr uint16_t NAPI_PID = 4;
inline constexpr uint16_t NAPI_THREADED = 8;

/// enum netdev_queue_type.
enum class QueueType : uint32_t
{
    rx = 0,
    tx = 1,
};

/// enum netdev_napi_threaded: softirq polling, a kthread woken by the IRQ, or a kthread that busy polls
/// with the IRQ left masked (busy_poll, Linux 7.1).
enum class NapiThreaded : uint32_t
{
    disabled = 0,
    enabled = 1,
    busy_poll = 2,
};

/// One queue as NETDEV_CMD_QUEUE_GET reports it.
struct QueueInfo
{
    uint32_t id{0};
    int ifindex{0};
    QueueType type{QueueType::rx};
    std::optional<uint32_t> napi_id{};  ///< none when the driver links no NAPI to the queue

    auto operator==(QueueInfo const&) const noexcept -> bool = default;
};

/// One NAPI instance as NETDEV_CMD_NAPI_GET reports it.
struct NapiInfo
{
    uint32_t id{0};
    int ifindex{0};
    std::optional<uint32_t> irq{};
    std::optional<uint32_t> pid{};           ///< its kthread, while threaded
    std::optional<NapiThreaded> threaded{};  ///< none before Linux 6.17

    auto operator==(NapiInfo const&) const noexcept -> bool = default;
};

/// The NAPIs serving one queue index: its RX queue's, then its TX queue's when that is another.
struct QueueNapis
{
    std::array<uint32_t, 2> ids{};
    std::array<uint32_t, 2> pids{};  ///< each one's kthread after set_queue_threaded() (0: none)
    size_t count{0};

    [[nodiscard]] auto napi_ids() const noexcept -> std::span<uint32_t const> { return std::span{ids}.first(count); }

    auto operator==(QueueNapis const&) const noexcept -> bool = default;
};

/// Build NETDEV_CMD_QUEUE_GET for `ifindex`'s `type` queue `queue_id` to family `family_id`
/// (NLM_F_REQUEST | NLM_F_ACK) into `out`: the message length.
[[nodiscard]] auto build_queue_get(
    std::span<uint8_t> out, uint16_t family_id, int ifindex, uint32_t queue_id, QueueType type, uint32_t seq)
    -> StatusValue<size_t>;

/// Build NETDEV_CMD_NAPI_GET for NAPI `napi_id` into `out`: the message length.
[[nodiscard]] auto build_napi_get(std::span<uint8_t> out, uint16_t family_id, uint32_t napi_id, uint32_t seq)
    -> StatusValue<size_t>;

/// Build NETDEV_CMD_NAPI_SET of NAPI `napi_id`'s threaded mode into `out`: the message length.
[[nodiscard]] auto build_napi_set_threaded(
    std::span<uint8_t> out, uint16_t family_id, uint32_t napi_id, NapiThreaded mode, uint32_t seq) -> StatusValue<size_t>;

/// The queue in one NETDEV_CMD_QUEUE_GET reply of family `family_id`. bad_message when truncated,
/// malformed, another message, or without the queue's id, device or type.
[[nodiscard]] auto parse_queue(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<QueueInfo>;

/// The NAPI in one NETDEV_CMD_NAPI_GET reply of family `family_id`. bad_message when truncated,
/// malformed, another message, or without the NAPI's id; an unknown threaded mode is left unset.
[[nodiscard]] auto parse_napi(std::span<uint8_t const> message, uint16_t family_id) -> StatusValue<NapiInfo>;

/// A blocking NETLINK_GENERIC socket for the netdev queue and NAPI commands: each call sends one
/// request and waits (at most about a second) for its ack. Not thread-safe; not for real-time threads.
class NapiClient
{
  public:
    NapiClient() noexcept = default;

    /// Open the socket and resolve the netdev family. Errors: the socket's errno; ENOENT before Linux 6.3.
    [[nodiscard]] auto open() -> Status;
    [[nodiscard]] auto is_open() const noexcept -> bool { return socket_.is_open(); }

    /// NETDEV_CMD_QUEUE_GET. Errors: ENODEV for no such device, ENOENT while it is down, EINVAL for no such
    /// queue, EOPNOTSUPP before 6.9, else the request's.
    [[nodiscard]] auto queue(int ifindex, uint32_t queue_id, QueueType type) -> StatusValue<QueueInfo>;
    /// NETDEV_CMD_NAPI_GET. Errors: ENOENT for no such NAPI or one whose device is down, else the request's.
    [[nodiscard]] auto napi(uint32_t napi_id) -> StatusValue<NapiInfo>;
    /// NETDEV_CMD_NAPI_SET of the threaded mode (CAP_NET_ADMIN). Errors: EINVAL where the kernel lacks
    /// `mode` (busy_poll before 7.1, any before 6.17), EOPNOTSUPP before 6.13, the driver's refusal.
    [[nodiscard]] auto set_threaded(uint32_t napi_id, NapiThreaded mode) -> Status;
    /// The NAPIs of `ifindex`'s RX and TX queue `queue_id` (RX's alone without that TX queue), pids unset.
    /// Errors: the RX queue()'s, and operation_not_supported when the driver links no NAPI to either.
    [[nodiscard]] auto queue_napis(int ifindex, uint32_t queue_id) -> StatusValue<QueueNapis>;

    /// The kernel's extended-ack message for the last failed request (empty: none given).
    [[nodiscard]] auto last_message() const noexcept -> std::string const& { return socket_.last_message(); }

  private:
    /// CTRL_CMD_GETFAMILY "netdev" into family_id_.
    [[nodiscard]] auto resolve_family() -> Status;
    /// Socket::request() of `build` (out, seq), each reply of nlmsg_type `type` handed to `parse` (message) -> Status.
    template <typename Build, typename Parse>
    [[nodiscard]] auto request(uint16_t type, Build const& build, Parse const& parse) -> Status;

    netlink::Socket socket_{};
    uint16_t family_id_{0};
    std::array<uint8_t, 4096> reply_{};  ///< queue and NAPI replies are under 256 octets
};

/// `client`'s queue_napis() of `ifindex`'s queue `queue_id` set to `mode`; a threaded mode is reached through
/// enabled, each kthread pinned SCHED_OTHER to `cpu` (pin_napi_thread()) first, and a failure leaves them
/// disabled, as does disabled (whatever mode they had before). Errors: the client's, or the pinning's errno.
[[nodiscard]] auto set_queue_threaded(NapiClient& client, int ifindex, uint32_t queue_id, NapiThreaded mode, int cpu)
    -> StatusValue<QueueNapis>;

/// Make kthread `pid` SCHED_OTHER (a busy-polling kthread at a real-time policy starves its CPU's
/// per-CPU kthreads) and pin it to `cpu`. Errors: sched_setscheduler()'s or sched_setaffinity()'s errno.
[[nodiscard]] auto pin_napi_thread(uint32_t pid, int cpu) -> Status;

}  // namespace statusbar::net::netdev

#endif  // __linux__
