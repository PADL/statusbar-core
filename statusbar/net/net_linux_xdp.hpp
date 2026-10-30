#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// AF_XDP module for statusbar.net
/// Provides lockless zero-copy Ethernet frame TX/RX using Linux AF_XDP sockets.
/// This module is Linux-specific and requires libbpf.

#if defined(__linux__) && defined(HAVE_XDP)

// BPF object is embedded via #embed in xdp_filter_bpf_embed.cpp (plain .cpp
// avoids clang-19 #embed bug in module interface units that places data in BSS).
extern unsigned char const xdp_filter_bpf_o[];
extern unsigned int const xdp_filter_bpf_o_len;

#    include <fcntl.h>
#    include <poll.h>
#    include <unistd.h>

#    include <cerrno>
#    include <cstring>
#    include <ctime>

#    include <arpa/inet.h>
#    include <bpf/bpf.h>
#    include <bpf/libbpf.h>
#    include <linux/bpf.h>
#    include <linux/if_ether.h>
#    include <linux/if_link.h>
#    include <linux/if_xdp.h>
#    include <net/if.h>
#    include <sys/ioctl.h>
#    include <sys/mman.h>
#    include <sys/socket.h>
#    include <xdp/xsk.h>

#endif  // __linux__ && HAVE_XDP

#if defined(__linux__)
#    include <linux/if_link.h>
#    include <linux/if_xdp.h>
#endif

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/net/net_tcam_bpf_abi.h"
#include "statusbar/status/status.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace statusbar::net {

// ──────────────────────────────────────────────
// Error handling
// ──────────────────────────────────────────────

enum class XdpError
{
    socket_creation_failed = 1,
    interface_not_found,
    get_hwaddr_failed,
    umem_creation_failed,
    xsk_creation_failed,
    bpf_load_failed,
    bpf_attach_failed,
    bpf_map_update_failed,
    tap_creation_failed,
    tap_configure_failed,
    not_open,
    tx_ring_full,
    rx_ring_empty,
    fill_ring_full,
    free_list_empty,
    invalid_addr,
    frame_too_large,
    tx_flush_failed,
    join_multicast_failed,
    not_supported_on_platform,
    invalid_bpf_program,
    too_many_filter_rules,
    leave_multicast_failed,
    bpf_query_failed,
    bpf_pin_failed,
    bpf_detach_failed,
    zero_copy_needs_native_attach,
    tx_metadata_not_supported,
};

class XdpErrorCategory : public std::error_category
{
  public:
    [[nodiscard]] auto name() const noexcept -> char const* override { return "statusbar.net.xdp"; }

    /// @param ev Error code value to convert to a message string
    [[nodiscard]] auto message(int ev) const -> std::string override;
};

[[nodiscard]] inline auto xdp_error_category() noexcept -> std::error_category const&
{
    static XdpErrorCategory const instance;
    return instance;
}

/// @param e The XdpError value to convert
[[nodiscard]] inline auto make_error_code(XdpError e) noexcept -> std::error_code
{
    return {static_cast<int>(e), xdp_error_category()};
}

// ──────────────────────────────────────────────
// Configuration types
// ──────────────────────────────────────────────

enum class XdpAction : uint8_t
{
    redirect_xsk,
    pass_kernel,
    redirect_tap,
};

/// How the XSK socket binds. auto_: zero-copy under a native program when the
/// driver offers it, else copy (never zero-copy under a generic program);
/// zero_copy: native and zero-copy or fail; copy: copy mode.
enum class XdpBindMode : uint8_t
{
    auto_,
    zero_copy,
    copy,
};

/// How the XDP program is attached. native (driver mode) is what zero-copy
/// needs, but attaching or detaching it on a running igb link resets the
/// adapter; generic (SKB mode): no reset, copy mode only.
enum class XdpAttachMode : uint8_t
{
    native,
    generic,
};

struct XdpConfig
{
    std::string_view interface_name;
    std::span<CompiledRule<32> const> filter_rules{};
    XdpAction default_action{XdpAction::pass_kernel};
    uint32_t queue_id{0};
    size_t rx_ring_size{256};
    size_t tx_ring_size{256};
    /// fill_replenish() keeps up to this many free frames in the fill ring for RX.
    size_t fill_ring_size{512};
    size_t completion_ring_size{512};
    /// A received frame must fit one NIC buffer: the frame size less the XDP headroom,
    /// rounded down to the driver's buffer granularity (igb: 1 KiB). 4096 leaves 3 KiB.
    size_t umem_frame_size{4096};
    /// tx_start() draws from what the fill ring leaves: umem_frame_count -
    /// fill_ring_size after open() (none if not larger), less frames held in RX.
    size_t umem_frame_count{1024};
    /// Octets reserved at the start of each frame; tx_launch_time adds TX_METADATA_SIZE to it.
    size_t umem_headroom{0};
    unsigned int tap_ifindex{0};
    size_t rx_drain_max{32};
    size_t completion_drain_max{64};
    /// The clock rx_start() stamps frames with; -1: none (timestamp_ns 0, no
    /// clock_gettime per frame).
    int rx_clock_id{CLOCK_MONOTONIC_RAW};
    XdpBindMode bind_mode{XdpBindMode::auto_};
    /// The mode a fresh attach asks for (a refused native attach falls back to
    /// generic unless bind_mode is zero_copy). An attached native program
    /// stays native whatever this says; a generic one gives way to native.
    XdpAttachMode attach_mode{XdpAttachMode::native};
    /// A bpffs directory (XdpProgram::pin_path_for()) where a fresh program is
    /// pinned and, with `adopt`, from which the same program still attached is
    /// adopted instead of attaching another. Empty: no pinning.
    std::string_view pin_path{};
    bool adopt{true};
    /// Detach the program at close. Default: a generic program this context
    /// attached; a native one stays (a native detach resets igb).
    std::optional<bool> detach_on_close{};
    /// Bind with XDP_USE_NEED_WAKEUP: tx_flush() kicks only when the kernel
    /// asks for it, fill_replenish() wakes RX only when the fill ring ran dry.
    bool need_wakeup{true};
    /// Reserve AF_XDP TX metadata so tx_start(launch_time_ns) carries launch times. open() fails with
    /// tx_metadata_not_supported without libxdp >= 1.5 or kernel support; whether the driver honours
    /// the time is launch_time_supported()'s to say (copy mode works without it).
    bool tx_launch_time{false};
};

/// The XDP program attached to an interface, as bpf_xdp_query() reports it.
struct XdpAttachedProgram
{
    uint32_t prog_id{0};
    XdpAttachMode mode{XdpAttachMode::native};
};

/// Counters of one XDP socket (XdpContext::stats()).
struct XdpSocketStats
{
    uint64_t rx_count{0};
    uint64_t tx_count{0};
    uint64_t tx_ring_full_count{0};
    uint64_t umem_exhausted_count{0};
    uint64_t rx_budget_hit_count{0};
    uint64_t tx_flush_count{0};      ///< kicks made (sendto)
    uint64_t tx_flush_skipped{0};    ///< kicks not needed (ring drained, or no wakeup asked for)
    uint64_t tx_flush_failed{0};     ///< kicks the kernel refused
    uint64_t tx_flush_transient{0};  ///< kicks that dropped a frame or found the link down (EBUSY, ENOBUFS, ENETDOWN)
    int tx_flush_errno{0};           ///< the last refused kick's errno
    uint64_t rx_wakeup_count{0};     ///< fill-ring wakeups (recvfrom)
};

namespace detail {

/// What an attach tries: `first`, then `fallback` if the driver refuses it.
struct AttachPlan
{
    XdpAttachMode first{XdpAttachMode::native};
    std::optional<XdpAttachMode> fallback;
};

/// A fresh attach's plan: zero-copy is native or nothing; native falls back to generic.
/// @param requested XdpConfig::attach_mode
/// @param bind XdpConfig::bind_mode
[[nodiscard]] constexpr auto attach_plan(XdpAttachMode requested, XdpBindMode bind) noexcept -> std::expected<AttachPlan, XdpError>
{
    if (bind == XdpBindMode::zero_copy) {
        if (requested != XdpAttachMode::native) {
            return std::unexpected(XdpError::zero_copy_needs_native_attach);
        }
        return AttachPlan{.first = XdpAttachMode::native, .fallback = std::nullopt};
    }
    if (requested == XdpAttachMode::native) {
        return AttachPlan{.first = XdpAttachMode::native, .fallback = XdpAttachMode::generic};
    }
    return AttachPlan{.first = XdpAttachMode::generic, .fallback = std::nullopt};
}

//
// TX metadata - Documentation/networking/xsk-tx-metadata.rst
//

/// struct xsk_tx_metadata (linux/if_xdp.h, 6.15+): what the driver reads from just before a
/// TX descriptor's data when the descriptor carries XDP_TX_METADATA. Host byte order.
struct XskTxMetadata
{
    uint64_t flags{0};
    uint16_t csum_start{0};
    uint16_t csum_offset{0};
    uint32_t reserved{0};
    uint64_t launch_time{0};  ///< ns on the NIC's PTP hardware clock
};
static_assert(sizeof(XskTxMetadata) == 24);
static_assert(offsetof(XskTxMetadata, csum_start) == 8 && offsetof(XskTxMetadata, launch_time) == 16);

/// The UMEM's tx_metadata_len when TX metadata is reserved.
inline constexpr size_t TX_METADATA_SIZE = sizeof(XskTxMetadata);
/// XDP_TXMD_FLAGS_LAUNCH_TIME: the driver sends the frame at request.launch_time.
inline constexpr uint64_t TX_METADATA_LAUNCH_TIME = 1U << 2U;
/// XDP_TX_METADATA: xdp_desc::options bit saying the metadata before the data is valid.
inline constexpr uint32_t TX_DESC_METADATA = 1U << 1U;
/// XDP_UMEM_TX_METADATA_LEN: xdp_umem_reg::flags bit that makes the kernel honour tx_metadata_len.
inline constexpr uint32_t UMEM_TX_METADATA_LEN = 1U << 2U;

/// The UMEM's tx_metadata_len for `tx_launch_time`: TX_METADATA_SIZE, or 0 when not asked
/// for. tx_metadata_not_supported when asked for but built without HAVE_XSK_TX_METADATA.
[[nodiscard]] constexpr auto tx_metadata_len(bool const tx_launch_time) noexcept -> std::expected<size_t, XdpError>
{
    if (!tx_launch_time) {
        return size_t{0};
    }
#if defined(HAVE_XSK_TX_METADATA)
    return TX_METADATA_SIZE;
#else
    return std::unexpected(XdpError::tx_metadata_not_supported);
#endif
}

/// Write a frame's TX metadata into `metadata` (its TX_METADATA_SIZE octets before the
/// data; empty: none reserved, nothing written): LAUNCH_TIME at `launch_time_ns` when > 0, else no request.
inline void write_tx_metadata(std::span<uint8_t> const metadata, int64_t const launch_time_ns) noexcept
{
    if (metadata.size() < TX_METADATA_SIZE) {
        return;
    }
    bool const timed = launch_time_ns > 0;
    span_store(
        metadata,
        XskTxMetadata{
            .flags = timed ? TX_METADATA_LAUNCH_TIME : 0, .launch_time = timed ? static_cast<uint64_t>(launch_time_ns) : 0});
}

/// The xdp_desc::options for a frame whose metadata is `metadata`: TX_DESC_METADATA when
/// it requests anything, else 0 (also for an empty span).
[[nodiscard]] inline auto tx_metadata_options(std::span<uint8_t const> const metadata) noexcept -> uint32_t
{
    if (metadata.size() < TX_METADATA_SIZE) {
        return 0;
    }
    uint64_t flags = 0;
    span_load(flags, metadata.first(sizeof(flags)));
    return flags != 0 ? TX_DESC_METADATA : 0;
}

/// The mode beside an attached program: native stays native, generic gives way to native.
/// @param attached The attached program's mode
/// @param requested XdpConfig::attach_mode
[[nodiscard]] constexpr auto effective_attach_mode(XdpAttachMode attached, XdpAttachMode requested) noexcept -> XdpAttachMode
{
    return attached == XdpAttachMode::native ? XdpAttachMode::native : requested;
}

}  // namespace detail

}  // namespace statusbar::net

/// Register XdpError as an error code enum (must be before XdpContext uses failure())
template <>
struct std::is_error_code_enum<statusbar::net::XdpError> : std::true_type
{};

namespace statusbar::net {

/// Whether AF_XDP frames can carry launch times, given the driver's answer @p driver
/// (netdev::launch_time_supported(), asked once by the host). Errors: the query's,
/// operation_not_supported (the driver), XdpError::tx_metadata_not_supported (libxdp before 1.5).
[[nodiscard]] inline auto launch_time_support(StatusValue<bool> const& driver) noexcept -> Status
{
    if (!driver) {
        return failure(driver.error());
    }
    if (!*driver) {
        return failure(std::errc::operation_not_supported);
    }
    if (auto const metadata = detail::tx_metadata_len(true); !metadata) {
        return failure(metadata.error());
    }
    return success();
}

/// Register a small UMEM with TX metadata and let it go, before anything is attached to an interface:
/// what a kernel before 6.11 refuses (XdpError::tx_metadata_not_supported); the build's refusal first.
/// A caller that asked for launch time opens untimed on a refusal, with the reason.
[[nodiscard]] auto probe_tx_metadata() -> Status;

/// Launch time as a host can have it at start: possible (the driver and the build), or why not.
struct LaunchTimePlan
{
    bool on{false};                   ///< wanted and possible: open the socket with TX metadata
    StatusValue<bool> driver{false};  ///< netdev::launch_time_supported(), asked once, for every user
    std::string why{};                ///< wanted and not possible: the reason
};

/// The plan for launch time @p wanted given the driver's answer @p driver (launch_time_support()).
[[nodiscard]] inline auto plan_launch_time(bool const wanted, StatusValue<bool> const& driver) -> LaunchTimePlan
{
    LaunchTimePlan plan{.driver = driver};
    auto const support = wanted ? launch_time_support(driver) : Status{};
    plan.on = wanted && support.has_value();
    if (!support) {
        plan.why = support.error() == std::errc::operation_not_supported ? std::string{"the driver reports no tx-launch-time-fifo"}
                                                                         : support.error().message();
    }
    return plan;
}

// ──────────────────────────────────────────────
// Internal utilities (detail namespace — not part of public API contract)
// ──────────────────────────────────────────────

namespace detail {

/// Bounded stack for tracking free UMEM frame addresses.
/// Single-threaded — no atomics needed.
class UmemFreeList
{
  public:
    UmemFreeList() = default;

    /// @param frame_count Total number of UMEM frames
    /// @param frame_size Size of each UMEM frame in bytes
    /// @param memory_resource Memory resource for the stack_ vector.
    ///        nullptr → std::pmr::get_default_resource().
    explicit UmemFreeList(size_t frame_count, size_t frame_size, std::pmr::memory_resource* memory_resource = nullptr)
        : stack_(frame_count, 0, memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource())
        , top_{frame_count}
    {
        for (size_t i = 0; i < frame_count; ++i) {
            stack_[i] = i * frame_size;
        }
    }

    [[nodiscard]] auto pop() noexcept -> std::optional<uint64_t>
    {
        if (top_ == 0) {
            return std::nullopt;
        }
        return stack_[--top_];
    }

    /// @param addr UMEM frame address to return to the free list
    void push(uint64_t addr) noexcept
    {
        if (top_ < stack_.size()) {
            stack_[top_++] = addr;
        } else {
            ++overflow_count_;
        }
    }

    [[nodiscard]] auto available() const noexcept -> size_t { return top_; }
    [[nodiscard]] auto overflow_count() const noexcept -> size_t { return overflow_count_; }

  private:
    std::pmr::vector<uint64_t> stack_;
    size_t top_{0};
    size_t overflow_count_{0};
};

/// Minimal RAII scope guard (file-local utility, can be deduplicated later).
/// Callable should be noexcept — if it throws, std::terminate is called.
template <typename F>
class ScopeGuard
{
  public:
    /// @param f Callable to invoke on destruction
    explicit ScopeGuard(F&& f) noexcept
        : f_(std::move(f))
    {}
    ~ScopeGuard() noexcept { f_(); }
    ScopeGuard(ScopeGuard const&) = delete;
    auto operator=(ScopeGuard const&) -> ScopeGuard& = delete;

  private:
    F f_;
};

/// @param f Callable to invoke when the guard goes out of scope
template <typename F>
auto scopeguard(F&& f)
{
    return ScopeGuard<std::decay_t<F>>(std::forward<F>(f));
}

/// NIC identity (interface index + MAC address)
struct InterfaceId
{
    ieee::Eui48 hardware_address{};
    unsigned int index{0};
};

/// Per-poll-cycle budget limits and counters
struct CycleBudget
{
    size_t rx_drain_max{0};
    size_t completion_drain_max{64};
    int rx_clock_id{0};
    size_t rx_cycle_count{0};
};

/// Number of fill ring slots to reserve. xsk_ring_prod__reserve() is
/// all-or-nothing, so never ask for more than the ring has free.
/// @param available Free UMEM frames
/// @param ring_free Free fill ring entries (xsk_prod_nb_free())
[[nodiscard]] constexpr auto fill_reserve_count(size_t available, uint32_t ring_free) noexcept -> uint32_t
{
    return available < ring_free ? static_cast<uint32_t>(available) : ring_free;
}

#if defined(__linux__)
/// The sxdp_flags for `mode` under a program attached in `attached` mode:
/// auto_ is 0 (the kernel picks) under native, XDP_COPY under generic;
/// zero_copy under generic is refused. Plus XDP_USE_NEED_WAKEUP if asked.
[[nodiscard]] constexpr auto xdp_bind_flags(XdpBindMode mode, XdpAttachMode attached, bool need_wakeup) noexcept
    -> std::expected<uint16_t, XdpError>
{
    auto const wakeup = static_cast<uint16_t>(need_wakeup ? XDP_USE_NEED_WAKEUP : 0);
    switch (mode) {
        case XdpBindMode::zero_copy:
            if (attached != XdpAttachMode::native) {
                return std::unexpected(XdpError::zero_copy_needs_native_attach);
            }
            return static_cast<uint16_t>(XDP_ZEROCOPY | wakeup);
        case XdpBindMode::copy:
            return static_cast<uint16_t>(XDP_COPY | wakeup);
        case XdpBindMode::auto_:
            break;
    }
    return static_cast<uint16_t>((attached == XdpAttachMode::native ? 0 : XDP_COPY) | wakeup);
}

/// Errors a kick may meet in passing: EAGAIN (the rest next kick), EBUSY (a
/// frame dropped), ENOBUFS, ENETDOWN (a link flap).
[[nodiscard]] constexpr auto is_transient_kick_error(int error) noexcept -> bool
{
    return error == EAGAIN || error == EWOULDBLOCK || error == EBUSY || error == ENOBUFS || error == ENETDOWN;
}

/// The XDP_FLAGS_* mode bit for an attach mode.
/// @param mode Attach mode
[[nodiscard]] constexpr auto xdp_attach_flags(XdpAttachMode mode) noexcept -> uint32_t
{
    return mode == XdpAttachMode::native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
}
#endif

}  // namespace detail

// ──────────────────────────────────────────────
// XdpContext — Linux implementation with libbpf/libxdp
// ──────────────────────────────────────────────

#if defined(__linux__) && defined(HAVE_XDP)

namespace detail {

/// The four XSK ring buffers
struct RingSet
{
    struct xsk_ring_prod fill{};
    struct xsk_ring_cons comp{};
    struct xsk_ring_prod tx{};
    struct xsk_ring_cons rx{};
};

/// The UMEM UmemRegion::allocate() creates.
struct UmemGeometry
{
    size_t frame_count{0};
    size_t frame_size{0};
    size_t headroom{0};         ///< reserved at the start of each frame, before any TX metadata
    size_t tx_metadata_len{0};  ///< 0 or TX_METADATA_SIZE, between the headroom and the data
    size_t fill_ring_size{0};
    size_t comp_ring_size{0};
};

/// The UMEM `config` asks for; tx_metadata_not_supported as tx_metadata_len(). The one
/// validation of tx_launch_time: XdpContext::open() calls it before closing or attaching.
/// @param config The socket's configuration
[[nodiscard]] constexpr auto umem_geometry(XdpConfig const& config) noexcept -> std::expected<UmemGeometry, XdpError>
{
    return tx_metadata_len(config.tx_launch_time).transform([&](size_t const metadata) {
        return UmemGeometry{
            .frame_count = config.umem_frame_count,
            .frame_size = config.umem_frame_size,
            .headroom = config.umem_headroom,
            .tx_metadata_len = metadata,
            .fill_ring_size = config.fill_ring_size,
            .comp_ring_size = config.completion_ring_size,
        };
    });
}

/// True when the kernel's XDP_UMEM_REG and libxdp's rings accept `geometry` (aligned chunks
/// of a power of two from 2048 to `page_size`, room after the headroom, power-of-two rings).
[[nodiscard]] constexpr auto valid_umem_geometry(UmemGeometry const& geometry, size_t const page_size) noexcept -> bool
{
    auto const power_of_two = [](size_t const n) { return n != 0 && (n & (n - 1)) == 0; };
    return power_of_two(geometry.frame_size) && geometry.frame_size >= 2048 && geometry.frame_size <= page_size &&
        geometry.headroom + geometry.tx_metadata_len + XDP_PACKET_HEADROOM < geometry.frame_size &&
        power_of_two(geometry.fill_ring_size) && power_of_two(geometry.comp_ring_size);
}

/// Owns the mmap'd UMEM region, frame config, and free list.
/// RAII — destructor calls close().
class UmemRegion
{
  public:
    UmemRegion() = default;
    ~UmemRegion() { close(); }

    UmemRegion(UmemRegion&& other) noexcept { swap(other); }

    auto operator=(UmemRegion&& other) noexcept -> UmemRegion&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    UmemRegion(UmemRegion const&) = delete;
    auto operator=(UmemRegion const&) -> UmemRegion& = delete;

    /// mmap + prefault + create the UMEM (its frame headroom geometry.headroom + tx_metadata_len)
    /// with `rings`' fill and completion rings. Returns xsk_umem* for xsk_socket__create.
    [[nodiscard]] auto allocate(UmemGeometry const& geometry, RingSet& rings) -> StatusValue<struct xsk_umem*>;

    void close() noexcept;

    /// @param addr UMEM frame address
    [[nodiscard]] auto writable_span(uint64_t addr) -> std::span<uint8_t>
    {
        return {area_ + addr + headroom_, frame_size_ - headroom_};
    }

    /// @param addr UMEM frame address
    /// @param len Number of bytes to expose as readable
    [[nodiscard]] auto readable_span(uint64_t addr, size_t len) -> std::span<uint8_t const> { return {area_ + addr, len}; }

    /// The TX metadata just before frame `addr`'s data (empty when none is reserved).
    /// @param addr UMEM frame address
    [[nodiscard]] auto tx_metadata_span(uint64_t addr) noexcept -> std::span<uint8_t>
    {
        return {area_ + addr + headroom_ - tx_metadata_len_, tx_metadata_len_};
    }

    /// The TX descriptor for `length` octets of frame `addr`, flagged when its metadata requests anything.
    /// @param addr UMEM frame address
    [[nodiscard]] auto tx_desc(uint64_t addr, size_t length) noexcept -> xdp_desc
    {
        return {
            .addr = addr + headroom_, .len = static_cast<uint32_t>(length), .options = tx_metadata_options(tx_metadata_span(addr))};
    }

    [[nodiscard]] auto alloc_frame() -> std::optional<uint64_t> { return free_list_.pop(); }

    /// @param addr UMEM frame address to return to the free list
    void free_frame(uint64_t addr) noexcept
    {
        if (frame_size_ != 0) {
            free_list_.push((addr / frame_size_) * frame_size_);
        }
    }

    [[nodiscard]] auto available_frames() const noexcept -> size_t { return free_list_.available(); }
    [[nodiscard]] auto frame_size() const noexcept -> size_t { return frame_size_; }
    /// Octets before a frame's data: the configured headroom plus tx_metadata_len().
    [[nodiscard]] auto headroom() const noexcept -> size_t { return headroom_; }
    [[nodiscard]] auto tx_metadata_len() const noexcept -> size_t { return tx_metadata_len_; }

  private:
    /// mmap and prefault `size` octets for area_.
    [[nodiscard]] auto map_area(size_t size) -> Status;
    /// Register area_ as the UMEM; through xsk_umem__create_opts when TX metadata is reserved.
    [[nodiscard]] auto create_umem(UmemGeometry const& geometry, RingSet& rings) -> Status;
    /// Take on the frame layout of the UMEM just created.
    void set_geometry(UmemGeometry const& geometry) noexcept
    {
        frame_size_ = geometry.frame_size;
        headroom_ = geometry.headroom + geometry.tx_metadata_len;
        tx_metadata_len_ = geometry.tx_metadata_len;
        free_list_ = UmemFreeList(geometry.frame_count, geometry.frame_size);
    }

    void swap(UmemRegion& other) noexcept
    {  // NOLINT(statusbar-block-statements): member-wise swap
        std::swap(umem_, other.umem_);
        std::swap(area_, other.area_);
        std::swap(area_size_, other.area_size_);
        std::swap(frame_size_, other.frame_size_);
        std::swap(headroom_, other.headroom_);
        std::swap(tx_metadata_len_, other.tx_metadata_len_);
        std::swap(free_list_, other.free_list_);
    }

    struct xsk_umem* umem_{nullptr};
    uint8_t* area_{nullptr};
    size_t area_size_{0};
    size_t frame_size_{0};
    size_t headroom_{0};
    size_t tx_metadata_len_{0};
    UmemFreeList free_list_;
};

/// RAII wrapper for a loaded bpf_object*.
/// Destructor calls bpf_object__close(). Map/program fds are borrowed
/// from the object and become invalid after destruction.
class BpfObject
{
  public:
    BpfObject() = default;

    ~BpfObject() noexcept { reset(); }

    BpfObject(BpfObject&& other) noexcept
        : obj_{other.obj_}
    {
        other.obj_ = nullptr;
    }

    auto operator=(BpfObject&& other) noexcept -> BpfObject&
    {
        if (this != &other) {
            reset();
            obj_ = other.obj_;
            other.obj_ = nullptr;
        }
        return *this;
    }

    BpfObject(BpfObject const&) = delete;
    auto operator=(BpfObject const&) -> BpfObject& = delete;

    void reset() noexcept
    {
        if (obj_ != nullptr) {
            bpf_object__close(obj_);
            obj_ = nullptr;
        }
    }

    [[nodiscard]] auto get() const noexcept -> struct bpf_object* { return obj_; }
    [[nodiscard]] explicit operator bool() const noexcept { return obj_ != nullptr; }

    /// Open and load a BPF object from memory. Returns error on failure.
    /// @param data Pointer to the BPF object bytes
    /// @param len Size of the BPF object in bytes
    [[nodiscard]] auto open_and_load(void const* data, size_t len) -> Status
    {
        reset();
        obj_ = bpf_object__open_mem(data, len, nullptr);
        if (obj_ == nullptr) {
            return failure(XdpError::bpf_load_failed);
        }
        if (bpf_object__load(obj_) != 0) {
            reset();
            return failure(XdpError::bpf_load_failed);
        }
        return success();
    }

  private:
    struct bpf_object* obj_{nullptr};
};

/// An owned file descriptor (a pinned BPF object from bpf_obj_get()).
class OwnedFd
{
  public:
    OwnedFd() = default;
    /// @param fd Descriptor to own (negative: none)
    explicit OwnedFd(int fd) noexcept
        : fd_{fd}
    {}
    ~OwnedFd() noexcept { reset(); }
    OwnedFd(OwnedFd&& other) noexcept
        : fd_{std::exchange(other.fd_, -1)}
    {}
    auto operator=(OwnedFd&& other) noexcept -> OwnedFd&
    {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }
    OwnedFd(OwnedFd const&) = delete;
    auto operator=(OwnedFd const&) -> OwnedFd& = delete;

    void reset() noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

  private:
    int fd_{-1};
};

}  // namespace detail

/// The XDP filter program (xdp_filter.bpf.c) on one interface: adopted from
/// its pins when still attached, else loaded, attached (replacing in place
/// what is attached in that mode) and pinned. Detached at close only if asked.
class XdpProgram
{
  public:
    struct Options
    {
        std::span<CompiledRule<32> const> filter_rules{};
        XdpAction default_action{XdpAction::pass_kernel};
        XdpAttachMode attach_mode{XdpAttachMode::native};
        /// A refused native attach falls back to generic.
        bool allow_generic_fallback{true};
        std::string_view pin_path{};
        bool adopt{true};
        std::optional<bool> detach_on_close{};
    };

    /// Where pin_path_for() puts an interface's pins.
    static constexpr std::string_view PIN_ROOT = "/sys/fs/bpf/statusbar";
    /// The names of the pins under a pin path.
    static constexpr std::string_view PIN_PROG = "prog";
    static constexpr std::string_view PIN_RULES_MAP = "rules_map";
    static constexpr std::string_view PIN_XSK_MAP = "xsk_map";
    static constexpr std::string_view PIN_DEVMAP = "devmap";

    /// PIN_ROOT/<ifname>.
    /// @param interface_name Interface name
    [[nodiscard]] static auto pin_path_for(std::string_view interface_name) -> std::string
    {
        return std::string{PIN_ROOT} + "/" + std::string{interface_name};
    }

    /// The program attached to `if_index`, or nullopt when none is.
    /// @param if_index Interface index
    [[nodiscard]] static auto query(unsigned int if_index) -> StatusValue<std::optional<XdpAttachedProgram>>;

    /// Detach any XDP program on `if_index` and remove the pins under
    /// `pin_path` (empty: none). A native detach on a running link resets igb.
    [[nodiscard]] static auto detach(unsigned int if_index, std::string_view pin_path) -> Status;

    XdpProgram() = default;
    ~XdpProgram() { close(); }
    XdpProgram(XdpProgram&& other) noexcept { std::swap(state_, other.state_); }
    auto operator=(XdpProgram&& other) noexcept -> XdpProgram&
    {
        if (this != &other) {
            close();
            std::swap(state_, other.state_);
        }
        return *this;
    }
    XdpProgram(XdpProgram const&) = delete;
    auto operator=(XdpProgram const&) -> XdpProgram& = delete;

    /// Adopt, or load, attach and pin, the program on `if_index`, with
    /// `options.filter_rules` installed either way.
    [[nodiscard]] auto open(unsigned int if_index, Options const& options) -> Status;
    /// Release the program, detaching it (and removing its pins) when
    /// will_detach_on_close().
    void close() noexcept;

    [[nodiscard]] auto valid() const noexcept -> bool { return state_.prog_fd >= 0; }
    /// The mode the program runs in.
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return state_.mode; }
    /// True when open() adopted a pinned program rather than attaching one.
    [[nodiscard]] auto adopted() const noexcept -> bool { return state_.adopted; }
    /// True when the program is pinned (by this open() or adopted from the pins).
    [[nodiscard]] auto pinned() const noexcept -> bool { return !state_.pin_path.empty(); }
    [[nodiscard]] auto prog_id() const noexcept -> uint32_t { return state_.prog_id; }
    [[nodiscard]] auto will_detach_on_close() const noexcept -> bool { return state_.detach_on_close; }
    [[nodiscard]] auto rules_map_fd() const noexcept -> int { return state_.rules_map_fd; }

    /// Redirect `queue_id`'s matching frames to `xsk_fd` (the kernel drops the
    /// entry when the socket closes).
    [[nodiscard]] auto register_socket(uint32_t queue_id, int xsk_fd) -> Status;

    /// Register TAP interface in devmap
    /// @param tap_ifindex Interface index of the TAP device
    [[nodiscard]] auto register_tap(unsigned int tap_ifindex) -> Status;

    /// Replace the rule set in-place. Stale slots are zeroed so old
    /// rules cannot match after the call returns.
    /// @param rules New rules to install; fails if
    ///              rules.size() > TCAM_MAX_RULES - (default_action != pass_kernel ? 1 : 0)
    [[nodiscard]] auto set_rules(std::span<CompiledRule<32> const> rules) -> Status
    {
        if (state_.rules_map_fd < 0) {
            return failure(XdpError::not_open);
        }
        return install_tcam_rules(rules);
    }

  private:
    struct State
    {
        detail::BpfObject obj;  ///< the program this open() loaded
        detail::OwnedFd adopted_prog;
        detail::OwnedFd adopted_rules_map;
        detail::OwnedFd adopted_xsk_map;
        detail::OwnedFd adopted_devmap;
        int prog_fd{-1};
        int rules_map_fd{-1};
        int xsk_map_fd{-1};
        int devmap_fd{-1};
        unsigned int if_index{0};
        uint32_t prog_id{0};
        XdpAttachMode mode{XdpAttachMode::native};
        XdpAction default_action{XdpAction::pass_kernel};
        bool attached{false};  ///< attached by this open() (not adopted)
        bool adopted{false};
        bool detach_on_close{false};
        std::string pin_path;  ///< pinned by this open(), or adopted from
    };

    [[nodiscard]] auto install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status;
    /// open() after its reset: query, load, then adopt or attach; the caller closes on failure.
    [[nodiscard]] auto adopt_or_attach(unsigned int if_index, Options const& options) -> Status;
    /// Load the built-in program and take its fds.
    [[nodiscard]] auto load_builtin() -> Status;
    [[nodiscard]] auto try_adopt(XdpAttachedProgram const& attached, Options const& options) -> bool;
    /// Take over the pinned `prog` and `maps` (rules, xsk, devmap; verified by try_adopt) in place of the loaded copy.
    void adopt(
        detail::OwnedFd prog, std::array<detail::OwnedFd, 3> maps, XdpAttachedProgram const& attached, std::string_view pin_path);
    /// Attach the loaded program (displacing a generic one for native), then pin it.
    [[nodiscard]] auto attach(unsigned int if_index, std::optional<XdpAttachedProgram> const& attached, Options const& options)
        -> Status;
    /// Attach in plan.first, else plan.fallback; on failure, restore the `displaced` generic program (fd, or -1).
    [[nodiscard]] auto attach_by_plan(unsigned int if_index, detail::AttachPlan const& plan, int displaced) noexcept -> Status;
    /// Work through these fds: the program's and its maps'.
    void set_fds(int prog, int rules_map, int xsk_map, int devmap) noexcept;
    [[nodiscard]] auto pin(std::string_view pin_path) -> Status;

    State state_;
};

/// One AF_XDP socket (UMEM and rings) bound to one interface queue, with the
/// EthernetPort operations: real-time safe, single-threaded.
class XdpSocket
{
  public:
    using Stats = XdpSocketStats;

    XdpSocket() = default;
    ~XdpSocket() { close(); }
    XdpSocket(XdpSocket&& other) noexcept { swap(other); }
    auto operator=(XdpSocket&& other) noexcept -> XdpSocket&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }
    XdpSocket(XdpSocket const&) = delete;
    auto operator=(XdpSocket const&) -> XdpSocket& = delete;

    /// open() retries a bind refused with EBUSY this often, BIND_BUSY_PAUSE_NS
    /// apart: a socket just closed on the queue is released by the kernel later.
    static constexpr size_t BIND_BUSY_RETRIES = 50;
    static constexpr long BIND_BUSY_PAUSE_NS = 10'000'000;

    /// Allocate a UMEM of `geometry` (detail::umem_geometry(config)) and bind to `config.queue_id`,
    /// with xdp_bind_flags() for a program attached in `attached` mode. Leaves the fill ring empty.
    [[nodiscard]] auto open(XdpConfig const& config, detail::UmemGeometry const& geometry, XdpAttachMode attached) -> Status;
    void close() noexcept;

    [[nodiscard]] auto valid() const noexcept -> bool { return xsk_ != nullptr; }
    [[nodiscard]] auto fd() const noexcept -> int { return xsk_ != nullptr ? xsk_socket__fd(xsk_) : -1; }
    /// True when the socket runs zero-copy: the program is native and the
    /// bind read back XDP_OPTIONS_ZEROCOPY.
    [[nodiscard]] auto zero_copy() const noexcept -> bool { return zero_copy_; }
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return bind_mode_; }
    /// True when the UMEM reserves TX metadata (XdpConfig::tx_launch_time).
    [[nodiscard]] auto tx_launch_time() const noexcept -> bool { return umem_.tx_metadata_len() != 0; }

    void begin_cycle() noexcept { budget_.rx_cycle_count = 0; }

    /// A free UMEM frame to fill and tx_commit(); free_list_empty when the fill
    /// ring and RX hold the rest (XdpConfig::umem_frame_count).
    /// @param launch_time_ns When to send, ns on the NIC's PHC; 0: now. Ignored without tx_launch_time().
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        auto addr = umem_.alloc_frame();
        if (!addr) {
            ++stats_.umem_exhausted_count;
            return failure(XdpError::free_list_empty);
        }
        detail::write_tx_metadata(umem_.tx_metadata_span(*addr), launch_time_ns);
        return EthernetTxSlot{
            .handle = *addr,
            .buffer = umem_.writable_span(*addr),
        };
    }

    /// Set (or, with 0, clear) the launch time of frame `handle`, taken by tx_start() and not yet
    /// committed: for frames taken ahead of time. Nothing without tx_launch_time().
    /// @param launch_time_ns When to send, ns on the NIC's PHC; 0: now
    void tx_set_launch_time(uint64_t handle, int64_t launch_time_ns) noexcept
    {
        detail::write_tx_metadata(umem_.tx_metadata_span(handle), launch_time_ns);
    }

    /// @param handle UMEM frame address from tx_start()
    /// @param frame_length Total frame size including Ethernet header
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) -> Status;

    /// @param handle UMEM frame address from tx_start()
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status
    {
        umem_.free_frame(handle);
        return success();
    }

    /// One sendto() kick, skipped when the ring is drained or no wakeup is
    /// asked for. Transient errors are counted, not failures; the rest fail
    /// (tx_flush_failed, tx_flush_errno).
    [[nodiscard]] auto tx_flush() -> Status;

    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;

    /// @param handle UMEM frame address from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status
    {
        umem_.free_frame(handle);
        return success();
    }

    /// Offer the kernel free UMEM frames for RX; with need_wakeup, wake the
    /// driver (one recvfrom()) when the fill ring's flag says it ran dry.
    [[nodiscard]] auto fill_replenish() -> Status;

    [[nodiscard]] auto tx_complete() -> Status;

    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }
    /// Zero the counters (the last errno too); on the socket's thread, between operations.
    void reset_stats() noexcept { stats_ = {}; }

  private:
    /// Create the socket on `config.queue_id`, retrying while the queue is busy.
    [[nodiscard]] auto bind_queue(XdpConfig const& config, detail::UmemGeometry const& geometry, uint16_t bind_flags) -> Status;
    /// One fresh UMEM (`geometry`) and socket create: true when bound, false when the queue
    /// was busy (EBUSY; closed again), else the UMEM's or xsk_creation_failed.
    [[nodiscard]] auto create_once(
        XdpConfig const& config, detail::UmemGeometry const& geometry, std::string const& ifname, xsk_socket_config const& xsk_cfg)
        -> StatusValue<bool>;
    /// Record what the bind obtained (mode, wakeup, zero-copy) and the cycle budget.
    void record_bind(XdpConfig const& config, XdpAttachMode attached) noexcept;

    void swap(XdpSocket& other) noexcept
    {
        std::swap(xsk_, other.xsk_);
        std::swap(umem_, other.umem_);
        std::swap(rings_, other.rings_);
        std::swap(budget_, other.budget_);
        std::swap(stats_, other.stats_);
        std::swap(bind_mode_, other.bind_mode_);
        std::swap(zero_copy_, other.zero_copy_);
        std::swap(need_wakeup_, other.need_wakeup_);
    }

    struct xsk_socket* xsk_{nullptr};
    detail::UmemRegion umem_;
    detail::RingSet rings_;
    detail::CycleBudget budget_;
    Stats stats_{};
    XdpBindMode bind_mode_{XdpBindMode::auto_};
    bool zero_copy_{false};
    bool need_wakeup_{false};
};

/// One XdpProgram and one XdpSocket on one interface queue: the EthernetPort
/// the users open with one XdpConfig.
class XdpContext
{
  public:
    using Stats = XdpSocketStats;

    XdpContext() = default;
    ~XdpContext() { close(); }

    XdpContext(XdpContext&& other) noexcept { swap(other); }

    auto operator=(XdpContext&& other) noexcept -> XdpContext&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    XdpContext(XdpContext const&) = delete;
    auto operator=(XdpContext const&) -> XdpContext& = delete;

    /// Open on `config.interface_name`. A config refused up front (tx_metadata_not_supported)
    /// leaves the context as it was; any later failure leaves it closed.
    [[nodiscard]] auto open(XdpConfig const& config) -> Status;
    void close() noexcept;
    [[nodiscard]] auto valid() const noexcept -> bool { return socket_.valid(); }

    [[nodiscard]] auto xsk_fd() const noexcept -> int { return socket_.fd(); }
    [[nodiscard]] auto fd() const noexcept -> int { return socket_.fd(); }

    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return interface_.hardware_address; }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return interface_.index; }

    /// True when the socket runs zero-copy: the program is attached in native
    /// mode and the bind read back XDP_OPTIONS_ZEROCOPY. False in copy mode
    /// or when not open.
    [[nodiscard]] auto zero_copy() const noexcept -> bool { return socket_.zero_copy(); }
    /// The bind mode requested at open().
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return socket_.bind_mode(); }
    /// The mode the program runs in (native when not open).
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return program_.attach_mode(); }
    /// True when open() adopted a pinned program.
    [[nodiscard]] auto adopted() const noexcept -> bool { return program_.adopted(); }
    /// True when tx_start() carries launch times (XdpConfig::tx_launch_time).
    [[nodiscard]] auto tx_launch_time() const noexcept -> bool { return socket_.tx_launch_time(); }
    /// Whether the driver honours AF_XDP launch times (netdev xsk-features tx-launch-time-fifo):
    /// one generic netlink query; not_open when closed. The queue also needs an offloaded ETF qdisc.
    [[nodiscard]] auto launch_time_supported() const -> StatusValue<bool>;

    [[nodiscard]] auto program() noexcept -> XdpProgram& { return program_; }
    [[nodiscard]] auto program() const noexcept -> XdpProgram const& { return program_; }
    [[nodiscard]] auto socket() noexcept -> XdpSocket& { return socket_; }

    void begin_cycle() noexcept { socket_.begin_cycle(); }

    [[nodiscard]] auto end_cycle() -> Status
    {
        auto fill_status = fill_replenish();
        auto comp_status = tx_complete();
        return fill_status ? comp_status : fill_status;
    }

    /// XdpSocket::tx_start().
    /// @param launch_time_ns When to send, ns on the NIC's PHC; 0: now
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        return socket_.tx_start(launch_time_ns);
    }

    /// XdpSocket::tx_set_launch_time().
    /// @param launch_time_ns When to send, ns on the NIC's PHC; 0: now
    void tx_set_launch_time(uint64_t handle, int64_t launch_time_ns) noexcept
    {
        socket_.tx_set_launch_time(handle, launch_time_ns);
    }

    /// @param handle UMEM frame address from tx_start()
    /// @param frame_length Total frame size including Ethernet header
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) -> Status { return socket_.tx_commit(handle, frame_length); }

    /// @param handle UMEM frame address from tx_start()
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status { return socket_.tx_cancel(handle); }

    [[nodiscard]] static auto is_transient_send_error(ssize_t ret) -> bool
    {
        return ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }

    /// XdpSocket::tx_flush().
    [[nodiscard]] auto tx_flush() -> Status { return socket_.tx_flush(); }

    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>> { return socket_.rx_start(); }

    /// @param handle UMEM frame address from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status { return socket_.rx_release(handle); }

    [[nodiscard]] auto fill_replenish() -> Status { return socket_.fill_replenish(); }

    [[nodiscard]] auto tx_complete() -> Status { return socket_.tx_complete(); }

    /// @param rules New filter rules to replace existing entries
    [[nodiscard]] auto set_rules(std::span<CompiledRule<32> const> rules) -> Status { return program_.set_rules(rules); }

    /// Add `addr` to the interface's multicast filter (SIOCADDMULTI).
    /// @param addr Multicast MAC address to join
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;

    /// Remove `addr` from the interface's multicast filter (SIOCDELMULTI).
    /// @param addr Multicast MAC address to leave
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const& addr) -> Status;

    [[nodiscard]] auto stats() const noexcept -> Stats const& { return socket_.stats(); }
    /// Zero the socket's counters; on its thread, between operations.
    void reset_stats() noexcept { socket_.reset_stats(); }

  private:
    void swap(XdpContext& other) noexcept
    {
        std::swap(program_, other.program_);
        std::swap(socket_, other.socket_);
        std::swap(interface_, other.interface_);
    }

    [[nodiscard]] auto multicast_ioctl(unsigned long request, ieee::Eui48 const& addr, XdpError error) -> Status;
    /// Adopt or attach the program on interface_ per `config`.
    [[nodiscard]] auto open_program(XdpConfig const& config) -> Status;
    /// Bind the socket, register it (and the TAP device) with the program, and prime the fill ring.
    [[nodiscard]] auto open_socket(XdpConfig const& config, detail::UmemGeometry const& geometry) -> Status;

    XdpProgram program_;
    XdpSocket socket_;
    detail::InterfaceId interface_;
};

#else  // !(__linux__ && HAVE_XDP)

// ──────────────────────────────────────────────
// XdpProgram, XdpContext — stubs for non-Linux or without libbpf/libxdp
// ──────────────────────────────────────────────

class XdpProgram
{
  public:
    struct Options
    {
        std::span<CompiledRule<32> const> filter_rules{};
        XdpAction default_action{XdpAction::pass_kernel};
        XdpAttachMode attach_mode{XdpAttachMode::native};
        bool allow_generic_fallback{true};
        std::string_view pin_path{};
        bool adopt{true};
        std::optional<bool> detach_on_close{};
    };
    static constexpr std::string_view PIN_ROOT = "/sys/fs/bpf/statusbar";
    [[nodiscard]] static auto pin_path_for(std::string_view interface_name) -> std::string
    {
        return std::string{PIN_ROOT} + "/" + std::string{interface_name};
    }
    [[nodiscard]] static auto query(unsigned int) -> StatusValue<std::optional<XdpAttachedProgram>>
    {
        return failure(XdpError::not_supported_on_platform);
    }
    [[nodiscard]] static auto detach(unsigned int, std::string_view) -> Status
    {
        return failure(XdpError::not_supported_on_platform);
    }
    [[nodiscard]] auto open(unsigned int, Options const&) -> Status { return failure(XdpError::not_supported_on_platform); }
    void close() noexcept {}
    [[nodiscard]] auto valid() const noexcept -> bool { return false; }
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return XdpAttachMode::native; }
    [[nodiscard]] auto adopted() const noexcept -> bool { return false; }
    [[nodiscard]] auto pinned() const noexcept -> bool { return false; }
    [[nodiscard]] auto prog_id() const noexcept -> uint32_t { return 0; }
    [[nodiscard]] auto will_detach_on_close() const noexcept -> bool { return false; }
};

class XdpContext
{
  public:
    using Stats = XdpSocketStats;

    XdpContext() = default;
    ~XdpContext() { close(); }

    XdpContext(XdpContext&& other) noexcept { swap(other); }

    auto operator=(XdpContext&& other) noexcept -> XdpContext&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    XdpContext(XdpContext const&) = delete;
    auto operator=(XdpContext const&) -> XdpContext& = delete;

    [[nodiscard]] auto open(XdpConfig const&) -> Status { return failure(XdpError::not_supported_on_platform); }
    void close() noexcept {}
    [[nodiscard]] auto valid() const noexcept -> bool { return false; }

    [[nodiscard]] auto xsk_fd() const noexcept -> int { return -1; }
    [[nodiscard]] auto fd() const noexcept -> int { return -1; }
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const&
    {
        static ieee::Eui48 const empty{};
        return empty;
    }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return 0; }
    [[nodiscard]] auto zero_copy() const noexcept -> bool { return false; }
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return XdpBindMode::auto_; }
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return XdpAttachMode::native; }
    [[nodiscard]] auto adopted() const noexcept -> bool { return false; }
    [[nodiscard]] auto tx_launch_time() const noexcept -> bool { return false; }
    [[nodiscard]] auto launch_time_supported() const -> StatusValue<bool> { return failure(XdpError::not_supported_on_platform); }
    [[nodiscard]] auto program() const noexcept -> XdpProgram const&
    {
        static XdpProgram const none{};
        return none;
    }

    void begin_cycle() noexcept {}

    [[nodiscard]] auto end_cycle() -> Status { return success(); }

    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        (void)launch_time_ns;
        return failure(XdpError::not_supported_on_platform);
    }
    void tx_set_launch_time(uint64_t /*handle*/, int64_t /*launch_time_ns*/) noexcept {}
    [[nodiscard]] auto tx_commit(uint64_t, size_t) -> Status { return failure(XdpError::not_supported_on_platform); }
    [[nodiscard]] auto tx_cancel(uint64_t) -> Status { return failure(XdpError::not_supported_on_platform); }
    [[nodiscard]] auto tx_flush() -> Status { return failure(XdpError::not_supported_on_platform); }

    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
    {
        return failure(XdpError::not_supported_on_platform);
    }
    [[nodiscard]] auto rx_release(uint64_t) -> Status { return failure(XdpError::not_supported_on_platform); }

    [[nodiscard]] auto fill_replenish() -> Status { return failure(XdpError::not_supported_on_platform); }
    [[nodiscard]] auto tx_complete() -> Status { return failure(XdpError::not_supported_on_platform); }

    [[nodiscard]] auto set_rules(std::span<CompiledRule<32> const>) -> Status
    {
        return failure(XdpError::not_supported_on_platform);
    }

    [[nodiscard]] auto join_multicast(ieee::Eui48 const&) -> Status { return failure(XdpError::not_supported_on_platform); }
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const&) -> Status { return failure(XdpError::not_supported_on_platform); }

    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }
    /// Zero the counters (nothing counts without AF_XDP); as the Linux one, on the socket's thread.
    void reset_stats() noexcept { stats_ = {}; }

  private:
    void swap(XdpContext& other) noexcept { std::swap(stats_, other.stats_); }
    Stats stats_{};
};

#endif  // __linux__ && HAVE_XDP

struct XdpContextOpen
{
    /// @param ctx XdpContext to open
    /// @param config Configuration for the AF_XDP context
    explicit XdpContextOpen(XdpContext& ctx, XdpConfig const& config)
    {
        if (auto status = ctx.open(config); !status) {
            throw_or_abort(status.error(), config.interface_name);
        }
    }
};

}  // namespace statusbar::net
