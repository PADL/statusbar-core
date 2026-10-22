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

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/net/net_tcam_bpf_abi.h"
#include "statusbar/status/status.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <array>
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

struct XdpConfig
{
    std::string_view interface_name;
    std::span<CompiledRule<32> const> filter_rules{};
    XdpAction default_action{XdpAction::pass_kernel};
    uint32_t queue_id{0};
    size_t rx_ring_size{256};
    size_t tx_ring_size{256};
    size_t fill_ring_size{512};
    size_t completion_ring_size{512};
    size_t umem_frame_size{2048};
    size_t umem_frame_count{1024};
    size_t umem_headroom{0};
    unsigned int tap_ifindex{0};
    size_t rx_drain_max{32};
    size_t completion_drain_max{64};
    int rx_clock_id{CLOCK_MONOTONIC_RAW};
};

}  // namespace statusbar::net

/// Register XdpError as an error code enum (must be before XdpContext uses failure())
template <>
struct std::is_error_code_enum<statusbar::net::XdpError> : std::true_type
{};

namespace statusbar::net {

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

    /// mmap + prefault + xsk_umem__create. Returns xsk_umem* for xsk_socket__create.
    /// @param frame_count Number of UMEM frames to allocate
    /// @param frame_size Size of each UMEM frame in bytes
    /// @param headroom Headroom bytes reserved at the start of each frame
    /// @param fill_ring_size Number of entries in the fill ring
    /// @param comp_ring_size Number of entries in the completion ring
    /// @param rings Ring set to initialize with fill and completion rings
    [[nodiscard]] auto allocate(
        size_t frame_count, size_t frame_size, size_t headroom, size_t fill_ring_size, size_t comp_ring_size, RingSet& rings)
        -> StatusValue<struct xsk_umem*>;

    void close() noexcept;

    /// @param addr UMEM frame address
    [[nodiscard]] auto writable_span(uint64_t addr) -> std::span<uint8_t>
    {
        return {area_ + addr + headroom_, frame_size_ - headroom_};
    }

    /// @param addr UMEM frame address
    /// @param len Number of bytes to expose as readable
    [[nodiscard]] auto readable_span(uint64_t addr, size_t len) -> std::span<uint8_t const> { return {area_ + addr, len}; }

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
    [[nodiscard]] auto headroom() const noexcept -> size_t { return headroom_; }

  private:
    void swap(UmemRegion& other) noexcept
    {
        std::swap(umem_, other.umem_);
        std::swap(area_, other.area_);
        std::swap(area_size_, other.area_size_);
        std::swap(frame_size_, other.frame_size_);
        std::swap(headroom_, other.headroom_);
        std::swap(free_list_, other.free_list_);
    }

    struct xsk_umem* umem_{nullptr};
    uint8_t* area_{nullptr};
    size_t area_size_{0};
    size_t frame_size_{0};
    size_t headroom_{0};
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

/// RAII wrapper for an XDP program attached to a network interface.
/// Owns a BpfObject — destructor detaches the program first, then
/// the BpfObject destructor closes the BPF object.
class BpfAttachment
{
  public:
    BpfAttachment() = default;

    ~BpfAttachment() noexcept { detach(); }

    BpfAttachment(BpfAttachment&& other) noexcept { swap(other); }

    auto operator=(BpfAttachment&& other) noexcept -> BpfAttachment&
    {
        if (this != &other) {
            detach();
            swap(other);
        }
        return *this;
    }

    BpfAttachment(BpfAttachment const&) = delete;
    auto operator=(BpfAttachment const&) -> BpfAttachment& = delete;

    /// Attach an XDP program to an interface. Takes ownership of the BpfObject.
    /// @param obj BPF object (ownership transferred)
    /// @param prog_fd File descriptor of the XDP program
    /// @param if_index Network interface index to attach to
    [[nodiscard]] auto attach(BpfObject&& obj, int prog_fd, unsigned int if_index) -> Status
    {
        detach();
        int const ret = bpf_xdp_attach(static_cast<int>(if_index), prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
        if (ret != 0) {
            return failure(XdpError::bpf_attach_failed);
        }
        obj_ = std::move(obj);
        if_index_ = if_index;
        attached_ = true;
        return success();
    }

    void detach() noexcept
    {
        if (attached_) {
            (void)bpf_xdp_detach(static_cast<int>(if_index_), XDP_FLAGS_SKB_MODE, nullptr);
            attached_ = false;
            if_index_ = 0;
        }
        obj_.reset();
    }

    [[nodiscard]] auto is_attached() const noexcept -> bool { return attached_; }

  private:
    void swap(BpfAttachment& other) noexcept
    {
        std::swap(obj_, other.obj_);
        std::swap(if_index_, other.if_index_);
        std::swap(attached_, other.attached_);
    }

    BpfObject obj_;
    unsigned int if_index_{0};
    bool attached_{false};
};

/// High-level BPF lifecycle: load, attach, manage filter maps.
/// Owns a BpfAttachment (which owns the BpfObject). Destruction order:
/// detach program -> close BPF object -> invalidate cached fds.
class BpfState
{
  public:
    BpfState() = default;
    ~BpfState() { close(); }

    BpfState(BpfState&& other) noexcept { swap(other); }

    auto operator=(BpfState&& other) noexcept -> BpfState&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    BpfState(BpfState const&) = delete;
    auto operator=(BpfState const&) -> BpfState& = delete;

    /// Load BPF object from embedded bytes, find maps, install rules, find program.
    /// @param rules Compiled TCAM rules to install into the BPF array map
    /// @param default_action Action applied to frames that match no user rule
    [[nodiscard]] auto load(std::span<CompiledRule<32> const> rules, XdpAction default_action) -> Status;

    /// Attach XDP program to interface, register XSK fd in xsk_map.
    /// @param if_index Network interface index to attach to
    /// @param queue_id Hardware queue ID for the XSK socket
    /// @param xsk_fd File descriptor of the XSK socket
    [[nodiscard]] auto attach(unsigned int if_index, uint32_t queue_id, int xsk_fd) -> Status
    {
        if (auto status = attachment_.attach(std::move(obj_), prog_fd_, if_index); !status) {
            return status;
        }

        int const ret = bpf_map_update_elem(xsk_map_fd_, &queue_id, &xsk_fd, BPF_ANY);
        if (ret != 0) {
            return failure(XdpError::bpf_map_update_failed);
        }

        return success();
    }

    /// Register TAP interface in devmap
    /// @param tap_ifindex Interface index of the TAP device
    [[nodiscard]] auto register_tap(unsigned int tap_ifindex) -> Status
    {
        uint32_t zero_key = 0;
        int const ret = bpf_map_update_elem(devmap_fd_, &zero_key, &tap_ifindex, BPF_ANY);
        if (ret != 0) {
            return failure(XdpError::bpf_map_update_failed);
        }
        return success();
    }

    /// Replace the rule set in-place. Stale slots are zeroed so old
    /// rules cannot match after the call returns.
    /// @param rules New rules to install; fails if
    ///              rules.size() > TCAM_MAX_RULES - (default_action != pass_kernel ? 1 : 0)
    [[nodiscard]] auto set_rules(std::span<CompiledRule<32> const> rules) -> Status
    {
        if (rules_map_fd_ < 0) {
            return failure(XdpError::not_open);
        }
        return install_tcam_rules(rules);
    }

    void close() noexcept
    {
        attachment_.detach();
        obj_.reset();
        prog_fd_ = -1;
        xsk_map_fd_ = -1;
        rules_map_fd_ = -1;
        devmap_fd_ = -1;
        default_action_ = XdpAction::pass_kernel;
    }

    [[nodiscard]] auto rules_map_fd() const noexcept -> int { return rules_map_fd_; }

  private:
    [[nodiscard]] auto install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status;

    void swap(BpfState& other) noexcept
    {
        std::swap(obj_, other.obj_);
        std::swap(attachment_, other.attachment_);
        std::swap(prog_fd_, other.prog_fd_);
        std::swap(default_action_, other.default_action_);
        std::swap(xsk_map_fd_, other.xsk_map_fd_);
        std::swap(rules_map_fd_, other.rules_map_fd_);
        std::swap(devmap_fd_, other.devmap_fd_);
    }

    BpfObject obj_;
    BpfAttachment attachment_;
    int prog_fd_{-1};
    XdpAction default_action_{XdpAction::pass_kernel};
    int xsk_map_fd_{-1};
    int rules_map_fd_{-1};
    int devmap_fd_{-1};
};

}  // namespace detail

class XdpContext
{
  public:
    struct Stats
    {
        uint64_t rx_count{0};
        uint64_t tx_count{0};
        uint64_t tx_ring_full_count{0};
        uint64_t umem_exhausted_count{0};
        uint64_t rx_budget_hit_count{0};
    };

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

    /// @param config Configuration specifying interface, filters, ring sizes, and UMEM layout
    [[nodiscard]] auto open(XdpConfig const& config) -> Status;
    void close() noexcept;
    [[nodiscard]] auto valid() const noexcept -> bool { return xsk_ != nullptr; }

    [[nodiscard]] auto xsk_fd() const noexcept -> int { return xsk_ != nullptr ? xsk_socket__fd(xsk_) : -1; }
    [[nodiscard]] auto fd() const noexcept -> int { return xsk_fd(); }

    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return interface_.hardware_address; }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return interface_.index; }

    void begin_cycle() noexcept { budget_.rx_cycle_count = 0; }

    [[nodiscard]] auto end_cycle() -> Status
    {
        auto fill_status = fill_replenish();
        auto comp_status = tx_complete();
        return fill_status ? comp_status : fill_status;
    }

    /// @param launch_time_ns TSN/AVB launch time in nanoseconds (currently unused, reserved)
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        (void)launch_time_ns;
        auto addr = umem_.alloc_frame();
        if (!addr) {
            ++stats_.umem_exhausted_count;
            return failure(XdpError::free_list_empty);
        }
        return EthernetTxSlot{
            .handle = *addr,
            .buffer = umem_.writable_span(*addr),
        };
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

    [[nodiscard]] static auto is_transient_send_error(ssize_t ret) -> bool
    {
        return ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }

    [[nodiscard]] auto tx_flush() -> Status
    {
        auto ret = ::sendto(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        if (ret < 0 && !is_transient_send_error(ret)) {
            return failure(XdpError::tx_flush_failed);
        }
        return success();
    }

    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;

    /// @param handle UMEM frame address from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status
    {
        umem_.free_frame(handle);
        return success();
    }

    [[nodiscard]] auto fill_replenish() -> Status;

    [[nodiscard]] auto tx_complete() -> Status;

    /// @param rules New filter rules to replace existing entries
    [[nodiscard]] auto set_rules(std::span<CompiledRule<32> const> rules) -> Status { return bpf_.set_rules(rules); }

    /// @param addr Multicast MAC address to join
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;

    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }

  private:
    void swap(XdpContext& other) noexcept
    {
        std::swap(xsk_, other.xsk_);
        std::swap(umem_, other.umem_);
        std::swap(bpf_, other.bpf_);
        std::swap(rings_, other.rings_);
        std::swap(interface_, other.interface_);
        std::swap(budget_, other.budget_);
        std::swap(stats_, other.stats_);
    }

    struct xsk_socket* xsk_{nullptr};

    detail::UmemRegion umem_;
    detail::BpfState bpf_;
    detail::RingSet rings_;
    detail::InterfaceId interface_;
    detail::CycleBudget budget_;
    Stats stats_{};
};

#else  // !(__linux__ && HAVE_XDP)

// ──────────────────────────────────────────────
// XdpContext — stub for non-Linux or without libbpf/libxdp
// ──────────────────────────────────────────────

class XdpContext
{
  public:
    struct Stats
    {
        uint64_t rx_count{0};
        uint64_t tx_count{0};
        uint64_t tx_ring_full_count{0};
        uint64_t umem_exhausted_count{0};
        uint64_t rx_budget_hit_count{0};
    };

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

    void begin_cycle() noexcept {}

    [[nodiscard]] auto end_cycle() -> Status { return success(); }

    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        (void)launch_time_ns;
        return failure(XdpError::not_supported_on_platform);
    }
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

    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }

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
