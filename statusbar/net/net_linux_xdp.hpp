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
    zero_copy_needs_native_attach,
    zero_copy_unavailable,
    bpffs_not_mounted,
    invalid_pin_path,
    pin_failed,
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

/// How the AF_XDP socket binds to the queue.
///
/// Zero-copy is the difference between a socket that can carry a media stream
/// and one that cannot: in copy mode every frame is memcpy'd between UMEM and
/// the driver. It needs driver support, so demanding it unconditionally fails
/// on hardware that would otherwise work, and never asking for it gives up the
/// performance on hardware that has it. Hence three answers, not two.
enum class XdpBindMode : uint8_t
{
    /// Take what the driver offers: zero-copy where available, copy otherwise.
    auto_ = 0,
    /// Insist on zero-copy; fail rather than fall back to copying.
    zero_copy,
    /// Insist on copy mode, even where zero-copy is available.
    copy,
};

/// Where the XDP program runs.
enum class XdpAttachMode : uint8_t
{
    /// In the driver (XDP_FLAGS_DRV_MODE). Faster, and needs driver support.
    native = 0,
    /// In the stack (XDP_FLAGS_SKB_MODE). Slower, and available everywhere -
    /// on veth pairs, which is how this gets tested at all, and on NICs whose
    /// driver has no XDP support.
    generic,
};

// Both zero values are the sensible default, so a caller can leave the
// XdpConfig fields default-initialised and mean it.
static_assert(XdpBindMode{} == XdpBindMode::auto_);
static_assert(XdpAttachMode{} == XdpAttachMode::native);

/// What is attached to an interface right now, as the kernel reports it.
struct XdpAttachedProgram
{
    /// The attached program's id. Zero when programs are attached in more
    /// than one mode at once, the one case where the kernel will not name a
    /// single program - and the one case where adopting would be a guess.
    uint32_t program_id{0};
    /// Where it runs. `native` when programs are attached in both modes,
    /// that being the one a frame meets first.
    XdpAttachMode mode{XdpAttachMode::native};
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
    XdpBindMode bind_mode{XdpBindMode::auto_};
    XdpAttachMode attach_mode{XdpAttachMode::native};
    /// Where to pin the program and its maps, from XdpProgram::pin_path_for().
    /// Empty - the default - means do not pin, which is the behaviour from
    /// before pinning existed: attach at open(), detach at close().
    /// A view, like interface_name: whatever it points at must outlive the
    /// open() call. XdpContext::program().pin_path() keeps a copy.
    std::string_view pin_path{};
    /// Reuse a program already pinned at `pin_path` instead of attaching a
    /// fresh one, when it is recognisably ours and matches this config.
    /// Ignored when `pin_path` is empty. True by default: a caller that named
    /// a pin path wants the pin used. False forces a fresh attach and pins
    /// the result, which is what an upgrade with a changed program wants.
    bool adopt{true};
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

/// Which attach mode to try, and what to try if that fails.
struct AttachPlan
{
    XdpAttachMode first{XdpAttachMode::native};
    /// Tried only if `first` fails. nullopt means there is nothing else to
    /// try and the failure is the answer.
    std::optional<XdpAttachMode> fallback{};
};

/// The bind/attach fallback policy, with no syscall in it:
///
///   | bind              | attach  | plan                         |
///   |-------------------|---------|------------------------------|
///   | zero_copy         | native  | native, no fallback          |
///   | zero_copy         | generic | impossible - nullopt         |
///   | auto_ / copy      | native  | native, falling back to      |
///   |                   |         | generic                      |
///   | auto_ / copy      | generic | generic only                 |
///
/// Zero-copy with generic attach is refused rather than attempted: generic
/// XDP runs in the stack, where there is no driver to hand a frame to, so the
/// combination cannot work. The caller hears about it at open(), as a
/// configuration mistake, instead of as a runtime surprise.
///
/// Zero-copy with native attach gets no fallback either: falling back to
/// generic would silently deliver copy mode, which is the thing the caller
/// said it did not want.
/// @param requested The attach mode asked for
/// @param bind The bind mode asked for
/// @return The plan, or nullopt when the two cannot be satisfied together
[[nodiscard]] constexpr auto attach_plan(XdpAttachMode const requested, XdpBindMode const bind) noexcept
    -> std::optional<AttachPlan>
{
    if (bind == XdpBindMode::zero_copy) {
        if (requested == XdpAttachMode::generic) {
            return std::nullopt;
        }
        return AttachPlan{.first = XdpAttachMode::native, .fallback = std::nullopt};
    }
    if (requested == XdpAttachMode::generic) {
        return AttachPlan{.first = XdpAttachMode::generic, .fallback = std::nullopt};
    }
    return AttachPlan{.first = XdpAttachMode::native, .fallback = XdpAttachMode::generic};
}

/// Whether `name` is a name the kernel would accept for an interface - which
/// is also exactly what makes it safe to paste into a pin path: no '/', so it
/// cannot climb out of the pin directory, and neither "." nor "..".
/// Mirrors the kernel's dev_valid_name(). The length limit is spelled out
/// rather than taken from IFNAMSIZ so this stays usable off Linux.
/// @param name The candidate interface name
[[nodiscard]] constexpr auto valid_interface_name(std::string_view const name) noexcept -> bool
{
    constexpr size_t MaxNameLength = 15;  // IFNAMSIZ - 1
    if (name.empty() || name.size() > MaxNameLength) {
        return false;
    }
    if (name == "." || name == "..") {
        return false;
    }
    for (char const c : name) {
        if (c == '/' || c == ':' || c == '\0' || c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') {
            return false;
        }
    }
    return true;
}

}  // namespace detail

// ──────────────────────────────────────────────
// XdpProgram — the program on the interface, and its pins
// ──────────────────────────────────────────────

class XdpContext;

/// The XDP program an XdpContext is using: where it is pinned, whether open()
/// adopted it rather than attaching one, and the operations on a pin path that
/// need no instance at all.
///
/// The loaded object and the map descriptors live inside XdpContext. What is
/// here is the part a caller can see and - the point of pinning - the part
/// that outlives the process.
///
/// ### Why pin
///
/// An unpinned program's lifetime is our process's. Restart the daemon and the
/// program comes off the interface and goes back on, and for that gap every
/// frame it was steering reaches the kernel instead: audio drops out on a
/// config reload, not just on a crash. Pinned into bpffs, the program stays
/// attached when we exit and the next start **adopts** it, so a reload does
/// not interrupt the data path and a crash leaves a working one. It also makes
/// the state inspectable - `bpftool map dump pinned <path>/rules_map` against
/// a known name, instead of hunting for a program id.
///
/// ### Close policy
///
/// A pinned program is deliberately **left attached** when the context closes;
/// that is what makes the next start seamless, and it is the whole difference
/// from the unpinned path. Nothing in the process removes it. detach() is the
/// only way, and a caller that wants the old lifetime leaves
/// XdpConfig::pin_path empty.
class XdpProgram
{
  public:
    /// The bpf filesystem every pin lives under. It must be mounted; a pin
    /// path anywhere else is refused rather than quietly creating ordinary
    /// directories that bpf_obj_pin() would then reject.
    static constexpr std::string_view BPFFS_ROOT = "/sys/fs/bpf";
    /// Our directory within it, one subdirectory per interface below that.
    static constexpr std::string_view PIN_NAMESPACE = "statusbar";

    /// Entry names inside a pin directory. Fixed and documented so an
    /// external tool knows what to look for.
    static constexpr std::string_view PIN_PROG = "prog";
    static constexpr std::string_view PIN_RULES_MAP = "rules_map";
    static constexpr std::string_view PIN_XSK_MAP = "xsk_map";
    static constexpr std::string_view PIN_DEVMAP = "devmap";

    /// The pin directory for an interface: BPFFS_ROOT/PIN_NAMESPACE/<name>,
    /// so two interfaces never collide. Pure - no filesystem is touched and
    /// nothing is created.
    /// @param interface_name The interface the program will steer
    /// @return The directory, or an empty string when the name is not one the
    ///         kernel would accept. Empty means "do not pin", so a bad name
    ///         degrades to the unpinned behaviour rather than yielding a path
    ///         that could point outside the pin directory.
    [[nodiscard]] static auto pin_path_for(std::string_view interface_name) -> std::string;

    /// One entry within a pin directory, e.g. pin_entry(dir, PIN_PROG).
    /// @param pin_path A pin directory, from pin_path_for()
    /// @param entry One of PIN_PROG, PIN_RULES_MAP, PIN_XSK_MAP, PIN_DEVMAP
    /// @return The full path, or empty if either argument is empty
    [[nodiscard]] static auto pin_entry(std::string_view pin_path, std::string_view entry) -> std::string;

    /// Whether anything can be pinned at `pin_path`: it is a path under
    /// BPFFS_ROOT with something below it, and a bpf filesystem is mounted
    /// there. Creates nothing and needs no privilege.
    ///
    /// open() asks this before it allocates anything, so a config pointing
    /// outside bpffs, or a host with no bpffs mounted, is reported as itself
    /// rather than as the ENOENT or EINVAL that the pin would produce much
    /// later. A daemon can ask the same question of its own config at
    /// startup.
    /// @param pin_path A pin directory, from pin_path_for()
    [[nodiscard]] static auto pinnable(std::string_view pin_path) -> Status;

    /// What is attached to an interface now, if anything - so open(), or a
    /// caller, can tell whether a pinned program is the one in force.
    /// @param if_index The interface index
    /// @return The attached program, or nullopt when nothing is attached
    [[nodiscard]] static auto query(unsigned int if_index) -> StatusValue<std::optional<XdpAttachedProgram>>;

    /// Unpin and detach: the counterpart to leaving a program running on
    /// purpose. Goes by path and interface index and holds no handle from the
    /// process that created the pin, so it works on a stale pin whose creator
    /// is long gone - which, once a crash leaves the program attached, is a
    /// normal state and not an exceptional one. Succeeds when there is
    /// nothing left to remove.
    /// A non-empty `pin_path` must be one pinnable() accepts - this call
    /// unlinks within it and then removes it, so a path built by hand rather
    /// than by pin_path_for() is refused instead of followed.
    /// @param if_index The interface to detach from
    /// @param pin_path The pin directory to empty; empty to only detach
    [[nodiscard]] static auto detach(unsigned int if_index, std::string_view pin_path) -> Status;

    /// Whether the program and its maps are pinned, and so outlive us.
    [[nodiscard]] auto pinned() const noexcept -> bool { return pinned_; }

    /// Whether open() reused a program already pinned instead of attaching
    /// one. False after a fresh attach, pinned or not.
    [[nodiscard]] auto adopted() const noexcept -> bool { return adopted_; }

    /// Where it is pinned; empty when it is not.
    [[nodiscard]] auto pin_path() const noexcept -> std::string_view { return pin_path_; }

    /// The kernel's id for the program, 0 when nothing is loaded.
    [[nodiscard]] auto id() const noexcept -> uint32_t { return id_; }

  private:
    // XdpContext is what opens, adopts and pins; these record what it did.
    friend class XdpContext;

    std::string pin_path_;
    uint32_t id_{0};
    bool pinned_{false};
    bool adopted_{false};
};

// ──────────────────────────────────────────────
// XdpContext — Linux implementation with libbpf/libxdp
// ──────────────────────────────────────────────

#if defined(__linux__) && defined(HAVE_XDP)

namespace detail {

/// The XDP_ZEROCOPY / XDP_COPY bind flag for a bind mode. auto_ asks for
/// nothing and lets the kernel pick zero-copy where the driver has it.
/// @param mode The bind mode asked for
[[nodiscard]] constexpr auto bind_flags(XdpBindMode const mode) noexcept -> uint16_t
{
    switch (mode) {
        case XdpBindMode::zero_copy:
            return XDP_ZEROCOPY;
        case XdpBindMode::copy:
            return XDP_COPY;
        case XdpBindMode::auto_:
            break;
    }
    return 0;
}

/// Whether the kernel bound this XSK socket zero-copy. Asked of the socket
/// rather than inferred: with XdpBindMode::auto_ the answer is the driver's,
/// and nothing we passed in tells us which way it went.
/// @param xsk_fd The AF_XDP socket descriptor
[[nodiscard]] inline auto socket_has_zero_copy(int const xsk_fd) noexcept -> bool
{
    struct xdp_options options{};
    socklen_t length = sizeof(options);
    if (::getsockopt(xsk_fd, SOL_XDP, XDP_OPTIONS, &options, &length) != 0) {
        return false;
    }
    return (options.flags & XDP_OPTIONS_ZEROCOPY) != 0;
}

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

    /// The bpf_xdp_attach/detach flag for an attach mode.
    /// @param mode Native or generic attach
    [[nodiscard]] static constexpr auto attach_flags(XdpAttachMode const mode) noexcept -> uint32_t
    {
        return mode == XdpAttachMode::native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    }

    /// Attach an XDP program to an interface following `plan`, falling back to
    /// the plan's second mode if the first does not take. Takes ownership of
    /// the BpfObject, and only once an attach has succeeded - a failed attempt
    /// must leave the program open for the next one.
    /// @param obj BPF object (ownership transferred on success)
    /// @param prog_fd File descriptor of the XDP program
    /// @param if_index Network interface index to attach to
    /// @param plan Which mode to try, and what to try next
    [[nodiscard]] auto attach(BpfObject&& obj, int prog_fd, unsigned int if_index, AttachPlan const& plan) -> Status
    {
        detach();
        auto const attempt = [prog_fd, if_index](XdpAttachMode const mode) {
            return bpf_xdp_attach(static_cast<int>(if_index), prog_fd, attach_flags(mode), nullptr);
        };

        auto mode = plan.first;
        int ret = attempt(mode);
        if (ret != 0 && plan.fallback.has_value()) {
            mode = *plan.fallback;
            ret = attempt(mode);
        }
        if (ret != 0) {
            return failure(XdpError::bpf_attach_failed);
        }

        obj_ = std::move(obj);
        if_index_ = if_index;
        mode_ = mode;
        attached_ = true;
        return success();
    }

    void detach() noexcept
    {
        if (attached_) {
            // With the flags it was attached by: the kernel refuses a detach
            // whose mode does not match, which would leave the program on the
            // interface after we think we are gone.
            (void)bpf_xdp_detach(static_cast<int>(if_index_), attach_flags(mode_), nullptr);
            attached_ = false;
            if_index_ = 0;
            mode_ = XdpAttachMode::native;
        }
        obj_.reset();
    }

    /// Leave the program on the interface when this object goes away, keeping
    /// the object open so the borrowed program and map descriptors stay valid
    /// for as long as we are running. Used once the program is pinned: the
    /// attachment is then outliving us on purpose, and detaching it at close
    /// would defeat the pin. The mode is kept so attach_mode() still answers
    /// truthfully.
    void disown() noexcept { attached_ = false; }

    [[nodiscard]] auto is_attached() const noexcept -> bool { return attached_; }

    /// The mode the program is attached in, which after a fallback is not
    /// always the mode that was asked for.
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return mode_; }

  private:
    void swap(BpfAttachment& other) noexcept
    {
        std::swap(obj_, other.obj_);
        std::swap(if_index_, other.if_index_);
        std::swap(mode_, other.mode_);
        std::swap(attached_, other.attached_);
    }

    BpfObject obj_;
    unsigned int if_index_{0};
    XdpAttachMode mode_{XdpAttachMode::native};
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
    /// @param plan Which attach mode to try, and what to try next
    [[nodiscard]] auto attach(unsigned int if_index, uint32_t queue_id, int xsk_fd, AttachPlan const& plan) -> Status
    {
        if (auto status = attachment_.attach(std::move(obj_), prog_fd_, if_index, plan); !status) {
            return status;
        }
        return register_xsk(queue_id, xsk_fd);
    }

    /// Put the XSK socket in xsk_map for its queue. Split out of attach()
    /// because an adopted program needs this and nothing else: the program on
    /// the interface is already the right one, but the socket behind the map
    /// entry belongs to the process that died.
    /// @param queue_id Hardware queue ID for the XSK socket
    /// @param xsk_fd File descriptor of the XSK socket
    [[nodiscard]] auto register_xsk(uint32_t queue_id, int xsk_fd) -> Status
    {
        if (xsk_map_fd_ < 0) {
            return failure(XdpError::not_open);
        }
        if (bpf_map_update_elem(xsk_map_fd_, &queue_id, &xsk_fd, BPF_ANY) != 0) {
            return failure(XdpError::bpf_map_update_failed);
        }
        return success();
    }

    /// Take over the program and maps pinned under `pin_path`, in place of
    /// load(): same post-conditions, no new program. Succeeds only when the
    /// pin is recognisably ours *and* is the program attached to `if_index`;
    /// anything else - a stale pin, an older build, someone else's program -
    /// is a plain failure and the caller loads fresh instead.
    ///
    /// `rules` are installed into the adopted map exactly as load() would
    /// install them. The rules in force are the ones this process asked for,
    /// not whatever the last one left behind: a map whose contents depend on
    /// history cannot be reasoned about, and a caller that wants its rules to
    /// survive the restart passes them to open().
    /// @param pin_path The pin directory to adopt from
    /// @param if_index The interface the program must already be attached to
    /// @param rules Compiled TCAM rules to install into the adopted map
    /// @param default_action Action applied to frames that match no user rule
    [[nodiscard]] auto adopt(
        std::string_view pin_path, unsigned int if_index, std::span<CompiledRule<32> const> rules, XdpAction default_action)
        -> Status;

    /// Pin the loaded program and its maps under `pin_path`, creating the
    /// directory. On success the attachment is disowned, so the program stays
    /// on the interface after we exit - which is the point of pinning.
    /// @param pin_path The pin directory to create and fill
    [[nodiscard]] auto pin(std::string_view pin_path) -> Status;

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
        // After load() the descriptors are borrowed from obj_ and go with it.
        // After adopt() they came from bpf_obj_get() and are ours to close.
        if (owns_fds_) {
            for (int* fd : {&prog_fd_, &xsk_map_fd_, &rules_map_fd_, &devmap_fd_}) {
                if (*fd >= 0) {
                    ::close(*fd);
                }
            }
            owns_fds_ = false;
        }
        obj_.reset();
        prog_fd_ = -1;
        xsk_map_fd_ = -1;
        rules_map_fd_ = -1;
        devmap_fd_ = -1;
        default_action_ = XdpAction::pass_kernel;
        program_id_ = 0;
        adopted_ = false;
    }

    [[nodiscard]] auto rules_map_fd() const noexcept -> int { return rules_map_fd_; }

    /// The mode the program is attached in, native unless nothing is attached.
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return attachment_.attach_mode(); }

    /// Whether the program came from a pin rather than from a fresh load.
    [[nodiscard]] auto adopted() const noexcept -> bool { return adopted_; }

    /// The kernel's id for the loaded or adopted program, 0 when none.
    [[nodiscard]] auto program_id() const noexcept -> uint32_t { return program_id_; }

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
        std::swap(owns_fds_, other.owns_fds_);
        std::swap(program_id_, other.program_id_);
        std::swap(adopted_, other.adopted_);
    }

    BpfObject obj_;
    BpfAttachment attachment_;
    int prog_fd_{-1};
    XdpAction default_action_{XdpAction::pass_kernel};
    int xsk_map_fd_{-1};
    int rules_map_fd_{-1};
    int devmap_fd_{-1};
    uint32_t program_id_{0};
    bool owns_fds_{false};
    bool adopted_{false};
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

    /// Whether the socket actually got zero-copy, read back from the kernel
    /// rather than inferred from what was asked for. A caller that asked for
    /// XdpBindMode::auto_ has no other way to find out, and it is exactly
    /// what it needs in order to report or log what it is running on.
    [[nodiscard]] auto zero_copy() const noexcept -> bool { return zero_copy_; }

    /// The bind mode in force: zero_copy or copy, never auto_ - auto_ is a
    /// request, and this is the answer.
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return zero_copy_ ? XdpBindMode::zero_copy : XdpBindMode::copy; }

    /// The mode the program is attached in, which after a native-to-generic
    /// fallback is not the mode that was asked for.
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return bpf_.attach_mode(); }

    /// The program in force, and its pins.
    [[nodiscard]] auto program() const noexcept -> XdpProgram const& { return program_; }

    /// Whether the program and its maps are pinned, and so stay attached
    /// after this context closes.
    [[nodiscard]] auto pinned() const noexcept -> bool { return program_.pinned(); }

    /// Whether open() adopted a program already pinned rather than attaching
    /// one - the restart that did not interrupt anything.
    [[nodiscard]] auto adopted() const noexcept -> bool { return program_.adopted(); }

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
        std::swap(program_, other.program_);
        std::swap(zero_copy_, other.zero_copy_);
    }

    struct xsk_socket* xsk_{nullptr};

    detail::UmemRegion umem_;
    detail::BpfState bpf_;
    detail::RingSet rings_;
    detail::InterfaceId interface_;
    detail::CycleBudget budget_;
    Stats stats_{};
    XdpProgram program_;
    bool zero_copy_{false};
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

    [[nodiscard]] auto zero_copy() const noexcept -> bool { return false; }
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return XdpBindMode::copy; }
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return XdpAttachMode::native; }

    [[nodiscard]] auto program() const noexcept -> XdpProgram const& { return program_; }
    [[nodiscard]] auto pinned() const noexcept -> bool { return false; }
    [[nodiscard]] auto adopted() const noexcept -> bool { return false; }

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
    void swap(XdpContext& other) noexcept
    {
        std::swap(stats_, other.stats_);
        std::swap(program_, other.program_);
    }
    Stats stats_{};
    XdpProgram program_;
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
