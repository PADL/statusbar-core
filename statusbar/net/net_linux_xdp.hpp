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
#include "statusbar/net/net_posix_util.hpp"
#include "statusbar/net/net_tcam_bpf_abi.h"
#include "statusbar/status/status.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <array>
#include <atomic>
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
    zero_copy_needs_native_attach,
    zero_copy_unavailable,
    bpffs_not_mounted,
    invalid_pin_path,
    pin_failed,
    queue_busy,
    foreign_program,
    pin_not_adoptable,
    program_unidentifiable,
    stats_read_failed,
    tx_metadata_not_supported,
    launch_time_not_supported,
    invalid_umem_geometry,
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

/// What the BPF program does with a frame.
enum class XdpAction : uint8_t
{
    /// To the AF_XDP socket, for this process to read.
    redirect_xsk,
    /// Up the ordinary kernel stack, as though no filter were there.
    pass_kernel,
    /// Out of the interface registered in the devmap - XdpConfig::tap_ifindex,
    /// in practice a net::TapBridge.
    ///
    /// It **diverts, it does not mirror.** A frame sent to the tap does not
    /// also reach the AF_XDP socket, and a rule carrying both flag::process
    /// and flag::forward_tap goes to the tap only: the BPF program checks
    /// forward_tap first, so process is silently the loser. The use this
    /// serves is getting traffic that is not ours off the real-time path and
    /// into something that can take its time with it, not watching traffic
    /// that is ours.
    ///
    /// A redirect into a devmap whose device is down, gone or busier than the
    /// source drops the frame without saying so. For a diversion of
    /// non-real-time traffic that is a reasonable bargain; anything that
    /// needs to know a frame was delivered must not use this.
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

/// Counters for the AF_XDP socket, so the hot path is diagnosable at all.
///
/// Every failure mode of an AF_XDP stream looks the same from outside - audio
/// glitches - and they need completely different fixes: the TX ring filled,
/// the UMEM ran out of frames, the RX drain hit its per-tick budget, or the
/// kernel refused a kick. Without counters, telling them apart is guesswork.
///
/// ### Threading
///
/// Updated on the real-time thread with plain stores: no locks, no atomics,
/// no ordering. A reader on another thread may therefore see a torn 64-bit
/// value or one counter from before an update and the next from after. That
/// is deliberate and accepted - these are counters, nobody acts on an exact
/// one, and the hot path is not paying for a precision no caller needs. A
/// reader that wants a consistent set snapshots it at a defined point; a
/// caller publishing a copy through a seqlock is why this has to stay
/// trivially copyable.
///
/// A plain struct at namespace scope, not a nested type and not an alias, so
/// a caller can forward-declare it and hold a reference without including
/// this header.
struct XdpSocketStats
{
    uint64_t rx_count{0};              ///< frames received
    uint64_t tx_count{0};              ///< frames sent
    uint64_t tx_ring_full_count{0};    ///< sends refused: TX ring full
    uint64_t umem_exhausted_count{0};  ///< sends refused: no UMEM frame
    uint64_t rx_budget_hit_count{0};   ///< drains that hit the per-tick budget
    uint64_t tx_flush_count{0};        ///< kicks made (sendto)
    uint64_t tx_flush_skipped{0};      ///< kicks not needed: nothing was waiting
    /// Kicks the kernel refused for a reason that will not pass by itself.
    /// Disjoint from tx_flush_transient: a caller rides out the transient
    /// ones and escalates on these.
    uint64_t tx_flush_failed{0};
    uint64_t tx_flush_transient{0};  ///< kicks refused with EAGAIN/EBUSY/ENOBUFS/ENETDOWN
    int tx_flush_errno{0};           ///< the last refused kick's errno, transient or not
    uint64_t rx_wakeup_count{0};     ///< fill-ring wakeups (recvfrom)
};

// A caller keeping a published copy in an itc::SeqlockValue needs this: a
// seqlock is only sound for a type that can be copied bytewise.
static_assert(std::is_trivially_copyable_v<XdpSocketStats>);

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

/// UMEM frames kept out of the fill ring so transmit has somewhere to write.
/// A quarter of the default 1024-frame UMEM; see detail::fillable_frames for
/// why a reserve is needed at all, and detail::effective_tx_reserve for what
/// happens to this number when the UMEM is smaller.
inline constexpr size_t xdp_default_tx_frame_reserve = 256;

/// How a bind refused because the queue is still busy is retried: this many
/// pauses of xdp_bind_busy_pause_ns each.
///
/// Closing an AF_XDP socket does not release its queue there and then. The
/// kernel keeps the socket's UMEM pool registered against the queue index
/// until the teardown completes, which it does behind an RCU grace period
/// and a deferred work item, and a bind arriving in that window is refused
/// with EBUSY. A restart lands squarely in that window: the new process
/// binds the same queue within a millisecond of the old one's descriptors
/// being reaped, and the bind fails although nothing is wrong.
///
/// 50 pauses of 10 ms is up to 500 ms in all - comfortably longer than an
/// RCU grace period, and short enough that a queue some other live process
/// is holding still fails fast enough to report.
inline constexpr size_t xdp_bind_busy_retries = 50;

/// How long to wait between two attempts at a busy queue. 10 ms, on the
/// open path only.
inline constexpr long xdp_bind_busy_pause_ns = 10'000'000;

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
    /// Bytes per UMEM frame. 4096 and not 2048: the kernel takes 256 octets
    /// of XDP headroom from the front, and igb and igc then allocate the RX
    /// buffer in whole 1 KiB units of what is left. 2048 leaves 1792, which
    /// rounds down to one 1 KiB buffer, and a 1522-octet frame arrives cut to
    /// 1024 - counted as received, with no error anywhere. 4096 leaves 3840,
    /// which rounds to 3 KiB.
    size_t umem_frame_size{4096};
    size_t umem_frame_count{1024};
    size_t umem_headroom{0};
    /// Interface the devmap points at, for rules whose action is
    /// XdpAction::redirect_tap. Zero - the default - registers nothing, and
    /// then a forward_tap rule has nowhere to send a frame. Registering it
    /// needs the same privilege as loading the program. See
    /// XdpAction::redirect_tap for what reaching it does and does not mean.
    unsigned int tap_ifindex{0};
    size_t rx_drain_max{32};
    size_t completion_drain_max{64};
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
    /// How many times to retry a bind the kernel refused with EBUSY, which
    /// is a queue the previous owner has not finished releasing. The default
    /// waits the window out; see xdp_bind_busy_retries. Zero makes the one
    /// attempt and reports the refusal, which is what a caller that would
    /// rather fail fast - or a test that wants to see the EBUSY - asks for.
    size_t bind_busy_retries{xdp_bind_busy_retries};
    /// How many UMEM frames to keep out of the fill ring for transmit. RX and
    /// TX share one free list, so without a reserve the fill ring can take
    /// every frame and leave tx_start() nothing. Capped at half the UMEM.
    /// Zero gives the old behaviour: receive may take everything, and a
    /// receive-only context loses nothing by it.
    size_t tx_frame_reserve{xdp_default_tx_frame_reserve};
    /// The other thing transmit sets aside, beside the frames above: room in
    /// every frame's headroom for AF_XDP TX metadata, so each frame can carry
    /// a launch time (XdpContext::tx_set_launch_time). The NIC must be in
    /// launch-time mode for the time to mean anything - an offloaded `etf` on
    /// this queue, which net_tc_launch_time.hpp lays - and the driver must
    /// honour it. open() asks the kernel, through probe_tx_launch_time(),
    /// whether this NIC does, and fails with
    /// XdpError::launch_time_not_supported when it does not - a kernel before
    /// 6.15 takes the metadata and discards the time - or with
    /// XdpError::tx_metadata_not_supported when this build or kernel cannot
    /// carry the metadata at all, rather than opening a socket whose times
    /// would be ignored.
    ///
    /// Costs sizeof(xsk_tx_metadata) bytes of every frame's headroom: the
    /// headroom is raised to that where a caller asked for less. Declared
    /// last so that a designated initializer may name it after the bind,
    /// attach and pin settings, which is where a caller setting up transmit
    /// reaches it.
    bool tx_launch_time{false};
};

// ──────────────────────────────────────────────
// Kernel-side socket statistics
// ──────────────────────────────────────────────

/// The kernel's own per-socket AF_XDP counters, as of the moment they were
/// read. These are frames the kernel threw away after we handed them over,
/// which is a thing XdpContext::Stats cannot see: it counts what we did.
///
/// Deliberately not folded into that struct. It is written by the TX/RX path
/// on one thread and may be read torn by another; this one comes from a
/// getsockopt that can fail, which is a different contract.
struct XdpKernelStats
{
    /// Frames dropped for want of a fill-ring buffer.
    uint64_t rx_dropped{0};
    /// A fill-ring descriptor the kernel refused.
    uint64_t rx_invalid_descs{0};
    /// A TX descriptor the kernel refused. The send that carried it still
    /// reported success, so this counter is the only sign the frame was lost.
    uint64_t tx_invalid_descs{0};
    /// Frames dropped because the RX ring was full.
    uint64_t rx_ring_full{0};
    /// Times the kernel wanted a fill-ring entry and found none.
    uint64_t rx_fill_ring_empty_descs{0};
    /// Times the kernel looked in the TX ring and found it empty. NOT a
    /// fault: a kick that drains the ring leaves it empty, so this ticks
    /// during ordinary transmission.
    uint64_t tx_ring_empty_descs{0};

    /// How many of the counters above the kernel actually filled, as it
    /// reported in the option length. A kernel from before the last three
    /// were added (Linux 5.9) answers with only the first three, and the
    /// rest read zero because we zeroed them -- not because nothing
    /// happened. Check before believing a zero.
    size_t counters_reported{0};

    [[nodiscard]] auto has_rx_ring_full() const noexcept -> bool { return counters_reported >= 4; }
    [[nodiscard]] auto has_ring_empty_counters() const noexcept -> bool { return counters_reported >= 6; }
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

/// Whether a refused TX kick will pass by itself. EAGAIN and EWOULDBLOCK are
/// the ring being momentarily busy; EBUSY, ENOBUFS and ENETDOWN are the
/// driver or the link being momentarily unable to take the frame. Anything
/// else means something is actually wrong, and the caller should escalate
/// rather than keep sending into it.
///
/// Pure, so the classification is testable without a socket - which is the
/// only way to check the arms a developer host will never produce.
/// @param err The errno from a refused sendto
[[nodiscard]] constexpr auto transient_kick_errno(int const err) noexcept -> bool
{
    return err == EAGAIN || err == EWOULDBLOCK || err == EBUSY || err == ENOBUFS || err == ENETDOWN;
}

/// What the kernel let us learn about a program attached to an interface.
enum class AttachedProgramOwner : uint8_t
{
    ours,     ///< loaded under our program name
    foreign,  ///< loaded under another name, or nobody's: an id of 0
    unknown,  ///< the kernel would not say: opening a program by its id needs CAP_SYS_ADMIN
};

/// Whether the attached program `id` is ours to take off the interface,
/// given what the kernel said of it and the id of the program our own pin
/// directory holds (0 for none).
///
/// Ours by name is ours, and so is a program the kernel would not name when
/// it is the one we pinned: a daemon running with CAP_BPF and CAP_NET_ADMIN
/// but not CAP_SYS_ADMIN - the capability set a service file gives it -
/// gets EPERM for its own program as for anybody's, and without this could
/// never replace its own pinned program across a redeploy. One the kernel
/// would not name and the pin does not vouch for is a refusal that says so,
/// `program_unidentifiable`, rather than a claim either way.
///
/// Pure, so every arm is testable without the kernel that would need root,
/// and then the lack of it, to produce them.
[[nodiscard]] inline auto attachment_is_ours(AttachedProgramOwner const owner, uint32_t const id, uint32_t const pinned_id) noexcept
    -> StatusValue<bool>
{
    switch (owner) {
        case AttachedProgramOwner::ours:
            return true;
        case AttachedProgramOwner::foreign:
            return false;
        case AttachedProgramOwner::unknown:
            break;
    }
    if (pinned_id != 0 && pinned_id == id) {
        return true;
    }
    return failure(XdpError::program_unidentifiable);
}

/// FNV-1a over `bytes`, 64 bits wide.
///
/// Used to fingerprint the embedded BPF object, so a filter that has been
/// recompiled is recognised as a different program without anybody having
/// to remember to bump a version number - which is the version number that
/// would have been forgotten.
///
/// Not a cryptographic hash and not trying to be. The question is "are
/// these the same bytes this build was made from", an accident is all that
/// has to be ruled out, and a wrong answer costs one program reload.
/// @param bytes The bytes to fingerprint
[[nodiscard]] constexpr auto fnv1a64(std::span<unsigned char const> const bytes) noexcept -> uint64_t
{
    constexpr uint64_t Basis = 0xcbf2'9ce4'8422'2325ULL;
    constexpr uint64_t Prime = 0x0000'0100'0000'01b3ULL;
    uint64_t hash = Basis;
    for (unsigned char const byte : bytes) {
        hash ^= static_cast<uint64_t>(byte);
        hash *= Prime;
    }
    return hash;
}

/// Call `attempt` until it stops reporting EBUSY, pausing with `pause`
/// between tries and giving up after `retries` of them. Hands back whatever
/// the last attempt said.
///
/// `attempt` reports 0 or a negative errno, the way libxdp's
/// xsk_socket__create() does. Only -EBUSY is retried: on a bind it is the
/// one refusal that means "not yet, the queue is still going away", and
/// retrying any other errno would turn a real fault - a wrong interface, a
/// driver without zero-copy - into a half-second stall and then the same
/// failure. `retries` of 0 makes the single attempt.
///
/// The pause is a parameter rather than a call to nanosleep inside, so the
/// policy can be tested against a counted attempt and a counted clock -
/// with no socket, no privileges and no real waiting, which is the only way
/// to check a window that a developer host will not reproduce on demand.
/// @param retries How many further attempts a busy queue is given
/// @param attempt What to call; returns 0 or a negative errno
/// @param pause Called between two attempts
template <typename Attempt, typename Pause>
[[nodiscard]] constexpr auto retry_while_busy(size_t const retries, Attempt attempt, Pause pause) -> int
{
    int result = attempt();
    for (size_t i = 0; i < retries && result == -EBUSY; ++i) {
        pause();
        result = attempt();
    }
    return result;
}

/// How many fill-ring slots to ask xsk_ring_prod__reserve() for.
///
/// xsk_ring_prod__reserve() is all-or-nothing: asked for more slots than the
/// ring has free, it reserves none and returns 0. So asking for every free
/// UMEM frame hands the kernel nothing at all whenever the UMEM has more
/// frames free than the ring has room for — the fill ring drains, the NIC runs
/// out of buffers and receive stops, with no error anywhere. It is a function
/// of ring sizing and load, so it presents as an intermittent deaf receiver.
///
/// @param available Free UMEM frames
/// @param ring_free Slots the fill ring reports free (xsk_prod_nb_free)
/// @return The lesser of the two
[[nodiscard]] constexpr auto fill_reserve_count(size_t const available, uint32_t const ring_free) noexcept -> uint32_t
{
    return available < ring_free ? static_cast<uint32_t>(available) : ring_free;
}

/// Free UMEM frames the fill ring may have, keeping `tx_reserve` of them back
/// for transmit.
///
/// RX and TX share one UMEM and one free list. fill_replenish() would
/// otherwise hand the fill ring every free frame it could, which it can
/// whenever the UMEM is no larger than the fill ring - and then tx_start()
/// finds the free list empty and the context can receive but never send.
/// With the shipped defaults the fill ring is the smaller of the two and the
/// leftover happens to be enough, so the fault is invisible until someone
/// configures a UMEM that fits inside the fill ring. The reserve makes it a
/// decision rather than an accident of ring sizing.
///
/// @param available Free UMEM frames
/// @param tx_reserve Frames to keep out of the fill ring for transmit
/// @return What is left for the fill ring, which may be none
[[nodiscard]] constexpr auto fillable_frames(size_t const available, size_t const tx_reserve) noexcept -> size_t
{
    return available > tx_reserve ? available - tx_reserve : 0;
}

/// The transmit reserve actually applied, which is never more than half the
/// UMEM however large a reserve was configured.
///
/// Without the cap a reserve bigger than the pool would starve receive in
/// exactly the way the reserve exists to stop happening to transmit, and the
/// shipped default - sized for the default 1024-frame UMEM - would do it to
/// anyone who asked for a smaller one.
///
/// @param requested XdpConfig::tx_frame_reserve
/// @param frame_count XdpConfig::umem_frame_count
/// @return The reserve to apply
[[nodiscard]] constexpr auto effective_tx_reserve(size_t const requested, size_t const frame_count) noexcept -> size_t
{
    size_t const cap = frame_count / 2;
    return requested < cap ? requested : cap;
}

}  // namespace detail

/// The magic in a pin directory's identity entry: the bytes "STATUSBR".
inline constexpr uint64_t xdp_pin_magic = 0x5354'4154'5553'4252ULL;

/// What a pin directory says about itself, kept in a one-entry array map
/// pinned beside the program as XdpProgram::PIN_IDENTITY.
///
/// This is an ABI between one run of statusbar and the next rather than one
/// between userspace and the BPF program: a restart reads it to decide
/// whether the program already on the interface is the one this build would
/// have attached. Structure alone cannot answer that - a recompiled filter
/// with the same maps has exactly the same shape as the old one, and that
/// is the common case, not the rare one - so the answer is written down
/// instead of inferred.
///
/// Also the only thing that distinguishes somebody else's pin from our own.
/// Adoption writes our rules into the map it adopts, so being wrong here
/// means writing into a stranger's memory; being deliberately
/// unadventurous is cheap by comparison.
struct XdpPinIdentity
{
    /// xdp_pin_magic when we wrote it. Anything else means the directory is
    /// not ours, and then nothing in it may be read, written or removed.
    uint64_t magic{0};
    /// fnv1a64() over the embedded BPF object. Changes whenever
    /// xdp_filter.bpf.c does, so a redeploy is detected by the build rather
    /// than declared by a developer.
    uint64_t program_hash{0};
    /// The TCAM geometry this build compiled against. Redundant against the
    /// checks on the pinned maps themselves, and kept because it makes the
    /// entry mean something on its own under `bpftool map dump`.
    uint32_t window_bytes{0};
    uint32_t max_rules{0};
};

static_assert(std::is_trivially_copyable_v<XdpPinIdentity>);
// The value size of a pinned map is part of what is on bpffs, so a change
// here is a change an older build will see. It is meant to be caught by the
// identity check rather than by luck, which is what the size check in
// XdpProgram::owner() is for - but a change should still be deliberate.
static_assert(sizeof(XdpPinIdentity) == 24);

/// Who the pin directory at a path belongs to, as far as it will say.
enum class XdpPinOwner : uint8_t
{
    /// Nothing claims it. Either nothing is pinned there, or what is
    /// pinned predates identities or was half written by a process that
    /// died mid-pin. All three mean the directory is ours to replace.
    none,
    /// Ours. Whether it is *this build's* is the further question that
    /// adoption asks.
    ours,
    /// Somebody else's. Nothing in it may be read, written, unlinked or
    /// detached - including by the replace path, which is every bit as
    /// destructive as adoption would be.
    foreign,
};

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
    /// Written last, so a directory that claims an identity is a directory
    /// whose other pins are all there.
    static constexpr std::string_view PIN_IDENTITY = "identity";

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
    /// @param entry One of PIN_IDENTITY, PIN_PROG, PIN_RULES_MAP, PIN_XSK_MAP, PIN_DEVMAP
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

    /// The identity this build writes into a pin directory, and the one it
    /// insists on finding before it will adopt. Reads the embedded BPF
    /// object and nothing else - no filesystem, no privilege - and gives
    /// the same answer every time within one build.
    [[nodiscard]] static auto identity() -> XdpPinIdentity;

    /// Who the pin directory at `pin_path` belongs to, from its identity
    /// entry alone. Opens a pin to read it; creates nothing and writes
    /// nothing.
    ///
    /// open() asks this before it adopts *and* before it replaces. Replacing
    /// means unlinking pins and taking a program off an interface, which is
    /// no more ours to do to a stranger's directory than adopting it would
    /// be - so the one question has to come before both answers.
    ///
    /// Reading a pin needs the same privilege pinning does. Where it is
    /// missing the call fails with that errno rather than answering `none`:
    /// not being able to tell who owns a directory is not the same as the
    /// directory being unclaimed, and only one of those is safe to act on.
    /// @param pin_path A pin directory, from pin_path_for()
    [[nodiscard]] static auto owner(std::string_view pin_path) -> StatusValue<XdpPinOwner>;

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
    /// Only ours: a pin directory that is somebody else's is refused as
    /// foreign_program and left as it is, and a program on the interface
    /// that is not ours by name stays attached - that counts as nothing of
    /// ours to remove, and succeeds. A program the kernel will not name -
    /// reading one by its id needs CAP_SYS_ADMIN - is ours when it is the
    /// one pinned at `pin_path`, and otherwise reported as
    /// program_unidentifiable rather than guessed at either way.
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

/// Wait out one slice of the window in which a just-closed queue is still
/// registered. On the open path, on the control thread - never on the
/// real-time path.
inline void pause_for_busy_bind() noexcept
{
    struct timespec remaining{};
    remaining.tv_nsec = xdp_bind_busy_pause_ns;
    // nanosleep() writes back what is left of the pause when a signal cuts
    // it short, so this resumes the same 10 ms rather than starting it over
    // and stretching the bound.
    while (::nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
    }
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
#    if defined(HAVE_XDP_TX_METADATA)

/// XDP_TX_METADATA, under a name the TX path can use unguarded. A kernel
/// header that predates TX metadata defines neither, and then no frame ever
/// asks for any.
inline constexpr uint32_t xdp_desc_tx_metadata = XDP_TX_METADATA;

/// Write a launch time into a frame's TX metadata, or clear it for 0.
///
/// The metadata is a kernel struct in the UMEM, so it is written through a
/// typed pointer rather than byte by byte; the span's length has already been
/// checked to be sizeof(xsk_tx_metadata).
inline auto write_launch_time(std::span<uint8_t> metadata, int64_t launch_time_ns) noexcept -> void
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) - the UMEM holds the kernel's struct
    auto* meta = reinterpret_cast<struct xsk_tx_metadata*>(metadata.data());
    *meta = xsk_tx_metadata{};
    if (launch_time_ns <= 0) {
        // No flag, so tx_commit() leaves XDP_TX_METADATA off and the frame
        // goes as soon as the NIC can send it.
        return;
    }
    meta->flags = XDP_TXMD_FLAGS_LAUNCH_TIME;
    meta->request.launch_time = static_cast<__u64>(launch_time_ns);
}

/// Whether a frame's metadata asks for anything, read back from the frame
/// itself. Keeping the answer in the UMEM rather than beside it is what makes
/// a batch of frames between tx_start() and tx_commit() safe.
[[nodiscard]] inline auto frame_wants_metadata(std::span<uint8_t const> metadata) noexcept -> bool
{
    if (metadata.size() < sizeof(struct xsk_tx_metadata)) {
        return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) - as above
    auto const* meta = reinterpret_cast<struct xsk_tx_metadata const*>(metadata.data());
    return meta->flags != 0;
}

#    else  // !HAVE_XDP_TX_METADATA

inline constexpr uint32_t xdp_desc_tx_metadata = 0;

inline auto write_launch_time(std::span<uint8_t>, int64_t) noexcept -> void
{}

[[nodiscard]] inline auto frame_wants_metadata(std::span<uint8_t const>) noexcept -> bool
{
    return false;
}

#    endif  // HAVE_XDP_TX_METADATA

/// XDP_PACKET_HEADROOM: what the kernel takes off the front of every frame
/// for its own use, before the caller's headroom.
inline constexpr size_t xdp_packet_headroom = 256;

/// The kernel's smallest UMEM chunk (XDP_UMEM_MIN_CHUNK_SIZE).
inline constexpr size_t xdp_min_frame_size = 2048;

/// Whether the kernel will register a UMEM of this geometry, by its own rules
/// in net/xdp/xdp_umem.c (xdp_umem_reg) for aligned chunks - the only mode
/// this module uses.
///
/// Pure, and takes the page size rather than reading it, because the answer
/// differs by host: a frame size above 4096 is legal where pages are 16 KiB
/// (Asahi, the Pi 5) and refused where they are 4 KiB (x86). 4096 is
/// therefore the largest portable value.
///
/// @param frame_size Bytes per UMEM frame
/// @param headroom The caller's headroom, on top of the kernel's own
/// @param page_size The host's page size, from sysconf(_SC_PAGESIZE)
[[nodiscard]] constexpr auto umem_geometry_is_valid(size_t frame_size, size_t headroom, size_t page_size) noexcept -> bool
{
    if (frame_size < xdp_min_frame_size || frame_size > page_size) {
        return false;
    }
    if ((frame_size & (frame_size - 1)) != 0) {
        return false;
    }
    // The kernel's own headroom comes out of the frame first, and what is left
    // has to be able to hold something.
    return headroom < frame_size - xdp_packet_headroom;
}

/// Bytes of per-frame UMEM metadata an AF_XDP socket needs to carry a launch
/// time. The kernel places the metadata immediately *below* the descriptor's
/// address, so a frame's headroom must be at least this for it to fit.
#    if defined(HAVE_XDP_TX_METADATA)
inline constexpr size_t xdp_tx_metadata_len = sizeof(struct xsk_tx_metadata);
#    else
inline constexpr size_t xdp_tx_metadata_len = 0;
#    endif

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
    /// @param tx_metadata_len Bytes of per-frame TX metadata to register, or
    ///        0 for none. Non-zero needs a libxdp that can set it; the caller
    ///        has already checked that with probe_tx_metadata().
    [[nodiscard]] auto allocate(
        size_t frame_count,
        size_t frame_size,
        size_t headroom,
        size_t fill_ring_size,
        size_t comp_ring_size,
        RingSet& rings,
        size_t tx_metadata_len = 0) -> StatusValue<struct xsk_umem*>;

    /// Where the TX metadata of the frame at `addr` lives: the bytes
    /// immediately below the descriptor address, which is `addr + headroom`.
    /// Empty when the UMEM carries no metadata, or the headroom cannot hold
    /// it.
    [[nodiscard]] auto tx_metadata_span(uint64_t addr) noexcept -> std::span<uint8_t>
    {
        if (tx_metadata_len_ == 0 || headroom_ < tx_metadata_len_) {
            return {};
        }
        return {area_ + addr + headroom_ - tx_metadata_len_, tx_metadata_len_};
    }

    [[nodiscard]] auto tx_metadata_len() const noexcept -> size_t { return tx_metadata_len_; }

    /// The errno the last UMEM registration left, 0 when it succeeded. Kept
    /// here because allocate() closes on failure, and a close() runs
    /// syscalls of its own that would overwrite the one worth reporting.
    [[nodiscard]] auto create_errno() const noexcept -> int { return create_errno_; }

    /// Create the umem itself, with or without TX metadata. Separated so the
    /// two libxdp entry points - only one of which can set tx_metadata_len -
    /// are chosen in one place.
    [[nodiscard]] auto create_umem(
        size_t total_size,
        size_t frame_size,
        size_t headroom,
        size_t fill_ring_size,
        size_t comp_ring_size,
        RingSet& rings) noexcept -> bool;
    /// The registration itself, with or without metadata as tx_metadata_len_ says.
    [[nodiscard]] auto create_umem_as_asked(
        size_t total_size,
        size_t frame_size,
        size_t headroom,
        size_t fill_ring_size,
        size_t comp_ring_size,
        RingSet& rings) noexcept -> bool;

    /// What a failed registration is reported as, from the errno it left.
    [[nodiscard]] auto create_refusal() const noexcept -> XdpError;

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
        std::swap(tx_metadata_len_, other.tx_metadata_len_);
        std::swap(create_errno_, other.create_errno_);
        std::swap(free_list_, other.free_list_);
    }

    struct xsk_umem* umem_{nullptr};
    uint8_t* area_{nullptr};
    size_t area_size_{0};
    size_t frame_size_{0};
    size_t headroom_{0};
    size_t tx_metadata_len_{0};
    int create_errno_{0};
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
        auto const [ret, mode] = try_attach(prog_fd, if_index, plan);
        if (ret != 0) {
            // A refusal because something is already there is somebody
            // else's program - open() has cleared away anything of ours
            // first - or one that arrived in the gap: theirs, not replaced.
            return failure(ret == -EBUSY || ret == -EEXIST ? XdpError::foreign_program : XdpError::bpf_attach_failed);
        }
        hold(std::move(obj), if_index, mode);
        return success();
    }

    /// One attempt per mode in the plan, the first and then the fallback.
    /// XDP_FLAGS_UPDATE_IF_NOEXIST on each: never over the top of a program
    /// that is already there, whoever's it is.
    /// @return bpf_xdp_attach()'s result, and the mode it belongs to
    [[nodiscard]] static auto try_attach(int const prog_fd, unsigned int const if_index, AttachPlan const& plan) noexcept
        -> std::pair<int, XdpAttachMode>
    {
        auto const attempt = [prog_fd, if_index](XdpAttachMode const mode) {
            return bpf_xdp_attach(static_cast<int>(if_index), prog_fd, attach_flags(mode) | XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
        };
        int const first = attempt(plan.first);
        if (first == 0 || !plan.fallback.has_value()) {
            return {first, plan.first};
        }
        return {attempt(*plan.fallback), *plan.fallback};
    }

    /// Take the attached program on: its object, where it is, and how.
    void hold(BpfObject&& obj, unsigned int const if_index, XdpAttachMode const mode) noexcept
    {
        obj_ = std::move(obj);
        if_index_ = if_index;
        mode_ = mode;
        attached_ = true;
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

    /// Take note of a program adopted from a pin: attached by an earlier
    /// process, in this mode, and the pin's to keep - not ours to detach at
    /// close, so it is recorded as not attached by us, the way disown()
    /// leaves a pinned one.
    /// @param if_index The interface it is on
    /// @param mode The mode XdpProgram::query() found it attached in
    void adopt(unsigned int const if_index, XdpAttachMode const mode) noexcept
    {
        detach();
        if_index_ = if_index;
        mode_ = mode;
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
    /// @param plan The attach modes this open() would accept; a program
    ///             attached in any other mode is not adopted
    [[nodiscard]] auto adopt(
        std::string_view pin_path,
        unsigned int if_index,
        std::span<CompiledRule<32> const> rules,
        XdpAction default_action,
        AttachPlan const& plan) -> Status;

    /// Pin the loaded program and its maps under `pin_path`, creating the
    /// directory. On success the attachment is disowned, so the program stays
    /// on the interface after we exit - which is the point of pinning.
    /// @param pin_path The pin directory to create and fill
    [[nodiscard]] auto pin(std::string_view pin_path) -> Status;

    /// Point the devmap's single entry at an interface, so a frame matching
    /// a forward_tap rule is redirected out of it by the BPF program.
    ///
    /// Internal on purpose. The devmap holds one entry at key 0 and
    /// XdpConfig::tap_ifindex is how a caller fills it; a public entry point
    /// would invite a second owner for a map the program reads on every
    /// frame.
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

    /// Empty the devmap's one slot, so a forward_tap rule has nowhere to
    /// send a frame. What an adopted program would otherwise inherit from
    /// the process before: devmap entries outlive the process that made
    /// them, and the interface index they hold may by now be somebody else.
    [[nodiscard]] auto unregister_tap() -> Status
    {
        uint32_t zero_key = 0;
        if (bpf_map_delete_elem(devmap_fd_, &zero_key) != 0 && errno != ENOENT) {
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

/// Turn the kernel's reply into XdpKernelStats.
///
/// Pure, and separate from the syscall, so that the field-by-field mapping
/// and the meaning of the reported length can be tested without a socket,
/// a NIC or a privilege.
///
/// @param raw The struct the kernel filled
/// @param reported_length The option length the kernel wrote back, in bytes
[[nodiscard]] auto kernel_stats_from(struct xdp_statistics const& raw, socklen_t reported_length) -> XdpKernelStats;

/// Read the kernel's counters off an AF_XDP socket descriptor.
///
/// Takes a descriptor rather than hanging off XdpContext so it can be read
/// from any AF_XDP socket -- which is what lets the counters be tested
/// against a real kernel socket with no privilege, since binding a
/// transmit-only socket needs no BPF program and a user namespace grants
/// CAP_NET_RAW over its own network namespace while never granting CAP_BPF.
///
/// @param fd An open AF_XDP socket descriptor
[[nodiscard]] auto read_xdp_kernel_stats(int fd) -> StatusValue<XdpKernelStats>;

/// The AF_PACKET socket an XdpContext takes its multicast memberships on.
/// Protocol 0, so it receives nothing; it exists for PACKET_ADD_MEMBERSHIP
/// and PACKET_DROP_MEMBERSHIP, which the kernel counts per socket and per
/// group and lets go of when the socket closes -- the same ownership the
/// rawnet and mmap backends have through their own sockets. Needs
/// CAP_NET_RAW, which AF_XDP needs anyway.
[[nodiscard]] auto open_membership_socket() -> StatusValue<FileDescriptor>;

/// Add (@p optname PACKET_ADD_MEMBERSHIP) or drop (PACKET_DROP_MEMBERSHIP)
/// one membership of @p addr on interface @p if_index through @p fd. A
/// repeated add raises the socket's count for the group without touching
/// the NIC again, a drop lowers it and the NIC entry goes when the count
/// does. Dropping a group the socket does not hold is a no-op the kernel
/// answers with success.
[[nodiscard]] auto change_membership(int fd, unsigned int if_index, ieee::Eui48 const& addr, int optname) -> Status;

}  // namespace detail

class XdpContext
{
  public:
    /// Kept as a name for XdpSocketStats so existing callers of
    /// XdpContext::Stats still compile; the type itself lives at namespace
    /// scope so it can be forward-declared.
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

    /// How many times the bind had to be retried because the queue was still
    /// registered to its previous owner. Normally 0; non-zero says this open
    /// followed a close of the same queue closely enough to catch it being
    /// released, which is what a restart does. Valid while open.
    [[nodiscard]] auto bind_retries() const noexcept -> size_t { return bind_retries_; }

    /// UMEM frames held back from the fill ring for transmit, after the
    /// half-the-UMEM cap. Zero before open().
    [[nodiscard]] auto tx_frame_reserve() const noexcept -> size_t { return tx_frame_reserve_; }

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

    /// @param launch_time_ns CLOCK_TAI nanoseconds to send the frame at, or 0
    ///        for as soon as possible. Needs XdpConfig::tx_launch_time;
    ///        without it a non-zero time is ignored, as it always was.
    ///        tx_set_launch_time() is the same thing after the fact, and
    ///        try_tx_set_launch_time() the same thing with its answer kept.
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        auto addr = umem_.alloc_frame();
        if (!addr) {
            ++stats_.umem_exhausted_count;
            return failure(XdpError::free_list_empty);
        }
        // A frame off the free list carries whatever its last use left in the
        // metadata, and a stale launch time stalls the queue rather than
        // being ignored. Clearing it is also how a 0 here means "now".
        auto metadata = umem_.tx_metadata_span(*addr);
        if (!metadata.empty()) {
            detail::write_launch_time(metadata, launch_time_ns);
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

    /// Whether a refused sendto will pass by itself, read off the current
    /// errno. Call it straight after the sendto, before anything else can
    /// overwrite errno.
    /// @param ret The sendto return value
    [[nodiscard]] static auto is_transient_send_error(ssize_t ret) -> bool
    {
        return ret < 0 && detail::transient_kick_errno(errno);
    }

    /// Tell the kernel there are frames in the TX ring, when there are.
    ///
    /// The kick is skipped when nothing has been submitted since the last one
    /// got through: "nothing submitted" is the one thing it is always safe
    /// to skip on, and it is the common case for a sender ticking faster
    /// than it sends. A healthy sender therefore skips most kicks, which
    /// makes a *low* skip ratio in the counters a signal in itself. The
    /// socket is bound with XDP_USE_NEED_WAKEUP, so a driver that is awake
    /// anyway may not need the kick - it is sent regardless when frames are
    /// pending, which costs a syscall and never a frame.
    ///
    /// A kick refused with EAGAIN and friends leaves the frames pending, so
    /// the next call tries again rather than counting them as delivered.
    ///
    /// May be called from a thread other than the one committing frames (a
    /// kicker that spares the sender the syscall): the pending flag is
    /// claimed before the kick and re-armed if the kick is refused, so a
    /// commit that lands between the claim and the syscall sets it again
    /// and the next kick carries that frame. Only this method and
    /// tx_commit share state, through that flag; the flush counters are
    /// this method's alone.
    [[nodiscard]] auto tx_flush() -> Status
    {
        if (!tx_pending_.exchange(false, std::memory_order_acq_rel)) {
            ++stats_.tx_flush_skipped;
            return success();
        }
        auto const ret = ::sendto(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        ++stats_.tx_flush_count;
        if (ret >= 0) {
            return success();
        }
        int const err = errno;
        stats_.tx_flush_errno = err;
        tx_pending_.store(true, std::memory_order_release);  // the frames are still waiting
        if (detail::transient_kick_errno(err)) {
            // Momentary, and the frames stay pending for the next kick. The
            // caller hears success so it does not escalate on a hiccup; the
            // counter is there for when the hiccups do not stop.
            ++stats_.tx_flush_transient;
            return success();
        }
        ++stats_.tx_flush_failed;
        return failure(XdpError::tx_flush_failed);
    }

    /// The next received frame, stamped @p now: the RX clock as the caller
    /// read it for this pass. Nothing once the cycle's RX budget is spent.
    [[nodiscard]] auto rx_start(RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
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

    /// Join a multicast group to receive frames sent to the given address.
    /// The membership belongs to this context: it is counted per group (two
    /// joins need two leaves), it is dropped by close(), and it dies with
    /// the process. Earlier versions set the NIC's filter directly
    /// (SIOCADDMULTI), one uncounted bit with no owner, which outlived a
    /// killed process and which one leave cleared for every user. Two
    /// consequences of the counting: a repeated join raises the count and
    /// no longer rewrites the NIC's table, so a lost table entry is repaired
    /// by leaving and joining again, not by joining again; and leaving a
    /// group this context does not hold succeeds silently (the kernel's
    /// answer; SIOCDELMULTI used to fail).
    /// @param addr Multicast MAC address to join
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;

    /// Drop one membership taken with join_multicast(); see there for what
    /// leaving a group not held does.
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const& addr) -> Status;

    /// The socket's counters, as of now. See XdpSocketStats on what a reader
    /// on another thread may and may not expect of them.
    [[nodiscard]] auto socket_stats() const noexcept -> XdpSocketStats const& { return stats_; }
    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }

    /// The kernel's own view of this socket, as of now: four counters of
    /// frames it discarded after we handed them over, plus two ring-empty
    /// ones. Read through rather than mirrored -- a getsockopt is cheap, and
    /// copying them in on a timer would only add a staleness question the
    /// caller is better placed to answer.
    ///
    /// Only the failure branch below is tested without privilege. Reaching
    /// the delegation needs an open context, and opening one loads the BPF
    /// filter, which wants CAP_BPF -- not a capability any user namespace
    /// grants. The success path is covered by
    /// xdp_integration.kernel_stats_on_an_open_context, under root, on a
    /// kernel built with CONFIG_XDP_SOCKETS.
    [[nodiscard]] auto kernel_stats() const -> StatusValue<XdpKernelStats>
    {
        if (!valid()) {
            return failure(XdpError::not_open);
        }
        return detail::read_xdp_kernel_stats(xsk_socket__fd(xsk_));
    }

    /// Whether this socket's frames can carry a launch time, i.e. the UMEM
    /// was registered with room for TX metadata (XdpConfig::tx_launch_time).
    [[nodiscard]] auto tx_launch_time() const noexcept -> bool { return umem_.tx_metadata_len() != 0; }

    /// Send the frame at @p handle at @p launch_time_ns on CLOCK_TAI, rather
    /// than as soon as the NIC can.
    ///
    /// Called between tx_start() and tx_commit() for that frame. The time is
    /// written into the frame's own metadata, which is what makes a batch
    /// safe: each frame carries its own, and commit reads it back.
    ///
    /// The NIC must be in launch-time mode for this to mean anything - an
    /// offloaded `etf` on this queue - and a time already past is the
    /// driver's to refuse. net::LaunchOrder is what keeps the times in the
    /// order the queue needs.
    ///
    /// Reports nothing, which is the shape a commit path wants: a real-time
    /// thread writing a frame's time has nobody to report a failed write to.
    /// The two things it could report - a closed socket, and a UMEM registered
    /// without room for metadata - are both settled before the first frame of
    /// a batch rather than per frame, and are what open() and
    /// tx_launch_time() answer. On either of them the frame simply carries no
    /// time: the write goes nowhere rather than into a UMEM that is not there.
    /// try_tx_set_launch_time() is this same call with that answer kept, for
    /// a caller that can act on it.
    ///
    /// @param handle UMEM frame address from tx_start()
    /// @param launch_time_ns CLOCK_TAI nanoseconds; 0 means "as soon as
    ///        possible", and clears any time already set on the frame
    void tx_set_launch_time(uint64_t const handle, int64_t const launch_time_ns) noexcept
    {
        static_cast<void>(try_tx_set_launch_time(handle, launch_time_ns));
    }

    /// tx_set_launch_time() with its answer kept rather than dropped: the same
    /// write, reporting whether the frame will carry the time. The failures
    /// are the two the silent form swallows, and both are a property of the
    /// socket rather than of this frame, so a caller that cannot tolerate an
    /// untimed frame wants this form, or wants tx_launch_time() checked once
    /// at startup.
    ///
    /// @return `not_open` on a closed socket, `tx_metadata_not_supported`
    ///         when the UMEM carries no metadata.
    [[nodiscard]] auto try_tx_set_launch_time(uint64_t const handle, int64_t const launch_time_ns) noexcept -> Status
    {
        if (!valid()) {
            return failure(XdpError::not_open);
        }
        auto metadata = umem_.tx_metadata_span(handle);
        if (metadata.empty()) {
            return failure(XdpError::tx_metadata_not_supported);
        }
        detail::write_launch_time(metadata, launch_time_ns);
        return success();
    }

    /// Zero the counters, keeping the socket. A run that has been going for
    /// days needs a fresh window without a reopen.
    auto reset_stats() noexcept -> void { stats_ = Stats{}; }

  private:
    void swap(XdpContext& other) noexcept
    {
        swap_socket(other);
        swap_settings(other);
        swap_tx_pending(other);
    }
    /// The kernel-side half: socket, memory, program, rings, the interface
    /// they sit on and the socket that holds the multicast memberships.
    void swap_socket(XdpContext& other) noexcept
    {
        std::swap(xsk_, other.xsk_);
        std::swap(umem_, other.umem_);
        std::swap(bpf_, other.bpf_);
        std::swap(rings_, other.rings_);
        std::swap(interface_, other.interface_);
        std::swap(membership_fd_, other.membership_fd_);
    }
    /// What open() decided and what has happened since.
    void swap_settings(XdpContext& other) noexcept
    {
        std::swap(budget_, other.budget_);
        std::swap(stats_, other.stats_);
        std::swap(program_, other.program_);
        std::swap(bind_retries_, other.bind_retries_);
        std::swap(tx_frame_reserve_, other.tx_frame_reserve_);
        std::swap(zero_copy_, other.zero_copy_);
    }
    /// The one atomic, swapped by value: nothing else touches either
    /// context while it is being moved.
    void swap_tx_pending(XdpContext& other) noexcept
    {
        bool const mine = tx_pending_.load(std::memory_order_relaxed);
        tx_pending_.store(other.tx_pending_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        other.tx_pending_.store(mine, std::memory_order_relaxed);
    }

    struct xsk_socket* xsk_{nullptr};

    detail::UmemRegion umem_;
    detail::BpfState bpf_;
    detail::RingSet rings_;
    detail::InterfaceId interface_;
    /// The frame at RX ring entry @p idx as a slot stamped @p now, the ring
    /// entry released: the UMEM frame stays valid until rx_release(handle).
    [[nodiscard]] auto take_rx_desc(uint32_t idx, RxTimePoint now) -> EthernetRxSlot;

    detail::CycleBudget budget_;
    Stats stats_{};
    XdpProgram program_;
    /// Pauses the bind needed before the queue was free; see bind_retries().
    size_t bind_retries_{0};
    /// detail::effective_tx_reserve() of the configured reserve, settled at
    /// open() so fill_replenish() does not recompute it per cycle.
    size_t tx_frame_reserve_{0};
    /// The socket the multicast memberships are held on; opened by the
    /// first join_multicast(), closed with the context. See
    /// detail::open_membership_socket().
    FileDescriptor membership_fd_{};
    /// Frames are in the TX ring that the kernel has not been kicked for.
    /// Set by tx_commit(), cleared only by a kick the kernel accepted.
    /// Frames submitted since the last kick that got through. Atomic so a
    /// kicker thread can run tx_flush() against this thread's tx_commit().
    std::atomic<bool> tx_pending_{false};
    bool zero_copy_{false};
};

/// Whether this build and this kernel can put a launch time on an AF_XDP
/// frame at all.
///
/// Three things have to line up, and only the first two can be answered
/// without a NIC: the build needs a kernel UAPI with `struct xsk_tx_metadata`
/// and a libxdp that can register `tx_metadata_len`; the running kernel needs
/// to accept such a UMEM. Whether the NIC then acts on a launch time in that
/// metadata is a different question, with a different answer on 6.8 to 6.14
/// kernels, and probe_tx_launch_time() is the one that asks it.
///
/// Registering a UMEM needs an AF_XDP socket, which needs CAP_NET_RAW, so an
/// unprivileged caller gets that refusal rather than a false negative. A
/// standalone query: open() asks its own UMEM registration the same thing.
///
/// @return success if a launch time can be asked for,
///         `XdpError::tx_metadata_not_supported` if it cannot, or the
///         kernel's own refusal.
[[nodiscard]] auto probe_tx_metadata() -> Status;

/// Whether the NIC at @p if_index will act on a launch time in an AF_XDP
/// frame's TX metadata, as the kernel reports it: the netdev family's
/// xsk-features, bit NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO, which Linux 6.15
/// added together with the feature and a driver sets for the queues that
/// take a launch time (igc, so far).
///
/// This is the question open() asks for XdpConfig::tx_launch_time, and not
/// probe_tx_metadata(): a kernel from 6.8 to 6.14 registers a UMEM with TX
/// metadata and then discards the launch-time flag inside it, which from the
/// outside looks exactly like a NIC that works. Needs no privilege.
///
/// @return success, `XdpError::launch_time_not_supported` when the kernel
///         or the NIC has no such thing, or the kernel's own refusal.
[[nodiscard]] auto probe_tx_launch_time(unsigned int if_index) -> Status;

namespace detail {

/// Whether this build can register a UMEM that carries TX metadata at all.
#    if defined(HAVE_XDP_TX_METADATA)
inline constexpr bool xdp_tx_metadata_built = true;
#    else
inline constexpr bool xdp_tx_metadata_built = false;
#    endif

/// The CTRL_ATTR_FAMILY_ID a generic-netlink family lookup answered with, if
/// the reply holds one. Pure; here for the tests.
[[nodiscard]] auto genl_family_id_in(std::span<uint8_t const> reply) noexcept -> std::optional<uint16_t>;

/// The NETDEV_A_DEV_XSK_FEATURES a netdev dev-get answered with, if the reply
/// holds one.
[[nodiscard]] auto xsk_features_in(std::span<uint8_t const> reply) noexcept -> std::optional<uint64_t>;

}  // namespace detail

#else  // !(__linux__ && HAVE_XDP)

// ──────────────────────────────────────────────
// XdpContext — stub for non-Linux or without libbpf/libxdp
// ──────────────────────────────────────────────

class XdpContext
{
  public:
    /// Kept as a name for XdpSocketStats so existing callers of
    /// XdpContext::Stats still compile; the type itself lives at namespace
    /// scope so it can be forward-declared.
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
    [[nodiscard]] auto bind_mode() const noexcept -> XdpBindMode { return XdpBindMode::copy; }
    [[nodiscard]] auto attach_mode() const noexcept -> XdpAttachMode { return XdpAttachMode::native; }
    [[nodiscard]] auto bind_retries() const noexcept -> size_t { return 0; }
    [[nodiscard]] auto tx_frame_reserve() const noexcept -> size_t { return 0; }

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

    [[nodiscard]] auto rx_start(RxTimePoint) -> StatusValue<std::optional<EthernetRxSlot>>
    {
        return failure(XdpError::not_supported_on_platform);
    }
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

    [[nodiscard]] auto socket_stats() const noexcept -> XdpSocketStats const& { return stats_; }
    [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }

    [[nodiscard]] auto tx_launch_time() const noexcept -> bool { return false; }

    void tx_set_launch_time(uint64_t, int64_t) noexcept {}

    [[nodiscard]] auto try_tx_set_launch_time(uint64_t, int64_t) noexcept -> Status
    {
        return failure(XdpError::not_supported_on_platform);
    }

    auto reset_stats() noexcept -> void { stats_ = Stats{}; }

    [[nodiscard]] auto kernel_stats() const -> StatusValue<XdpKernelStats> { return failure(XdpError::not_supported_on_platform); }

  private:
    void swap(XdpContext& other) noexcept
    {
        std::swap(stats_, other.stats_);
        std::swap(program_, other.program_);
    }
    Stats stats_{};
    XdpProgram program_;
};

/// Without the build's XDP support there is nothing to probe: a launch time
/// cannot be asked for at all.
[[nodiscard]] inline auto probe_tx_metadata() -> Status
{
    return failure(XdpError::not_supported_on_platform);
}

/// Nor a NIC to ask about one.
[[nodiscard]] inline auto probe_tx_launch_time(unsigned int) -> Status
{
    return failure(XdpError::not_supported_on_platform);
}

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
