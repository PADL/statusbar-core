#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One UMEM bound by AF_XDP sockets on several devices (XDP_SHARED_UMEM), each owning a share of its frames, any
/// sending from any share's (a held received frame gathered); XdpFrameLedger counts those loans, so a frame goes
/// home only once its owner and every transmit pointing into it are done with it.

#include "statusbar/status/status.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

struct xsk_umem;

namespace statusbar::net {

namespace detail {
struct UmemAnchor;
}

/// Per UMEM frame: whether its owner has it in hand, how many transmits point into it and whose, and whether the
/// kernel holds it; and, per pair of shares, the frames one share's completions hand back to another. Real-time
/// safe: no allocation after construction, no locks. A frame's owner is the one thread that drives its share's socket.
class XdpFrameLedger
{
  public:
    /// Shares at most.
    static constexpr size_t MAX_SHARES = 4;

    /// `shares` shares of `frames_per_share` frames of `frame_size` bytes each: share s owns frames
    /// [s * frames_per_share, (s + 1) * frames_per_share). Control thread; allocates.
    XdpFrameLedger(size_t frames_per_share, size_t shares, size_t frame_size);

    [[nodiscard]] auto frame_size() const noexcept -> size_t { return frame_size_; }
    [[nodiscard]] auto frames_per_share() const noexcept -> size_t { return frames_per_share_; }
    [[nodiscard]] auto shares() const noexcept -> size_t { return shares_; }
    /// The share owning the frame UMEM address `addr` lies in.
    [[nodiscard]] auto share_of(uint64_t const addr) const noexcept -> size_t { return frame_of(addr) / frames_per_share_; }

    /// The owner has the frame at `addr` in hand (received, or taken to send), out of the kernel: a transmit
    /// may point into it from now until give_back(). The owner's thread.
    void hold(uint64_t addr) noexcept;
    /// A transmit of share `lender`'s socket points into the frame at `addr` (any offset within it) until its
    /// completion: false, nothing recorded, once the owner has given the frame back. The lender's thread.
    [[nodiscard]] auto lend(uint64_t addr, size_t lender) noexcept -> bool;
    /// Whether a transmit still points into the frame at `addr`.
    [[nodiscard]] auto lent(uint64_t addr) const noexcept -> bool;
    /// How many transmits of share `lender`'s socket point into the frame at `addr`. The lender's thread.
    [[nodiscard]] auto lent_by(uint64_t addr, size_t lender) const noexcept -> size_t;
    /// The owner is done with the frame at `addr`: true when no transmit points into it, so it is free now;
    /// else the last completion frees it. The owner's thread.
    [[nodiscard]] auto give_back(uint64_t addr) noexcept -> bool;
    /// A transmit of share `completer`'s socket pointing into the frame at `addr` completed: true when the frame
    /// is free now and `completer` owns it; another share's frame freed is queued for its owner (take_returns()).
    /// Nothing, false, without a loan of `completer`'s on it. The completer's thread.
    [[nodiscard]] auto complete(uint64_t addr, size_t completer) noexcept -> bool;
    /// Every loan share `lender`'s socket still has undone, as its completions would (frames go home, its own
    /// to reopen()). When that socket closes; its thread stopped.
    void forget(size_t lender) noexcept;

    /// The frame at `addr` went into the kernel (the fill ring, or the TX ring sent whole), out of the owner's
    /// hands; it comes back through the RX or completion ring. The owner's thread.
    void to_kernel(uint64_t addr) noexcept;
    /// Whether the frame at `addr` is in the kernel (to_kernel(), not hold()ed or completed since).
    [[nodiscard]] auto in_kernel(uint64_t addr) const noexcept -> bool { return in_kernel_[frame_of(addr)] != 0; }
    /// The kernel let go of the frame at `addr` (a frame of this share's own completed). The owner's thread.
    void from_kernel(uint64_t const addr) noexcept { in_kernel_[frame_of(addr)] = 0; }
    /// Share `share`'s socket's pool is gone with it (its queue's fill and completion rings): the kernel holds
    /// none of its frames. Control thread, the socket closed.
    void pool_gone(size_t share) noexcept;

    /// Share `share`'s socket opens afresh: each frame of it the kernel does not hold and no transmit points
    /// into to `free` (uint64_t frame address), once; the rest come through their completions. Before it receives.
    template <typename Free>
    void reopen(size_t const share, Free const& free) noexcept
    {
        for (size_t frame = share * frames_per_share_; frame < (share + 1) * frames_per_share_; ++frame) {
            if (in_kernel_[frame] == 0 && reclaim(frame)) {
                free(uint64_t{frame} * frame_size_);
            }
        }
        take_returns(share, free);  // after the reclaim pass: a frame queued meanwhile is freed here, once
    }
    /// Each frame another share's completions freed for `share`, oldest first, to `free` (uint64_t frame
    /// address). The owner's thread.
    template <typename Free>
    void take_returns(size_t const share, Free const& free) noexcept
    {
        auto const returned = [this, &free](uint64_t const addr) {
            loans_[frame_of(addr)].store(0, std::memory_order_relaxed);  // queued no more
            free(addr);
        };
        for (size_t from = 0; from < shares_; ++from) {
            if (from != share) {
                returns_[(from * MAX_SHARES) + share].drain(returned);
            }
        }
    }

  private:
    /// One producer's frames to one consumer: a ring as deep as a share is large, so it never fills.
    class Returns
    {
      public:
        void reset(size_t capacity);
        void push(uint64_t addr) noexcept;
        template <typename Free>
        void drain(Free const& free) noexcept
        {
            uint64_t const tail = tail_.load(std::memory_order_acquire);
            uint64_t head = head_.load(std::memory_order_relaxed);
            for (; head != tail; ++head) {
                free(slots_[head % capacity_]);
            }
            head_.store(head, std::memory_order_release);
        }

      private:
        std::unique_ptr<uint64_t[]> slots_;
        size_t capacity_{0};
        std::atomic<uint64_t> head_{0};
        std::atomic<uint64_t> tail_{0};
    };

    /// The owner has the frame in hand.
    static constexpr uint32_t HOLDS = 0x8000'0000U;
    /// Freed by another share's completion, in that share's queue to the owner.
    static constexpr uint32_t QUEUED = 0x4000'0000U;
    /// The transmits pointing into the frame.
    static constexpr uint32_t LOANS = 0x3FFF'FFFFU;

    /// The owner lets go of frame `frame`: true when nothing points into it (free now); false when a transmit
    /// does (its completion frees it) or another share's completion already queued it.
    [[nodiscard]] auto reclaim(size_t frame) noexcept -> bool;
    /// `count` loans of share `completer`'s on the frame at `addr` returned: true when the frame is free now and
    /// `completer` owns it; another share's frame freed is queued for its owner.
    [[nodiscard]] auto release(uint64_t addr, uint32_t count, size_t completer) noexcept -> bool;

    [[nodiscard]] auto frame_of(uint64_t const addr) const noexcept -> size_t { return static_cast<size_t>(addr / frame_size_); }
    [[nodiscard]] auto lent_by_index(size_t const frame, size_t const lender) const noexcept -> size_t
    {
        return (frame * MAX_SHARES) + lender;
    }

    size_t frames_per_share_;
    size_t shares_;
    size_t frame_size_;
    std::unique_ptr<std::atomic<uint32_t>[]> loans_;        ///< per frame: HOLDS, QUEUED, and the transmits pointing into it
    std::unique_ptr<uint16_t[]> lent_by_;                   ///< per frame and lender, the lender's thread's own
    std::unique_ptr<uint8_t[]> in_kernel_;                  ///< per frame, the owner's thread's own
    std::array<Returns, MAX_SHARES * MAX_SHARES> returns_;  ///< [from * MAX_SHARES + to]
};

/// The UMEM area itself, mapped once, and its registration: the libxdp UMEM the first socket makes, with a
/// socket of the UMEM's own bound on that first socket's queue, whose fill and completion rings every socket
/// there shares. Sockets name it in XdpConfig::shared_umem with their share. Outlives every socket bound to it.
class XdpSharedUmem
{
  public:
    /// An area of `shares` x `frames_per_share` frames of `frame_size` bytes, mapped and prefaulted.
    /// Errors: invalid_argument for a geometry XdpConfig would refuse or more than MAX_SHARES shares;
    /// not_supported off Linux; the mmap's errno.
    [[nodiscard]] static auto create(size_t frames_per_share, size_t shares, size_t frame_size = 4096)
        -> StatusValue<std::unique_ptr<XdpSharedUmem>>;

  private:
    /// Who may construct one: create() only.
    struct Key
    {
        explicit Key() = default;
    };

  public:
    /// Public for std::make_unique only: Key is private, so create() makes it.
    XdpSharedUmem(Key key, uint8_t* area, size_t size, size_t frames_per_share, size_t shares, size_t frame_size);
    ~XdpSharedUmem();
    XdpSharedUmem(XdpSharedUmem const&) = delete;
    auto operator=(XdpSharedUmem const&) -> XdpSharedUmem& = delete;
    XdpSharedUmem(XdpSharedUmem&&) = delete;
    auto operator=(XdpSharedUmem&&) -> XdpSharedUmem& = delete;

    [[nodiscard]] auto area() const noexcept -> uint8_t* { return area_; }
    [[nodiscard]] auto size() const noexcept -> size_t { return size_; }
    [[nodiscard]] auto ledger() noexcept -> XdpFrameLedger& { return ledger_; }
    [[nodiscard]] auto ledger() const noexcept -> XdpFrameLedger const& { return ledger_; }
    /// The UMEM address of `bytes` if they lie wholly within one frame of the area; else nullopt.
    [[nodiscard]] auto address_of(uint8_t const* bytes, size_t length) const noexcept -> std::optional<uint64_t>;

    /// The registration (the first socket's, kept until the last socket closes), or nullptr. Control thread.
    [[nodiscard]] auto anchor() noexcept -> detail::UmemAnchor* { return anchor_.get(); }
    [[nodiscard]] auto anchor() const noexcept -> detail::UmemAnchor const* { return anchor_.get(); }
    /// The libxdp UMEM registered on the area (nullptr before the first socket, and after the last).
    [[nodiscard]] auto registered() const noexcept -> xsk_umem*;
    /// Whether the registration binds XDP_USE_SG: the kernel binds every socket on it so.
    [[nodiscard]] auto scatter_gather() const noexcept -> bool;
    /// The first socket registered the area: `anchor` is kept until the last socket closes. Control thread.
    void set_anchor(std::unique_ptr<detail::UmemAnchor> anchor) noexcept;
    /// One more socket binds the registration. Control thread.
    void bound() noexcept { ++bound_; }
    /// A socket closed: the last to go takes the registration with it. Control thread.
    void unbound() noexcept;

  private:
    /// Whether create() takes the geometry: 1 to MAX_SHARES shares of frames XdpConfig would register.
    [[nodiscard]] static auto geometry_is_valid(size_t frames_per_share, size_t shares, size_t frame_size) noexcept -> bool;
    /// The registration deleted: every socket is closed, so the kernel holds no frame of any share.
    void release_anchor() noexcept;

    uint8_t* area_;
    size_t size_;
    XdpFrameLedger ledger_;
    std::unique_ptr<detail::UmemAnchor> anchor_;
    size_t bound_{0};
};

}  // namespace statusbar::net
