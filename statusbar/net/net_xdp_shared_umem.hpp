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

/// Per UMEM frame: whether its owner is done with it, and how many transmits point into it; and, per pair of
/// shares, the frames one share's completions hand back to another. Real-time safe: no allocation after
/// construction, no locks. A frame's owner is the one thread that drives its share's socket.
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

    /// A transmit now points into the frame at `addr` (any offset within it). The sending socket's thread.
    void lend(uint64_t addr) noexcept;
    /// Whether a transmit still points into the frame at `addr`: a completed address that is not lent
    /// is the sending socket's own frame. The completing socket's thread.
    [[nodiscard]] auto lent(uint64_t addr) const noexcept -> bool;
    /// The owner is done with the frame at `addr` (its receiver released it): true when no transmit
    /// points into it, so it is free now; else the last completion frees it. The owner's thread.
    [[nodiscard]] auto give_back(uint64_t addr) noexcept -> bool;
    /// A transmit pointing into the frame at `addr` completed on share `completer`'s socket: true when the
    /// frame is free now and `completer` owns it. The last loan of another share's frame done is queued for
    /// its owner (take_returns()). The completing socket's thread.
    [[nodiscard]] auto complete(uint64_t addr, size_t completer) noexcept -> bool;
    /// Share `share`'s socket opens afresh: each frame of it no transmit points into to `free`, the rest left to
    /// their completions (queued home), what the old socket was owed forgotten. Before it receives.
    template <typename Free>
    void reopen(size_t const share, Free const& free) noexcept
    {
        take_returns(share, [](uint64_t) {});  // freed below with the rest
        for (size_t frame = share * frames_per_share_; frame < (share + 1) * frames_per_share_; ++frame) {
            if (reclaim(frame)) {
                free(uint64_t{frame} * frame_size_);
            }
        }
    }
    /// Each frame another share's completions freed for `share`, oldest first, to `free` (uint64_t frame
    /// address). The owner's thread.
    template <typename Free>
    void take_returns(size_t const share, Free const& free) noexcept
    {
        for (size_t from = 0; from < shares_; ++from) {
            if (from != share) {
                returns_[(from * MAX_SHARES) + share].drain(free);
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

    static constexpr uint32_t OWNER_DONE = 0x8000'0000U;

    /// reopen() of frame `frame`: true (cleared) when no transmit points into it, else its owner marked done.
    [[nodiscard]] auto reclaim(size_t frame) noexcept -> bool;
    /// A frame free again after `completer`'s completion: true when `completer` owns it, else queued for its owner.
    [[nodiscard]] auto send_home(uint64_t addr, size_t completer) noexcept -> bool;

    [[nodiscard]] auto frame_of(uint64_t const addr) const noexcept -> size_t { return static_cast<size_t>(addr / frame_size_); }

    size_t frames_per_share_;
    size_t shares_;
    size_t frame_size_;
    std::unique_ptr<std::atomic<uint32_t>[]> loans_;        ///< per frame: OWNER_DONE, and the transmits pointing into it
    std::array<Returns, MAX_SHARES * MAX_SHARES> returns_;  ///< [from * MAX_SHARES + to]
};

/// The UMEM area itself, mapped once, and the libxdp UMEM the first socket registers on it; sockets name it
/// in XdpConfig::shared_umem with their share. Outlives every socket bound to it. Linux with AF_XDP only.
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

    /// The libxdp UMEM the first socket registered on the area (nullptr before), for the rest to share.
    [[nodiscard]] auto registered() const noexcept -> xsk_umem* { return umem_; }
    /// The headroom and TX metadata length it was registered with: every socket on it takes the same.
    [[nodiscard]] auto headroom() const noexcept -> size_t { return headroom_; }
    [[nodiscard]] auto tx_metadata_len() const noexcept -> size_t { return tx_metadata_len_; }
    /// Whether the first socket bound it with XDP_USE_SG: the kernel binds every other socket on it so.
    [[nodiscard]] auto scatter_gather() const noexcept -> bool { return scatter_gather_; }
    void set_scatter_gather(bool const on) noexcept { scatter_gather_ = on; }
    /// The first socket registered the area as `umem` with `headroom` and `tx_metadata_len`; it is deleted with
    /// this object. Control thread.
    void set_registered(xsk_umem* const umem, size_t const headroom, size_t const tx_metadata_len) noexcept
    {
        umem_ = umem;
        headroom_ = headroom;
        tx_metadata_len_ = tx_metadata_len;
    }

  private:
    /// Whether create() takes the geometry: 1 to MAX_SHARES shares of frames XdpConfig would register.
    [[nodiscard]] static auto geometry_is_valid(size_t frames_per_share, size_t shares, size_t frame_size) noexcept -> bool;

    uint8_t* area_;
    size_t size_;
    XdpFrameLedger ledger_;
    xsk_umem* umem_{nullptr};
    size_t headroom_{0};
    size_t tx_metadata_len_{0};
    bool scatter_gather_{false};
};

}  // namespace statusbar::net
