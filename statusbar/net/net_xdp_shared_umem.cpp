// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_xdp_shared_umem.hpp"

#include "statusbar/net/net_linux_xdp.hpp"

#if defined(__linux__) && defined(HAVE_XDP)
#    include <unistd.h>

#    include <sys/mman.h>
#    include <xdp/xsk.h>
#endif

#include <algorithm>
#include <cerrno>
#include <system_error>

namespace statusbar::net {

//
// XdpFrameLedger
//

XdpFrameLedger::XdpFrameLedger(size_t const frames_per_share, size_t const shares, size_t const frame_size)
    : frames_per_share_{std::max<size_t>(frames_per_share, 1)}
    , shares_{std::clamp<size_t>(shares, 1, MAX_SHARES)}
    , frame_size_{std::max<size_t>(frame_size, 1)}
    , loans_{std::make_unique<std::atomic<uint32_t>[]>(frames_per_share_ * shares_)}
    , lent_by_{std::make_unique<uint16_t[]>(frames_per_share_ * shares_ * MAX_SHARES)}
    , in_kernel_{std::make_unique<uint8_t[]>(frames_per_share_ * shares_)}
{
    for (size_t from = 0; from < shares_; ++from) {
        for (size_t to = 0; to < shares_; ++to) {
            if (from != to) {
                returns_[(from * MAX_SHARES) + to].reset(frames_per_share_);
            }
        }
    }
}

void XdpFrameLedger::hold(uint64_t const addr) noexcept
{
    in_kernel_[frame_of(addr)] = 0;
    loans_[frame_of(addr)].fetch_or(HOLDS, std::memory_order_release);
}

auto XdpFrameLedger::lend(uint64_t const addr, size_t const lender) noexcept -> bool
{
    auto& loans = loans_[frame_of(addr)];
    uint32_t v = loans.load(std::memory_order_acquire);
    do {
        if ((v & HOLDS) == 0) {
            return false;  // given back: the owner may have freed it already
        }
    } while (!loans.compare_exchange_weak(v, v + 1, std::memory_order_acq_rel, std::memory_order_acquire));
    ++lent_by_[lent_by_index(frame_of(addr), lender)];
    return true;
}

auto XdpFrameLedger::lent(uint64_t const addr) const noexcept -> bool
{
    return (loans_[frame_of(addr)].load(std::memory_order_acquire) & LOANS) != 0;
}

auto XdpFrameLedger::lent_by(uint64_t const addr, size_t const lender) const noexcept -> size_t
{
    return lent_by_[lent_by_index(frame_of(addr), lender)];
}

auto XdpFrameLedger::reclaim(size_t const frame) noexcept -> bool
{
    auto& loans = loans_[frame];
    uint32_t v = loans.load(std::memory_order_acquire);
    do {
        if ((v & QUEUED) != 0) {
            return false;  // another share's completion freed it: take_returns() has it
        }
    } while (!loans.compare_exchange_weak(v, v & LOANS, std::memory_order_acq_rel, std::memory_order_acquire));
    return (v & LOANS) == 0;  // else the last completion frees it
}

auto XdpFrameLedger::give_back(uint64_t const addr) noexcept -> bool
{
    return reclaim(frame_of(addr));
}

auto XdpFrameLedger::release(uint64_t const addr, uint32_t const count, size_t const completer) noexcept -> bool
{  // NOLINT(statusbar-block-statements): one atomic transition, what goes into it and what follows from it
    size_t const owner = share_of(addr);
    bool const home = owner == completer;
    auto& loans = loans_[frame_of(addr)];
    uint32_t v = loans.load(std::memory_order_acquire);
    bool last = false;
    uint32_t next = 0;
    do {
        uint32_t const remaining = (v & LOANS) - count;
        last = remaining == 0 && (v & HOLDS) == 0;
        next = last && !home ? QUEUED : (v & HOLDS) | remaining;
    } while (!loans.compare_exchange_weak(v, next, std::memory_order_acq_rel, std::memory_order_acquire));
    if (last && !home) {
        returns_[(completer * MAX_SHARES) + owner].push((addr / frame_size_) * frame_size_);
    }
    return last && home;
}

auto XdpFrameLedger::complete(uint64_t const addr, size_t const completer) noexcept -> bool
{
    auto& mine = lent_by_[lent_by_index(frame_of(addr), completer)];
    if (mine == 0) {
        return false;  // not a loan of this share's: nothing to return
    }
    --mine;
    return release(addr, 1, completer);
}

void XdpFrameLedger::forget(size_t const lender) noexcept
{
    for (size_t frame = 0; frame < frames_per_share_ * shares_; ++frame) {
        auto& mine = lent_by_[lent_by_index(frame, lender)];
        if (mine != 0) {
            uint32_t const count = mine;
            mine = 0;
            (void)release(uint64_t{frame} * frame_size_, count, lender);  // its own freed now: reopen() reclaims them
        }
    }
}

void XdpFrameLedger::to_kernel(uint64_t const addr) noexcept
{
    in_kernel_[frame_of(addr)] = 1;
    loans_[frame_of(addr)].fetch_and(~HOLDS, std::memory_order_release);
}

void XdpFrameLedger::pool_gone(size_t const share) noexcept
{
    std::fill_n(in_kernel_.get() + (share * frames_per_share_), frames_per_share_, uint8_t{0});
}

void XdpFrameLedger::Returns::reset(size_t const capacity)
{
    slots_ = std::make_unique<uint64_t[]>(capacity);
    capacity_ = capacity;
    head_.store(0, std::memory_order_relaxed);
    tail_.store(0, std::memory_order_relaxed);
}

void XdpFrameLedger::Returns::push(uint64_t const addr) noexcept
{
    // Never full: a share's frames are all its producer could free at once.
    uint64_t const tail = tail_.load(std::memory_order_relaxed);
    slots_[tail % capacity_] = addr;
    tail_.store(tail + 1, std::memory_order_release);
}

//
// XdpSharedUmem
//

XdpSharedUmem::XdpSharedUmem(
    Key /*key*/,
    uint8_t* const area,
    size_t const size,
    size_t const frames_per_share,
    size_t const shares,
    size_t const frame_size)
    : area_{area}
    , size_{size}
    , ledger_{frames_per_share, shares, frame_size}
{}

auto XdpSharedUmem::address_of(uint8_t const* const bytes, size_t const length) const noexcept -> std::optional<uint64_t>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): addresses compared, never dereferenced
    auto const at = reinterpret_cast<std::uintptr_t>(bytes);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): as above
    auto const base = reinterpret_cast<std::uintptr_t>(area_);
    if (length == 0 || at < base || at - base + length > size_) {
        return std::nullopt;
    }
    uint64_t const addr = at - base;
    size_t const frame = ledger_.frame_size();
    return addr / frame == (addr + length - 1) / frame ? std::optional{addr} : std::nullopt;
}

void XdpSharedUmem::set_anchor(std::unique_ptr<detail::UmemAnchor> anchor) noexcept
{
    anchor_ = std::move(anchor);
}

void XdpSharedUmem::unbound() noexcept
{
    if (bound_ == 0) {
        return;
    }
    --bound_;
    if (bound_ == 0) {
        release_anchor();
    }
}

#if defined(__linux__) && defined(HAVE_XDP)

auto XdpSharedUmem::create(size_t const frames_per_share, size_t const shares, size_t const frame_size)
    -> StatusValue<std::unique_ptr<XdpSharedUmem>>
{
    if (!geometry_is_valid(frames_per_share, shares, frame_size)) {
        return failure(std::errc::invalid_argument);
    }
    size_t const size = frames_per_share * shares * frame_size;
    uint8_t* const area = detail::map_umem_area(size);
    if (area == nullptr) {
        return failure(std::error_code{errno, std::system_category()});
    }
    return std::make_unique<XdpSharedUmem>(Key{}, area, size, frames_per_share, shares, frame_size);
}

auto XdpSharedUmem::geometry_is_valid(size_t const frames_per_share, size_t const shares, size_t const frame_size) noexcept -> bool
{
    auto const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    return shares != 0 && shares <= XdpFrameLedger::MAX_SHARES && frames_per_share != 0 &&
        detail::umem_geometry_is_valid(frame_size, 0, page_size);
}

auto XdpSharedUmem::registered() const noexcept -> xsk_umem*
{
    return anchor_ ? anchor_->umem : nullptr;
}

auto XdpSharedUmem::scatter_gather() const noexcept -> bool
{
    return anchor_ && anchor_->scatter_gather;
}

void XdpSharedUmem::release_anchor() noexcept
{
    if (!anchor_) {
        return;
    }
    if (anchor_->xsk != nullptr) {
        xsk_socket__delete(anchor_->xsk);
    }
    if (anchor_->umem != nullptr) {
        (void)xsk_umem__delete(anchor_->umem);
    }
    anchor_.reset();
    for (size_t share = 0; share < ledger_.shares(); ++share) {
        ledger_.pool_gone(share);  // every queue's pool went with its sockets
    }
}

XdpSharedUmem::~XdpSharedUmem()
{
    release_anchor();
    ::munmap(area_, size_);
}

#else

auto XdpSharedUmem::create(size_t /*frames_per_share*/, size_t /*shares*/, size_t /*frame_size*/)
    -> StatusValue<std::unique_ptr<XdpSharedUmem>>
{
    return failure(std::errc::not_supported);
}

auto XdpSharedUmem::registered() const noexcept -> xsk_umem*
{
    return nullptr;
}

auto XdpSharedUmem::scatter_gather() const noexcept -> bool
{
    return false;
}

void XdpSharedUmem::release_anchor() noexcept
{
    anchor_.reset();
}

XdpSharedUmem::~XdpSharedUmem() = default;

#endif

}  // namespace statusbar::net
