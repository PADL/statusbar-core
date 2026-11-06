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
{
    for (size_t from = 0; from < shares_; ++from) {
        for (size_t to = 0; to < shares_; ++to) {
            if (from != to) {
                returns_[(from * MAX_SHARES) + to].reset(frames_per_share_);
            }
        }
    }
}

void XdpFrameLedger::lend(uint64_t const addr) noexcept
{
    loans_[frame_of(addr)].fetch_add(1, std::memory_order_acq_rel);
}

auto XdpFrameLedger::lent(uint64_t const addr) const noexcept -> bool
{
    return (loans_[frame_of(addr)].load(std::memory_order_acquire) & ~OWNER_DONE) != 0;
}

auto XdpFrameLedger::reclaim(size_t const frame) noexcept -> bool
{
    auto& loans = loans_[frame];
    if ((loans.fetch_or(OWNER_DONE, std::memory_order_acq_rel) & ~OWNER_DONE) != 0) {
        return false;  // a transmit points into it: its completion sends it home
    }
    loans.store(0, std::memory_order_relaxed);
    return true;
}

auto XdpFrameLedger::give_back(uint64_t const addr) noexcept -> bool
{
    auto& loans = loans_[frame_of(addr)];
    if ((loans.fetch_or(OWNER_DONE, std::memory_order_acq_rel) & ~OWNER_DONE) != 0) {
        return false;  // a transmit still points into it: its completion frees it
    }
    loans.store(0, std::memory_order_relaxed);
    return true;
}

auto XdpFrameLedger::complete(uint64_t const addr, size_t const completer) noexcept -> bool
{
    auto& loans = loans_[frame_of(addr)];
    if (loans.fetch_sub(1, std::memory_order_acq_rel) != (OWNER_DONE | 1U)) {
        return false;  // the owner still holds it, or another transmit does
    }
    loans.store(0, std::memory_order_relaxed);
    return send_home(addr, completer);
}

auto XdpFrameLedger::send_home(uint64_t const addr, size_t const completer) noexcept -> bool
{
    size_t const owner = share_of(addr);
    if (owner != completer) {
        returns_[(completer * MAX_SHARES) + owner].push((addr / frame_size_) * frame_size_);
    }
    return owner == completer;
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

#if defined(__linux__) && defined(HAVE_XDP)

auto XdpSharedUmem::create(size_t const frames_per_share, size_t const shares, size_t const frame_size)
    -> StatusValue<std::unique_ptr<XdpSharedUmem>>
{
    if (!geometry_is_valid(frames_per_share, shares, frame_size)) {
        return failure(std::errc::invalid_argument);
    }
    size_t const size = frames_per_share * shares * frame_size;
    void* const area = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (area == MAP_FAILED) {
        return failure(std::error_code{errno, std::system_category()});
    }
    (void)::madvise(area, size, MADV_DONTFORK);
    return std::make_unique<XdpSharedUmem>(Key{}, static_cast<uint8_t*>(area), size, frames_per_share, shares, frame_size);
}

auto XdpSharedUmem::geometry_is_valid(size_t const frames_per_share, size_t const shares, size_t const frame_size) noexcept -> bool
{
    auto const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    return shares != 0 && shares <= XdpFrameLedger::MAX_SHARES && frames_per_share != 0 &&
        detail::umem_geometry_is_valid(frame_size, 0, page_size);
}

XdpSharedUmem::~XdpSharedUmem()
{
    if (umem_ != nullptr) {
        (void)xsk_umem__delete(umem_);
    }
    ::munmap(area_, size_);
}

#else

auto XdpSharedUmem::create(size_t /*frames_per_share*/, size_t /*shares*/, size_t /*frame_size*/)
    -> StatusValue<std::unique_ptr<XdpSharedUmem>>
{
    return failure(std::errc::not_supported);
}

XdpSharedUmem::~XdpSharedUmem() = default;

#endif

}  // namespace statusbar::net
