#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A whole file mapped read-only, with page-range locking: a reader may keep only a window of a large
/// file resident (mlock(2)) so that another thread reading inside the window never faults. POSIX
/// (Linux, Darwin); every call is a system call, for a non-real-time thread.

#include "statusbar/status/status.hpp"

#include <cstdint>
#include <span>

namespace statusbar::mem {

/// Advice for the kernel's read-ahead over a mapping (posix_madvise(3)).
enum class MapAdvice : uint8_t
{
    normal,
    sequential,
    random,
    will_need,
    dont_need,
};

/// A whole file mapped read-only and shared (mmap(2) PROT_READ, MAP_SHARED), with page-range locking
/// (mlock(2)/munlock(2)). Move-only; unmaps on destruction. Not thread-safe: one owner thread.
class MappedFile
{
  public:
    /// An empty mapping: bytes() is empty.
    MappedFile() noexcept = default;
    ~MappedFile();
    MappedFile(MappedFile const&) = delete;
    auto operator=(MappedFile const&) -> MappedFile& = delete;
    /// Moves the mapping; `other` is left empty.
    MappedFile(MappedFile&& other) noexcept;
    /// Unmaps this mapping, then moves `other`'s; `other` is left empty.
    auto operator=(MappedFile&& other) noexcept -> MappedFile&;

    /// Map all of open file `fd` (its size from fstat(2) at the call); the descriptor may be closed after.
    /// A zero-length file maps to an empty MappedFile. The errno (generic category) on failure.
    [[nodiscard]] static auto map(int fd) noexcept -> StatusValue<MappedFile>;
    /// Open `path` read-only (O_CLOEXEC) relative to directory `dir_fd` (AT_FDCWD: the working
    /// directory) and map it; the descriptor is closed before returning. The errno on failure.
    [[nodiscard]] static auto open(int dir_fd, char const* path) noexcept -> StatusValue<MappedFile>;

    /// The file's bytes as mapped; valid while this object holds the mapping.
    [[nodiscard]] auto bytes() const noexcept -> std::span<uint8_t const> { return {data_, size_}; }
    /// The mapped length in bytes (the file's size when mapped).
    [[nodiscard]] auto size() const noexcept -> uint64_t { return size_; }

    /// mlock the pages covering [offset, offset + length), clipped to the file, populating them so later
    /// reads do not fault. An empty or wholly clipped range succeeds; the errno on failure.
    [[nodiscard]] auto lock_range(uint64_t offset, uint64_t length) noexcept -> Status;
    /// munlock the pages covering [offset, offset + length), clipped to the file; the errno on failure.
    [[nodiscard]] auto unlock_range(uint64_t offset, uint64_t length) noexcept -> Status;
    /// Advise the kernel how the whole mapping will be read; an empty mapping succeeds.
    [[nodiscard]] auto advise(MapAdvice advice) noexcept -> Status;

    /// The page size ranges are rounded to (sysconf(_SC_PAGESIZE)).
    [[nodiscard]] static auto page_size() noexcept -> uint64_t;

  private:
    MappedFile(uint8_t const* data, uint64_t size) noexcept
        : data_{data}
        , size_{size}
    {}

    /// The page-aligned span covering [offset, offset + length) clipped to the mapping; empty when nothing is left.
    [[nodiscard]] auto page_span(uint64_t offset, uint64_t length) const noexcept -> std::span<uint8_t const>;
    /// Unmap, leaving this object empty.
    void reset() noexcept;

    uint8_t const* data_{nullptr};
    uint64_t size_{0};
};

}  // namespace statusbar::mem
