// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
//
// MappedFile — a file mapped read-only (or a region of it, writable on
// request), with page-range locking.
//
// A real-time thread may read inside a mapping only where the pages are
// resident and locked; everything else here is a system call for a
// non-real-time thread. The intended shape: the control thread maps the file
// once, locks the window the real-time thread is about to read
// (lock_range()), advances the window ahead of it and unlocks behind it
// (unlock_range()), while the real-time thread reads through bytes() without
// faulting. mlockall(MCL_CURRENT) from a timer would take in the whole
// mapping; a process that uses this class turns that off
// (realtime::TimerConfig::lock_memory) and locks once at startup.
//
// The mapping is PROT_READ, MAP_SHARED: the file's bytes as the kernel has
// them, including what another process appends after the map (within the
// size at the time of the map), and nothing is copied. MapOptions maps a
// page-aligned region instead, of a regular file or of a device that maps,
// and adds PROT_WRITE on request; the pages are not populated. Every offset
// given to the methods counts from the start of the mapping, a region's and
// not the file's.

#pragma once

#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace statusbar::mem {

/// What MappedFile::map() maps: by default the whole file, read-only.
struct MapOptions
{
    /// Where the region starts in the file, in bytes; a multiple of the page size that fits off_t.
    uint64_t offset{0};
    /// The region's length in bytes; none: to the end of a regular file. A file that is
    /// not regular (a device) has no size, so it needs one, and the caller is to get it
    /// right: a read past what the device backs raises SIGBUS.
    std::optional<size_t> length{};
    /// PROT_READ | PROT_WRITE (the descriptor must be O_RDWR: O_RDONLY and O_WRONLY are refused EACCES);
    /// else PROT_READ.
    bool writable{false};
};

class MappedFile
{
  public:
    /// What the kernel is told about a range (madvise(2) on Linux,
    /// posix_madvise(3) elsewhere).
    enum class Advice : uint8_t
    {
        normal,
        sequential,
        random,
        will_need,
        dont_need,
    };

    /// Map the file open on @p fd as @p options says: by default all of it,
    /// read-only. The descriptor is not kept: the caller may close it once
    /// this returns. A zero-length region gives a valid, empty mapping.
    /// invalid_argument for an offset off a page boundary, a region past the
    /// end of a regular file, or a file that is neither regular nor given a
    /// length; otherwise errors are the errno as Status.
    [[nodiscard]] static auto map(int fd, MapOptions const& options = {}) -> StatusValue<MappedFile>;

    /// Open @p path read-only, relative to @p dir_fd (AT_FDCWD for the
    /// working directory, as openat(2)), map it, and close it. @p path must
    /// fit a PATH_MAX buffer (name_too_long otherwise).
    [[nodiscard]] static auto open(int dir_fd, std::string_view path) -> StatusValue<MappedFile>;

    /// An unmapped file: valid() is false and bytes() is empty.
    MappedFile() noexcept = default;
    ~MappedFile() noexcept { unmap(); }

    MappedFile(MappedFile&& other) noexcept
        : base_{other.base_}
        , size_{other.size_}
        , valid_{other.valid_}
        , writable_{other.writable_}
    {
        other.forget();
    }
    auto operator=(MappedFile&& other) noexcept -> MappedFile&;
    MappedFile(MappedFile const&) = delete;
    auto operator=(MappedFile const&) -> MappedFile& = delete;

    /// True once a map succeeded, an empty file included.
    [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }

    /// The mapping's bytes. Reading them is safe on a real-time thread only
    /// inside a range lock_range() has locked.
    [[nodiscard]] auto bytes() const noexcept -> std::span<uint8_t const> { return {static_cast<uint8_t const*>(base_), size_}; }

    /// The mapping's bytes to write through: empty unless it was mapped
    /// writable (MapOptions::writable). Writing to a file a disk filesystem
    /// holds is not for a real-time thread, locked or not: the first write
    /// after each writeback faults to mark the page dirty, and that may block.
    /// A device's or shared memory's mapping has no such fault.
    [[nodiscard]] auto writable_bytes() noexcept -> std::span<uint8_t>
    {
        return writable_ ? std::span<uint8_t>{static_cast<uint8_t*>(base_), size_} : std::span<uint8_t>{};
    }

    /// Whether the mapping was made writable.
    [[nodiscard]] auto writable() const noexcept -> bool { return writable_; }

    [[nodiscard]] auto size() const noexcept -> size_t { return size_; }

    /// Lock the pages covering [offset, offset + length) of the mapping,
    /// clipped to it, into memory and read them in (mlock(2) populates). Nothing to
    /// lock, because the range lies past the end or is empty, is success.
    [[nodiscard]] auto lock_range(size_t offset, size_t length) const noexcept -> Status;

    /// Unlock the pages covering the range (munlock(2)). The pages stay
    /// mapped and may be read again; they may then fault.
    [[nodiscard]] auto unlock_range(size_t offset, size_t length) const noexcept -> Status;

    /// Tell the kernel how the range will be read. On Linux this is
    /// madvise(2): posix_madvise(3) there turns dont_need into a no-op (glibc
    /// and musl answer it with 0 and no system call), where MADV_DONTNEED
    /// drops the pages from the mapping, which is the point of dont_need for
    /// a window slid over a large file. dont_need on a range still locked by
    /// lock_range() is refused (EINVAL): unlock it first.
    [[nodiscard]] auto advise(size_t offset, size_t length, Advice advice) const noexcept -> Status;

    /// The page-aligned span of the mapping that covers [offset, offset +
    /// length): from the page holding offset to the end of the page holding
    /// the last byte, clipped to the mapping. Empty when the range is empty
    /// or starts past the end. What lock_range() and unlock_range() act on.
    [[nodiscard]] auto page_span(size_t offset, size_t length) const noexcept -> std::span<uint8_t const>;

    /// The system page size.
    [[nodiscard]] static auto page_size() noexcept -> size_t;

  private:
    MappedFile(void* base, size_t size, bool writable) noexcept
        : base_{base}
        , size_{size}
        , valid_{true}
        , writable_{writable}
    {}

    /// The valid, empty mapping of a zero-length region, the descriptor's access mode checked as mmap(2) checks it
    /// (EACCES, or EBADF for O_PATH); mmap's other refusals (a pipe, a sealed memfd) are not repeated.
    [[nodiscard]] static auto empty_region(int fd, MapOptions const& options) noexcept -> StatusValue<MappedFile>;

    void unmap() noexcept;
    void forget() noexcept
    {
        base_ = nullptr;
        size_ = 0;
        valid_ = false;
        writable_ = false;
    }

    void* base_{nullptr};
    size_t size_{0};
    bool valid_{false};
    bool writable_{false};
};

}  // namespace statusbar::mem
