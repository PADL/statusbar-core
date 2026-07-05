#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/colbin/colbin.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace statusbar::colbin {

/// Configuration for `Writer::create`.
struct WriterConfig
{
    /// Initial mmap region size in bytes. Rounded up to a multiple of
    /// the system page size. The file is `ftruncate`d to this size on
    /// creation and the mapping is grown when full (via
    /// `mremap(MREMAP_MAYMOVE)` on Linux, `munmap`+`mmap` elsewhere).
    /// Default 4 MiB.
    uint64_t initial_capacity_bytes{4ULL * 1024 * 1024};

    /// Hard upper bound on mmap region size. `write_row` returns
    /// `capacity_exceeded` if a grow would exceed this. Default 64 GiB.
    /// When `preallocate` is set this is the EXACT size mapped up front.
    uint64_t max_capacity_bytes{64ULL * 1024 * 1024 * 1024};

    /// Growth factor applied each time the mmap region fills. Default 2.
    /// Ignored when `preallocate` is set (the region never grows).
    uint32_t grow_factor{2};

    /// Fully pre-allocate `max_capacity_bytes` at `create` and NEVER grow:
    /// the file is `ftruncate`d to the full size, its blocks are reserved
    /// (`posix_fallocate`, best-effort), and the mapping is pre-faulted
    /// (`MAP_POPULATE` on Linux). `write_row` then returns `capacity_exceeded`
    /// once the region is full — it never calls `mremap`.
    ///
    /// Use this on real-time recording paths. A mid-run `mremap` of a large
    /// file-backed region takes the kernel's mmap_lock and can stall sibling
    /// threads (e.g. the data plane) for tens-to-hundreds of ms; pre-allocating
    /// moves that one-time cost to `create`, before streaming starts. The
    /// caller MUST size `max_capacity_bytes` for the whole run
    /// (≈ duration × row_rate × row_size, plus headroom). On a tmpfs/RAM
    /// filesystem the full size is reserved in RAM immediately, so an
    /// over-large value fails fast at `create` instead of OOM-ing mid-run.
    bool preallocate{false};
};

/// Linux-only mmap-append writer for the .colbin format.
///
/// Hot path is `write_row`: range-check, memcpy(row_size), advance cursor.
/// No syscalls per row. The mmap region is grown via `ftruncate +
/// mremap(MREMAP_MAYMOVE)` when full — this happens infrequently
/// (geometric backoff). Call `commit()` periodically to publish the
/// row count into the header so a concurrent reader (or a reader after
/// the writer crashes) sees a coherent count.
///
/// Movable, non-copyable: holds an open fd and an mmap'd address, with
/// ownership transferred (and the source disarmed) on move.
///
/// Append-mode: opening an existing file with the same schema
/// continues writing from `committed_rows`. Mismatch returns
/// `schema_row_size_mismatch` / `invalid_schema`.
class Writer
{
  public:
    [[nodiscard]] static auto create(
        std::filesystem::path const& path, std::span<ColumnSpec const> schema, WriterConfig const& cfg = {}) -> StatusValue<Writer>;

    Writer(Writer const&) = delete;
    auto operator=(Writer const&) -> Writer& = delete;
    Writer(Writer&&) noexcept;
    auto operator=(Writer&&) noexcept -> Writer&;
    ~Writer() noexcept;

    /// Append one row. `row` must have exactly `row_size()` bytes.
    /// Hot path; no syscalls in the common case.
    [[nodiscard]] auto write_row(std::span<uint8_t const> row) noexcept -> Status;

    /// Publish the current row count into the header's committed_rows
    /// field. Safe to call at any frequency; intended cadence is once
    /// per second from the writer thread.
    [[nodiscard]] auto commit() noexcept -> Status;

    /// Force-flush dirty pages to the OS (msync MS_ASYNC). Optional.
    [[nodiscard]] auto sync() noexcept -> Status;

    [[nodiscard]] auto row_size() const noexcept -> uint32_t { return row_size_; }
    [[nodiscard]] auto rows_written() const noexcept -> uint64_t { return row_count_; }
    [[nodiscard]] auto header_size() const noexcept -> uint32_t { return header_total_; }

  private:
    Writer() = default;

    [[nodiscard]] auto grow() noexcept -> Status;
    void destroy() noexcept;

    int fd_{-1};
    uint8_t* base_{nullptr};
    uint64_t mapped_size_{0};
    uint64_t cursor_{0};  ///< absolute byte offset within mapped region
    uint64_t max_capacity_{0};
    uint32_t grow_factor_{2};
    bool fixed_capacity_{false};  ///< preallocate mode: never grow, fail with capacity_exceeded
    uint32_t header_total_{0};
    uint32_t row_size_{0};
    uint64_t row_count_{0};
    std::string path_;
};

}  // namespace statusbar::colbin
