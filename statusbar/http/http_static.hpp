#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// StaticManifest — manifest-driven static files (docs/HTTP_PLAN.md §4).
/// A TOML file loaded once at startup maps exact URIs to filesystem
/// entries:
///
///   [[route]]
///   uri = "/"
///   file = "site/index.html"
///   type = "text/html; charset=utf-8"
///   cache = "max-age=60"        # optional Cache-Control
///   stream = true               # optional: serve by pread from a kept
///                               # fd instead of mmap
///
/// Every entry is opened at load: fstat supplies size and Last-Modified,
/// a strong ETag derives from (size, mtime), and the content is mmap-ed
/// (default — zero-copy, page-cache-backed, fd closed after mapping) or
/// kept as an open fd for pread streaming (`stream = true`, or when mmap
/// fails). A route that cannot be opened fails the whole load — a
/// control UI with missing assets is a broken deployment, not a runtime
/// 404. Reload = restart, by design.
///
/// Lookup is exact-match over a table sorted once at load: no globbing,
/// no fallback file, and no filesystem access at request time.

#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::http {

struct StaticRoute
{
    std::string uri;
    std::string file;
    std::string content_type;
    std::string cache_control;  ///< empty => no Cache-Control header
    std::string etag;           ///< strong, from (size, mtime)
    std::string last_modified;  ///< IMF-fixdate
    uint64_t size{0};

    // Exactly one body source:
    std::span<uint8_t const> data;  ///< mmap-ed content (empty when streamed)
    int fd{-1};                     ///< kept-open fd for pread (owned by the manifest)
};

class StaticManifest
{
  public:
    /// Parses @p manifest_path and opens every route. Relative `file`
    /// paths resolve against the manifest's own directory. Any failure —
    /// TOML error, missing key, duplicate uri, unopenable or unmappable
    /// file — fails the load with a Status carrying the reason.
    [[nodiscard]] static auto load(std::string const& manifest_path) -> StatusValue<StaticManifest>;

    StaticManifest(StaticManifest&& other) noexcept;
    auto operator=(StaticManifest&& other) noexcept -> StaticManifest&;
    StaticManifest(StaticManifest const&) = delete;
    auto operator=(StaticManifest const&) -> StaticManifest& = delete;
    ~StaticManifest();

    /// Exact-match lookup (binary search); nullptr when unmapped.
    [[nodiscard]] auto find(std::string_view path) const noexcept -> StaticRoute const*;

    [[nodiscard]] auto size() const noexcept -> size_t { return routes_.size(); }
    [[nodiscard]] auto routes() const noexcept -> std::span<StaticRoute const> { return routes_; }

  private:
    StaticManifest() = default;
    void release() noexcept;

    std::vector<StaticRoute> routes_;             ///< sorted by uri
    std::vector<FileDescriptor> kept_fds_;        ///< pread sources
    std::vector<std::span<uint8_t const>> maps_;  ///< munmap-ed at destruction
};

}  // namespace statusbar::http
