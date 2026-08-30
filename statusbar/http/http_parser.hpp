#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// HttpParser — incremental HTTP/1.1 request-head parser
/// (docs/HTTP_PLAN.md §3). A pure function of bytes: no I/O, no clock,
/// and no allocation after construction (header slots and the decoded
/// path buffer are sized once from HttpLimits), so it can be
/// torture-tested byte-split by byte-split.
///
/// Feeding model: the connection owns one rx buffer whose start is the
/// start of the current request; parse() is (re)invoked with the whole
/// buffered region as more bytes arrive, and the parser resumes from its
/// internal offset. Raw views (target, header names/values) point into
/// that caller buffer — the caller keeps its address stable and
/// append-only between reset() calls. The decoded, dot-normalized path
/// points into parser-owned storage.
///
/// Framing: Content-Length only. Inbound Transfer-Encoding is refused
/// (501), a missing length on PUT/POST is 411, and the body itself is the
/// connection engine's job — on complete, consumed() marks where it
/// starts.
///
/// Every rejection carries a specific status: 400 malformed (bad tokens,
/// obs-fold, NUL or encoded '/', traversal above root, duplicate
/// Host/Content-Length), 411 length required, 414 request line too long,
/// 431 header block too large or too many fields, 501 unknown method or
/// Transfer-Encoding, 505 unknown HTTP version.

#include "statusbar/http/http_limits.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace statusbar::http {

enum class HttpMethod : uint8_t
{
    get,
    head,
    put,
    post,
    options,
};

struct HttpHeader
{
    std::string_view name;   ///< as received (compare case-insensitively)
    std::string_view value;  ///< OWS-trimmed
};

/// The parsed request head. Raw views point into the caller's rx buffer;
/// `path` points into the parser and both live until reset().
struct HttpRequest
{
    HttpMethod method{HttpMethod::get};
    std::string_view target;   ///< raw request-target as received
    std::string_view path;     ///< percent-decoded, dot-normalized, query stripped
    std::string_view query;    ///< raw bytes after '?', empty when absent
    uint8_t version_minor{1};  ///< HTTP/1.<minor>; 0 or 1
    bool keep_alive{true};
    bool has_content_length{false};
    uint64_t content_length{0};

    std::span<HttpHeader const> headers;

    /// First case-insensitive match, empty view when absent.
    [[nodiscard]] auto header(std::string_view name) const noexcept -> std::string_view;
};

enum class ParseState : uint8_t
{
    need_more,  ///< head incomplete — feed more bytes
    complete,   ///< request() and consumed() are valid
    failed,     ///< error_status() is valid; the connection should respond and close
};

class HttpParser
{
  public:
    explicit HttpParser(HttpLimits const& limits);

    HttpParser(HttpParser const&) = delete;
    auto operator=(HttpParser const&) -> HttpParser& = delete;
    HttpParser(HttpParser&&) noexcept = default;
    auto operator=(HttpParser&&) noexcept -> HttpParser& = default;
    ~HttpParser() = default;

    /// Ready the parser for the next request (views from the previous one
    /// become invalid).
    void reset() noexcept;

    /// Parse the buffered request bytes (always the full region from the
    /// request's first byte). Idempotent on re-feed: already-parsed bytes
    /// are skipped via the internal offset.
    [[nodiscard]] auto parse(std::span<uint8_t const> buffer) noexcept -> ParseState;

    /// Bytes of @p buffer consumed by the head; the body begins here.
    /// Valid when complete.
    [[nodiscard]] auto consumed() const noexcept -> size_t { return consumed_; }

    [[nodiscard]] auto request() const noexcept -> HttpRequest const& { return request_; }

    /// The HTTP status describing the failure. Valid when failed.
    [[nodiscard]] auto error_status() const noexcept -> uint16_t { return error_status_; }

    [[nodiscard]] auto state() const noexcept -> ParseState { return state_; }

  private:
    enum class Phase : uint8_t
    {
        request_line,
        headers,
        done,
    };

    // Not [[nodiscard]]: used both as `return fail(s);` and in the
    // `return fail(s), false;` comma idiom inside bool helpers.
    auto fail(uint16_t status) noexcept -> ParseState;
    [[nodiscard]] auto parse_request_line(std::string_view line) noexcept -> bool;
    [[nodiscard]] auto parse_header_line(std::string_view line) noexcept -> bool;
    [[nodiscard]] auto finish_head() noexcept -> bool;
    [[nodiscard]] auto decode_and_normalize_path(std::string_view raw) noexcept -> bool;

    HttpLimits limits_;
    std::vector<HttpHeader> headers_;  ///< sized max_header_count at construction
    std::vector<char> path_;           ///< decoded path storage, sized max_request_line
    HttpRequest request_{};
    Phase phase_{Phase::request_line};
    ParseState state_{ParseState::need_more};
    uint16_t error_status_{0};
    size_t scanned_{0};   ///< bytes examined for a line terminator so far
    size_t consumed_{0};  ///< bytes owned by the head (line starts here)
    size_t header_count_{0};
    size_t head_bytes_after_line_{0};
    bool seen_host_{false};
    bool seen_connection_close_{false};
    bool seen_connection_keep_alive_{false};
};

}  // namespace statusbar::http
