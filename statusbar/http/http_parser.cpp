// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_parser.hpp"

#include <algorithm>

namespace statusbar::http {

namespace {

[[nodiscard]] auto ascii_lower(char c) noexcept -> char
{
    return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
}

[[nodiscard]] auto iequals(std::string_view a, std::string_view b) noexcept -> bool
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return false;
        }
    }
    return true;
}

/// RFC 9110 token characters (header names, methods).
[[nodiscard]] auto is_tchar(char c) noexcept -> bool
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return true;
    }
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

[[nodiscard]] auto hex_nibble(char c) noexcept -> int
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

[[nodiscard]] auto trim_ows(std::string_view v) noexcept -> std::string_view
{
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
        v.remove_prefix(1);
    }
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) {
        v.remove_suffix(1);
    }
    return v;
}

/// Visits each comma-separated, OWS-trimmed element of a list header.
template <typename Visit>
void split_list(std::string_view value, Visit visit)
{
    size_t at = 0;
    while (at <= value.size()) {
        auto comma = value.find(',', at);
        if (comma == std::string_view::npos) {
            comma = value.size();
        }
        auto item = trim_ows(value.substr(at, comma - at));
        if (!item.empty()) {
            visit(item);
        }
        at = comma + 1;
    }
}

}  // namespace

auto HttpRequest::header(std::string_view name) const noexcept -> std::string_view
{
    for (auto const& h : headers) {
        if (iequals(h.name, name)) {
            return h.value;
        }
    }
    return {};
}

HttpParser::HttpParser(HttpLimits const& limits)
    : limits_{limits}
    , headers_(limits.max_header_count)
    , path_(limits.max_request_line)
{
    reset();
}

void HttpParser::reset() noexcept
{
    request_ = HttpRequest{};
    phase_ = Phase::request_line;
    state_ = ParseState::need_more;
    error_status_ = 0;
    scanned_ = 0;
    consumed_ = 0;
    header_count_ = 0;
    head_bytes_after_line_ = 0;
    seen_host_ = false;
    seen_connection_close_ = false;
    seen_connection_keep_alive_ = false;
}

auto HttpParser::fail(uint16_t status) noexcept -> ParseState
{
    error_status_ = status;
    state_ = ParseState::failed;
    phase_ = Phase::done;
    return state_;
}

auto HttpParser::parse(std::span<uint8_t const> buffer) noexcept -> ParseState
{
    if (state_ != ParseState::need_more) {
        return state_;
    }
    auto const* data = reinterpret_cast<char const*>(buffer.data());  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    while (phase_ != Phase::done) {
        // Find the next line terminator, resuming where the last feed
        // stopped scanning.
        size_t i = scanned_;
        while (i < buffer.size() && buffer[i] != '\n') {
            ++i;
        }
        if (i >= buffer.size()) {
            scanned_ = i;
            // Enforce limits on the still-incomplete line so an attacker
            // cannot park an endless line in the rx buffer.
            if (phase_ == Phase::request_line && (i - consumed_) > limits_.max_request_line) {
                return fail(414);
            }
            if (phase_ == Phase::headers && head_bytes_after_line_ + (i - consumed_) > limits_.max_header_block) {
                return fail(431);
            }
            return state_;
        }
        size_t end = i;
        if (end > consumed_ && buffer[end - 1] == '\r') {
            --end;
        }
        std::string_view const line{data + consumed_, end - consumed_};
        size_t const line_total = (i + 1) - consumed_;

        if (phase_ == Phase::request_line) {
            if (line_total > limits_.max_request_line) {
                return fail(414);
            }
            if (line.empty()) {
                // RFC 9112 §2.2: ignore blank line(s) before the request line.
                consumed_ = i + 1;
                scanned_ = consumed_;
                continue;
            }
            if (!parse_request_line(line)) {
                return state_;
            }
            phase_ = Phase::headers;
        } else {
            head_bytes_after_line_ += line_total;
            if (head_bytes_after_line_ > limits_.max_header_block) {
                return fail(431);
            }
            if (line.empty()) {
                if (!finish_head()) {
                    return state_;
                }
                phase_ = Phase::done;
                state_ = ParseState::complete;
            } else if (!parse_header_line(line)) {
                return state_;
            }
        }
        consumed_ = i + 1;
        scanned_ = consumed_;
    }
    return state_;
}

auto HttpParser::parse_request_line(std::string_view line) noexcept -> bool
{
    auto const sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) {
        return fail(400), false;
    }
    auto const sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos) {
        return fail(400), false;
    }
    auto const method = line.substr(0, sp1);
    auto const target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    auto const version = line.substr(sp2 + 1);

    if (method == "GET") {
        request_.method = HttpMethod::get;
    } else if (method == "HEAD") {
        request_.method = HttpMethod::head;
    } else if (method == "PUT") {
        request_.method = HttpMethod::put;
    } else if (method == "POST") {
        request_.method = HttpMethod::post;
    } else if (method == "OPTIONS") {
        request_.method = HttpMethod::options;
    } else {
        bool const token = !method.empty() && std::all_of(method.begin(), method.end(), is_tchar);
        return fail(token ? 501 : 400), false;
    }

    if (version == "HTTP/1.1") {
        request_.version_minor = 1;
    } else if (version == "HTTP/1.0") {
        request_.version_minor = 0;
    } else if (version.starts_with("HTTP/")) {
        return fail(505), false;
    } else {
        return fail(400), false;
    }

    // Origin-form only: an embedded server has no use for absolute-form,
    // authority-form, or asterisk-form targets.
    if (target.empty() || target.front() != '/') {
        return fail(400), false;
    }
    for (char const c : target) {
        if (c < 0x21 || c > 0x7E) {
            return fail(400), false;  // control bytes, space, or non-ASCII
        }
    }
    request_.target = target;
    auto const question = target.find('?');
    request_.query = question == std::string_view::npos ? std::string_view{} : target.substr(question + 1);
    return decode_and_normalize_path(target.substr(0, question));
}

auto HttpParser::decode_and_normalize_path(std::string_view raw) noexcept -> bool
{
    // Pass 1: percent-decode into path_. Encoded NUL is an attack, and an
    // encoded '/' would alter segmentation after decoding — both refused.
    size_t n = 0;
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '%') {
            if (i + 2 >= raw.size()) {
                return fail(400), false;
            }
            int const hi = hex_nibble(raw[i + 1]);
            int const lo = hex_nibble(raw[i + 2]);
            if (hi < 0 || lo < 0) {
                return fail(400), false;
            }
            c = char((hi << 4) | lo);
            if (c == '\0' || c == '/') {
                return fail(400), false;
            }
            i += 2;
        }
        path_[n++] = c;
    }

    // Pass 2: dot-segment removal (RFC 3986 §5.2.4) in place. ".." above
    // the root is a traversal attempt, not a path — refused. A trailing
    // "." or ".." keeps its directory form (trailing '/').
    std::string_view const in{path_.data(), n};
    size_t out = 0;
    size_t i = 0;
    bool trailing_slash = false;
    while (i < in.size()) {
        // in[i] == '/' by construction.
        size_t j = i + 1;
        while (j < in.size() && in[j] != '/') {
            ++j;
        }
        auto const seg = in.substr(i + 1, j - i - 1);
        if (seg.empty() || seg == ".") {
            trailing_slash = true;  // collapse "//", drop "."
        } else if (seg == "..") {
            if (out == 0) {
                return fail(400), false;
            }
            while (out > 0 && path_[out - 1] != '/') {
                --out;
            }
            --out;  // drop the '/' too
            trailing_slash = true;
        } else {
            // Shift the kept segment down over any removed bytes.
            path_[out++] = '/';
            for (size_t k = 0; k < seg.size(); ++k) {
                path_[out++] = seg[k];  // seg aliases path_ further ahead; out never overtakes it
            }
            trailing_slash = false;
        }
        i = j;
    }
    if (out == 0) {
        path_[out++] = '/';
    } else if (trailing_slash) {
        path_[out++] = '/';
    }
    request_.path = std::string_view{path_.data(), out};
    return true;
}

auto HttpParser::parse_header_line(std::string_view line) noexcept -> bool
{
    if (line.front() == ' ' || line.front() == '\t') {
        return fail(400), false;  // obs-fold is obsolete
    }
    auto const colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) {
        return fail(400), false;
    }
    auto const name = line.substr(0, colon);
    if (!std::all_of(name.begin(), name.end(), is_tchar)) {
        return fail(400), false;
    }
    auto const value = trim_ows(line.substr(colon + 1));
    for (char const c : value) {
        if ((c < 0x20 || c == 0x7F) && c != '\t') {
            return fail(400), false;
        }
    }
    if (header_count_ >= limits_.max_header_count) {
        return fail(431), false;
    }
    headers_[header_count_++] = HttpHeader{.name = name, .value = value};

    if (iequals(name, "host")) {
        if (seen_host_) {
            return fail(400), false;
        }
        seen_host_ = true;
    } else if (iequals(name, "content-length")) {
        if (request_.has_content_length || value.empty()) {
            return fail(400), false;
        }
        uint64_t length = 0;
        for (char const c : value) {
            if (c < '0' || c > '9' || length > (UINT64_MAX - 9) / 10) {
                return fail(400), false;
            }
            length = (length * 10) + uint64_t(c - '0');
        }
        request_.has_content_length = true;
        request_.content_length = length;
    } else if (iequals(name, "transfer-encoding")) {
        return fail(501), false;  // Content-Length framing only
    } else if (iequals(name, "connection")) {
        split_list(value, [&](std::string_view item) {
            if (iequals(item, "close")) {
                seen_connection_close_ = true;
            } else if (iequals(item, "keep-alive")) {
                seen_connection_keep_alive_ = true;
            }
        });
    }
    return true;
}

auto HttpParser::finish_head() noexcept -> bool
{
    if (request_.version_minor == 1 && !seen_host_) {
        return fail(400), false;
    }
    request_.keep_alive = request_.version_minor == 1 ? !seen_connection_close_ : seen_connection_keep_alive_;
    if ((request_.method == HttpMethod::put || request_.method == HttpMethod::post) && !request_.has_content_length) {
        return fail(411), false;
    }
    request_.headers = std::span<HttpHeader const>{headers_.data(), header_count_};
    return true;
}

}  // namespace statusbar::http
