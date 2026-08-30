// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_server.hpp"

#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace statusbar::http {

namespace {

[[nodiscard]] auto reason_phrase(uint16_t status) noexcept -> char const*
{
    switch (status) {
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 204:
            return "No Content";
        case 304:
            return "Not Modified";
        case 400:
            return "Bad Request";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 408:
            return "Request Timeout";
        case 411:
            return "Length Required";
        case 413:
            return "Content Too Large";
        case 414:
            return "URI Too Long";
        case 418:
            return "I'm a teapot";
        case 431:
            return "Request Header Fields Too Large";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 503:
            return "Service Unavailable";
        case 505:
            return "HTTP Version Not Supported";
        default:
            return "Status";
    }
}

[[nodiscard]] auto method_name(HttpMethod method) noexcept -> char const*
{
    switch (method) {
        case HttpMethod::get:
            return "GET";
        case HttpMethod::head:
            return "HEAD";
        case HttpMethod::put:
            return "PUT";
        case HttpMethod::post:
            return "POST";
        case HttpMethod::options:
            return "OPTIONS";
    }
    return "GET";
}

}  // namespace

// ---- ResponseWriter -------------------------------------------------------

auto ResponseWriter::add_header(std::string_view name, std::string_view value) noexcept -> bool
{
    return server_->writer_add_header(slot_, name, value);
}

auto ResponseWriter::send(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool
{
    return server_->writer_send(slot_, status, content_type, body, false);
}

auto ResponseWriter::send_external(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool
{
    return server_->writer_send(slot_, status, content_type, body, true);
}

void ResponseWriter::send_status(uint16_t status) noexcept
{
    auto const* text = reason_phrase(status);
    char body[64];
    int const n = snprintf(body, sizeof body, "%u %s\n", status, text);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    (void)server_->writer_send(slot_, status, "text/plain", {reinterpret_cast<uint8_t const*>(body), size_t(n)}, false);
}

auto ResponseWriter::sent() const noexcept -> bool
{
    return server_->writer_sent(slot_);
}

// ---- HttpServer -----------------------------------------------------------

HttpServer::HttpServer(
    net::SocketAddress const& bind_addr,
    HttpLimits const& limits,
    StaticManifest const* static_manifest,
    net::TcpServerOptions tcp_options)
    : limits_{limits}
    , static_{static_manifest}
    , discard_(4096)
    , pool_{bind_addr, limits.max_connections, *this, [&] {
                // The server owns connection lifetime (408 vs silent idle
                // close differ) — the pool's blunt idle sweep stays off.
                tcp_options.idle_timeout_ns = 0;
                return tcp_options;
            }()}
{
    size_t const rx_size = limits_.max_request_line + limits_.max_header_block + limits_.max_body;
    connections_.resize(limits_.max_connections);
    parsers_.reserve(limits_.max_connections);
    for (auto& c : connections_) {
        c.rx.resize(rx_size);
        c.tx.resize(limits_.max_response_head);
        c.extra.resize(512);
        parsers_.emplace_back(limits_);
    }
}

auto HttpServer::add_route(HttpMethod method, std::string path, HttpHandler& handler) -> bool
{
    if (path.empty() || path.front() != '/') {
        return false;
    }
    for (auto const& route : routes_) {
        if (route.method == method && route.path == path) {
            return false;
        }
    }
    routes_.push_back(Route{.path = std::move(path), .method = method, .handler = &handler});
    return true;
}

auto HttpServer::find_route(HttpMethod method, std::string_view path) const noexcept -> HttpHandler*
{
    for (auto const& route : routes_) {
        if (route.method == method && route.path == path) {
            return route.handler;
        }
    }
    return nullptr;
}

auto HttpServer::path_registered(std::string_view path) const noexcept -> bool
{
    return std::any_of(routes_.begin(), routes_.end(), [&](Route const& r) { return r.path == path; });
}

void HttpServer::append_allow_header(size_t slot, std::string_view path) noexcept
{
    char allow[64];
    size_t at = 0;
    for (auto const& route : routes_) {
        if (route.path != path) {
            continue;
        }
        auto const* name = method_name(route.method);
        auto const len = strlen(name);
        if (at + len + 2 >= sizeof allow) {
            break;
        }
        if (at > 0) {
            allow[at++] = ',';
            allow[at++] = ' ';
        }
        std::copy_n(name, len, allow + at);  // length-delimited, never NUL-terminated
        at += len;
    }
    (void)writer_add_header(slot, "Allow", std::string_view{allow, at});
}

auto HttpServer::respond(size_t slot) noexcept -> std::optional<ResponseWriter>
{
    if (slot >= connections_.size() || !pool_.is_open(slot) || connections_[slot].state != ConnState::awaiting_response) {
        return std::nullopt;
    }
    return ResponseWriter{*this, slot};
}

void HttpServer::on_accept(size_t slot, net::SocketAddress const& /*peer*/, int64_t now_ns)
{
    auto& c = connections_[slot];
    c.rx_len = 0;
    c.tx_len = 0;
    c.tx_sent = 0;
    c.extra_len = 0;
    c.leftover_at = 0;
    c.body_remaining = 0;
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    c.handler = nullptr;
    c.body_mode = BodyMode::discard;
    c.pending_status = 0;
    c.state = ConnState::reading_head;
    c.close_after_send = false;
    c.suppress_body = false;
    c.response_staged = false;
    c.head_started = false;
    c.head_start_ns = 0;
    c.idle_since_ns = now_ns;
    parsers_[slot].reset();
}

void HttpServer::on_readable(size_t slot, int64_t now_ns)
{
    process(slot, now_ns);
}

void HttpServer::on_writable(size_t slot, int64_t now_ns)
{
    if (connections_[slot].state == ConnState::sending) {
        pump_tx(slot, now_ns);
        // A drained response may leave a pipelined request already
        // buffered; no readable event will come for it.
        if (pool_.is_open(slot) && connections_[slot].state == ConnState::reading_head) {
            process(slot, now_ns);
        }
    }
}

void HttpServer::on_closed(size_t slot, int64_t /*now_ns*/)
{
    connections_[slot].state = ConnState::reading_head;
    connections_[slot].handler = nullptr;
}

void HttpServer::tick(int64_t now_ns)
{
    pool_.tick(now_ns);
    for (size_t slot = 0; slot < connections_.size(); ++slot) {
        if (!pool_.is_open(slot)) {
            continue;
        }
        auto const& c = connections_[slot];
        if (c.state == ConnState::reading_head && c.head_started && (now_ns - c.head_start_ns) > limits_.header_read_timeout_ns) {
            respond_status(slot, 408, true, now_ns);
        } else if (
            c.state == ConnState::reading_head && !c.head_started && (now_ns - c.idle_since_ns) > limits_.keep_alive_idle_ns) {
            pool_.close(slot);
        }
    }
}

void HttpServer::process(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto& parser = parsers_[slot];
    while (pool_.is_open(slot)) {
        switch (c.state) {
            case ConnState::sending:
            case ConnState::awaiting_response:
                return;  // later bytes wait in the socket until this request finishes

            case ConnState::reading_body: {
                if (c.body_mode == BodyMode::buffered) {
                    auto const room = c.rx.size() - c.rx_len;
                    auto const want = size_t(std::min<uint64_t>(c.body_remaining, room));
                    auto n = pool_.read(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, want});
                    if (!n) {
                        return;
                    }
                    if (*n == 0) {
                        pool_.close(slot);
                        return;
                    }
                    c.rx_len += *n;
                    c.body_remaining -= *n;
                } else {
                    auto const want = size_t(std::min<uint64_t>(c.body_remaining, discard_.size()));
                    auto n = pool_.read(slot, std::span<uint8_t>{discard_.data(), want});
                    if (!n) {
                        return;
                    }
                    if (*n == 0) {
                        pool_.close(slot);
                        return;
                    }
                    c.body_remaining -= *n;
                    if (c.body_mode == BodyMode::streamed && c.handler != nullptr) {
                        c.handler->on_body_chunk(parser.request(), std::span<uint8_t const>{discard_.data(), *n});
                    }
                }
                if (c.body_remaining == 0) {
                    body_finished(slot, now_ns);
                }
                break;
            }

            case ConnState::reading_head: {
                auto const state = parser.parse(std::span<uint8_t const>{c.rx.data(), c.rx_len});
                if (state == ParseState::failed) {
                    respond_status(slot, parser.error_status(), true, now_ns);
                    break;
                }
                if (state == ParseState::complete) {
                    handle_complete_head(slot, now_ns);
                    break;
                }
                if (c.rx_len == c.rx.size()) {
                    respond_status(slot, 431, true, now_ns);  // defensive; parser limits are smaller
                    break;
                }
                auto n = pool_.read(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
                if (!n) {
                    return;
                }
                if (*n == 0) {
                    pool_.close(slot);
                    return;
                }
                if (!c.head_started) {
                    c.head_started = true;
                    c.head_start_ns = now_ns;
                }
                c.rx_len += *n;
                break;
            }
        }
    }
}

void HttpServer::handle_complete_head(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto& parser = parsers_[slot];
    auto const& request = parser.request();
    auto const head_len = parser.consumed();
    uint64_t const body_len = request.has_content_length ? request.content_length : 0;
    uint64_t const body_in_rx = std::min<uint64_t>(body_len, c.rx_len - head_len);

    c.handler = find_route(request.method, request.path);
    c.suppress_body = request.method == HttpMethod::head;
    c.pending_status = 0;
    c.response_staged = false;
    c.extra_len = 0;

    if (c.handler != nullptr) {
        ResponseWriter writer{*this, slot};
        auto const disposition = c.handler->on_headers(request, writer);
        switch (disposition.kind()) {
            case Disposition::Kind::reject:
                c.handler = nullptr;
                c.body_mode = BodyMode::discard;
                c.pending_status = disposition.status();
                break;
            case Disposition::Kind::buffer:
                if (body_len > limits_.max_body) {
                    c.handler = nullptr;
                    c.body_mode = BodyMode::discard;
                    c.pending_status = 413;  // buffered acceptance is capped
                    break;
                }
                c.body_mode = BodyMode::buffered;
                break;
            case Disposition::Kind::stream:
                c.body_mode = BodyMode::streamed;
                if (body_in_rx > 0) {
                    c.handler->on_body_chunk(request, std::span<uint8_t const>{c.rx.data() + head_len, size_t(body_in_rx)});
                }
                break;
        }
    } else {
        c.body_mode = BodyMode::discard;
        if (body_len > limits_.max_body) {
            respond_status(slot, 413, true, now_ns);
            return;
        }
    }

    // Buffered mode keeps body bytes in rx; the other modes have already
    // consumed what was buffered.
    c.leftover_at = c.body_mode == BodyMode::buffered ? head_len + size_t(body_len) : head_len + size_t(body_in_rx);
    c.body_remaining = body_len - body_in_rx;
    c.state = ConnState::reading_body;
    if (c.body_remaining == 0) {
        body_finished(slot, now_ns);
    }
}

void HttpServer::body_finished(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto& parser = parsers_[slot];
    auto const& request = parser.request();

    if (c.handler != nullptr) {
        if (c.body_mode == BodyMode::buffered) {
            auto const head_len = parser.consumed();
            auto const body_len = size_t(request.has_content_length ? request.content_length : 0);
            if (body_len > 0) {
                c.handler->on_body_chunk(request, std::span<uint8_t const>{c.rx.data() + head_len, body_len});
            }
        }
        ResponseWriter writer{*this, slot};
        c.handler->on_complete(request, writer);
        // A synchronous send has already moved the state on (sending, or
        // reading_head after a fast completion) — response_staged is no
        // longer meaningful here because next_request resets it. Only an
        // untouched state means the handler deferred.
        if (c.state == ConnState::reading_body) {
            c.state = ConnState::awaiting_response;  // async completion via HttpServer::respond()
        }
        return;
    }
    if (c.pending_status != 0) {
        respond_status(slot, c.pending_status, !request.keep_alive, now_ns);
        return;
    }
    if (static_ != nullptr && (request.method == HttpMethod::get || request.method == HttpMethod::head)) {
        if (auto const* route = static_->find(request.path)) {
            serve_static(slot, *route, request, now_ns);
            return;
        }
    }
    if (path_registered(request.path)) {
        append_allow_header(slot, request.path);
        respond_status(slot, 405, !request.keep_alive, now_ns);
        return;
    }
    respond_status(slot, dispatch(slot, request), !request.keep_alive, now_ns);
}

void HttpServer::serve_static(size_t slot, StaticRoute const& route, HttpRequest const& request, int64_t now_ns)
{
    auto& c = connections_[slot];
    bool const close_after = !request.keep_alive;
    char const* const connection = close_after ? "close" : "keep-alive";

    if (request.header("if-none-match") == route.etag) {
        int const n = snprintf(
            reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            c.tx.size(),
            "HTTP/1.1 304 Not Modified\r\nETag: %s\r\nConnection: %s\r\n\r\n",
            route.etag.c_str(),
            connection);
        c.tx_len = std::min(size_t(n), c.tx.size());
        c.tx_sent = 0;
        c.close_after_send = close_after;
        c.state = ConnState::sending;
        pump_tx(slot, now_ns);
        return;
    }

    char cache_line[160];
    cache_line[0] = '\0';
    if (!route.cache_control.empty()) {
        (void)snprintf(cache_line, sizeof cache_line, "Cache-Control: %s\r\n", route.cache_control.c_str());
    }
    int const n = snprintf(
        reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        c.tx.size(),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "ETag: %s\r\n"
        "Last-Modified: %s\r\n"
        "%s"
        "Connection: %s\r\n"
        "\r\n",
        route.content_type.c_str(),
        (unsigned long long)route.size,
        route.etag.c_str(),
        route.last_modified.c_str(),
        cache_line,
        connection);
    c.tx_len = std::min(size_t(n), c.tx.size());
    c.tx_sent = 0;
    if (!c.suppress_body) {
        c.body_map = route.data;
        c.body_fd = route.fd;
        c.body_size = route.size;
        c.body_sent = 0;
    }
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
}

void HttpServer::respond_status(size_t slot, uint16_t status, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    char body[64];
    int const body_len = snprintf(body, sizeof body, "%u %s\n", status, reason_phrase(status));
    bool const with_body = !c.suppress_body || status >= 400;
    int const head_len = snprintf(
        reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        c.tx.size(),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "%.*s"
        "Connection: %s\r\n"
        "\r\n%s",
        status,
        reason_phrase(status),
        body_len,
        int(c.extra_len),
        c.extra.data(),
        close_after ? "close" : "keep-alive",
        with_body ? body : "");
    c.tx_len = std::min(size_t(head_len), c.tx.size());
    c.tx_sent = 0;
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
}

auto HttpServer::writer_add_header(size_t slot, std::string_view name, std::string_view value) noexcept -> bool
{
    auto& c = connections_[slot];
    auto const need = name.size() + 2 + value.size() + 2;
    if (c.extra_len + need > c.extra.size()) {
        return false;
    }
    auto* at = c.extra.data() + c.extra_len;
    std::memcpy(at, name.data(), name.size());
    at += name.size();
    *at++ = ':';
    *at++ = ' ';
    std::memcpy(at, value.data(), value.size());
    at += value.size();
    *at++ = '\r';
    *at++ = '\n';
    c.extra_len += need;
    return true;
}

auto HttpServer::writer_send(
    size_t slot, uint16_t status, std::string_view content_type, std::span<uint8_t const> body, bool external) noexcept -> bool
{
    auto& c = connections_[slot];
    if (c.response_staged || !pool_.is_open(slot)) {
        return false;
    }
    bool const was_awaiting = c.state == ConnState::awaiting_response;
    auto const& request = parsers_[slot].request();
    bool const close_after = !request.keep_alive;
    int const head_len = snprintf(
        reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        c.tx.size(),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: %.*s\r\n"
        "Content-Length: %zu\r\n"
        "%.*s"
        "Connection: %s\r\n"
        "\r\n",
        status,
        reason_phrase(status),
        int(content_type.size()),
        content_type.data(),
        body.size(),
        int(c.extra_len),
        c.extra.data(),
        close_after ? "close" : "keep-alive");
    if (size_t(head_len) >= c.tx.size()) {
        respond_status(slot, 500, true, c.idle_since_ns);
        return false;
    }
    c.tx_len = size_t(head_len);
    c.tx_sent = 0;
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    if (!c.suppress_body && !body.empty()) {
        if (external) {
            c.body_map = body;
            c.body_size = body.size();
        } else {
            if (c.tx_len + body.size() > c.tx.size()) {
                respond_status(slot, 500, true, c.idle_since_ns);
                return false;
            }
            std::memcpy(c.tx.data() + c.tx_len, body.data(), body.size());
            c.tx_len += body.size();
        }
    }
    c.response_staged = true;
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, c.idle_since_ns);
    // An asynchronous completion has no surrounding process() loop: a
    // pipelined request already in rx would otherwise wait forever. The
    // synchronous path must NOT re-enter process (its loop continues).
    if (was_awaiting && pool_.is_open(slot) && c.state == ConnState::reading_head) {
        process(slot, c.idle_since_ns);
    }
    return true;
}

auto HttpServer::writer_sent(size_t slot) const noexcept -> bool
{
    return connections_[slot].response_staged;
}

void HttpServer::pump_tx(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    for (;;) {
        while (c.tx_sent < c.tx_len) {
            auto n = pool_.write(slot, std::span<uint8_t const>{c.tx.data() + c.tx_sent, c.tx_len - c.tx_sent});
            if (!n) {
                pool_.close(slot);
                return;
            }
            c.tx_sent += *n;
            if (*n == 0) {
                return;  // backpressured: on_writable continues
            }
        }
        if (!c.body_map.empty() && c.body_sent < c.body_size) {
            auto const remaining = c.body_map.subspan(size_t(c.body_sent));
            auto n = pool_.write(slot, remaining);
            if (!n) {
                pool_.close(slot);
                return;
            }
            c.body_sent += *n;
            if (c.body_sent < c.body_size) {
                return;  // backpressured
            }
        }
        if (c.body_fd >= 0 && c.body_sent < c.body_size) {
            auto const chunk = size_t(std::min<uint64_t>(c.body_size - c.body_sent, c.tx.size()));
            auto const n = ::pread(c.body_fd, c.tx.data(), chunk, off_t(c.body_sent));
            if (n <= 0) {
                pool_.close(slot);  // truncated behind our back
                return;
            }
            c.body_sent += uint64_t(n);
            c.tx_len = size_t(n);
            c.tx_sent = 0;
            continue;  // drain the staged chunk
        }
        break;  // everything sent
    }
    if (c.close_after_send) {
        pool_.close(slot);
        return;
    }
    next_request(slot, now_ns);
}

void HttpServer::next_request(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    size_t const leftover = c.rx_len > c.leftover_at ? c.rx_len - c.leftover_at : 0;
    if (leftover > 0) {
        std::memmove(c.rx.data(), c.rx.data() + c.leftover_at, leftover);
    }
    c.rx_len = leftover;
    c.leftover_at = 0;
    c.handler = nullptr;
    c.body_mode = BodyMode::discard;
    c.pending_status = 0;
    c.response_staged = false;
    c.suppress_body = false;
    c.extra_len = 0;
    parsers_[slot].reset();
    c.state = ConnState::reading_head;
    c.head_started = leftover > 0;
    c.head_start_ns = now_ns;
    c.idle_since_ns = now_ns;
    // No recursive process() here: when this runs inside process()'s loop
    // the loop parses the leftover on its next iteration; the on_writable
    // and async-respond paths process explicitly afterwards.
}

}  // namespace statusbar::http
