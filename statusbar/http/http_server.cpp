// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_server.hpp"

#include "statusbar/http/http_sha1.hpp"

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

[[nodiscard]] auto iequals(std::string_view a, std::string_view b) noexcept -> bool
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        auto const lower = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; };
        if (lower(a[i]) != lower(b[i])) {
            return false;
        }
    }
    return true;
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
    , discard_(limits.body_chunk)
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
        c.extra.resize(limits_.max_extra_headers);
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

auto HttpServer::add_ws_route(std::string path, WsEndpoint& endpoint) -> bool
{
    if (path.empty() || path.front() != '/') {
        return false;
    }
    for (auto const& route : ws_routes_) {
        if (route.path == path) {
            return false;
        }
    }
    // First WebSocket route: size the per-slot reassembly buffers (still
    // startup — the reactor is not running yet).
    if (!connections_.empty() && connections_.front().ws_msg.empty()) {
        for (auto& c : connections_) {
            c.ws_msg.resize(limits_.max_ws_message);
        }
    }
    ws_routes_.push_back(WsRoute{.path = std::move(path), .endpoint = &endpoint});
    return true;
}

auto HttpServer::find_ws_route(std::string_view path) const noexcept -> WsRoute const*
{
    for (auto const& route : ws_routes_) {
        if (route.path == path) {
            return &route;
        }
    }
    return nullptr;
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
    c.last_event_ns = now_ns;
    c.ws_endpoint = nullptr;
    c.ws_msg_len = 0;
    c.ws_mode = false;
    c.ws_fragmented = false;
    c.ws_closing = false;
    c.upgrade_pending = false;
    parsers_[slot].reset();
}

void HttpServer::on_readable(size_t slot, int64_t now_ns)
{
    connections_[slot].last_event_ns = now_ns;
    process(slot, now_ns);
}

void HttpServer::on_writable(size_t slot, int64_t now_ns)
{
    connections_[slot].last_event_ns = now_ns;
    if (connections_[slot].state == ConnState::sending) {
        pump_tx(slot, now_ns);
        if (!pool_.is_open(slot)) {
            return;
        }
        auto& c = connections_[slot];
        if (c.ws_mode && c.tx_sent >= c.tx_len && c.body_sent >= c.body_size) {
            ws_process(slot, now_ns);  // frames queued behind the drained frame
        } else if (c.state == ConnState::reading_head) {
            // A drained response may leave a pipelined request already
            // buffered; no readable event will come for it.
            process(slot, now_ns);
        }
    }
}

void HttpServer::on_closed(size_t slot, int64_t /*now_ns*/)
{
    auto& c = connections_[slot];
    if (c.ws_mode && c.ws_endpoint != nullptr) {
        c.ws_endpoint->on_ws_closed(slot);
    }
    c.state = ConnState::reading_head;
    c.handler = nullptr;
    c.ws_mode = false;
    c.ws_endpoint = nullptr;
}

void HttpServer::tick(int64_t now_ns)
{
    pool_.tick(now_ns);
    for (size_t slot = 0; slot < connections_.size(); ++slot) {
        if (!pool_.is_open(slot)) {
            continue;
        }
        auto& c = connections_[slot];
        c.last_event_ns = now_ns;
        if (c.ws_mode) {
            if ((now_ns - c.ws_last_rx_ns) > limits_.ws_drop_ns) {
                pool_.close(slot);
            } else if (
                (now_ns - c.ws_last_rx_ns) > limits_.ws_ping_ns && (now_ns - c.ws_last_ping_ns) > limits_.ws_ping_ns &&
                c.tx_sent >= c.tx_len && c.body_sent >= c.body_size && !c.ws_closing) {
                c.ws_last_ping_ns = now_ns;
                (void)ws_stage_frame(slot, WsOpcode::ping, {}, false, now_ns);
            }
            continue;
        }
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
    if (c.ws_mode) {
        ws_process(slot, now_ns);
        return;
    }
    while (pool_.is_open(slot)) {
        switch (c.state) {
            case ConnState::sending:
            case ConnState::awaiting_response:
                return;  // later bytes wait in the socket until this request finishes

            case ConnState::reading_body: {
                if (c.body_mode == BodyMode::buffered) {
                    auto const room = c.rx.size() - c.rx_len;
                    auto const want = size_t(std::min<uint64_t>(c.body_remaining, room));
                    auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, want});
                    if (!n) {
                        return;
                    }
                    c.rx_len += *n;
                    c.body_remaining -= *n;
                } else {
                    auto const want = size_t(std::min<uint64_t>(c.body_remaining, discard_.size()));
                    auto const n = read_some(slot, std::span<uint8_t>{discard_.data(), want});
                    if (!n) {
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
                auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
                if (!n) {
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

    // RFC 9110 §10.1.1: a client that sent "Expect: 100-continue" holds
    // the body back until it sees an interim 100 or a final status (curl
    // gives up waiting after ~1 s and sends anyway). HTTP/1.1 only — a
    // 1xx to a 1.0 client is a framing error — and moot once any body
    // byte has arrived with the head.
    bool const expects_continue =
        request.version_minor == 1 && body_len > body_in_rx && iequals(request.header("expect"), "100-continue");

    c.suppress_body = request.method == HttpMethod::head;
    c.pending_status = 0;
    c.response_staged = false;
    c.extra_len = 0;

    if (request.method == HttpMethod::get && body_len == 0) {
        if (auto const* ws_route = find_ws_route(request.path)) {
            try_upgrade(slot, request, *ws_route, now_ns);
            return;
        }
    }

    c.handler = find_route(request.method, request.path);
    if (c.handler != nullptr) {
        // A send from on_headers is refused by writer_send (the state is
        // still reading_head), so the disposition alone decides here.
        ResponseWriter writer{*this, slot};
        auto const disposition = c.handler->on_headers(request, writer);
        switch (disposition.kind()) {
            case Disposition::Kind::reject:
                c.handler = nullptr;
                c.body_mode = BodyMode::discard;
                if (body_len > limits_.max_body || expects_continue) {
                    // Draining is what keeps keep-alive framing, but only
                    // up to the buffered cap — not a rejected upload of
                    // any size, at 4 KiB per pass with no timeout. A
                    // client waiting on its Expect gets the final status
                    // now instead of a 100, and the close tells it not to
                    // send the body at all.
                    respond_status(slot, disposition.status(), true, now_ns);
                    return;
                }
                c.pending_status = disposition.status();
                break;
            case Disposition::Kind::buffer:
                if (body_len > limits_.max_body) {
                    // Buffered acceptance is capped, and like every other
                    // refusal of an over-cap body this does not drain it.
                    respond_status(slot, 413, true, now_ns);
                    return;
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

    if (expects_continue) {
        if (c.handler == nullptr) {
            // No route wants the body: the final status now, and close
            // — the same "do not send it" answer the reject path gives.
            respond_unhandled(slot, true, now_ns);
            return;
        }
        // Fixed bytes straight to the socket: tx is idle between
        // responses and the interim must not disturb the response the
        // handler will stage. A short write of 25 bytes into an idle
        // socket only happens on a dead peer.
        static constexpr std::string_view CONTINUE_100 = "HTTP/1.1 100 Continue\r\n\r\n";
        auto const n = pool_.write(
            slot,
            std::span<uint8_t const>{
                reinterpret_cast<uint8_t const*>(CONTINUE_100.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                CONTINUE_100.size()});
        if (!n || *n != CONTINUE_100.size()) {
            pool_.close(slot);
            return;
        }
    }

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
    respond_unhandled(slot, !request.keep_alive, now_ns);
}

void HttpServer::respond_unhandled(size_t slot, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto const& request = parsers_[slot].request();

    if (c.pending_status != 0) {
        respond_status(slot, c.pending_status, close_after, now_ns);
        return;
    }
    if (static_ != nullptr && (request.method == HttpMethod::get || request.method == HttpMethod::head)) {
        if (auto const* route = static_->find(request.path)) {
            serve_static(slot, *route, request, close_after, now_ns);
            return;
        }
    }
    if (path_registered(request.path)) {
        append_allow_header(slot, request.path);
        respond_status(slot, 405, close_after, now_ns);
        return;
    }
    respond_status(slot, dispatch(slot, request), close_after, now_ns);
}

void HttpServer::serve_static(size_t slot, StaticRoute const& route, HttpRequest const& request, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    char const* const connection = close_after ? "close" : "keep-alive";

    if (request.header("if-none-match") == route.etag) {
        int const n = snprintf(
            reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            c.tx.size(),
            "HTTP/1.1 304 Not Modified\r\nETag: %s\r\nConnection: %s\r\n\r\n",
            route.etag.c_str(),
            connection);
        if (!stage_head(slot, n, now_ns)) {
            return;
        }
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
    if (!stage_head(slot, n, now_ns)) {
        return;
    }
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
    // HEAD never carries a body, whatever the status (RFC 9110 §9.3.2):
    // one after a 404 would be read as the start of the next response.
    bool const with_body = !c.suppress_body;
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
    if (!stage_head(slot, head_len, now_ns)) {
        return;
    }
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
}

auto HttpServer::read_some(size_t slot, std::span<uint8_t> out) noexcept -> std::optional<size_t>
{
    auto const n = pool_.read(slot, out);
    if (n && *n > 0) {
        return *n;
    }
    // Orderly EOF, or a hard error: either way the slot is finished. An
    // error left open would keep reporting readable (level-triggered) —
    // only would-block means "come back later".
    if (!n && n.error() == net::NetError::would_block) {
        return std::nullopt;
    }
    pool_.close(slot);
    return std::nullopt;
}

auto HttpServer::stage_head(size_t slot, int head_len, int64_t now_ns) noexcept -> bool
{
    auto& c = connections_[slot];
    if (head_len >= 0 && size_t(head_len) < c.tx.size()) {
        c.tx_len = size_t(head_len);
        c.tx_sent = 0;
        return true;
    }
    // Truncated by snprintf: shipping it would send a head with no blank
    // line, followed by a body.
    fail_response(slot, now_ns);
    return false;
}

void HttpServer::fail_response(size_t slot, int64_t now_ns) noexcept
{
    auto& c = connections_[slot];
    // Fixed bytes, no formatting: this is the path for "the tx buffer
    // cannot hold what the response needs", so it must not need it either.
    static constexpr std::string_view OVERFLOW_500 =
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    c.extra_len = 0;
    c.response_staged = true;  // single-shot: a retry after this is refused
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    c.close_after_send = true;
    if (c.tx.size() < OVERFLOW_500.size()) {
        pool_.close(slot);  // a tx buffer too small even for this
        return;
    }
    std::memcpy(c.tx.data(), OVERFLOW_500.data(), OVERFLOW_500.size());
    c.tx_len = OVERFLOW_500.size();
    c.tx_sent = 0;
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
    // Only on_complete (reading_body) and an asynchronous respond()
    // (awaiting_response) may send: a send from on_headers, before the
    // body is framed, would leave handle_complete_head to clobber the
    // state machine behind it.
    bool const may_send = c.state == ConnState::reading_body || c.state == ConnState::awaiting_response;
    if (c.response_staged || !may_send || !pool_.is_open(slot)) {
        return false;
    }
    bool const was_awaiting = c.state == ConnState::awaiting_response;
    int64_t const now_ns = c.last_event_ns;
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
    if (!stage_head(slot, head_len, now_ns)) {
        return false;
    }
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
                fail_response(slot, now_ns);
                return false;
            }
            std::memcpy(c.tx.data() + c.tx_len, body.data(), body.size());
            c.tx_len += body.size();
        }
    }
    c.response_staged = true;
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
    // An asynchronous completion has no surrounding process() loop: a
    // pipelined request already in rx would otherwise wait forever. The
    // synchronous path must NOT re-enter process (its loop continues).
    if (was_awaiting && pool_.is_open(slot) && c.state == ConnState::reading_head) {
        process(slot, now_ns);
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
    if (c.upgrade_pending) {
        c.upgrade_pending = false;
        enter_ws_mode(slot, now_ns);
        return;
    }
    if (c.ws_mode) {
        return;  // frame drained; callers resume ws_process where needed
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

// ---- WebSocket engine -----------------------------------------------------

void HttpServer::try_upgrade(size_t slot, HttpRequest const& request, WsRoute const& route, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto const upgrade = request.header("upgrade");
    auto const key = request.header("sec-websocket-key");
    auto const version = request.header("sec-websocket-version");
    if (upgrade.empty()) {
        respond_status(slot, 426, !request.keep_alive, now_ns);  // plain GET on a WS path
        return;
    }
    if (!iequals(upgrade, "websocket") || key.empty() || version != "13") {
        respond_status(slot, 400, true, now_ns);
        return;
    }
    auto const accept = ws_accept_key(key);
    int const n = snprintf(
        reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        c.tx.size(),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %.*s\r\n"
        "\r\n",
        int(accept.view().size()),
        accept.view().data());
    if (!stage_head(slot, n, now_ns)) {
        return;
    }
    c.leftover_at = parsers_[slot].consumed();
    c.ws_endpoint = route.endpoint;
    c.upgrade_pending = true;
    c.close_after_send = false;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
}

void HttpServer::enter_ws_mode(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    // The endpoint sees the request before rx is compacted (its views
    // die with the compaction).
    c.ws_mode = true;
    c.ws_msg_len = 0;
    c.ws_fragmented = false;
    c.ws_closing = false;
    c.ws_last_rx_ns = now_ns;
    c.ws_last_ping_ns = now_ns;
    if (c.ws_endpoint != nullptr) {
        c.ws_endpoint->on_ws_open(slot, parsers_[slot].request());
    }
    size_t const leftover = c.rx_len > c.leftover_at ? c.rx_len - c.leftover_at : 0;
    if (leftover > 0) {
        std::memmove(c.rx.data(), c.rx.data() + c.leftover_at, leftover);
    }
    c.rx_len = leftover;
    c.leftover_at = 0;
    if (pool_.is_open(slot)) {
        ws_process(slot, now_ns);  // frames may have ridden in with the upgrade
    }
}

void HttpServer::ws_fail(size_t slot, uint16_t code, int64_t now_ns)
{
    auto& c = connections_[slot];
    uint8_t reason[2] = {uint8_t(code >> 8), uint8_t(code)};
    c.ws_closing = true;
    c.close_after_send = true;
    (void)ws_stage_frame(slot, WsOpcode::close, std::span<uint8_t const>{reason, 2}, false, now_ns);
}

auto HttpServer::ws_stage_frame(
    size_t slot, WsOpcode opcode, std::span<uint8_t const> payload, bool external, int64_t now_ns) noexcept -> bool
{
    auto& c = connections_[slot];
    if (c.tx_sent < c.tx_len || c.body_sent < c.body_size) {
        return false;  // previous frame still draining — refuse, never queue
    }
    auto const header_len = ws_write_frame_header(c.tx, opcode, true, payload.size());
    if (header_len == 0) {
        return false;
    }
    c.tx_len = header_len;
    c.tx_sent = 0;
    c.body_map = {};
    c.body_fd = -1;
    c.body_size = 0;
    c.body_sent = 0;
    if (!payload.empty()) {
        if (external) {
            c.body_map = payload;
            c.body_size = payload.size();
        } else {
            if (header_len + payload.size() > c.tx.size()) {
                return false;
            }
            std::memcpy(c.tx.data() + c.tx_len, payload.data(), payload.size());
            c.tx_len += payload.size();
        }
    }
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
    return true;
}

auto HttpServer::ws_send(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool
{
    if (slot >= connections_.size() || !pool_.is_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return false;
    }
    return ws_stage_frame(slot, is_text ? WsOpcode::text : WsOpcode::binary, payload, false, connections_[slot].last_event_ns);
}

auto HttpServer::ws_send_external(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool
{
    if (slot >= connections_.size() || !pool_.is_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return false;
    }
    return ws_stage_frame(slot, is_text ? WsOpcode::text : WsOpcode::binary, payload, true, connections_[slot].last_event_ns);
}

void HttpServer::ws_close(size_t slot, uint16_t code) noexcept
{
    if (slot >= connections_.size() || !pool_.is_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return;
    }
    ws_fail(slot, code, connections_[slot].last_event_ns);
}

void HttpServer::ws_process(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    while (pool_.is_open(slot) && c.tx_sent >= c.tx_len && c.body_sent >= c.body_size) {
        WsFrameHeader header;
        auto const parsed = ws_parse_frame_header(std::span<uint8_t const>{c.rx.data(), c.rx_len}, header);
        if (parsed == WsParse::protocol_error) {
            ws_fail(slot, 1002, now_ns);
            return;
        }
        bool need_bytes = parsed == WsParse::need_more;
        if (!need_bytes) {
            if (header.payload_len > limits_.max_ws_message || header.header_len + header.payload_len > c.rx.size()) {
                ws_fail(slot, 1009, now_ns);
                return;
            }
            need_bytes = c.rx_len < header.header_len + header.payload_len;
        }
        if (need_bytes) {
            auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
            if (!n) {
                return;  // would-block, or closed
            }
            c.rx_len += *n;
            c.ws_last_rx_ns = now_ns;
            continue;
        }
        if (!header.masked) {
            ws_fail(slot, 1002, now_ns);  // client frames must be masked
            return;
        }
        auto payload = std::span<uint8_t>{c.rx.data() + header.header_len, size_t(header.payload_len)};
        ws_unmask(payload, header.mask);
        c.ws_last_rx_ns = now_ns;

        bool close_now = false;
        switch (header.opcode) {
            case WsOpcode::ping:
                (void)ws_stage_frame(slot, WsOpcode::pong, payload, false, now_ns);
                break;
            case WsOpcode::pong:
                break;  // liveness already updated
            case WsOpcode::close: {
                if (c.ws_closing) {
                    close_now = true;  // our close was already sent
                    break;
                }
                uint16_t const code = payload.size() >= 2 ? uint16_t((uint16_t(payload[0]) << 8) | payload[1]) : uint16_t(1000);
                ws_fail(slot, code, now_ns);
                break;
            }
            case WsOpcode::text:
            case WsOpcode::binary:
                if (c.ws_fragmented) {
                    ws_fail(slot, 1002, now_ns);  // new message inside a fragment
                    return;
                }
                c.ws_msg_opcode = header.opcode;
                c.ws_msg_len = 0;
                [[fallthrough]];
            case WsOpcode::continuation: {
                if (header.opcode == WsOpcode::continuation && !c.ws_fragmented) {
                    ws_fail(slot, 1002, now_ns);  // continuation of nothing
                    return;
                }
                if (c.ws_msg_len + payload.size() > c.ws_msg.size()) {
                    ws_fail(slot, 1009, now_ns);
                    return;
                }
                std::memcpy(c.ws_msg.data() + c.ws_msg_len, payload.data(), payload.size());
                c.ws_msg_len += payload.size();
                c.ws_fragmented = !header.fin;
                break;
            }
        }

        // Consume the frame before any callback so re-entrant sends see a
        // consistent buffer.
        size_t const frame_len = header.header_len + size_t(header.payload_len);
        std::memmove(c.rx.data(), c.rx.data() + frame_len, c.rx_len - frame_len);
        c.rx_len -= frame_len;

        if (close_now) {
            pool_.close(slot);
            return;
        }
        bool const message_done = !ws_is_control(header.opcode) && header.fin;
        if (message_done && c.ws_endpoint != nullptr) {
            c.ws_endpoint->on_ws_message(
                slot, std::span<uint8_t const>{c.ws_msg.data(), c.ws_msg_len}, c.ws_msg_opcode == WsOpcode::text);
            if (!pool_.is_open(slot)) {
                return;
            }
            c.ws_msg_len = 0;
        }
    }
}

}  // namespace statusbar::http
