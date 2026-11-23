// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_engine.hpp"

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

/// The Connection header's token for a response.
[[nodiscard]] constexpr auto connection_token(bool close_after) noexcept -> char const*
{
    return close_after ? "close" : "keep-alive";
}

/// Add @p name to the comma-separated list of @p at characters in @p list.
/// @return the new length, or @p at unchanged when the name does not fit
[[nodiscard]] auto append_to_list(std::span<char> list, size_t at, std::string_view name) noexcept -> size_t
{
    if (at + name.size() + 2 >= list.size()) {
        return at;
    }
    std::string_view const separator = at > 0 ? ", " : "";
    std::copy_n(separator.data(), separator.size(), list.data() + at);
    std::copy_n(name.data(), name.size(), list.data() + at + separator.size());  // length-delimited, never NUL-terminated
    return at + separator.size() + name.size();
}

/// Copy @p text to @p at.
/// @return where the next character goes
[[nodiscard]] auto put(char* at, std::string_view text) noexcept -> char*
{
    std::memcpy(at, text.data(), text.size());
    return at + text.size();
}

/// A static route's Cache-Control header line, written into @p line: the
/// empty string when the route sets none.
[[nodiscard]] auto cache_control_line(StaticRoute const& route, std::span<char> line) noexcept -> char const*
{
    line[0] = '\0';
    if (!route.cache_control.empty()) {
        (void)snprintf(line.data(), line.size(), "Cache-Control: %s\r\n", route.cache_control.c_str());
    }
    return line.data();
}

/// The first of the subprotocols a client offered, without its padding.
[[nodiscard]] auto first_offered_subprotocol(std::string_view offered) noexcept -> std::string_view
{
    auto chosen = offered.substr(0, offered.find(','));
    while (!chosen.empty() && (chosen.front() == ' ' || chosen.front() == '\t')) {
        chosen.remove_prefix(1);
    }
    while (!chosen.empty() && (chosen.back() == ' ' || chosen.back() == '\t')) {
        chosen.remove_suffix(1);
    }
    return chosen;
}

}  // namespace

// ---- ResponseWriter -------------------------------------------------------

auto ResponseWriter::add_header(std::string_view name, std::string_view value) noexcept -> bool
{
    return engine_->writer_add_header(slot_, name, value);
}

auto ResponseWriter::send(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool
{
    return engine_->writer_send(slot_, status, content_type, body, false);
}

auto ResponseWriter::send_external(uint16_t status, std::string_view content_type, std::span<uint8_t const> body) noexcept -> bool
{
    return engine_->writer_send(slot_, status, content_type, body, true);
}

void ResponseWriter::send_status(uint16_t status) noexcept
{
    auto const* text = reason_phrase(status);
    char body[64];
    int const n = snprintf(body, sizeof body, "%u %s\n", status, text);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    (void)engine_->writer_send(slot_, status, "text/plain", {reinterpret_cast<uint8_t const*>(body), size_t(n)}, false);
}

auto ResponseWriter::sent() const noexcept -> bool
{
    return engine_->writer_sent(slot_);
}

// ---- HttpEngine::Connection ------------------------------------------------
//
// The fields of a connection that always change together, changed together.

void HttpEngine::Connection::reopen(int64_t now_ns) noexcept
{
    // Everything as constructed, with the buffers kept: a slot's storage
    // outlives the connections that pass through it.
    *this = Connection{
        .rx = std::move(rx),
        .tx = std::move(tx),
        .extra = std::move(extra),
        .idle_since_ns = now_ns,
        .last_event_ns = now_ns,
        .ws_msg = std::move(ws_msg)};
}

void HttpEngine::Connection::closed() noexcept
{
    state = ConnState::reading_head;
    handler = nullptr;
    ws_mode = false;
    ws_endpoint = nullptr;
}

void HttpEngine::Connection::begin_response(bool head_request) noexcept
{
    suppress_body = head_request;
    pending_status = 0;
    response_staged = false;
    extra_len = 0;
}

void HttpEngine::Connection::frame_body(HeadFraming const& head) noexcept
{
    // Buffered mode keeps body bytes in rx; the other modes have already
    // consumed what was buffered.
    leftover_at = body_mode == BodyMode::buffered ? head.head_len + size_t(head.body_len) : head.head_len + size_t(head.body_in_rx);
    body_remaining = head.body_len - head.body_in_rx;
    state = ConnState::reading_body;
}

void HttpEngine::Connection::took_head_bytes(size_t len, int64_t now_ns) noexcept
{
    // The header-read timeout runs from the first byte of a head.
    if (!head_started) {
        head_started = true;
        head_start_ns = now_ns;
    }
    rx_len += len;
}

void HttpEngine::Connection::took_body_into_rx(size_t len) noexcept
{
    rx_len += len;
    body_remaining -= len;
}

void HttpEngine::Connection::clear_body() noexcept
{
    body_map = {};
    body_fd = -1;
    body_size = 0;
    body_sent = 0;
}

void HttpEngine::Connection::set_body(std::span<uint8_t const> map, int fd, uint64_t size) noexcept
{
    body_map = map;
    body_fd = fd;
    body_size = size;
    body_sent = 0;
}

auto HttpEngine::Connection::reference_body(std::span<uint8_t const> bytes) noexcept -> bool
{
    body_map = bytes;
    body_size = bytes.size();
    return true;
}

auto HttpEngine::Connection::append_tx(std::span<uint8_t const> bytes) noexcept -> bool
{
    if (tx_len + bytes.size() > tx.size()) {
        return false;
    }
    std::memcpy(tx.data() + tx_len, bytes.data(), bytes.size());
    tx_len += bytes.size();
    return true;
}

void HttpEngine::Connection::stage_tx(size_t len) noexcept
{
    tx_len = len;
    tx_sent = 0;
}

void HttpEngine::Connection::stage_fixed(std::string_view bytes) noexcept
{
    std::memcpy(tx.data(), bytes.data(), bytes.size());
    stage_tx(bytes.size());
}

void HttpEngine::Connection::abandon_response() noexcept
{
    extra_len = 0;
    response_staged = true;  // single-shot: a retry after this is refused
    clear_body();
    close_after_send = true;
}

auto HttpEngine::Connection::tx_drained() const noexcept -> bool
{
    return tx_sent >= tx_len && body_sent >= body_size;
}

auto HttpEngine::Connection::may_send() const noexcept -> bool
{
    return !response_staged && (state == ConnState::reading_body || state == ConnState::awaiting_response);
}

auto HttpEngine::Connection::tx_chars() noexcept -> char*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<char*>(tx.data());
}

void HttpEngine::Connection::enter_ws(int64_t now_ns) noexcept
{
    ws_mode = true;
    ws_msg_len = 0;
    ws_fragmented = false;
    ws_closing = false;
    ws_last_rx_ns = now_ns;
    ws_last_ping_ns = now_ns;
}

auto HttpEngine::Connection::ws_payload(WsFrameHeader const& header, int64_t now_ns) noexcept -> std::span<uint8_t>
{
    auto const payload = std::span<uint8_t>{rx.data() + header.header_len, size_t(header.payload_len)};
    ws_unmask(payload, header.mask);
    ws_last_rx_ns = now_ns;
    return payload;
}

void HttpEngine::Connection::consume_rx(size_t len) noexcept
{
    std::memmove(rx.data(), rx.data() + len, rx_len - len);
    rx_len -= len;
}

// ---- HttpEngine -----------------------------------------------------------

HttpEngine::HttpEngine(HttpLimits const& limits, StaticManifest const* static_manifest)
    : limits_{limits}
    , static_{static_manifest}
    , discard_(limits.body_chunk)
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

auto HttpEngine::add_route(HttpMethod method, std::string path, HttpHandler& handler) -> bool
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

auto HttpEngine::add_ws_route(std::string path, WsEndpoint& endpoint) -> bool
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

auto HttpEngine::find_ws_route(std::string_view path) const noexcept -> WsRoute const*
{
    for (auto const& route : ws_routes_) {
        if (route.path == path) {
            return &route;
        }
    }
    return nullptr;
}

auto HttpEngine::find_route(HttpMethod method, std::string_view path) const noexcept -> HttpHandler*
{
    for (auto const& route : routes_) {
        if (route.method == method && route.path == path) {
            return route.handler;
        }
    }
    return nullptr;
}

auto HttpEngine::path_registered(std::string_view path) const noexcept -> bool
{
    return std::any_of(routes_.begin(), routes_.end(), [&](Route const& r) { return r.path == path; });
}

void HttpEngine::append_allow_header(size_t slot, std::string_view path) noexcept
{
    char allow[64];
    size_t at = 0;
    for (auto const& route : routes_) {
        if (route.path != path) {
            continue;
        }
        size_t const longer = append_to_list(allow, at, method_name(route.method));
        if (longer == at) {
            break;
        }
        at = longer;
    }
    (void)writer_add_header(slot, "Allow", std::string_view{allow, at});
}

auto HttpEngine::respond(size_t slot) noexcept -> std::optional<ResponseWriter>
{
    if (slot >= connections_.size() || !slot_open(slot) || connections_[slot].state != ConnState::awaiting_response) {
        return std::nullopt;
    }
    return ResponseWriter{*this, slot};
}

void HttpEngine::on_accept(size_t slot, net::SocketAddress const& /*peer*/, int64_t now_ns)
{
    connections_[slot].reopen(now_ns);
    parsers_[slot].reset();
    ++active_;
}

void HttpEngine::on_readable(size_t slot, int64_t now_ns)
{
    connections_[slot].last_event_ns = now_ns;
    process(slot, now_ns);
}

void HttpEngine::on_writable(size_t slot, int64_t now_ns)
{
    connections_[slot].last_event_ns = now_ns;
    if (connections_[slot].state == ConnState::sending) {
        pump_tx(slot, now_ns);
        if (!slot_open(slot)) {
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

void HttpEngine::on_closed(size_t slot, int64_t /*now_ns*/)
{
    auto& c = connections_[slot];
    if (c.ws_mode && c.ws_endpoint != nullptr) {
        c.ws_endpoint->on_ws_closed(slot);
    }
    c.closed();
    --active_;
}

void HttpEngine::tick(int64_t now_ns)
{
    for (size_t slot = 0; slot < connections_.size(); ++slot) {
        if (!slot_open(slot)) {
            continue;
        }
        auto& c = connections_[slot];
        c.last_event_ns = now_ns;
        if (c.ws_mode) {
            if ((now_ns - c.ws_last_rx_ns) > limits_.ws_drop_ns) {
                transport_->close(slot);
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
            transport_->close(slot);
        }
    }
}

void HttpEngine::process(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    if (c.ws_mode) {
        ws_process(slot, now_ns);
        return;
    }
    while (slot_open(slot)) {
        switch (c.state) {
            case ConnState::sending:
            case ConnState::awaiting_response:
                // Later bytes wait in the socket until this request finishes.
                // Without the interest off, the level-triggered multiplexer
                // would report them on every poll and spin the reactor for as
                // long as the response takes. next_request() turns it back on.
                // An upgrade that just completed is ws_process's business: it
                // has set the interest for the frames that may follow.
                if (!c.ws_mode) {
                    transport_->set_read_interest(slot, false);
                }
                return;

            case ConnState::reading_body:
                if (!read_body(slot, now_ns)) {
                    return;
                }
                break;

            case ConnState::reading_head:
                if (!read_head(slot, now_ns)) {
                    return;
                }
                break;
        }
    }
}

auto HttpEngine::read_body(size_t slot, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    bool const read = c.body_mode == BodyMode::buffered ? read_buffered_body(slot) : read_passing_body(slot);
    if (!read) {
        return false;
    }
    if (c.body_remaining == 0) {
        body_finished(slot, now_ns);
    }
    return true;
}

auto HttpEngine::read_buffered_body(size_t slot) -> bool
{
    auto& c = connections_[slot];
    auto const want = size_t(std::min<uint64_t>(c.body_remaining, c.rx.size() - c.rx_len));
    auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, want});
    if (!n) {
        return false;
    }
    c.took_body_into_rx(*n);
    return true;
}

auto HttpEngine::read_passing_body(size_t slot) -> bool
{
    auto& c = connections_[slot];
    auto const want = size_t(std::min<uint64_t>(c.body_remaining, discard_.size()));
    auto const n = read_some(slot, std::span<uint8_t>{discard_.data(), want});
    if (!n) {
        return false;
    }
    pass_body_chunk(slot, *n);
    return true;
}

void HttpEngine::pass_body_chunk(size_t slot, size_t len)
{
    auto& c = connections_[slot];
    c.body_remaining -= len;
    if (c.body_mode == BodyMode::streamed && c.handler != nullptr) {
        c.handler->on_body_chunk(parsers_[slot].request(), std::span<uint8_t const>{discard_.data(), len});
    }
}

auto HttpEngine::read_head(size_t slot, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    auto& parser = parsers_[slot];
    auto const state = parser.parse(std::span<uint8_t const>{c.rx.data(), c.rx_len});
    if (state == ParseState::failed) {
        respond_status(slot, parser.error_status(), true, now_ns);
        return true;
    }
    if (state == ParseState::complete) {
        handle_complete_head(slot, now_ns);
        return true;
    }
    return read_more_head(slot, now_ns);
}

auto HttpEngine::read_more_head(size_t slot, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    if (c.rx_len == c.rx.size()) {
        respond_status(slot, 431, true, now_ns);  // defensive; parser limits are smaller
        return true;
    }
    auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
    if (!n) {
        return false;
    }
    c.took_head_bytes(*n, now_ns);
    return true;
}

auto HttpEngine::head_framing(HttpRequest const& request, size_t head_len, size_t rx_len) noexcept -> HeadFraming
{
    uint64_t const body_len = request.has_content_length ? request.content_length : 0;
    uint64_t const body_in_rx = std::min<uint64_t>(body_len, rx_len - head_len);
    // RFC 9110 §10.1.1: a client that sent "Expect: 100-continue" holds
    // the body back until it sees an interim 100 or a final status (curl
    // gives up waiting after ~1 s and sends anyway). HTTP/1.1 only — a
    // 1xx to a 1.0 client is a framing error — and moot once any body
    // byte has arrived with the head.
    bool const expects_continue =
        request.version_minor == 1 && body_len > body_in_rx && iequals(request.header("expect"), "100-continue");
    return {.head_len = head_len, .body_len = body_len, .body_in_rx = body_in_rx, .expects_continue = expects_continue};
}

void HttpEngine::handle_complete_head(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    auto const& request = parsers_[slot].request();
    HeadFraming const head = head_framing(request, parsers_[slot].consumed(), c.rx_len);
    c.begin_response(request.method == HttpMethod::head);
    if (upgrade_if_websocket(slot, head, now_ns) || !choose_body_mode(slot, head, now_ns)) {
        return;  // answered already
    }
    finish_head(slot, head, now_ns);
}

auto HttpEngine::upgrade_if_websocket(size_t slot, HeadFraming const& head, int64_t now_ns) -> bool
{
    auto const& request = parsers_[slot].request();
    if (request.method != HttpMethod::get || head.body_len != 0) {
        return false;
    }
    auto const* ws_route = find_ws_route(request.path);
    if (ws_route == nullptr) {
        return false;
    }
    try_upgrade(slot, request, *ws_route, now_ns);
    return true;
}

auto HttpEngine::choose_body_mode(size_t slot, HeadFraming const& head, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    auto const& request = parsers_[slot].request();
    c.handler = find_route(request.method, request.path);
    if (c.handler != nullptr) {
        return ask_handler(slot, head, now_ns);
    }
    c.body_mode = BodyMode::discard;
    return !refuse_oversize_body(slot, head, now_ns);
}

auto HttpEngine::refuse_oversize_body(size_t slot, HeadFraming const& head, int64_t now_ns) -> bool
{
    if (head.body_len <= limits_.max_body) {
        return false;
    }
    respond_status(slot, 413, true, now_ns);
    return true;
}

auto HttpEngine::ask_handler(size_t slot, HeadFraming const& head, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    // A send from on_headers is refused by writer_send (the state is
    // still reading_head), so the disposition alone decides here.
    ResponseWriter writer{*this, slot};
    auto const disposition = c.handler->on_headers(parsers_[slot].request(), writer);
    switch (disposition.kind()) {
        case Disposition::Kind::reject:
            return reject_body(slot, disposition.status(), head, now_ns);
        case Disposition::Kind::buffer:
            return buffer_body(slot, head, now_ns);
        case Disposition::Kind::stream:
            stream_body(slot, head);
            return true;
    }
    return true;
}

auto HttpEngine::reject_body(size_t slot, uint16_t status, HeadFraming const& head, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    c.handler = nullptr;
    c.body_mode = BodyMode::discard;
    if (head.body_len > limits_.max_body || head.expects_continue) {
        // Draining is what keeps keep-alive framing, but only
        // up to the buffered cap — not a rejected upload of
        // any size, at 4 KiB per pass with no timeout. A
        // client waiting on its Expect gets the final status
        // now instead of a 100, and the close tells it not to
        // send the body at all.
        respond_status(slot, status, true, now_ns);
        return false;
    }
    c.pending_status = status;
    return true;
}

auto HttpEngine::buffer_body(size_t slot, HeadFraming const& head, int64_t now_ns) -> bool
{
    // Buffered acceptance is capped, and like every other refusal of an
    // over-cap body this does not drain it.
    if (refuse_oversize_body(slot, head, now_ns)) {
        return false;
    }
    connections_[slot].body_mode = BodyMode::buffered;
    return true;
}

void HttpEngine::stream_body(size_t slot, HeadFraming const& head)
{
    auto& c = connections_[slot];
    c.body_mode = BodyMode::streamed;
    if (head.body_in_rx > 0) {
        c.handler->on_body_chunk(
            parsers_[slot].request(), std::span<uint8_t const>{c.rx.data() + head.head_len, size_t(head.body_in_rx)});
    }
}

void HttpEngine::finish_head(size_t slot, HeadFraming const& head, int64_t now_ns)
{
    auto& c = connections_[slot];
    c.frame_body(head);
    if (head.expects_continue && !answer_expect_continue(slot, now_ns)) {
        return;
    }
    if (c.body_remaining == 0) {
        body_finished(slot, now_ns);
    }
}

auto HttpEngine::answer_expect_continue(size_t slot, int64_t now_ns) -> bool
{
    if (connections_[slot].handler == nullptr) {
        // No route wants the body: the final status now, and close
        // — the same "do not send it" answer the reject path gives.
        respond_unhandled(slot, true, now_ns);
        return false;
    }
    // Fixed bytes straight to the socket: tx is idle between
    // responses and the interim must not disturb the response the
    // handler will stage. A short write of 25 bytes into an idle
    // socket only happens on a dead peer.
    static constexpr std::string_view CONTINUE_100 = "HTTP/1.1 100 Continue\r\n\r\n";
    auto const n = transport_->write(
        slot,
        std::span<uint8_t const>{
            reinterpret_cast<uint8_t const*>(CONTINUE_100.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            CONTINUE_100.size()});
    if (!n || *n != CONTINUE_100.size()) {
        transport_->close(slot);
        return false;
    }
    return true;
}

void HttpEngine::body_finished(size_t slot, int64_t now_ns)
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
            c.state = ConnState::awaiting_response;  // async completion via HttpEngine::respond()
        }
        return;
    }
    respond_unhandled(slot, !request.keep_alive, now_ns);
}

void HttpEngine::respond_unhandled(size_t slot, bool close_after, int64_t now_ns)
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

void HttpEngine::serve_static(size_t slot, StaticRoute const& route, HttpRequest const& request, bool close_after, int64_t now_ns)
{
    if (request.header("if-none-match") == route.etag) {
        serve_not_modified(slot, route, close_after, now_ns);
        return;
    }
    serve_found(slot, route, close_after, now_ns);
}

void HttpEngine::serve_not_modified(size_t slot, StaticRoute const& route, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    int const n = snprintf(
        c.tx_chars(),
        c.tx.size(),
        "HTTP/1.1 304 Not Modified\r\nETag: %s\r\nConnection: %s\r\n\r\n",
        route.etag.c_str(),
        connection_token(close_after));
    if (stage_head(slot, n, now_ns)) {
        start_sending(slot, close_after, now_ns);
    }
}

void HttpEngine::serve_found(size_t slot, StaticRoute const& route, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    char cache_line[160];
    int const n = snprintf(
        c.tx_chars(),
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
        cache_control_line(route, cache_line),
        connection_token(close_after));
    if (!stage_head(slot, n, now_ns)) {
        return;
    }
    if (!c.suppress_body) {
        c.set_body(route.data, route.fd, route.size);
    }
    start_sending(slot, close_after, now_ns);
}

void HttpEngine::respond_status(size_t slot, uint16_t status, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    char body[64];
    int const body_len = snprintf(body, sizeof body, "%u %s\n", status, reason_phrase(status));
    // HEAD never carries a body, whatever the status (RFC 9110 §9.3.2):
    // one after a 404 would be read as the start of the next response.
    int const head_len = snprintf(
        c.tx_chars(),
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
        connection_token(close_after),
        c.suppress_body ? "" : body);
    if (stage_head(slot, head_len, now_ns)) {
        c.clear_body();
        start_sending(slot, close_after, now_ns);
    }
}

void HttpEngine::send_staged(size_t slot, int64_t now_ns)
{
    connections_[slot].state = ConnState::sending;
    pump_tx(slot, now_ns);
}

void HttpEngine::start_sending(size_t slot, bool close_after, int64_t now_ns)
{
    connections_[slot].close_after_send = close_after;
    send_staged(slot, now_ns);
}

auto HttpEngine::read_some(size_t slot, std::span<uint8_t> out) noexcept -> std::optional<size_t>
{
    auto const n = transport_->read(slot, out);
    if (n && *n > 0) {
        return *n;
    }
    // Orderly EOF, or a hard error: either way the slot is finished. An
    // error left open would keep reporting readable (level-triggered) —
    // only would-block means "come back later".
    if (!n && n.error() == net::NetError::would_block) {
        return std::nullopt;
    }
    transport_->close(slot);
    return std::nullopt;
}

auto HttpEngine::stage_head(size_t slot, int head_len, int64_t now_ns) noexcept -> bool
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

void HttpEngine::fail_response(size_t slot, int64_t now_ns) noexcept
{
    auto& c = connections_[slot];
    // Fixed bytes, no formatting: this is the path for "the tx buffer
    // cannot hold what the response needs", so it must not need it either.
    static constexpr std::string_view OVERFLOW_500 =
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    c.abandon_response();
    if (c.tx.size() < OVERFLOW_500.size()) {
        transport_->close(slot);  // a tx buffer too small even for this
        return;
    }
    c.stage_fixed(OVERFLOW_500);
    start_sending(slot, true, now_ns);
}

auto HttpEngine::refuse_response(size_t slot) noexcept -> bool
{
    fail_response(slot, connections_[slot].last_event_ns);
    return false;
}

auto HttpEngine::writer_add_header(size_t slot, std::string_view name, std::string_view value) noexcept -> bool
{
    auto& c = connections_[slot];
    auto const need = name.size() + 2 + value.size() + 2;
    if (c.extra_len + need > c.extra.size()) {
        return false;
    }
    (void)put(put(put(put(c.extra.data() + c.extra_len, name), ": "), value), "\r\n");
    c.extra_len += need;
    return true;
}

auto HttpEngine::writer_send(
    size_t slot, uint16_t status, std::string_view content_type, std::span<uint8_t const> body, bool external) noexcept -> bool
{
    auto& c = connections_[slot];
    // Only on_complete (reading_body) and an asynchronous respond()
    // (awaiting_response) may send: a send from on_headers, before the
    // body is framed, would leave handle_complete_head to clobber the
    // state machine behind it.
    if (!c.may_send() || !slot_open(slot)) {
        return false;
    }
    bool const was_awaiting = c.state == ConnState::awaiting_response;
    if (!send_response(slot, status, content_type, body, external)) {
        return false;
    }
    // An asynchronous completion has no surrounding process() loop: a
    // pipelined request already in rx would otherwise wait forever. The
    // synchronous path must NOT re-enter process (its loop continues).
    if (was_awaiting && slot_open(slot) && c.state == ConnState::reading_head) {
        process(slot, c.last_event_ns);
    }
    return true;
}

auto HttpEngine::send_response(
    size_t slot, uint16_t status, std::string_view content_type, std::span<uint8_t const> body, bool external) noexcept -> bool
{
    auto& c = connections_[slot];
    bool const close_after = !parsers_[slot].request().keep_alive;
    if (!stage_response_head(slot, status, content_type, body.size(), close_after) || !stage_response_body(slot, body, external)) {
        return false;
    }
    c.response_staged = true;
    start_sending(slot, close_after, c.last_event_ns);
    return true;
}

auto HttpEngine::stage_response_head(
    size_t slot, uint16_t status, std::string_view content_type, size_t body_size, bool close_after) noexcept -> bool
{
    auto& c = connections_[slot];
    int const head_len = snprintf(
        c.tx_chars(),
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
        body_size,
        int(c.extra_len),
        c.extra.data(),
        connection_token(close_after));
    return stage_head(slot, head_len, c.last_event_ns);
}

auto HttpEngine::stage_response_body(size_t slot, std::span<uint8_t const> body, bool external) noexcept -> bool
{
    auto& c = connections_[slot];
    c.clear_body();
    if (c.suppress_body || body.empty()) {
        return true;
    }
    if (external) {
        return c.reference_body(body);
    }
    return c.append_tx(body) || refuse_response(slot);
}

auto HttpEngine::writer_sent(size_t slot) const noexcept -> bool
{
    return connections_[slot].response_staged;
}

void HttpEngine::pump_tx(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    for (;;) {
        while (c.tx_sent < c.tx_len) {
            auto n = transport_->write(slot, std::span<uint8_t const>{c.tx.data() + c.tx_sent, c.tx_len - c.tx_sent});
            if (!n) {
                transport_->close(slot);
                return;
            }
            c.tx_sent += *n;
            if (*n == 0) {
                return;  // backpressured: on_writable continues
            }
        }
        if (!c.body_map.empty() && c.body_sent < c.body_size) {
            auto const remaining = c.body_map.subspan(size_t(c.body_sent));
            auto n = transport_->write(slot, remaining);
            if (!n) {
                transport_->close(slot);
                return;
            }
            c.body_sent += *n;
            if (c.body_sent < c.body_size) {
                return;  // backpressured
            }
        }
        if (c.body_fd >= 0 && c.body_sent < c.body_size) {
            if (!stage_file_chunk(slot)) {
                return;
            }
            continue;  // drain the staged chunk
        }
        break;  // everything sent
    }
    if (c.close_after_send) {
        transport_->close(slot);
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

auto HttpEngine::stage_file_chunk(size_t slot) -> bool
{
    auto& c = connections_[slot];
    auto const n =
        ::pread(c.body_fd, c.tx.data(), size_t(std::min<uint64_t>(c.body_size - c.body_sent, c.tx.size())), off_t(c.body_sent));
    if (n <= 0) {
        transport_->close(slot);  // truncated behind our back
        return false;
    }
    c.body_sent += uint64_t(n);
    c.stage_tx(size_t(n));
    return true;
}

void HttpEngine::next_request(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    size_t const leftover = compact_leftover(c);
    reset_request_state(c);
    begin_reading_head(slot, c, leftover, now_ns);
    // No recursive process() here: when this runs inside process()'s loop
    // the loop parses the leftover on its next iteration; the on_writable
    // and async-respond paths process explicitly afterwards.
}

auto HttpEngine::compact_leftover(Connection& c) -> size_t
{
    size_t const leftover = c.rx_len > c.leftover_at ? c.rx_len - c.leftover_at : 0;
    if (leftover > 0) {
        std::memmove(c.rx.data(), c.rx.data() + c.leftover_at, leftover);
    }
    c.rx_len = leftover;
    c.leftover_at = 0;
    return leftover;
}

void HttpEngine::reset_request_state(Connection& c)
{
    c.handler = nullptr;
    c.body_mode = BodyMode::discard;
    c.pending_status = 0;
    c.response_staged = false;
    c.suppress_body = false;
    c.extra_len = 0;
}

void HttpEngine::begin_reading_head(size_t slot, Connection& c, size_t leftover, int64_t now_ns)
{
    parsers_[slot].reset();
    c.state = ConnState::reading_head;
    c.head_started = leftover > 0;
    c.head_start_ns = now_ns;
    c.idle_since_ns = now_ns;
    transport_->set_read_interest(slot, true);  // bytes that waited out the response may come in now
}

// ---- WebSocket engine -----------------------------------------------------

void HttpEngine::try_upgrade(size_t slot, HttpRequest const& request, WsRoute const& route, int64_t now_ns)
{
    auto const upgrade = request.header("upgrade");
    if (upgrade.empty()) {
        respond_status(slot, 426, !request.keep_alive, now_ns);  // plain GET on a WS path
        return;
    }
    bool const valid = iequals(upgrade, "websocket") && !request.header("sec-websocket-key").empty() &&
        request.header("sec-websocket-version") == "13";
    if (!valid) {
        respond_status(slot, 400, true, now_ns);
        return;
    }
    if (stage_switching_protocols(slot, request, now_ns)) {
        begin_upgrade(slot, route, now_ns);
    }
}

auto HttpEngine::stage_switching_protocols(size_t slot, HttpRequest const& request, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    auto const accept = ws_accept_key(request.header("sec-websocket-key"));
    // RFC 6455 §4.2.2: when the client offers subprotocols the server
    // must select one, or the client MUST fail the connection — Chrome
    // enforces this and closes the socket right after the 101. The
    // endpoints here don't dispatch on subprotocol, so select the
    // client's first offer.
    auto const chosen = first_offered_subprotocol(request.header("sec-websocket-protocol"));
    int const n = snprintf(
        c.tx_chars(),
        c.tx.size(),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %.*s\r\n"
        "%s%.*s%s"
        "\r\n",
        int(accept.view().size()),
        accept.view().data(),
        chosen.empty() ? "" : "Sec-WebSocket-Protocol: ",
        int(chosen.size()),
        chosen.data(),
        chosen.empty() ? "" : "\r\n");
    return stage_head(slot, n, now_ns);
}

void HttpEngine::begin_upgrade(size_t slot, WsRoute const& route, int64_t now_ns)
{
    auto& c = connections_[slot];
    c.leftover_at = parsers_[slot].consumed();
    c.ws_endpoint = route.endpoint;
    c.upgrade_pending = true;
    start_sending(slot, false, now_ns);
}

void HttpEngine::enter_ws_mode(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    c.enter_ws(now_ns);
    // The endpoint sees the request before rx is compacted (its views
    // die with the compaction).
    if (c.ws_endpoint != nullptr) {
        c.ws_endpoint->on_ws_open(slot, parsers_[slot].request());
    }
    (void)compact_leftover(c);
    if (slot_open(slot)) {
        ws_process(slot, now_ns);  // frames may have ridden in with the upgrade
    }
}

void HttpEngine::ws_fail(size_t slot, uint16_t code, int64_t now_ns)
{
    auto& c = connections_[slot];
    uint8_t reason[2] = {uint8_t(code >> 8), uint8_t(code)};
    c.ws_closing = true;
    c.close_after_send = true;
    (void)ws_stage_frame(slot, WsOpcode::close, std::span<uint8_t const>{reason, 2}, false, now_ns);
}

auto HttpEngine::ws_stage_frame(
    size_t slot, WsOpcode opcode, std::span<uint8_t const> payload, bool external, int64_t now_ns) noexcept -> bool
{
    auto& c = connections_[slot];
    // A previous frame still draining: refuse, never queue.
    if (!c.tx_drained() || !ws_stage_frame_bytes(c, opcode, payload, external)) {
        return false;
    }
    send_staged(slot, now_ns);
    return true;
}

auto HttpEngine::ws_stage_frame_bytes(Connection& c, WsOpcode opcode, std::span<uint8_t const> payload, bool external) noexcept
    -> bool
{
    auto const header_len = ws_write_frame_header(c.tx, opcode, true, payload.size());
    // A copied payload goes behind the header in tx. One that does not fit
    // is refused before anything is staged: a header left staged with no
    // frame to follow would make the connection look busy for good, and it
    // would neither send nor read again.
    if (header_len == 0 || (!external && header_len + payload.size() > c.tx.size())) {
        return false;
    }
    c.stage_tx(header_len);
    c.clear_body();
    if (payload.empty()) {
        return true;
    }
    return external ? c.reference_body(payload) : c.append_tx(payload);
}

auto HttpEngine::ws_send(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool
{
    if (slot >= connections_.size() || !slot_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return false;
    }
    return ws_stage_frame(slot, is_text ? WsOpcode::text : WsOpcode::binary, payload, false, connections_[slot].last_event_ns);
}

auto HttpEngine::ws_send_external(size_t slot, std::span<uint8_t const> payload, bool is_text) noexcept -> bool
{
    if (slot >= connections_.size() || !slot_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return false;
    }
    return ws_stage_frame(slot, is_text ? WsOpcode::text : WsOpcode::binary, payload, true, connections_[slot].last_event_ns);
}

void HttpEngine::ws_close(size_t slot, uint16_t code) noexcept
{
    if (slot >= connections_.size() || !slot_open(slot) || !connections_[slot].ws_mode || connections_[slot].ws_closing) {
        return;
    }
    ws_fail(slot, code, connections_[slot].last_event_ns);
}

void HttpEngine::ws_process(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    ws_read_frames(slot, now_ns);
    // Frames are read only while the previous one's reply has drained; in
    // between, the bytes wait in the socket and must not re-wake the poll.
    if (slot_open(slot)) {
        transport_->set_read_interest(slot, c.tx_sent >= c.tx_len && c.body_sent >= c.body_size);
    }
}

void HttpEngine::ws_read_frames(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    bool more = true;
    while (more && slot_open(slot) && c.tx_drained()) {
        more = ws_read_step(slot, now_ns);
    }
}

auto HttpEngine::ws_read_step(size_t slot, int64_t now_ns) -> bool
{
    WsFrameHeader header;
    switch (ws_frame_ready(slot, header, now_ns)) {
        case FrameReady::failed:
            return false;
        case FrameReady::need_bytes:
            return ws_read_more(slot, now_ns);
        case FrameReady::ready:
            return ws_handle_frame(slot, header, now_ns);
    }
    return false;
}

auto HttpEngine::ws_frame_ready(size_t slot, WsFrameHeader& header, int64_t now_ns) -> FrameReady
{
    auto& c = connections_[slot];
    auto const parsed = ws_parse_frame_header(std::span<uint8_t const>{c.rx.data(), c.rx_len}, header);
    if (parsed == WsParse::protocol_error) {
        ws_fail(slot, 1002, now_ns);
        return FrameReady::failed;
    }
    if (parsed == WsParse::need_more) {
        return FrameReady::need_bytes;
    }
    if (header.payload_len > limits_.max_ws_message || header.header_len + header.payload_len > c.rx.size()) {
        ws_fail(slot, 1009, now_ns);
        return FrameReady::failed;
    }
    return c.rx_len < header.header_len + header.payload_len ? FrameReady::need_bytes : FrameReady::ready;
}

auto HttpEngine::ws_read_more(size_t slot, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    auto const n = read_some(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
    if (!n) {
        return false;  // would-block, or closed
    }
    c.rx_len += *n;
    c.ws_last_rx_ns = now_ns;
    return true;
}

auto HttpEngine::ws_handle_frame(size_t slot, WsFrameHeader const& header, int64_t now_ns) -> bool
{
    auto& c = connections_[slot];
    if (!header.masked) {
        ws_fail(slot, 1002, now_ns);  // client frames must be masked
        return false;
    }
    FrameOutcome const outcome = ws_apply_frame(slot, header, c.ws_payload(header, now_ns), now_ns);
    if (outcome == FrameOutcome::failed) {
        return false;
    }
    // Consume the frame before any callback so re-entrant sends see a
    // consistent buffer.
    c.consume_rx(header.header_len + size_t(header.payload_len));
    return ws_finish_frame(slot, header, outcome);
}

auto HttpEngine::ws_apply_frame(size_t slot, WsFrameHeader const& header, std::span<uint8_t const> payload, int64_t now_ns)
    -> FrameOutcome
{
    switch (header.opcode) {
        case WsOpcode::ping:
            (void)ws_stage_frame(slot, WsOpcode::pong, payload, false, now_ns);
            return FrameOutcome::handled;
        case WsOpcode::pong:
            return FrameOutcome::handled;  // liveness already updated
        case WsOpcode::close:
            return ws_peer_closes(slot, payload, now_ns);
        case WsOpcode::text:
        case WsOpcode::binary:
            return ws_begin_message(slot, header, payload, now_ns);
        case WsOpcode::continuation:
            return ws_continue_message(slot, header, payload, now_ns);
    }
    return FrameOutcome::handled;
}

auto HttpEngine::ws_peer_closes(size_t slot, std::span<uint8_t const> payload, int64_t now_ns) -> FrameOutcome
{
    if (connections_[slot].ws_closing) {
        return FrameOutcome::close_now;  // our close was already sent
    }
    uint16_t const code = payload.size() >= 2 ? uint16_t((uint16_t(payload[0]) << 8) | payload[1]) : uint16_t(1000);
    ws_fail(slot, code, now_ns);
    return FrameOutcome::handled;
}

auto HttpEngine::ws_begin_message(size_t slot, WsFrameHeader const& header, std::span<uint8_t const> payload, int64_t now_ns)
    -> FrameOutcome
{
    auto& c = connections_[slot];
    if (c.ws_fragmented) {
        ws_fail(slot, 1002, now_ns);  // new message inside a fragment
        return FrameOutcome::failed;
    }
    c.ws_msg_opcode = header.opcode;
    c.ws_msg_len = 0;
    return ws_append_message(slot, header, payload, now_ns);
}

auto HttpEngine::ws_continue_message(size_t slot, WsFrameHeader const& header, std::span<uint8_t const> payload, int64_t now_ns)
    -> FrameOutcome
{
    if (!connections_[slot].ws_fragmented) {
        ws_fail(slot, 1002, now_ns);  // continuation of nothing
        return FrameOutcome::failed;
    }
    return ws_append_message(slot, header, payload, now_ns);
}

auto HttpEngine::ws_append_message(size_t slot, WsFrameHeader const& header, std::span<uint8_t const> payload, int64_t now_ns)
    -> FrameOutcome
{
    auto& c = connections_[slot];
    if (c.ws_msg_len + payload.size() > c.ws_msg.size()) {
        ws_fail(slot, 1009, now_ns);
        return FrameOutcome::failed;
    }
    std::memcpy(c.ws_msg.data() + c.ws_msg_len, payload.data(), payload.size());
    c.ws_msg_len += payload.size();
    c.ws_fragmented = !header.fin;
    return FrameOutcome::handled;
}

auto HttpEngine::ws_finish_frame(size_t slot, WsFrameHeader const& header, FrameOutcome outcome) -> bool
{
    auto& c = connections_[slot];
    if (outcome == FrameOutcome::close_now) {
        transport_->close(slot);
        return false;
    }
    bool const message_done = !ws_is_control(header.opcode) && header.fin;
    if (!message_done || c.ws_endpoint == nullptr) {
        return true;
    }
    return ws_deliver_message(slot);
}

auto HttpEngine::ws_deliver_message(size_t slot) -> bool
{
    auto& c = connections_[slot];
    c.ws_endpoint->on_ws_message(slot, std::span<uint8_t const>{c.ws_msg.data(), c.ws_msg_len}, c.ws_msg_opcode == WsOpcode::text);
    if (!slot_open(slot)) {
        return false;
    }
    c.ws_msg_len = 0;
    return true;
}

}  // namespace statusbar::http
