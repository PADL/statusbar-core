// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_server.hpp"

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
        case 204:
            return "No Content";
        case 304:
            return "Not Modified";
        case 400:
            return "Bad Request";
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
        case 431:
            return "Request Header Fields Too Large";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 505:
            return "HTTP Version Not Supported";
        default:
            return "Status";
    }
}

}  // namespace

HttpServer::HttpServer(net::SocketAddress const& bind_addr, HttpLimits const& limits, net::TcpServerOptions tcp_options)
    : limits_{limits}
    , discard_(4096)
    , pool_{bind_addr, limits.max_connections, *this, [&] {
                // The server owns connection lifetime (408 vs silent idle
                // close need different behavior) — the pool's blunt idle
                // sweep stays off.
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
        parsers_.emplace_back(limits_);
    }
}

void HttpServer::on_accept(size_t slot, net::SocketAddress const& /*peer*/, int64_t now_ns)
{
    auto& c = connections_[slot];
    c.rx_len = 0;
    c.tx_len = 0;
    c.tx_sent = 0;
    c.leftover_at = 0;
    c.discard_remaining = 0;
    c.state = ConnState::reading_head;
    c.close_after_send = false;
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
                return;  // pipelined bytes wait in the socket until the response drains

            case ConnState::discarding_body: {
                auto const want = size_t(std::min<uint64_t>(c.discard_remaining, discard_.size()));
                auto n = pool_.read(slot, std::span<uint8_t>{discard_.data(), want});
                if (!n) {
                    return;  // would_block (a dead socket reports on the next event)
                }
                if (*n == 0) {
                    pool_.close(slot);
                    return;
                }
                c.discard_remaining -= *n;
                if (c.discard_remaining == 0) {
                    finish_body_and_respond(slot, now_ns);
                }
                break;
            }

            case ConnState::reading_head: {
                // Parse what is buffered before reading more — a pipelined
                // request may already be complete in rx.
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
                    // Head cannot legally grow this far (parser limits are
                    // smaller); defensive close.
                    respond_status(slot, 431, true, now_ns);
                    break;
                }
                auto n = pool_.read(slot, std::span<uint8_t>{c.rx.data() + c.rx_len, c.rx.size() - c.rx_len});
                if (!n) {
                    return;  // would_block
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
    auto const& parser = parsers_[slot];
    auto const& request = parser.request();
    auto const head_len = parser.consumed();
    uint64_t const body_len = request.has_content_length ? request.content_length : 0;

    if (body_len > limits_.max_body) {
        respond_status(slot, 413, true, now_ns);
        return;
    }
    uint64_t const body_in_rx = std::min<uint64_t>(body_len, c.rx_len - head_len);
    if (body_in_rx < body_len) {
        c.discard_remaining = body_len - body_in_rx;
        c.leftover_at = c.rx_len;  // everything buffered belongs to this request
        c.state = ConnState::discarding_body;
        return;
    }
    c.leftover_at = head_len + size_t(body_len);
    finish_body_and_respond(slot, now_ns);
}

void HttpServer::finish_body_and_respond(size_t slot, int64_t now_ns)
{
    auto const& request = parsers_[slot].request();
    auto const status = dispatch(slot, request);
    respond_status(slot, status, !request.keep_alive, now_ns);
}

void HttpServer::respond_status(size_t slot, uint16_t status, bool close_after, int64_t now_ns)
{
    auto& c = connections_[slot];
    char body[64];
    int const body_len = snprintf(body, sizeof body, "%u %s\n", status, reason_phrase(status));
    int const head_len = snprintf(
        reinterpret_cast<char*>(c.tx.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        c.tx.size(),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n"
        "\r\n%s",
        status,
        reason_phrase(status),
        body_len,
        close_after ? "close" : "keep-alive",
        body);
    c.tx_len = std::min(size_t(head_len), c.tx.size());
    c.tx_sent = 0;
    c.close_after_send = close_after;
    c.state = ConnState::sending;
    pump_tx(slot, now_ns);
}

void HttpServer::pump_tx(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
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
    if (c.close_after_send) {
        pool_.close(slot);
        return;
    }
    next_request(slot, now_ns);
}

void HttpServer::next_request(size_t slot, int64_t now_ns)
{
    auto& c = connections_[slot];
    // Compact any pipelined tail to the front and go again.
    size_t const leftover = c.rx_len > c.leftover_at ? c.rx_len - c.leftover_at : 0;
    if (leftover > 0) {
        std::memmove(c.rx.data(), c.rx.data() + c.leftover_at, leftover);
    }
    c.rx_len = leftover;
    c.leftover_at = 0;
    parsers_[slot].reset();
    c.state = ConnState::reading_head;
    c.head_started = leftover > 0;
    c.head_start_ns = now_ns;
    c.idle_since_ns = now_ns;
    // No recursive process() here: when this runs inside process()'s loop
    // the loop parses the leftover on its next iteration; the on_writable
    // path processes explicitly after pump_tx.
}

}  // namespace statusbar::http
