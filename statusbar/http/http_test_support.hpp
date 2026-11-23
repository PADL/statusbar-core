#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// What the http unit tests stand an HttpEngine on: no socket, no kernel,
/// no clock. A ToldSite is an engine on a net::ToldConnectionTransport; a
/// ToldClient is one peer of it. The test says what each peer sends, turns
/// the reactor by hand on a clock it makes up, and reads back exactly what
/// the engine wrote.
///
/// The tests that run the same engine on real sockets are the functional
/// tests (http_*_functional_test.cpp).

#include "statusbar/http/http_engine.hpp"
#include "statusbar/net/net_told_connection_transport.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::http::test_support {

/// An engine and the made-up wire its connections live on.
/// @tparam EngineT HttpEngine, or a test's subclass of it
template <typename EngineT = HttpEngine>
struct ToldSite
{
    /// Room for the largest request and response a test passes in one go.
    static constexpr size_t DEFAULT_WIRE_BYTES = size_t{1} << 17U;

    EngineT engine;
    net::ToldConnectionTransport wire;

    explicit ToldSite(HttpLimits const& limits, StaticManifest const* manifest = nullptr, size_t wire_bytes = DEFAULT_WIRE_BYTES)
        : engine{limits, manifest}
        , wire{engine.events(), {.connections = limits.max_connections, .inbound_bytes = wire_bytes, .outbound_bytes = wire_bytes}}
    {
        engine.attach(wire);
    }

    /// Turn the reactor @p rounds times, as it would: raise what is ready,
    /// then tick, on the clock @p now0, @p now0 + 1, ...
    /// @return how many readiness callbacks were raised in all
    auto pump(int rounds = 20, int64_t now0 = 1) -> size_t
    {
        size_t raised = 0;
        for (int i = 0; i < rounds; ++i) {
            raised += wire.poll(now0 + i);
            engine.tick(now0 + i);
        }
        return raised;
    }
};

/// One peer of a ToldSite: it connects when constructed and shuts its side
/// down when destroyed, as a socket's owner would.
class ToldClient
{
  public:
    explicit ToldClient(net::ToldConnectionTransport& wire, int64_t now_ns = 1)
        : wire_{&wire}
        , slot_{wire.connect(now_ns)}
        , generation_{slot_ ? wire.generation(*slot_) : 0}
    {}

    ~ToldClient()
    {
        if (mine()) {
            wire_->peer_shuts_down(*slot_);
        }
    }

    ToldClient(ToldClient const&) = delete;
    auto operator=(ToldClient const&) -> ToldClient& = delete;
    ToldClient(ToldClient&&) = delete;
    auto operator=(ToldClient&&) -> ToldClient& = delete;

    /// False when the site had no free slot and turned the peer away.
    [[nodiscard]] auto connected() const noexcept -> bool { return slot_.has_value(); }
    [[nodiscard]] auto slot() const noexcept -> size_t { return slot_.value_or(SIZE_MAX); }

    /// Put @p text on the wire for the engine to read at the next pump.
    auto send_all(std::string_view text) const -> bool { return mine() && wire_->peer_sends(*slot_, text); }
    auto send_all(std::span<uint8_t const> bytes) const -> bool { return mine() && wire_->peer_sends(*slot_, bytes); }

    /// Everything the engine has written to this peer since the last call.
    [[nodiscard]] auto received() const -> std::string
    {
        if (!connected() || wire_->generation(*slot_) != generation_) {
            return {};
        }
        auto const bytes = wire_->written(*slot_);
        std::string out{bytes.begin(), bytes.end()};
        wire_->take_written(*slot_);
        return out;
    }

    /// The same, as bytes (WebSocket frames).
    [[nodiscard]] auto received_bytes() const -> std::vector<uint8_t>
    {
        auto const text = received();
        return {text.begin(), text.end()};
    }

    /// Whether the engine has closed this connection.
    [[nodiscard]] auto at_eof() const noexcept -> bool { return !mine(); }

    /// Abort the connection: the engine's next read fails.
    void reset() const
    {
        if (mine()) {
            wire_->peer_resets(*slot_);
        }
    }

    /// Stop reading: the engine's writes are accepted up to @p bytes more.
    void accept_only(size_t bytes) const
    {
        if (mine()) {
            wire_->set_write_window(*slot_, bytes);
        }
    }

  private:
    /// Whether the slot still holds the connection this peer made.
    [[nodiscard]] auto mine() const noexcept -> bool
    {
        return connected() && wire_->is_open(*slot_) && wire_->generation(*slot_) == generation_;
    }

    net::ToldConnectionTransport* wire_;
    std::optional<size_t> slot_;
    uint64_t generation_;
};

/// "HTTP/1.1 200 OK" of a response.
[[nodiscard]] inline auto status_line(std::string const& response) -> std::string
{
    return response.substr(0, response.find('\r'));
}

/// The value of header @p name in a response, or empty.
[[nodiscard]] inline auto header_value(std::string const& response, std::string_view name) -> std::string
{
    auto const at = response.find(std::string(name) + ": ");
    if (at == std::string::npos) {
        return {};
    }
    auto const start = at + name.size() + 2;
    return response.substr(start, response.find('\r', start) - start);
}

/// Everything after the blank line of a response.
[[nodiscard]] inline auto body_of(std::string const& response) -> std::string
{
    auto const at = response.find("\r\n\r\n");
    return at == std::string::npos ? std::string{} : response.substr(at + 4);
}

}  // namespace statusbar::http::test_support
