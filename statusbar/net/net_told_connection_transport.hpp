#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// ToldConnectionTransport: a ConnectionTransport made of memory.
///
/// It stands where TcpConnectionPool stands, and is told what the peers
/// do: a peer connects, sends bytes, stops accepting them, shuts down or
/// resets. poll() is one turn of the reactor: it raises the same
/// readiness callbacks, in the same order and under the same interest
/// rules, as the pool does from its multiplexer. Whatever the engine
/// writes is kept per slot for the caller to read back.
///
/// There is no socket, no kernel buffer and no time in it: the only clock
/// is the `now_ns` each call is told. Every buffer is sized at
/// construction, so an engine's promise not to allocate can be checked
/// across it.

#include "statusbar/net/net_connection_transport.hpp"
#include "statusbar/net/net_error.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace statusbar::net {

class ToldConnectionTransport final : public ConnectionTransport
{
  public:
    struct Config
    {
        size_t connections{4};
        /// Bytes a peer may have sent that the engine has not read yet.
        size_t inbound_bytes{size_t{1} << 16U};
        /// Bytes the engine may have written that the caller has not taken.
        size_t outbound_bytes{size_t{1} << 16U};
    };

    /// No limit on what write() accepts.
    static constexpr size_t UNLIMITED = SIZE_MAX;

    ToldConnectionTransport(TcpConnectionHandler& handler, Config const& config)
        : handler_{&handler}
        , slots_(config.connections)
    {
        for (auto& slot : slots_) {
            slot.inbound.resize(config.inbound_bytes);
            slot.outbound.resize(config.outbound_bytes);
        }
    }

    //
    // What the peers do, as the caller tells it
    //

    /// A peer connects: it lands in the lowest free slot and the engine is
    /// told on_accept(). At capacity the engine is told on_rejected() and
    /// nothing is returned.
    auto connect(int64_t now_ns) -> std::optional<size_t>
    {
        last_now_ns_ = now_ns;
        auto const slot = static_cast<size_t>(std::ranges::find_if(slots_, [](Slot const& s) { return !s.open; }) - slots_.begin());
        if (slot == slots_.size()) {
            handler_->on_rejected(SocketAddress{}, now_ns);
            return std::nullopt;
        }
        slots_[slot].reopen();
        handler_->on_accept(slot, SocketAddress{}, now_ns);
        return slot;
    }

    /// The peer sends @p bytes: they wait, unread, until a poll() raises
    /// on_readable() and the engine reads them. False when the slot is
    /// closed or the bytes do not fit the inbound buffer.
    auto peer_sends(size_t slot, std::span<uint8_t const> bytes) -> bool
    {
        if (!slot_ok(slot) || bytes.size() > slots_[slot].inbound.size() - slots_[slot].inbound_end) {
            return false;
        }
        auto& s = slots_[slot];
        std::ranges::copy(bytes, s.inbound.begin() + static_cast<std::ptrdiff_t>(s.inbound_end));
        s.inbound_end += bytes.size();
        return true;
    }

    auto peer_sends(size_t slot, std::string_view text) -> bool
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return peer_sends(slot, std::span<uint8_t const>{reinterpret_cast<uint8_t const*>(text.data()), text.size()});
    }

    /// The peer closes its sending side: once the engine has read what was
    /// sent, read() returns 0.
    void peer_shuts_down(size_t slot)
    {
        if (slot_ok(slot)) {
            slots_[slot].peer_shut_down = true;
        }
    }

    /// The peer resets the connection: what it sent is lost and read()
    /// fails.
    void peer_resets(size_t slot)
    {
        if (slot_ok(slot)) {
            slots_[slot].peer_reset = true;
            slots_[slot].inbound_begin = slots_[slot].inbound_end;
        }
    }

    /// How many more bytes write() will accept on this slot: a peer that
    /// has stopped reading, or reads slowly. UNLIMITED by default.
    void set_write_window(size_t slot, size_t bytes)
    {
        if (slot < slots_.size()) {
            slots_[slot].write_window = bytes;
        }
    }

    /// What the engine has written to the slot and the caller has not
    /// taken yet. It outlives a close of the slot (the peer may still read
    /// what was sent before it) and is cleared by the next connect() there.
    [[nodiscard]] auto written(size_t slot) const noexcept -> std::span<uint8_t const>
    {
        return {slots_[slot].outbound.data(), slots_[slot].outbound_end};
    }

    /// Forget what written() holds, as a peer that has read it.
    void take_written(size_t slot) noexcept { slots_[slot].outbound_end = 0; }

    //
    // One turn of the reactor
    //

    /// Raise what is ready, as the pool does from its multiplexer:
    /// on_writable() for a slot whose short write can now go on, then
    /// on_readable() for a slot with read interest and something to read.
    /// Level-triggered: bytes the engine leaves unread raise on_readable()
    /// again on the next call.
    /// @return how many callbacks were made
    auto poll(int64_t now_ns) -> size_t
    {
        last_now_ns_ = now_ns;
        size_t raised = 0;
        for (size_t slot = 0; slot < slots_.size(); ++slot) {
            raised += raise_writable(slot, now_ns) ? 1 : 0;
            raised += raise_readable(slot, now_ns) ? 1 : 0;
        }
        return raised;
    }

    //
    // State, for a caller to assert on
    //

    /// Which connection the slot holds: it changes with every connect()
    /// there, so a peer can tell its own connection from a later one that
    /// landed in the same slot.
    [[nodiscard]] auto generation(size_t slot) const noexcept -> uint64_t { return slots_[slot].generation; }
    [[nodiscard]] auto read_interest(size_t slot) const noexcept -> bool { return slot_ok(slot) && slots_[slot].want_read; }
    [[nodiscard]] auto write_interest(size_t slot) const noexcept -> bool { return slot_ok(slot) && slots_[slot].want_write; }
    [[nodiscard]] auto unread(size_t slot) const noexcept -> size_t
    {
        return slots_[slot].inbound_end - slots_[slot].inbound_begin;
    }
    [[nodiscard]] auto capacity() const noexcept -> size_t { return slots_.size(); }
    [[nodiscard]] auto active_count() const noexcept -> size_t
    {
        return static_cast<size_t>(std::ranges::count_if(slots_, [](Slot const& s) { return s.open; }));
    }

    //
    // ConnectionTransport
    //

    [[nodiscard]] auto read(size_t slot, std::span<uint8_t> out) -> StatusValue<size_t> override
    {
        if (!slot_ok(slot)) {
            return failure(NetError::invalid_handle);
        }
        auto& s = slots_[slot];
        if (s.peer_reset) {
            return failure(NetError::receive_failed);
        }
        size_t const n = s.take(out);
        // Nothing to hand over: the end of the stream if the peer has shut
        // down, else nothing yet.
        if (n == 0 && !s.peer_shut_down) {
            return failure(NetError::would_block);
        }
        return n;
    }

    [[nodiscard]] auto write(size_t slot, std::span<uint8_t const> data) -> StatusValue<size_t> override
    {
        if (!slot_ok(slot)) {
            return failure(NetError::invalid_handle);
        }
        auto& s = slots_[slot];
        if (s.peer_reset) {
            return failure(NetError::send_failed);
        }
        size_t const n = s.accept(data);
        s.want_write = n < data.size();  // a short write arms write interest; a whole one disarms it
        return n;
    }

    void close(size_t slot) override
    {
        if (slot_ok(slot)) {
            slots_[slot].open = false;
            handler_->on_closed(slot, last_now_ns_);
        }
    }

    void set_read_interest(size_t slot, bool want_read) override
    {
        if (slot_ok(slot)) {
            slots_[slot].want_read = want_read;
        }
    }

    [[nodiscard]] auto is_open(size_t slot) const noexcept -> bool override { return slot_ok(slot); }

  private:
    struct Slot
    {
        std::vector<uint8_t> inbound;   ///< peer -> engine, [inbound_begin, inbound_end) unread
        std::vector<uint8_t> outbound;  ///< engine -> peer, [0, outbound_end) not yet taken
        uint64_t generation{0};         ///< counts the connections this slot has held
        size_t inbound_begin{0};
        size_t inbound_end{0};
        size_t outbound_end{0};
        size_t write_window{UNLIMITED};
        bool open{false};
        bool want_read{true};
        bool want_write{false};
        bool peer_shut_down{false};
        bool peer_reset{false};

        /// Take a new connection: everything as constructed, the buffers
        /// kept and emptied, the generation moved on.
        void reopen() noexcept
        {
            *this =
                Slot{.inbound = std::move(inbound), .outbound = std::move(outbound), .generation = generation + 1, .open = true};
        }

        /// Hand the engine up to out.size() unread bytes.
        auto take(std::span<uint8_t> out) noexcept -> size_t
        {
            size_t const n = std::min(out.size(), inbound_end - inbound_begin);
            std::copy_n(inbound.begin() + static_cast<std::ptrdiff_t>(inbound_begin), n, out.begin());
            inbound_begin += n;
            // Once everything sent has been read, the buffer is empty again.
            if (inbound_begin == inbound_end) {
                inbound_begin = 0;
                inbound_end = 0;
            }
            return n;
        }

        /// Take from the engine what the peer's window and the buffer allow.
        auto accept(std::span<uint8_t const> data) noexcept -> size_t
        {
            size_t const n = std::min({data.size(), write_window, outbound.size() - outbound_end});
            std::copy_n(data.begin(), n, outbound.begin() + static_cast<std::ptrdiff_t>(outbound_end));
            outbound_end += n;
            write_window -= write_window == UNLIMITED ? 0 : n;
            return n;
        }
    };

    [[nodiscard]] auto slot_ok(size_t slot) const noexcept -> bool { return slot < slots_.size() && slots_[slot].open; }

    auto raise_writable(size_t slot, int64_t now_ns) -> bool
    {
        if (!slot_ok(slot) || !slots_[slot].want_write || slots_[slot].write_window == 0) {
            return false;
        }
        handler_->on_writable(slot, now_ns);
        return true;
    }

    auto raise_readable(size_t slot, int64_t now_ns) -> bool
    {
        if (!slot_ok(slot) || !slots_[slot].want_read) {
            return false;
        }
        Slot const& s = slots_[slot];
        if (s.inbound_begin == s.inbound_end && !s.peer_shut_down && !s.peer_reset) {
            return false;
        }
        handler_->on_readable(slot, now_ns);
        return true;
    }

    TcpConnectionHandler* handler_;
    std::vector<Slot> slots_;
    int64_t last_now_ns_{0};
};

}  // namespace statusbar::net
