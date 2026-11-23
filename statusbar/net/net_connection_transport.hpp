#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The seam between a connection engine and whatever carries its bytes.
///
/// An engine (an HTTP server's request logic, say) works purely in slot
/// indices. It is told what happens on its connections through
/// TcpConnectionHandler, and it reads, writes and closes them through
/// ConnectionTransport. Neither side of the seam names a socket.
///
/// TcpConnectionPool is the transport made of real sockets.
/// ToldConnectionTransport is one made of memory, for exercising an
/// engine's logic with no socket, no kernel and no clock.

#include "statusbar/net/net_address.hpp"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::net {

/// Slot-indexed connection events, delivered from the reactor's poll
/// thread. Handlers may call the transport's read/write/close from inside
/// any callback.
class TcpConnectionHandler
{
  public:
    virtual ~TcpConnectionHandler() = default;

    virtual void on_accept(size_t slot, SocketAddress const& peer, int64_t now_ns) = 0;
    virtual void on_readable(size_t slot, int64_t now_ns) = 0;
    virtual void on_writable(size_t slot, int64_t now_ns) { (void)slot, (void)now_ns; }
    virtual void on_closed(size_t slot, int64_t now_ns) = 0;

    /// A connection arrived while every slot was in use and was closed.
    virtual void on_rejected(SocketAddress const& peer, int64_t now_ns) { (void)peer, (void)now_ns; }
};

/// What a connection engine asks of its transport, by slot.
class ConnectionTransport
{
  public:
    virtual ~ConnectionTransport() = default;

    /// Reads into @p out. 0 => orderly EOF; NetError::would_block => no
    /// data now; other errors mean the connection is dead: close() it.
    [[nodiscard]] virtual auto read(size_t slot, std::span<uint8_t> out) -> StatusValue<size_t> = 0;

    /// Sends what the transport accepts (possibly 0) and returns the
    /// count; a short write arms write interest for an on_writable()
    /// follow-up.
    [[nodiscard]] virtual auto write(size_t slot, std::span<uint8_t const> data) -> StatusValue<size_t> = 0;

    /// Closes the slot's connection and fires on_closed().
    virtual void close(size_t slot) = 0;

    /// Whether the slot's unread bytes should raise on_readable(). Off,
    /// the bytes wait where they are; on again, a pending byte raises
    /// on_readable() at the next poll.
    virtual void set_read_interest(size_t slot, bool want_read) = 0;

    [[nodiscard]] virtual auto is_open(size_t slot) const noexcept -> bool = 0;
};

}  // namespace statusbar::net
