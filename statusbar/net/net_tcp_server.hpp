#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TcpConnectionPool — a fixed-capacity, readiness-driven TCP server that
/// occupies ONE slot in the MessageReactor: the pool's fd() is an
/// FdMultiplexer holding the listener and every connection, so any member
/// socket wakes the outer poll (no tick-cadence latency), while connection
/// slots, the free list, and the event buffer are all sized at
/// construction — nothing allocates after startup.
///
/// The pool owns the sockets; the handler works purely in slot indices:
///
///   on_accept(slot, peer)   a connection landed in `slot`
///   on_readable(slot)       call read(slot, buf) until would_block
///   on_writable(slot)       a short write() has drained — write the rest
///   on_closed(slot)         the slot's fd is closed (close() or idle sweep)
///
/// read() returning 0 is orderly EOF; the handler decides when to
/// close(slot). write() is unbuffered: it sends what the kernel accepts and
/// returns the count — on a short write the pool arms write interest and
/// on_writable(slot) fires when the socket drains (the caller keeps the
/// unsent remainder in its own storage, which keeps this layer zero-copy
/// and allocation-free). When a write completes fully, write interest is
/// disarmed automatically.
///
/// At capacity, new connections are accepted and immediately closed
/// (otherwise the pending connection would keep the listener readable and
/// spin the poll); on_rejected(peer) reports it.

#include "statusbar/net/net_address.hpp"
#include "statusbar/net/net_fd_multiplexer.hpp"
#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_socket.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace statusbar::net {

/// Slot-indexed connection events, delivered from the reactor's poll
/// thread. Handlers may call the pool's read/write/close from inside any
/// callback.
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

struct TcpServerOptions
{
    int backlog = 128;
    int dscp = -1;                ///< applied to accepted sockets when >= 0
    bool nodelay = true;          ///< TCP_NODELAY on accepted sockets
    int64_t idle_timeout_ns = 0;  ///< close slots idle this long; 0 = never
};

class TcpConnectionPool : public Pollable
{
  public:
    TcpConnectionPool(
        SocketAddress const& bind_addr,
        size_t max_connections,
        TcpConnectionHandler& handler,
        TcpServerOptions const& options = {});

    TcpConnectionPool(TcpConnectionPool const&) = delete;
    auto operator=(TcpConnectionPool const&) -> TcpConnectionPool& = delete;

    /// False when the listener or multiplexer failed to come up.
    [[nodiscard]] auto valid() const noexcept -> bool;

    /// The listener's bound address (resolves port 0).
    [[nodiscard]] auto local_addr() const -> StatusValue<SocketAddress>;

    /// Reads into @p out. 0 => orderly EOF; NetError::would_block => no
    /// data now; other errors mean the connection is dead — close() it.
    [[nodiscard]] auto read(size_t slot, std::span<uint8_t> out) -> StatusValue<size_t>;

    /// Sends what the kernel accepts (possibly 0) and returns the count;
    /// a short write arms write interest for an on_writable() follow-up.
    [[nodiscard]] auto write(size_t slot, std::span<uint8_t const> data) -> StatusValue<size_t>;

    /// Closes the slot's connection and fires on_closed().
    void close(size_t slot);

    [[nodiscard]] auto peer(size_t slot) const -> SocketAddress const&;
    [[nodiscard]] auto is_open(size_t slot) const noexcept -> bool;
    [[nodiscard]] auto active_count() const noexcept -> size_t { return active_; }
    [[nodiscard]] auto capacity() const noexcept -> size_t { return slots_.size(); }

    // -- Pollable --
    [[nodiscard]] auto fd() const noexcept -> int override { return mux_.fd(); }
    void on_ready(int64_t now_ns) override;
    void tick(int64_t now_ns) override;
    [[nodiscard]] auto finished() const noexcept -> bool override { return false; }

  private:
    static constexpr uint32_t LISTENER_TAG = 0xffffffffU;

    struct Slot
    {
        FileDescriptor fd{};
        SocketAddress peer{};
        int64_t last_activity_ns{0};
        bool in_use{false};
        bool want_write{false};
    };

    void accept_ready(int64_t now_ns);
    void close_slot(size_t slot, int64_t now_ns);
    [[nodiscard]] auto slot_ok(size_t slot) const noexcept -> bool { return slot < slots_.size() && slots_[slot].in_use; }

    TcpConnectionHandler& handler_;
    TcpServerOptions options_;
    FileDescriptor listener_{};
    FdMultiplexer mux_;
    std::vector<Slot> slots_;     ///< sized at construction
    std::vector<uint32_t> free_;  ///< free slot indices, sized at construction
    size_t active_{0};
    int64_t last_now_ns_{0};
};

}  // namespace statusbar::net
