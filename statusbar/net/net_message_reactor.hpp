#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Message-oriented Reactor with injected clock.
///
/// Manages multiple Pollable ports in a single poll() loop. The clock
/// function is injected at construction — called once per cycle, the
/// timestamp is passed to all callbacks.

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/sg14/inplace_function.h"

#include <poll.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <vector>

namespace statusbar::net {

/// A pollable port that the reactor manages.
///
/// Threading: all methods are called from the reactor's poll thread.
/// Implementations must not block and should not throw.
class Pollable
{
  public:
    virtual ~Pollable() = default;

    /// File descriptor for poll(). Return -1 if not pollable (tick-only).
    [[nodiscard]] virtual auto fd() const noexcept -> int = 0;

    /// Poll event mask. Override to include POLLOUT for write-readiness.
    [[nodiscard]] virtual auto poll_events() const noexcept -> short { return POLLIN; }

    /// Called when the fd has data ready (POLLIN), and also when poll()
    /// reports an error or hangup condition (POLLERR / POLLHUP / POLLNVAL,
    /// which poll() delivers regardless of the requested event mask). The
    /// read path observes the error/EOF and should mark the port finished()
    /// so the reactor removes it instead of spinning on the dead fd.
    virtual void on_ready(int64_t now_ns) = 0;

    /// Called when the fd is writable (POLLOUT). Only fires if poll_events() includes POLLOUT.
    virtual void on_writable(int64_t now_ns) { (void)now_ns; }

    /// Called every poll cycle (after processing ready events).
    virtual void tick(int64_t now_ns) = 0;

    /// Return true when this port should be removed from the reactor.
    [[nodiscard]] virtual auto finished() const noexcept -> bool = 0;
};

/// Clock function type: returns nanoseconds since some epoch.
using ClockFn = statusbar::sg14::inplace_function<int64_t(), 64>;

/// Default monotonic clock (nanoseconds since boot).
[[nodiscard]] inline auto monotonic_ns() -> int64_t
{
    auto const now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

/// Message-oriented reactor with injected clock.
///
/// Single-threaded: poll_once() / run() must be called from one thread.
/// The stop flag and NotificationPipe::notify() are safe to call from other threads.
class MessageReactor
{
  public:
    /// @param memory_resource Memory resource for the ports_, pollfds_, and
    ///        pollfd_port_idx_ vectors. nullptr → std::pmr::get_default_resource().
    MessageReactor(
        statusbar::itc::StopToken& stop,
        ClockFn clock,
        int poll_timeout_ms = 10,
        std::pmr::memory_resource* memory_resource = nullptr)
        : ports_{memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource()}
        , stop_{&stop}
        , clock_{std::move(clock)}
        , poll_timeout_ms_{poll_timeout_ms}
        , pollfds_{ports_.get_allocator()}
        , pollfd_port_idx_{ports_.get_allocator()}
    {}

    /// Add a pollable port.
    void add(std::unique_ptr<Pollable> port) { ports_.push_back(std::move(port)); }

    /// Run the event loop until stop is set or all ports are finished.
    void run();

    /// Execute one poll cycle. Returns false when the reactor should stop.
    auto poll_once(int timeout_ms) -> bool;

    /// Number of active (non-finished) ports.
    [[nodiscard]] auto active_count() const noexcept -> size_t;

  private:
    [[nodiscard]] auto should_run() const noexcept -> bool;
    void fill_pollfds();
    void dispatch_ready(int64_t now_ns);
    void tick_all(int64_t now_ns);
    void remove_finished();

    std::pmr::vector<std::unique_ptr<Pollable>> ports_;
    statusbar::itc::StopToken* stop_{nullptr};
    ClockFn clock_;
    int poll_timeout_ms_{10};

    // Reusable buffers
    std::pmr::vector<pollfd> pollfds_;
    std::pmr::vector<size_t> pollfd_port_idx_;
};

}  // namespace statusbar::net
