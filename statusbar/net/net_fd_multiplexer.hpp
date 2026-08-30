#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// FdMultiplexer — many fds behind ONE kernel readiness fd (epoll on Linux,
/// kqueue on BSD/macOS), so a Pollable can own a whole connection set while
/// occupying a single slot in the MessageReactor's poll(). The event buffer
/// is sized at construction and drain() visits ready members without
/// allocating, keeping the no-allocation-after-startup contract.
///
/// Members are identified by a caller-chosen 32-bit tag (e.g. a slot
/// index); readiness is delivered as {tag, readable, writable, error}.
/// Error/hangup conditions are reported with readable set as well, so a
/// caller that only acts on readable still observes the failure through
/// its next read (which returns EOF or an error).

#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <vector>

#if defined(__linux__)
#    include <sys/epoll.h>
#else
#    include <sys/event.h>
#    include <sys/time.h>
#    include <sys/types.h>
#endif

namespace statusbar::net {

class FdMultiplexer
{
  public:
    struct Event
    {
        uint32_t tag{0};
        bool readable{false};
        bool writable{false};
        bool error{false};
    };

    /// @param max_events Events fetched per drain() call — size to the
    ///        expected member count (more members simply take extra drains).
    explicit FdMultiplexer(size_t max_events)
        : events_(max_events < 1 ? 1 : max_events)
    {
#if defined(__linux__)
        mux_ = FileDescriptor{::epoll_create1(EPOLL_CLOEXEC)};
#else
        mux_ = FileDescriptor{::kqueue()};
#endif
    }

    FdMultiplexer(FdMultiplexer const&) = delete;
    auto operator=(FdMultiplexer const&) -> FdMultiplexer& = delete;

    [[nodiscard]] auto valid() const noexcept -> bool { return mux_.get() >= 0; }

    /// The single fd to hand to the outer poll loop (readable when any
    /// member is ready).
    [[nodiscard]] auto fd() const noexcept -> int { return mux_.get(); }

    /// Register a member fd under @p tag with the given interest set.
    [[nodiscard]] auto add(int fd, uint32_t tag, bool want_read, bool want_write) noexcept -> Status
    {
#if defined(__linux__)
        epoll_event ev{};
        ev.events = interest_bits(want_read, want_write);
        ev.data.u32 = tag;
        if (::epoll_ctl(mux_.get(), EPOLL_CTL_ADD, fd, &ev) < 0) {
            return failure(NetError::socket_option_failed);
        }
        return success();
#else
        return kqueue_set(fd, tag, want_read, want_write);
#endif
    }

    /// Change a member's interest set (the tag may be updated too).
    [[nodiscard]] auto modify(int fd, uint32_t tag, bool want_read, bool want_write) noexcept -> Status
    {
#if defined(__linux__)
        epoll_event ev{};
        ev.events = interest_bits(want_read, want_write);
        ev.data.u32 = tag;
        if (::epoll_ctl(mux_.get(), EPOLL_CTL_MOD, fd, &ev) < 0) {
            return failure(NetError::socket_option_failed);
        }
        return success();
#else
        return kqueue_set(fd, tag, want_read, want_write);
#endif
    }

    /// Deregister a member. Safe to call for an fd that is about to close
    /// (and on Linux, closing the fd deregisters it implicitly anyway).
    void remove(int fd) noexcept
    {
#if defined(__linux__)
        (void)::epoll_ctl(mux_.get(), EPOLL_CTL_DEL, fd, nullptr);
#else
        struct kevent kevs[2];
        EV_SET(&kevs[0], uintptr_t(fd), EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&kevs[1], uintptr_t(fd), EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        struct timespec const zero{};
        (void)::kevent(mux_.get(), kevs, 2, nullptr, 0, &zero);  // ENOENT is fine
#endif
    }

    /// Fetch pending readiness without blocking and visit each event.
    /// Returns the number of events visited (call again if it equals the
    /// buffer size — more may be pending).
    template <typename Visit>
    auto drain(Visit visit) -> int
    {
#if defined(__linux__)
        int const n = ::epoll_wait(mux_.get(), events_.data(), int(events_.size()), 0);
        for (int i = 0; i < n; ++i) {
            auto const& ev = events_[size_t(i)];
            bool const err = (ev.events & (EPOLLERR | EPOLLHUP)) != 0;
            visit(Event{
                .tag = ev.data.u32,
                .readable = (ev.events & EPOLLIN) != 0 || err,
                .writable = (ev.events & EPOLLOUT) != 0,
                .error = err,
            });
        }
        return n < 0 ? 0 : n;
#else
        struct timespec const zero{};
        int const n = ::kevent(mux_.get(), nullptr, 0, events_.data(), int(events_.size()), &zero);
        for (int i = 0; i < n; ++i) {
            auto const& ev = events_[size_t(i)];
            bool const err = (ev.flags & EV_ERROR) != 0 || (ev.flags & EV_EOF) != 0;
            visit(Event{
                .tag = uint32_t(reinterpret_cast<uintptr_t>(ev.udata)),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                .readable = ev.filter == EVFILT_READ || err,
                .writable = ev.filter == EVFILT_WRITE,
                .error = err,
            });
        }
        return n < 0 ? 0 : n;
#endif
    }

  private:
#if defined(__linux__)
    [[nodiscard]] static auto interest_bits(bool want_read, bool want_write) noexcept -> uint32_t
    {
        uint32_t bits = 0;
        if (want_read) {
            bits |= EPOLLIN;
        }
        if (want_write) {
            bits |= EPOLLOUT;
        }
        return bits;
    }
#else
    [[nodiscard]] auto kqueue_set(int fd, uint32_t tag, bool want_read, bool want_write) noexcept -> Status
    {
        // EV_ADD is an upsert, so add and modify share this path; the
        // uninterested filter is disabled rather than deleted so a later
        // modify can flip it without racing a missing registration.
        struct kevent kevs[2];
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr): kqueue's udata is the only tag channel
        void* const udata = reinterpret_cast<void*>(uintptr_t(tag));
        EV_SET(&kevs[0], uintptr_t(fd), EVFILT_READ, EV_ADD | (want_read ? EV_ENABLE : EV_DISABLE), 0, 0, udata);
        EV_SET(&kevs[1], uintptr_t(fd), EVFILT_WRITE, EV_ADD | (want_write ? EV_ENABLE : EV_DISABLE), 0, 0, udata);
        struct timespec const zero{};
        if (::kevent(mux_.get(), kevs, 2, nullptr, 0, &zero) < 0) {
            return failure(NetError::socket_option_failed);
        }
        return success();
    }
#endif

    FileDescriptor mux_{};
#if defined(__linux__)
    std::vector<epoll_event> events_;
#else
    std::vector<struct kevent> events_;
#endif
};

}  // namespace statusbar::net
