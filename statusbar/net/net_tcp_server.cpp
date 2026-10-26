// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace statusbar::net {

namespace {

// Portable EPIPE suppression: Linux uses MSG_NOSIGNAL per send; macOS/BSD
// set SO_NOSIGPIPE once per socket at accept.
#if defined(MSG_NOSIGNAL)
constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
constexpr int SEND_FLAGS = 0;
#endif

void set_accepted_options(int fd, TcpServerOptions const& options, int family)
{
    bool const is_unix = family == AF_UNIX;
    (void)set_nonblocking(fd);
    if (options.nodelay && !is_unix) {
        int const one = 1;
        (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    if (options.dscp >= 0 && !is_unix) {
        (void)set_dscp(fd, family, uint8_t(options.dscp));
    }
#if defined(SO_NOSIGPIPE)
    int const one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

/// An AF_UNIX SOCK_SEQPACKET socket bound to `addr`.
auto create_seqpacket_socket(SocketAddress const& addr) -> StatusValue<FileDescriptor>
{
    FileDescriptor fd{::socket(AF_UNIX, SOCK_SEQPACKET, 0)};
    if (!fd.valid()) {
        return failure(NetError::socket_creation_failed);
    }
    if (::bind(fd.get(), addr.sockaddr(), addr.length()) < 0) {
        return failure(NetError::bind_failed);
    }
    return fd;
}

}  // namespace

TcpConnectionPool::TcpConnectionPool(
    SocketAddress const& bind_addr, size_t max_connections, TcpConnectionHandler& handler, TcpServerOptions const& options)
    : handler_{handler}
    , options_{options}
    , mux_{max_connections + 1}
    , slots_(max_connections)
{
    free_.reserve(max_connections);
    for (size_t i = max_connections; i > 0; --i) {
        free_.push_back(uint32_t(i - 1));  // pop_back hands out low slots first
    }
    if (bind_addr.family() == AF_UNIX) {
        unix_path_ = std::string{bind_addr.path()};
        if (unix_path_.empty() || !prepare_unix_path(bind_addr)) {
            return;
        }
    }
    auto listener = open_listener(bind_addr);
    if (!listener || !mux_.valid()) {
        return;
    }
    listener_ = FileDescriptor{listener->release()};
    (void)set_nonblocking(listener_.get());
    if (!mux_.add(listener_.get(), LISTENER_TAG, true, false)) {
        listener_.close();
    }
}

TcpConnectionPool::~TcpConnectionPool()
{
    if (!owns_unix_path_) {
        return;
    }
    struct stat st{};
    if (::lstat(unix_path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode) && st.st_dev == unix_dev_ && st.st_ino == unix_ino_) {
        (void)::unlink(unix_path_.c_str());
    }
}

auto TcpConnectionPool::prepare_unix_path(SocketAddress const& bind_addr) const -> bool
{
    struct stat st{};
    if (::lstat(unix_path_.c_str(), &st) != 0) {
        return true;  // nothing there (or unreachable: bind reports it)
    }
    if (!S_ISSOCK(st.st_mode)) {
        return false;  // never clobber a non-socket
    }
    // Live or stale? Only a refused connect proves nobody is listening;
    // success or a full backlog (EAGAIN) means a running instance owns it.
    FileDescriptor const probe{::socket(AF_UNIX, options_.unix_seqpacket ? SOCK_SEQPACKET : SOCK_STREAM, 0)};
    if (!probe.valid() || !set_nonblocking(probe.get())) {
        return false;
    }
    if (::connect(probe.get(), bind_addr.sockaddr(), bind_addr.length()) == 0) {
        return false;
    }
    if (errno == ENOENT) {
        return true;  // vanished since lstat
    }
    if (errno != ECONNREFUSED) {
        return false;  // live (EAGAIN/EINPROGRESS) or unknowable: leave it
    }
    // A stale socket from a previous run.
    return ::unlink(unix_path_.c_str()) == 0 || errno == ENOENT;
}

auto TcpConnectionPool::open_listener(SocketAddress const& bind_addr) -> StatusValue<FileDescriptor>
{
    if (!is_unix()) {
        return create_tcp_listener(bind_addr, options_.backlog, options_.dscp);
    }
    // Bound, given its mode and listening inside a private (0700) directory
    // beside the path, then linked into place: the mode never reaches
    // anything but our own socket file, whatever is swapped in at the path,
    // and link(), like bind(), never follows or replaces what is there (a
    // live socket that appeared since prepare_unix_path is refused). Nobody
    // can connect until the socket is at the path, with its final mode.
    // A socket there afterwards is ours to unlink (claim_unix_path).
    // "<dir>/.XXXXXX/s": short, as it must fit sun_path like the path itself.
    auto const slash = unix_path_.rfind('/');
    std::string private_dir = (slash == std::string::npos ? std::string{"."} : unix_path_.substr(0, slash)) + "/.XXXXXX";
    if (::mkdtemp(private_dir.data()) == nullptr) {
        return failure(NetError::bind_failed);
    }
    std::string const private_path = private_dir + "/s";
    auto const discard = [&private_dir, &private_path] {
        (void)::unlink(private_path.c_str());
        (void)::rmdir(private_dir.c_str());
    };
    auto private_addr = SocketAddress::local(private_path);
    if (!private_addr) {
        discard();
        return failure(NetError::bind_failed);  // the path leaves no room for the private directory
    }
    auto listener = options_.unix_seqpacket ? create_seqpacket_socket(*private_addr) : create_tcp_socket(*private_addr, true);
    if (!listener) {
        discard();
        return listener;
    }
    if (options_.unix_mode >= 0 && ::chmod(private_path.c_str(), mode_t(options_.unix_mode)) < 0) {
        discard();
        return failure(NetError::socket_option_failed);
    }
    if (::listen(listener->get(), options_.backlog) < 0) {
        discard();
        return failure(NetError::listen_failed);
    }
    if (::link(private_path.c_str(), unix_path_.c_str()) < 0) {
        discard();
        return failure(NetError::bind_failed);
    }
    discard();
    claim_unix_path();
    return listener;
}

void TcpConnectionPool::claim_unix_path()
{
    // Remember which file bind created so the destructor never unlinks a
    // socket some later process put at the same path.
    struct stat st{};
    if (::lstat(unix_path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        owns_unix_path_ = true;
        unix_dev_ = st.st_dev;
        unix_ino_ = st.st_ino;
    }
}

auto TcpConnectionPool::valid() const noexcept -> bool
{
    return listener_.valid() && mux_.valid();
}

auto TcpConnectionPool::local_addr() const -> StatusValue<SocketAddress>
{
    if (!listener_.valid()) {
        return failure(NetError::not_connected);
    }
    if (is_unix()) {
        // Not getsockname(): the socket was bound in a private directory and
        // linked to the path (open_listener).
        return SocketAddress::local(unix_path_);
    }
    SocketAddress addr;
    addr.reset_length();
    if (::getsockname(listener_.get(), addr.sockaddr(), addr.length_ptr()) < 0) {
        return failure(NetError::bind_failed);
    }
    return addr;
}

auto TcpConnectionPool::read(size_t slot, std::span<uint8_t> out) -> StatusValue<size_t>
{
    if (!slot_ok(slot)) {
        return failure(NetError::invalid_handle);
    }
    auto& s = slots_[slot];
    ssize_t const n = ::recv(s.fd.get(), out.data(), out.size(), 0);
    if (n > 0) {
        s.last_activity_ns = last_now_ns_;
        return size_t(n);
    }
    if (n == 0) {
        return size_t(0);  // orderly EOF
    }
    if (would_block() || was_interrupted()) {
        return failure(NetError::would_block);
    }
    return failure(NetError::receive_failed);
}

auto TcpConnectionPool::write(size_t slot, std::span<uint8_t const> data) -> StatusValue<size_t>
{
    if (!slot_ok(slot)) {
        return failure(NetError::invalid_handle);
    }
    auto& s = slots_[slot];
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t const n = ::send(s.fd.get(), data.data() + sent, data.size() - sent, SEND_FLAGS);
        if (n > 0) {
            sent += size_t(n);
            continue;
        }
        if (would_block()) {
            break;
        }
        if (was_interrupted()) {
            continue;
        }
        return failure(NetError::send_failed);
    }
    s.last_activity_ns = last_now_ns_;
    bool const need_write_interest = sent < data.size();
    if (need_write_interest != s.want_write) {
        s.want_write = need_write_interest;
        (void)mux_.modify(s.fd.get(), uint32_t(slot), true, need_write_interest);
    }
    return sent;
}

void TcpConnectionPool::close(size_t slot)
{
    if (slot_ok(slot)) {
        close_slot(slot, last_now_ns_);
    }
}

auto TcpConnectionPool::peer(size_t slot) const -> SocketAddress const&
{
    assert(slot < slots_.size());
    return slots_[slot].peer;
}

auto TcpConnectionPool::is_open(size_t slot) const noexcept -> bool
{
    return slot_ok(slot);
}

void TcpConnectionPool::on_ready(int64_t now_ns)
{
    last_now_ns_ = now_ns;
    // Drain until the multiplexer is empty. Connection events dispatch as
    // they appear; accepts run after each batch so an event for a slot the
    // handler closed mid-batch can never land on a same-batch replacement.
    // The pass bound guards against a handler that leaves data unread (the
    // level-triggered event would recur forever); leftover readiness then
    // simply re-wakes the outer poll.
    for (int pass = 0; pass < 4; ++pass) {
        bool listener_ready = false;
        int const n = mux_.drain([&](FdMultiplexer::Event const& ev) {
            if (ev.tag == LISTENER_TAG) {
                listener_ready = true;
                return;
            }
            size_t const slot = ev.tag;
            if (!slot_ok(slot)) {
                return;  // closed earlier in this batch
            }
            if (ev.writable && slots_[slot].want_write) {
                handler_.on_writable(slot, now_ns);
            }
            if (ev.readable && slot_ok(slot)) {
                handler_.on_readable(slot, now_ns);
            }
        });
        if (listener_ready) {
            accept_ready(now_ns);
        }
        if (n == 0) {
            break;
        }
    }
}

void TcpConnectionPool::tick(int64_t now_ns)
{
    last_now_ns_ = now_ns;
    if (options_.idle_timeout_ns <= 0) {
        return;
    }
    for (size_t slot = 0; slot < slots_.size(); ++slot) {
        if (slots_[slot].in_use && (now_ns - slots_[slot].last_activity_ns) > options_.idle_timeout_ns) {
            close_slot(slot, now_ns);
        }
    }
}

void TcpConnectionPool::accept_ready(int64_t now_ns)
{
    for (;;) {
        SocketAddress peer;
        peer.reset_length();
        int const fd = ::accept(listener_.get(), peer.sockaddr(), peer.length_ptr());
        if (fd < 0) {
            return;  // EAGAIN (or transient error): nothing more pending
        }
        if (is_unix() && peer.family() != AF_UNIX) {
            // Unnamed peer reported with no address at all: normalise to
            // AF_UNIX with an empty path so peer() stays a valid address.
            peer.sockaddr()->sa_family = AF_UNIX;
            peer.set_length(socklen_t(offsetof(sockaddr_un, sun_path)));
        }
        if (free_.empty()) {
            ::close(fd);
            handler_.on_rejected(peer, now_ns);
            continue;
        }
        set_accepted_options(fd, options_, peer.family());
        size_t const slot = free_.back();
        auto& s = slots_[slot];
        s.fd = FileDescriptor{fd};
        if (!mux_.add(fd, uint32_t(slot), true, false)) {
            s.fd.close();
            handler_.on_rejected(peer, now_ns);
            continue;
        }
        free_.pop_back();
        s.peer = peer;
        s.last_activity_ns = now_ns;
        s.in_use = true;
        s.want_write = false;
        ++active_;
        handler_.on_accept(slot, s.peer, now_ns);
    }
}

void TcpConnectionPool::close_slot(size_t slot, int64_t now_ns)
{
    auto& s = slots_[slot];
    mux_.remove(s.fd.get());
    s.fd.close();
    s.in_use = false;
    s.want_write = false;
    --active_;
    free_.push_back(uint32_t(slot));
    handler_.on_closed(slot, now_ns);
}

}  // namespace statusbar::net
