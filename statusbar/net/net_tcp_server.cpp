// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include <poll.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <utility>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

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
    (void)set_nonblocking(fd);
    // TCP_NODELAY and DSCP are TCP and IP notions. On an AF_UNIX connection
    // there is no Nagle to disable and no IP header to mark, so they are
    // skipped rather than attempted and ignored.
    bool const is_local = family == AF_UNIX;
    if (options.nodelay && !is_local) {
        int const one = 1;
        (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    if (options.dscp >= 0 && !is_local) {
        (void)set_dscp(fd, family, uint8_t(options.dscp));
    }
#if defined(SO_NOSIGPIPE)
    int const one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

#if defined(POLLRDHUP)
constexpr short PEER_SHUT_DOWN = POLLRDHUP | POLLHUP;
#else
constexpr short PEER_SHUT_DOWN = POLLHUP;
#endif

/// After a read of 0 on SOCK_SEQPACKET @p fd: true for EOF (the peer shut down, nothing queued: Linux's
/// FIONREAD sums a seqpacket queue, so only empty messages read as nothing), false for an empty message.
/// A failed poll counts as EOF, so the read cannot spin on it.
[[nodiscard]] auto seqpacket_eof(int const fd) noexcept -> bool
{
    pollfd peer{.fd = fd, .events = PEER_SHUT_DOWN, .revents = 0};
    int const ready = ::poll(&peer, 1, 0);
    if (ready >= 0 && (ready == 0 || (peer.revents & PEER_SHUT_DOWN) == 0)) {
        return false;
    }
    int queued = 0;
    return ::ioctl(fd, FIONREAD, &queued) < 0 || queued == 0;
}

/// One message of SOCK_SEQPACKET @p fd into @p out: recvmsg()'s result, and
/// @p truncated when it was longer than @p out (the rest discarded).
/// recvmsg()'s MSG_TRUNC output flag is POSIX, unlike recv()'s input flag.
[[nodiscard]] auto receive_one(int const fd, std::span<uint8_t> const out, bool& truncated) noexcept -> ssize_t
{
    iovec io{.iov_base = out.data(), .iov_len = out.size()};
    msghdr message{.msg_iov = &io, .msg_iovlen = 1};
    ssize_t const n = ::recvmsg(fd, &message, 0);
    truncated = n >= 0 && (message.msg_flags & MSG_TRUNC) != 0;
    return n;
}

/// Empty messages read in a row before a seqpacket read gives up for now (would_block).
constexpr size_t MAX_EMPTY_MESSAGES = 64;

/// One non-empty message of SOCK_SEQPACKET @p fd into @p out, as receive_one(); 0 for EOF. A run of
/// MAX_EMPTY_MESSAGES empty ones (a half-closed peer raises no POLLHUP without POLLRDHUP) is EAGAIN.
[[nodiscard]] auto receive_message(int const fd, std::span<uint8_t> const out, bool& truncated) noexcept -> ssize_t
{
    for (size_t empty = 0; empty < MAX_EMPTY_MESSAGES; ++empty) {
        ssize_t const n = receive_one(fd, out, truncated);
        if (n != 0 || truncated || seqpacket_eof(fd)) {
            return n;
        }
    }
    errno = EAGAIN;
    return -1;
}

/// Remove a socket file only while it is still the one we created. Compared
/// by device and inode rather than by path: between bind and here, somebody
/// may have replaced the name, and unlinking by path would delete their file.
void unlink_if_ours(std::string const& path, uint64_t dev, uint64_t ino)
{
    if (path.empty()) {
        return;
    }
    struct stat st{};
    if (::lstat(path.c_str(), &st) < 0) {
        return;  // already gone
    }
    if (static_cast<uint64_t>(st.st_dev) != dev || static_cast<uint64_t>(st.st_ino) != ino) {
        return;  // not ours any more
    }
    (void)::unlink(path.c_str());
}

/// What is sitting at a socket path we have been asked to bind.
enum class PathVerdict
{
    absent,    ///< nothing there; bind away
    stale,     ///< a socket file nobody is listening on: ours to replace
    occupied,  ///< something is listening: a second instance must not steal it
    unusable,  ///< not a socket, or a symlink: not ours to remove either
};

auto inspect_socket_path(std::string const& path, int sock_type) -> PathVerdict
{
    struct stat st{};
    if (::lstat(path.c_str(), &st) < 0) {
        return (errno == ENOENT) ? PathVerdict::absent : PathVerdict::unusable;
    }
    // lstat, never stat: a symlink must report as a symlink, so it fails the
    // test below and is refused. Through stat() a link pointing at somebody
    // else's stale socket would read as stale, and "replace the stale socket"
    // would delete the link and bind in its place -- or, with a live target,
    // probe through it. A regular file is not ours to delete either.
    if (!S_ISSOCK(st.st_mode)) {
        return PathVerdict::unusable;
    }

    auto probe_addr = SocketAddress::local(path);
    if (!probe_addr) {
        return PathVerdict::unusable;
    }
    // The listener's own socket type, so a live peer answers the probe
    // outright instead of through an error code. It is not what makes the
    // verdict safe -- that is the ECONNREFUSED rule below, which refuses to
    // call anything else stale whatever type is at the path.
    int const probe = ::socket(AF_UNIX, sock_type, 0);
    if (probe < 0) {
        return PathVerdict::unusable;
    }
    (void)set_nonblocking(probe);
    int const rc = ::connect(probe, probe_addr->sockaddr(), probe_addr->length());
    int const err = (rc == 0) ? 0 : errno;
    ::close(probe);

    if (rc == 0) {
        return PathVerdict::occupied;  // somebody answered
    }
    // ECONNREFUSED is the one answer that means nobody is listening. ENOENT
    // means it vanished under us, which is just as good. Everything else --
    // EAGAIN from a full backlog, EPROTOTYPE from a live socket of the other
    // type, a permission error -- is a reason to leave the path alone.
    if (err == ECONNREFUSED || err == ENOENT) {
        return PathVerdict::stale;
    }
    return PathVerdict::occupied;
}

struct LocalListener
{
    FileDescriptor fd{};
    uint64_t dev{0};
    uint64_t ino{0};
};

/// The staged name "<dir>/.XXXXXX/s" beside @p path is this much longer than <dir>.
constexpr size_t STAGED_SUFFIX = sizeof("/.XXXXXX/s") - 1;

/// Whether the staged name beside @p path fits sun_path: not for a short basename near the limit.
[[nodiscard]] auto staged_name_fits(std::string const& path) noexcept -> bool
{
    auto const slash = path.rfind('/');
    size_t const dir = slash == std::string::npos ? 1 : slash;
    return dir + STAGED_SUFFIX < sizeof(sockaddr_un::sun_path);
}

/// A fresh private (0700) directory "<dir>/.XXXXXX" beside @p path, to stage its socket in.
[[nodiscard]] auto make_private_dir(std::string const& path) -> StatusValue<std::string>
{
    auto const slash = path.rfind('/');
    std::string dir = (slash == std::string::npos ? std::string{"."} : path.substr(0, slash)) + "/.XXXXXX";
    if (::mkdtemp(dir.data()) == nullptr) {
        return failure(NetError::bind_failed);
    }
    return dir;
}

/// A socket of @p sock_type bound at @p staged.
[[nodiscard]] auto bind_staged(std::string const& staged, int const sock_type) -> StatusValue<FileDescriptor>
{
    auto const addr = SocketAddress::local(staged);
    FileDescriptor sock{::socket(AF_UNIX, sock_type, 0)};
    if (!addr || !sock.valid()) {
        return failure(addr ? NetError::socket_creation_failed : NetError::invalid_address);
    }
    if (::bind(sock.get(), addr->sockaddr(), addr->length()) < 0) {
        return failure(NetError::bind_failed);
    }
    return sock;
}

/// The listener @p sock bound at @p staged, with that file's device and inode
/// (fstat() on the socket reports the socket's own inode). Read inside the
/// private directory, before the link puts the same inode at the path.
[[nodiscard]] auto claim_staged(std::string const& staged, FileDescriptor sock) -> StatusValue<LocalListener>
{
    struct stat bound{};
    if (::lstat(staged.c_str(), &bound) < 0 || S_ISSOCK(bound.st_mode) == 0) {
        return failure(NetError::bind_failed);
    }
    return LocalListener{
        .fd = std::move(sock), .dev = static_cast<uint64_t>(bound.st_dev), .ino = static_cast<uint64_t>(bound.st_ino)};
}

/// A socket of @p sock_type bound at @p staged, given its mode and listening.
[[nodiscard]] auto listen_staged(std::string const& staged, int const sock_type, TcpServerOptions const& options)
    -> StatusValue<LocalListener>
{
    auto sock = bind_staged(staged, sock_type);
    if (!sock) {
        return failure(sock.error());
    }
    if (options.unix_mode >= 0 && ::chmod(staged.c_str(), static_cast<mode_t>(options.unix_mode)) < 0) {
        return failure(NetError::socket_option_failed);
    }
    if (::listen(sock->get(), options.backlog) < 0) {
        return failure(NetError::listen_failed);
    }
    return claim_staged(staged, std::move(*sock));
}

/// Remove the staged name and its directory, whatever became of them.
void remove_staged(std::string const& staged, std::string const& dir) noexcept
{
    (void)::unlink(staged.c_str());
    (void)::rmdir(dir.c_str());
}

/// The listener staged in @p dir, hard-linked to @p path. link(), like
/// bind(), neither follows nor replaces what is at the path. The staged name
/// and its directory are removed either way.
[[nodiscard]] auto link_staged(
    std::string const& dir, std::string const& path, int const sock_type, TcpServerOptions const& options)
    -> StatusValue<LocalListener>
{
    std::string const staged = dir + "/s";
    auto local = listen_staged(staged, sock_type, options);
    bool const linked = local.has_value() && ::link(staged.c_str(), path.c_str()) == 0;
    remove_staged(staged, dir);
    if (local && !linked) {
        return failure(NetError::bind_failed);
    }
    return local;
}

/// Make way at @p path: nothing there, or a stale socket that is removed.
/// A live socket, anything that is not a socket, or a path that cannot be
/// inspected is refused.
[[nodiscard]] auto clear_socket_path(std::string const& path, int const sock_type) -> Status
{
    switch (inspect_socket_path(path, sock_type)) {
        case PathVerdict::absent:
            return success();
        case PathVerdict::stale:
            return ::unlink(path.c_str()) == 0 ? success() : failure(NetError::bind_failed);
        case PathVerdict::occupied:
        case PathVerdict::unusable:
            break;
    }
    return failure(NetError::bind_failed);
}

/// Bind, chmod and listen in a private directory, then link into place, so
/// the socket never answers at its path before its mode is final and a path
/// swapped for a symlink is never followed by chmod().
auto create_local_listener(SocketAddress const& addr, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    std::string const path{addr.path()};
    if (path.empty()) {
        // An unnamed or abstract address has no file to own or protect.
        return failure(NetError::invalid_address);
    }
    int const sock_type = options.unix_seqpacket ? SOCK_SEQPACKET : SOCK_STREAM;
    if (auto const cleared = clear_socket_path(path, sock_type); !cleared) {
        return failure(cleared.error());
    }
    if (!staged_name_fits(path)) {
        return listen_staged(path, sock_type, options);  // bound in place: the mode follows the bind
    }
    return make_private_dir(path).and_then([&](std::string const& dir) { return link_staged(dir, path, sock_type, options); });
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
        open_local_listener(bind_addr);
    } else {
        open_tcp_listener(bind_addr);
    }
}

void TcpConnectionPool::open_local_listener(SocketAddress const& bind_addr)
{
    auto local = create_local_listener(bind_addr, options_);
    if (!local) {
        return;
    }
    if (!mux_.valid() || !register_listener(local->fd.release())) {
        // Bound but never serving: the socket file bind() just made is
        // ours to remove, and nobody else will. The destructor goes by
        // the path recorded below, which this path never reaches.
        unlink_if_ours(std::string{bind_addr.path()}, local->dev, local->ino);
        return;
    }
    unix_path_ = std::string{bind_addr.path()};
    unix_dev_ = local->dev;
    unix_ino_ = local->ino;
}

void TcpConnectionPool::open_tcp_listener(SocketAddress const& bind_addr)
{
    auto listener = create_tcp_listener(bind_addr, options_.backlog, options_.dscp);
    if (!listener || !mux_.valid()) {
        return;
    }
    (void)register_listener(listener->release());
}

auto TcpConnectionPool::register_listener(int fd) -> bool
{
    listener_ = FileDescriptor{fd};
    (void)set_nonblocking(listener_.get());
    if (mux_.add(listener_.get(), LISTENER_TAG, true, false)) {
        return true;
    }
    listener_.close();
    return false;
}

TcpConnectionPool::~TcpConnectionPool()
{
    unlink_if_ours(unix_path_, unix_dev_, unix_ino_);
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
    if (!unix_path_.empty()) {
        // Not getsockname(): the socket was bound under a staged name.
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
    return options_.unix_seqpacket && !unix_path_.empty() ? read_message(s, out) : read_stream(s, out);
}

auto TcpConnectionPool::read_stream(Slot& s, std::span<uint8_t> const out) -> StatusValue<size_t>
{
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

auto TcpConnectionPool::read_message(Slot& s, std::span<uint8_t> const out) -> StatusValue<size_t>
{
    bool truncated = false;
    ssize_t const n = receive_message(s.fd.get(), out, truncated);
    if (n < 0) {
        return failure(would_block() || was_interrupted() ? NetError::would_block : NetError::receive_failed);
    }
    if (n > 0) {
        s.last_activity_ns = last_now_ns_;  // as a stream read: EOF is not activity
    }
    return truncated ? StatusValue<size_t>{failure(NetError::buffer_full)} : static_cast<size_t>(n);
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
