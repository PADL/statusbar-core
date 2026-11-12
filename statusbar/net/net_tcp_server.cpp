// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <utility>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
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

/// The lock file that stands for a socket path: the path with ".lock"
/// appended, beside the socket.
auto lock_path_for(std::string const& socket_path) -> std::string
{
    return socket_path + ".lock";
}

/// Whether @p fd is still the file at @p path. A holder that released
/// between our open() and our flock() unlinked the file we hold, so the
/// lock we won guards a name nobody can find any more.
auto fd_is_the_file_at(int fd, std::string const& path) -> bool
{
    struct stat held{};
    struct stat at_path{};
    if (::fstat(fd, &held) < 0 || ::lstat(path.c_str(), &at_path) < 0) {
        return false;
    }
    return held.st_dev == at_path.st_dev && held.st_ino == at_path.st_ino;
}

/// How one attempt at the lock ended.
enum class ClaimOutcome
{
    claimed,  ///< ours: the descriptor holds the lock
    held,     ///< somebody else has it: a second instance at this path
    swapped,  ///< the holder released and unlinked under us: try again
};

struct ClaimAttempt
{
    ClaimOutcome outcome{ClaimOutcome::held};
    FileDescriptor lock{};
};

/// One attempt at the lock. An error means the file cannot be ours at all
/// (a symlink, somebody else's regular file, a directory we cannot write),
/// which the caller reports as bind_failed.
auto try_claim(std::string const& lock_path) -> StatusValue<ClaimAttempt>
{
    // O_NOFOLLOW: a symlink planted at the lock name is refused, not
    // followed to a file of the planter's choosing. 0600: the lock is a
    // token, nobody else needs to read it.
    int const fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return failure(NetError::bind_failed);
    }
    ClaimAttempt attempt{.outcome = ClaimOutcome::claimed, .lock = FileDescriptor{fd}};
    if (::flock(attempt.lock.get(), LOCK_EX | LOCK_NB) < 0) {
        if (errno != EWOULDBLOCK) {
            return failure(NetError::bind_failed);
        }
        attempt.outcome = ClaimOutcome::held;
    } else if (!fd_is_the_file_at(attempt.lock.get(), lock_path)) {
        attempt.outcome = ClaimOutcome::swapped;
    }
    return attempt;
}

/// Claim the socket path for this listener's lifetime: an exclusive
/// flock() on its lock file. Two instances starting at one path then
/// contend on the lock, not on the stale-socket probe below, which cannot
/// tell "bound, about to listen" from "left behind by a dead process" --
/// both answer ECONNREFUSED. The probe stays for a listener that predates
/// the lock; the lock is what closes the race between two of ours.
auto claim_socket_path(std::string const& lock_path) -> StatusValue<FileDescriptor>
{
    constexpr int ATTEMPTS = 3;
    for (int attempt = 0; attempt < ATTEMPTS; ++attempt) {
        auto tried = try_claim(lock_path);
        if (!tried) {
            return failure(tried.error());
        }
        if (tried->outcome == ClaimOutcome::claimed) {
            return std::move(tried->lock);
        }
        if (tried->outcome == ClaimOutcome::held) {
            return failure(NetError::bind_failed);
        }
    }
    return failure(NetError::bind_failed);  // swapped three times running
}

/// Let the path go: remove the lock file while still holding the lock (so
/// nobody can open it between the unlink and the close and believe they
/// hold a live name), then close. A file that replaced ours is left alone.
void release_socket_path(FileDescriptor& lock, std::string const& lock_path)
{
    if (!lock.valid()) {
        return;
    }
    if (fd_is_the_file_at(lock.get(), lock_path)) {
        (void)::unlink(lock_path.c_str());
    }
    lock.close();
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
    LocalSocketFile file{};
};

/// Clear what is at @p path when it is ours to clear; refuse otherwise.
auto clear_socket_path(std::string const& path, int sock_type) -> Status
{
    switch (inspect_socket_path(path, sock_type)) {
        case PathVerdict::absent:
            return success();
        case PathVerdict::stale:
            return (::unlink(path.c_str()) < 0) ? failure(NetError::bind_failed) : success();
        case PathVerdict::occupied:
        case PathVerdict::unusable:
            return failure(NetError::bind_failed);
    }
    return failure(NetError::bind_failed);
}

/// Record the socket file bind() just made. Ownership is its device and
/// inode read back from the filesystem -- fstat() on the socket reports the
/// socket's own inode, which is a different number. From here every failure
/// has to remove the file.
auto record_socket_file(LocalListener listener, std::string const& path) -> StatusValue<LocalListener>
{
    struct stat bound{};
    if (::lstat(path.c_str(), &bound) < 0 || S_ISSOCK(bound.st_mode) == 0) {
        (void)::unlink(path.c_str());
        return failure(NetError::bind_failed);
    }
    listener.file.path = path;
    listener.file.dev = static_cast<uint64_t>(bound.st_dev);
    listener.file.ino = static_cast<uint64_t>(bound.st_ino);
    return listener;
}

/// Where the socket is made before it has its public name: a fresh 0700
/// directory beside the final path, so nothing but this process can reach
/// the file while it is bound, given its mode and linked into place.
struct StagedSocket
{
    std::string dir{};   ///< the private directory, ours alone
    std::string path{};  ///< "<dir>/s": where bind() makes the file
};

/// The mkdtemp() template for a socket at @p socket_path: in its directory,
/// hidden, and named for this process so a test can see what one left.
auto staging_template_for(std::string const& socket_path) -> std::string
{
    auto const slash = socket_path.rfind('/');
    std::string const dir = (slash == 0) ? std::string{} : socket_path.substr(0, slash);
    return dir + "/.sb" + std::to_string(::getpid()) + ".XXXXXX";
}

/// A private directory for the socket to be made in. mkdtemp() makes it
/// 0700 whatever the umask.
auto make_staging(std::string const& socket_path) -> StatusValue<StagedSocket>
{
    std::string dir = staging_template_for(socket_path);
    if (::mkdtemp(dir.data()) == nullptr) {
        return failure(NetError::bind_failed);
    }
    return StagedSocket{.dir = dir, .path = dir + "/s"};
}

/// Remove the private directory and whatever is still in it: the staged
/// name once the socket has its public one, or the whole attempt when it
/// failed.
void remove_staging(StagedSocket const& staged)
{
    (void)::unlink(staged.path.c_str());
    (void)::rmdir(staged.dir.c_str());
}

/// A fresh socket bound at @p path.
auto bind_at(SocketAddress const& addr, std::string const& path, int sock_type) -> StatusValue<LocalListener>
{
    int const fd = ::socket(AF_UNIX, sock_type, 0);
    if (fd < 0) {
        return failure(NetError::socket_creation_failed);
    }
    LocalListener listener{.fd = FileDescriptor{fd}, .file = {}};
    // No SO_REUSEADDR: on AF_UNIX it does nothing, and the public path has
    // already been dealt with.
    if (::bind(fd, addr.sockaddr(), addr.length()) < 0) {
        return failure(NetError::bind_failed);
    }
    return record_socket_file(std::move(listener), path);
}

/// The socket, bound at its staged name. A socket path within the staged
/// name's extra length of sun_path's limit cannot be staged and is refused
/// as invalid_address, the same answer as a path that does not fit at all.
auto bind_socket_file(StagedSocket const& staged, int sock_type) -> StatusValue<LocalListener>
{
    auto const addr = SocketAddress::local(staged.path);
    if (!addr) {
        return failure(NetError::invalid_address);
    }
    return bind_at(*addr, staged.path, sock_type);
}

/// The requested mode, put on the file while it is still inside the private
/// directory, where nobody can swap a symlink in under the chmod.
auto apply_mode(LocalListener listener, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    if (options.unix_mode >= 0 && ::chmod(listener.file.path.c_str(), static_cast<mode_t>(options.unix_mode)) < 0) {
        return failure(NetError::socket_option_failed);
    }
    return listener;
}

/// The socket's public name: link() the staged file to @p path. A link
/// fails with EEXIST rather than replace whatever appeared at the name
/// since it was cleared, and the name is then checked to be our file by
/// device and inode before anything trusts it.
auto move_into_place(LocalListener listener, std::string const& path) -> StatusValue<LocalListener>
{
    if (::link(listener.file.path.c_str(), path.c_str()) < 0) {
        return failure(NetError::bind_failed);
    }
    struct stat at_path{};
    if (::lstat(path.c_str(), &at_path) < 0 || static_cast<uint64_t>(at_path.st_dev) != listener.file.dev ||
        static_cast<uint64_t>(at_path.st_ino) != listener.file.ino) {
        unlink_if_ours(path, listener.file.dev, listener.file.ino);
        return failure(NetError::bind_failed);
    }
    listener.file.path = path;
    return listener;
}

/// Bind in the private directory, give the file its mode there, and link
/// it to @p path.
auto make_socket_file(StagedSocket const& staged, std::string const& path, TcpServerOptions const& options)
    -> StatusValue<LocalListener>
{
    int const sock_type = options.unix_seqpacket ? SOCK_SEQPACKET : SOCK_STREAM;
    auto bound = bind_socket_file(staged, sock_type);
    if (!bound) {
        return failure(bound.error());
    }
    auto moded = apply_mode(std::move(*bound), options);
    if (!moded) {
        return failure(moded.error());
    }
    return move_into_place(std::move(*moded), path);
}

/// The whole staged pass: the private directory comes and goes within it,
/// whether the socket reached its public name or not.
auto stage_socket_file(std::string const& path, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    auto staged = make_staging(path);
    if (!staged) {
        return failure(staged.error());
    }
    auto made = make_socket_file(*staged, path, options);
    remove_staging(*staged);
    return made;
}

/// listen(): from here the socket answers at its name, already with its
/// mode. A refusal removes the file, which is ours by device and inode.
auto serve_socket_file(LocalListener listener, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    auto const& file = listener.file;
    if (::listen(listener.fd.get(), options.backlog) < 0) {
        unlink_if_ours(file.path, file.dev, file.ino);
        return failure(NetError::listen_failed);
    }
    return listener;
}

/// Clear a stale socket at @p path, make the new one beside it in a private
/// directory and link it into place, then listen. The path is already
/// claimed; a failure leaves nothing of ours behind.
auto bind_local_listener(std::string const& path, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    int const sock_type = options.unix_seqpacket ? SOCK_SEQPACKET : SOCK_STREAM;
    if (auto cleared = clear_socket_path(path, sock_type); !cleared) {
        return failure(cleared.error());
    }
    auto made = stage_socket_file(path, options);
    if (!made) {
        return failure(made.error());
    }
    return serve_socket_file(std::move(*made), options);
}

/// Bind under a claim already taken: the claim travels with the listener on
/// success and is let go on failure.
auto bind_under_claim(FileDescriptor lock, std::string const& path, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    auto bound = bind_local_listener(path, options);
    if (!bound) {
        release_socket_path(lock, lock_path_for(path));
        return failure(bound.error());
    }
    bound->file.lock = std::move(lock);
    return std::move(*bound);
}

/// Whether @p mode is a file mode at all. Anything else is refused before
/// the path is touched rather than discovered by chmod() after bind().
auto usable_mode(int mode) -> bool
{
    return mode <= 07777;
}

/// Claim the path, then make the socket, give it the path and listen. From
/// the claim to the pool's destructor this process is the one allowed to
/// clear, bind and remove it.
auto create_local_listener(SocketAddress const& addr, TcpServerOptions const& options) -> StatusValue<LocalListener>
{
    std::string const path{addr.path()};
    if (path.empty() || !usable_mode(options.unix_mode)) {
        // An unnamed or abstract address has no file to own or protect; a
        // value that is not a mode has nothing to be applied to.
        return failure(path.empty() ? NetError::invalid_address : NetError::invalid_argument);
    }
    auto lock = claim_socket_path(lock_path_for(path));
    if (!lock) {
        return failure(lock.error());
    }
    return bind_under_claim(std::move(*lock), path, options);
}

/// A listener that was bound but will never serve: remove its file and let
/// the path go, since nobody else will.
void abandon_local_listener(LocalListener& listener)
{
    auto& file = listener.file;
    unlink_if_ours(file.path, file.dev, file.ino);
    release_socket_path(file.lock, lock_path_for(file.path));
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
        abandon_local_listener(*local);
        return;
    }
    unix_ = std::move(local->file);
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
    // The socket file first, the claim on the path last: a successor
    // waiting on the lock finds the path clear when it wins.
    unlink_if_ours(unix_.path, unix_.dev, unix_.ino);
    release_socket_path(unix_.lock, lock_path_for(unix_.path));
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
    if (!unix_.path.empty()) {
        // The public name. getsockname() would answer the staged one the
        // socket was bound at, which no longer exists.
        return SocketAddress::local(unix_.path);
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
    finish_write(slot, sent < data.size());
    return sent;
}

void TcpConnectionPool::finish_write(size_t slot, bool unsent)
{
    auto& s = slots_[slot];
    s.last_activity_ns = last_now_ns_;
    if (unsent != s.want_write) {
        s.want_write = unsent;
        (void)mux_.modify(s.fd.get(), uint32_t(slot), s.want_read, unsent);
    }
}

void TcpConnectionPool::set_read_interest(size_t slot, bool want_read)
{
    if (!slot_ok(slot) || slots_[slot].want_read == want_read) {
        return;
    }
    auto& s = slots_[slot];
    s.want_read = want_read;
    (void)mux_.modify(s.fd.get(), uint32_t(slot), want_read, s.want_write);
}

auto TcpConnectionPool::read_interest(size_t slot) const noexcept -> bool
{
    return slot_ok(slot) && slots_[slot].want_read;
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
            if (ev.readable && slot_ok(slot) && slots_[slot].want_read) {
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
        adopt_accepted(fd, peer, now_ns);
    }
}

void TcpConnectionPool::adopt_accepted(int fd, SocketAddress const& peer, int64_t now_ns)
{
    set_accepted_options(fd, options_, peer.family());
    size_t const slot = free_.back();
    if (!mux_.add(fd, uint32_t(slot), true, false)) {
        ::close(fd);
        handler_.on_rejected(peer, now_ns);
        return;
    }
    slots_[claim_slot()].open(fd, peer, now_ns);
    handler_.on_accept(slot, peer, now_ns);
}

auto TcpConnectionPool::claim_slot() -> size_t
{
    size_t const slot = free_.back();
    free_.pop_back();
    ++active_;
    return slot;
}

void TcpConnectionPool::close_slot(size_t slot, int64_t now_ns)
{
    auto& s = slots_[slot];
    mux_.remove(s.fd.get());
    s.close();
    --active_;
    free_.push_back(uint32_t(slot));
    handler_.on_closed(slot, now_ns);
}

}  // namespace statusbar::net
