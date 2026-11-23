// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tcp_server.hpp"

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/test/test.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// Echo handler that also records lifecycle events.
class EchoHandler : public TcpConnectionHandler
{
  public:
    explicit EchoHandler(TcpConnectionPool*& pool)
        : pool_{pool}
    {}

    void on_accept(size_t slot, SocketAddress const&, int64_t) override { accepts.push_back(slot); }

    void on_readable(size_t slot, int64_t) override
    {
        std::array<uint8_t, 1024> buf{};
        for (;;) {
            auto n = pool_->read(slot, buf);
            if (!n) {
                return;  // would_block (or dead — next event handles it)
            }
            if (*n == 0) {
                pool_->close(slot);
                return;
            }
            (void)pool_->write(slot, std::span<uint8_t const>{buf.data(), *n});
        }
    }

    void on_closed(size_t slot, int64_t) override { closes.push_back(slot); }
    void on_rejected(SocketAddress const&, int64_t) override { ++rejects; }

    std::vector<size_t> accepts;
    std::vector<size_t> closes;
    int rejects{0};
    TcpConnectionPool*& pool_;
};

/// Owns a socket path for a test: clears a leftover on the way in, and
/// removes whatever is there on the way out. A failed EXPECT_* leaves a test
/// by return or by exception, so the cleanup has to be a destructor.
class LocalPath
{
  public:
    explicit LocalPath(std::string_view tag)
        : path_{std::string{"/tmp/sb_pool_"} + std::string{tag} + "_" + std::to_string(::getpid()) + ".sock"}
    {
        (void)::unlink(path_.c_str());
        (void)::unlink(lock_str().c_str());
    }
    ~LocalPath()
    {
        (void)::unlink(path_.c_str());
        (void)::unlink(lock_str().c_str());
    }
    LocalPath(LocalPath const&) = delete;
    LocalPath(LocalPath&&) = delete;
    auto operator=(LocalPath const&) -> LocalPath& = delete;
    auto operator=(LocalPath&&) -> LocalPath& = delete;

    [[nodiscard]] auto str() const -> std::string const& { return path_; }
    /// The pool's claim on the path lives in this file beside it.
    [[nodiscard]] auto lock_str() const -> std::string { return path_ + ".lock"; }
    [[nodiscard]] auto lock_exists() const -> bool
    {
        struct stat st{};
        return ::lstat(lock_str().c_str(), &st) == 0;
    }
    [[nodiscard]] auto addr() const -> SocketAddress
    {
        auto a = SocketAddress::local(path_);
        return a ? *a : SocketAddress{};
    }
    [[nodiscard]] auto exists() const -> bool
    {
        struct stat st{};
        return ::lstat(path_.c_str(), &st) == 0;
    }
    [[nodiscard]] auto is_socket() const -> bool
    {
        struct stat st{};
        return ::lstat(path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
    }
    [[nodiscard]] auto mode_bits() const -> unsigned
    {
        struct stat st{};
        if (::lstat(path_.c_str(), &st) != 0) {
            return 0;
        }
        return static_cast<unsigned>(st.st_mode) & 0777U;
    }
    /// Private directories this process's pools staged a socket in and did
    /// not remove: entries beside the path named ".sb<pid>.".
    [[nodiscard]] auto staging_leftovers() const -> int { return count_staging_leftovers(path_); }

    static auto count_staging_leftovers(std::string const& socket_path) -> int
    {
        std::string const dir = socket_path.substr(0, socket_path.rfind('/'));
        std::string const prefix = ".sb" + std::to_string(::getpid()) + ".";
        DIR* d = ::opendir(dir.c_str());
        if (d == nullptr) {
            return -1;
        }
        int count = 0;
        for (struct dirent* e = ::readdir(d); e != nullptr; e = ::readdir(d)) {
            if (std::string_view{e->d_name}.starts_with(prefix)) {
                ++count;
            }
        }
        ::closedir(d);
        return count;
    }

  private:
    std::string path_;
};

}  // namespace

TEST_MAIN(statusbar_net, net_tcp_server_test)

//
// AF_UNIX local control socket
//

TEST(net_tcp_server_local, a_regular_file_at_the_path_is_left_alone)
{
    LocalPath const path{"regular"};
    {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        std::FILE* f = std::fopen(path.str().c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        if (f != nullptr) {
            EXPECT_EQ(std::fwrite("keep", 4, 1, f), size_t{1});
            (void)std::fclose(f);
        }
    }

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());

    // Not a socket, so not ours to delete -- whatever it is, it is still here.
    EXPECT_TRUE(path.exists());
    EXPECT_FALSE(path.is_socket());
}

TEST(net_tcp_server_local, a_dangling_symlink_at_the_path_is_refused)
{
    LocalPath const path{"dangling"};
    std::string const target = path.str() + ".missing";
    (void)::unlink(target.c_str());
    EXPECT_EQ(::symlink(target.c_str(), path.str().c_str()), 0);

    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpConnectionPool pool{path.addr(), 2, handler};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());

    // Nothing was created where it pointed: bind() does not follow a trailing
    // symlink either, so this one is refused twice over.
    struct stat st{};
    EXPECT_EQ(::lstat(path.str().c_str(), &st), 0);
    EXPECT_TRUE(S_ISLNK(st.st_mode));
    EXPECT_TRUE(::lstat(target.c_str(), &st) != 0);

    (void)::unlink(target.c_str());
}

TEST(net_tcp_server_local, a_value_that_is_not_a_mode_is_refused_before_the_path_is_claimed)
{
    LocalPath const path{"badmode"};
    TcpConnectionPool* pool_ptr = nullptr;
    EchoHandler handler{pool_ptr};
    TcpServerOptions options;
    options.unix_mode = 010000;  // one bit above the mode bits
    TcpConnectionPool pool{path.addr(), 2, handler, options};
    pool_ptr = &pool;
    EXPECT_FALSE(pool.valid());
    // Refused before anything was made: no socket, no lock, no staging.
    EXPECT_FALSE(path.exists());
    EXPECT_FALSE(path.lock_exists());
    EXPECT_EQ(path.staging_leftovers(), 0);
}

TEST(net_tcp_server_local, a_path_whose_directory_is_too_long_to_stage_in_is_refused_and_nothing_is_left)
{
    // A directory name that leaves the socket path two bytes inside
    // sun_path's limit: the path fits, the staged name beside it
    // ("<dir>/.sb<pid>.XXXXXX/s") cannot. The directory itself is made for
    // the test and removed after it.
    std::string const name{"/s.sock"};
    std::string dir{"/tmp/sb_pool_longdir_" + std::to_string(::getpid()) + "_"};
    dir.append(sizeof(sockaddr_un{}.sun_path) - 2 - name.size() - dir.size(), 'x');
    EXPECT_EQ(::mkdir(dir.c_str(), 0700), 0);
    std::string const path = dir + name;
    auto const addr = SocketAddress::local(path);
    EXPECT_TRUE(addr.has_value());

    {
        TcpConnectionPool* pool_ptr = nullptr;
        EchoHandler handler{pool_ptr};
        TcpConnectionPool pool{*addr, 2, handler};
        pool_ptr = &pool;
        EXPECT_FALSE(pool.valid());
        struct stat st{};
        EXPECT_TRUE(::lstat(path.c_str(), &st) != 0);
        EXPECT_EQ(LocalPath::count_staging_leftovers(path), 0);
    }
    // The lock went with the pool; the directory is empty again.
    EXPECT_EQ(::rmdir(dir.c_str()), 0);
}
