// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
// write_file_durably(): the bytes arrive whole, a target is replaced in one
// step, no temporary is left behind, a temporary left by a crashed earlier
// life is overwritten, an interrupted write is resumed, and a directory that
// is not there is the errno.
#include "statusbar/buffer/file_write.hpp"

#include "statusbar/test/test.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/ioctl.h>
#include <sys/stat.h>

using namespace statusbar;

namespace {

/// A fresh directory under the temp root, removed with its contents on destruction.
class TempDir
{
  public:
    TempDir()
    {
        char name[] = "/tmp/statusbar_file_write_test_XXXXXX";
        path_ = ::mkdtemp(name) != nullptr ? name : "";
    }
    ~TempDir()
    {
        if (path_.empty()) {
            return;
        }
        if (DIR* const dir = ::opendir(path_.c_str()); dir != nullptr) {
            while (dirent const* entry = ::readdir(dir)) {
                if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0) {
                    (void)::unlink((path_ + "/" + entry->d_name).c_str());
                }
            }
            (void)::closedir(dir);
        }
        (void)::rmdir(path_.c_str());
    }
    TempDir(TempDir const&) = delete;
    auto operator=(TempDir const&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;

    [[nodiscard]] auto path() const -> std::string const& { return path_; }
    [[nodiscard]] auto file(std::string_view const name) const -> std::string { return path_ + "/" + std::string{name}; }

    /// The names in the directory, "." and ".." left out.
    [[nodiscard]] auto entries() const -> std::vector<std::string>
    {
        std::vector<std::string> names;
        if (DIR* const dir = ::opendir(path_.c_str()); dir != nullptr) {
            while (dirent const* entry = ::readdir(dir)) {
                if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0) {
                    names.emplace_back(entry->d_name);
                }
            }
            (void)::closedir(dir);
        }
        return names;
    }

  private:
    std::string path_{};
};

auto read_all(std::string const& path) -> std::vector<uint8_t>
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

auto bytes_of(std::string_view const text) -> std::vector<uint8_t>
{
    return {text.begin(), text.end()};
}

[[nodiscard]] auto errno_of(std::error_code const& ec) -> int
{
    return ec.category() == std::system_category() ? ec.value() : -1;
}

/// How many times the handler has run. A lock-free atomic is the one thing
/// a handler may write that another thread may wait on.
std::atomic<int> signals_handled{0};

extern "C" void note_the_signal(int /*signal*/)
{
    signals_handled.fetch_add(1, std::memory_order_relaxed);
}

/// Bytes waiting in a pipe, as its read end sees them.
auto bytes_in_pipe(int const read_fd) -> int
{
    int waiting = 0;
    (void)::ioctl(read_fd, FIONREAD, &waiting);
    return waiting;
}

/// SIGUSR1 handled without SA_RESTART for the life of this object, so a
/// blocking write() the signal lands on returns EINTR instead of resuming.
class InterruptingSignal
{
  public:
    InterruptingSignal()
    {
        struct sigaction action{};
        action.sa_handler = note_the_signal;
        action.sa_flags = 0;
        (void)sigemptyset(&action.sa_mask);  // a macro on Darwin, so unqualified
        (void)::sigaction(SIGUSR1, &action, &previous_);
    }
    ~InterruptingSignal() { (void)::sigaction(SIGUSR1, &previous_, nullptr); }
    InterruptingSignal(InterruptingSignal const&) = delete;
    auto operator=(InterruptingSignal const&) -> InterruptingSignal& = delete;
    InterruptingSignal(InterruptingSignal&&) = delete;
    auto operator=(InterruptingSignal&&) -> InterruptingSignal& = delete;

  private:
    struct sigaction previous_{};
};

/// Everything readable from `fd` until end of file.
auto drain(int const fd) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    std::vector<uint8_t> chunk(65536);
    for (;;) {
        ssize_t const got = ::read(fd, chunk.data(), chunk.size());
        if (got <= 0) {
            return out;
        }
        out.insert(out.end(), chunk.begin(), chunk.begin() + got);
    }
}

}  // namespace

TEST(file_write, the_bytes_arrive_whole_and_no_temporary_is_left)
{
    TempDir const dir;
    EXPECT_FALSE(dir.path().empty());
    auto const content = bytes_of("the quick brown fox\n");
    EXPECT_TRUE(write_file_durably(dir.file("model.bin"), content).has_value());
    EXPECT_TRUE(read_all(dir.file("model.bin")) == content);
    auto const names = dir.entries();
    EXPECT_EQ(names.size(), size_t{1});
    EXPECT_TRUE(names.size() == 1 && names[0] == "model.bin");

    struct stat st{};
    EXPECT_EQ(::stat(dir.file("model.bin").c_str(), &st), 0);
    EXPECT_EQ(static_cast<size_t>(st.st_size), content.size());
}

TEST(file_write, an_existing_target_is_replaced_whole)
{
    TempDir const dir;
    EXPECT_TRUE(write_file_durably(dir.file("state"), bytes_of("one two three")).has_value());
    EXPECT_TRUE(write_file_durably(dir.file("state"), bytes_of("four")).has_value());
    EXPECT_TRUE(read_all(dir.file("state")) == bytes_of("four"));  // not "four two three"
    EXPECT_EQ(dir.entries().size(), size_t{1});
}

TEST(file_write, relative_to_a_directory_descriptor)
{
    TempDir const dir;
    int const dir_fd = ::open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT_TRUE(dir_fd >= 0);
    EXPECT_TRUE(write_file_durably(dir_fd, "counters", bytes_of("7"), 0600).has_value());
    EXPECT_TRUE(read_all(dir.file("counters")) == bytes_of("7"));
    struct stat st{};
    EXPECT_EQ(::stat(dir.file("counters").c_str(), &st), 0);
    EXPECT_EQ(static_cast<int>(st.st_mode & 0777), 0600);
    (void)::close(dir_fd);
}

TEST(file_write, an_empty_file_is_written_too)
{
    TempDir const dir;
    EXPECT_TRUE(write_file_durably(dir.file("empty"), std::span<uint8_t const>{}).has_value());
    EXPECT_TRUE(read_all(dir.file("empty")).empty());
    struct stat st{};
    EXPECT_EQ(::stat(dir.file("empty").c_str(), &st), 0);
}

TEST(file_write, a_temporary_left_by_a_crashed_earlier_life_is_overwritten)
{
    TempDir const dir;
    // The leftover is the one this process would make: the same pid, as a
    // daemon restarted at the same point of every boot sequence gets.
    std::string const leftover = detail::temporary_name(dir.file("state"));
    EXPECT_TRUE(write_file_durably(leftover, bytes_of("half-written junk from before the crash")).has_value());
    EXPECT_TRUE(write_file_durably(dir.file("state"), bytes_of("whole")).has_value());
    EXPECT_TRUE(read_all(dir.file("state")) == bytes_of("whole"));
    auto const names = dir.entries();
    EXPECT_EQ(names.size(), size_t{1});
    EXPECT_TRUE(names.size() == 1 && names[0] == "state");
}

TEST(file_write, an_interrupted_write_is_resumed_until_every_byte_is_out)
{
    // A pipe holds 64 KiB or so; a 1 MiB write_all() blocks in write() until
    // the other end reads, and a signal landing on the blocked write() makes
    // it return EINTR. Nobody reads until the signals have been sent, so the
    // writer is interrupted while it still has bytes to go. A write_all()
    // that took EINTR for success would return early and the reader would
    // see a short file.
    InterruptingSignal const interrupting;
    int fds[2] = {-1, -1};
    EXPECT_EQ(::pipe(fds), 0);
    std::vector<uint8_t> const payload(1U << 20U, 0x5a);
    std::vector<uint8_t> received;
    pthread_t const writer = ::pthread_self();
    signals_handled.store(0);
    std::thread interrupter([&] {
        // The writer has filled the pipe once nothing more goes in: it is
        // in write(), or on its way back there, with bytes still to go.
        for (int before = -1, now = bytes_in_pipe(fds[0]); now == 0 || now != before; now = bytes_in_pipe(fds[0])) {
            before = now;
            std::this_thread::yield();
        }
        // Twenty signals, each sent once the one before has been handled,
        // so none of them merges into its neighbour.
        for (int i = 0; i < 20; ++i) {
            (void)::pthread_kill(writer, SIGUSR1);
            while (signals_handled.load(std::memory_order_relaxed) <= i) {
                std::this_thread::yield();
            }
        }
        received = drain(fds[0]);
    });
    auto const written = detail::write_all(fds[1], payload);
    (void)::close(fds[1]);
    interrupter.join();
    (void)::close(fds[0]);
    EXPECT_TRUE(written.has_value());
    EXPECT_EQ(received.size(), payload.size());
    EXPECT_TRUE(received == payload);
}

TEST(file_write, a_directory_that_is_not_there_is_the_errno_and_nothing_is_left)
{
    TempDir const dir;
    auto const result = write_file_durably(dir.file("no/such/dir/file"), bytes_of("x"));
    EXPECT_FALSE(result.has_value());
    if (!result) {
        EXPECT_EQ(errno_of(result.error()), ENOENT);
    }
    EXPECT_TRUE(dir.entries().empty());
}

TEST_MAIN(statusbar_buffer, file_write_test)
