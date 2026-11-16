// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
// write_file_durably(): the bytes arrive whole, a target is replaced in one
// step, no temporary is left behind, and a directory that is not there is the
// errno.
#include "statusbar/buffer/file_write.hpp"

#include "statusbar/test/test.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

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
