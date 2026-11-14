// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for MappedFile over files in a temporary directory: mapping, range locking, and a mapping
/// outliving the unlink or replacement of its path.

#include "statusbar/mem/mem_mapped_file.hpp"

#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using statusbar::mem::MapAdvice;
using statusbar::mem::MappedFile;

namespace {

/// A fresh directory under the system's temporary directory, removed with its files.
class TempDir
{
  public:
    TempDir()
    {
        std::string pattern = (std::filesystem::temp_directory_path() / "mem_mapped_file_XXXXXX").string();
        path_ = ::mkdtemp(pattern.data()) != nullptr ? pattern : std::string{};
    }
    ~TempDir()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    TempDir(TempDir const&) = delete;
    auto operator=(TempDir const&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;

    [[nodiscard]] auto file(std::string const& name) const -> std::string { return path_ + "/" + name; }

  private:
    std::string path_;
};

auto pattern_bytes(size_t const count, uint8_t const seed) -> std::vector<uint8_t>
{
    std::vector<uint8_t> bytes(count);
    for (size_t i = 0; i < count; ++i) {
        bytes[i] = static_cast<uint8_t>((i * 7U) + seed);
    }
    return bytes;
}

void write_file(std::string const& path, std::vector<uint8_t> const& bytes)
{
    int const fd =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);  // NOLINT(cppcoreguidelines-pro-type-vararg): open(2)
    (void)::write(fd, bytes.data(), bytes.size());
    (void)::close(fd);
}

auto same_bytes(MappedFile const& file, std::vector<uint8_t> const& expected) -> bool
{
    auto const bytes = file.bytes();
    return bytes.size() == expected.size() && std::equal(bytes.begin(), bytes.end(), expected.begin());
}

/// Whether a lock failure is the unprivileged memlock limit rather than a fault in MappedFile.
auto lock_limited(std::error_code const& error) -> bool
{
    return error == std::errc::operation_not_permitted || error == std::errc::not_enough_memory ||
        error == std::errc::resource_unavailable_try_again;
}

}  // namespace

TEST(mem_mapped_file, a_mapped_file_reads_its_bytes)
{
    TempDir const dir;
    auto const expected = pattern_bytes(10000, 3);
    write_file(dir.file("a.bin"), expected);
    auto const mapped = MappedFile::open(AT_FDCWD, dir.file("a.bin").c_str());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_EQ(mapped->size(), expected.size());
    EXPECT_TRUE(same_bytes(*mapped, expected));
}

TEST(mem_mapped_file, map_reads_an_open_descriptor_that_is_closed_after)
{
    TempDir const dir;
    auto const expected = pattern_bytes(300, 9);
    write_file(dir.file("b.bin"), expected);
    int const fd = ::open(dir.file("b.bin").c_str(), O_RDONLY | O_CLOEXEC);
    auto const mapped = MappedFile::map(fd);
    (void)::close(fd);
    EXPECT_TRUE(mapped.has_value() && same_bytes(*mapped, expected));
}

TEST(mem_mapped_file, an_empty_file_maps_empty)
{
    TempDir const dir;
    write_file(dir.file("empty.bin"), {});
    auto mapped = MappedFile::open(AT_FDCWD, dir.file("empty.bin").c_str());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->bytes().empty());
    EXPECT_TRUE(mapped->lock_range(0, 100).has_value());
    EXPECT_TRUE(mapped->advise(MapAdvice::sequential).has_value());
}

TEST(mem_mapped_file, a_missing_file_fails_with_no_such_file)
{
    TempDir const dir;
    auto const mapped = MappedFile::open(AT_FDCWD, dir.file("missing.bin").c_str());
    EXPECT_FALSE(mapped.has_value());
    EXPECT_TRUE(mapped.error() == std::errc::no_such_file_or_directory);
}

TEST(mem_mapped_file, ranges_lock_and_unlock_clipped_to_the_file)
{
    TempDir const dir;
    write_file(dir.file("c.bin"), pattern_bytes(3 * MappedFile::page_size(), 1));
    auto mapped = MappedFile::open(AT_FDCWD, dir.file("c.bin").c_str());
    auto const locked = mapped->lock_range(MappedFile::page_size() + 10, 100 * MappedFile::page_size());
    if (!locked && lock_limited(locked.error())) {
        SKIP("RLIMIT_MEMLOCK is below three pages");
    }
    EXPECT_TRUE(locked.has_value());
    EXPECT_TRUE(mapped->unlock_range(MappedFile::page_size() + 10, 100 * MappedFile::page_size()).has_value());
    EXPECT_TRUE(mapped->lock_range(mapped->size() + 1, 10).has_value());
    EXPECT_TRUE(mapped->lock_range(0, 0).has_value());
}

TEST(mem_mapped_file, every_advice_is_accepted)
{
    TempDir const dir;
    write_file(dir.file("d.bin"), pattern_bytes(5000, 2));
    auto mapped = MappedFile::open(AT_FDCWD, dir.file("d.bin").c_str());
    EXPECT_TRUE(mapped->advise(MapAdvice::sequential).has_value());
    EXPECT_TRUE(mapped->advise(MapAdvice::random).has_value());
    EXPECT_TRUE(mapped->advise(MapAdvice::will_need).has_value());
    EXPECT_TRUE(mapped->advise(MapAdvice::normal).has_value());
}

TEST(mem_mapped_file, a_mapping_outlives_an_unlink_and_a_replacement_of_its_path)
{
    TempDir const dir;
    auto const original = pattern_bytes(6000, 5);
    write_file(dir.file("e.bin"), original);
    auto const first = MappedFile::open(AT_FDCWD, dir.file("e.bin").c_str());
    write_file(dir.file("e.new"), pattern_bytes(100, 77));
    std::filesystem::rename(dir.file("e.new"), dir.file("e.bin"));
    EXPECT_TRUE(same_bytes(*first, original));
    std::filesystem::remove(dir.file("e.bin"));
    EXPECT_TRUE(same_bytes(*first, original));
}

TEST(mem_mapped_file, moving_transfers_the_mapping)
{
    TempDir const dir;
    auto const expected = pattern_bytes(700, 4);
    write_file(dir.file("f.bin"), expected);
    auto mapped = MappedFile::open(AT_FDCWD, dir.file("f.bin").c_str());
    MappedFile moved{std::move(*mapped)};
    EXPECT_TRUE(
        mapped->bytes().empty());  // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move): a moved-from mapping is empty
    EXPECT_TRUE(same_bytes(moved, expected));
    MappedFile assigned;
    assigned = std::move(moved);
    EXPECT_TRUE(same_bytes(assigned, expected));
}

TEST_MAIN(statusbar_mem, mem_mapped_file_test)
