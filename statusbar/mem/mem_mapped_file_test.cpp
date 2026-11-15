// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for MappedFile: mapping, the page arithmetic, range locking and advice,
// the error paths and the move semantics.

#include "statusbar/mem/mem_mapped_file.hpp"

#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using statusbar::mem::MappedFile;

namespace {

/// A temporary file of `size` bytes, byte i holding (i * 7 + 3) & 0xff,
/// removed on destruction.
class TempFile
{
  public:
    explicit TempFile(size_t const size)
    {
        char name[] = "/tmp/statusbar_mapped_file_test_XXXXXX";
        fd_ = ::mkstemp(name);
        path_ = name;
        std::vector<uint8_t> bytes(size);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<uint8_t>((i * 7 + 3) & 0xffU);
        }
        if (fd_ >= 0 && size > 0) {
            (void)::write(fd_, bytes.data(), bytes.size());
        }
    }
    ~TempFile()
    {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
        (void)std::remove(path_.c_str());
    }
    TempFile(TempFile const&) = delete;
    auto operator=(TempFile const&) -> TempFile& = delete;
    TempFile(TempFile&&) = delete;
    auto operator=(TempFile&&) -> TempFile& = delete;

    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }
    [[nodiscard]] auto path() const noexcept -> std::string const& { return path_; }
    [[nodiscard]] static auto byte_at(size_t const i) noexcept -> uint8_t { return static_cast<uint8_t>((i * 7 + 3) & 0xffU); }

  private:
    int fd_{-1};
    std::string path_{};
};

[[nodiscard]] auto errno_of(std::error_code const& ec) -> int
{
    return ec.category() == std::system_category() ? ec.value() : -1;
}

#if defined(__linux__)
/// The process's locked memory in kB, from /proc/self/status, or -1.
auto vm_lck_kb() -> long
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmLck:")) {
            return std::strtol(line.c_str() + 6, nullptr, 10);
        }
    }
    return -1;
}

/// How many pages of `bytes` are mapped into the process (the present bit,
/// 63, of /proc/self/pagemap, which needs no privilege), or -1.
auto present_pages(std::span<uint8_t const> const bytes) -> long
{
    size_t const page = MappedFile::page_size();
    auto const address = reinterpret_cast<uintptr_t>(bytes.data());  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    std::vector<uint64_t> entries(((address + bytes.size() + page - 1) / page) - (address / page));
    int const fd = ::open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    auto const size = static_cast<ssize_t>(entries.size() * sizeof(uint64_t));
    auto const offset = static_cast<off_t>(address / page * sizeof(uint64_t));
    bool const read = fd >= 0 && ::pread(fd, entries.data(), static_cast<size_t>(size), offset) == size;
    if (fd >= 0) {
        (void)::close(fd);
    }
    return read ? static_cast<long>(std::ranges::count_if(entries, [](uint64_t const e) { return (e >> 63U) != 0; })) : -1;
}

/// Read one byte of every page of `bytes`, so each is mapped.
void touch_pages(std::span<uint8_t const> const bytes)
{
    uint8_t volatile sink = 0;
    for (size_t i = 0; i < bytes.size(); i += MappedFile::page_size()) {
        sink = static_cast<uint8_t>(sink + bytes[i]);
    }
}
#endif

}  // namespace

TEST(mem_mapped_file, maps_the_whole_file_read_only)
{
    size_t const size = MappedFile::page_size() * 3 + 17;
    TempFile const file{size};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->valid());
    EXPECT_EQ(mapped->size(), size);
    auto const bytes = mapped->bytes();
    EXPECT_EQ(bytes.size(), size);
    EXPECT_EQ(bytes[0], TempFile::byte_at(0));
    EXPECT_EQ(bytes[size / 2], TempFile::byte_at(size / 2));
    EXPECT_EQ(bytes[size - 1], TempFile::byte_at(size - 1));
}

TEST(mem_mapped_file, open_by_path_maps_and_keeps_no_descriptor)
{
    TempFile const file{1000};
    auto mapped = MappedFile::open(AT_FDCWD, file.path());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_EQ(mapped->size(), size_t{1000});
    EXPECT_EQ(mapped->bytes()[999], TempFile::byte_at(999));
}

TEST(mem_mapped_file, an_empty_file_is_a_valid_empty_mapping)
{
    TempFile const file{0};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->valid());
    EXPECT_EQ(mapped->size(), size_t{0});
    EXPECT_TRUE(mapped->bytes().empty());
    EXPECT_TRUE(mapped->page_span(0, 100).empty());
    EXPECT_TRUE(mapped->lock_range(0, 100).has_value());  // nothing to lock is success
}

TEST(mem_mapped_file, errors_are_the_errno)
{
    auto missing = MappedFile::open(AT_FDCWD, "/nonexistent/statusbar_mapped_file_test");
    EXPECT_FALSE(missing.has_value());
    EXPECT_EQ(errno_of(missing.error()), ENOENT);

    auto bad_fd = MappedFile::map(-1);
    EXPECT_FALSE(bad_fd.has_value());
    EXPECT_EQ(errno_of(bad_fd.error()), EBADF);

    auto empty_path = MappedFile::open(AT_FDCWD, "");
    EXPECT_FALSE(empty_path.has_value());
    EXPECT_EQ(empty_path.error(), std::make_error_code(std::errc::filename_too_long));

    int const dir = ::open("/tmp", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(dir >= 0);
    auto directory = MappedFile::map(dir);
    (void)::close(dir);
    EXPECT_FALSE(directory.has_value());
    EXPECT_EQ(directory.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(mem_mapped_file, page_span_is_page_aligned_and_clipped)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 3 + 17};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    auto const all = mapped->bytes();

    // Mid-page offset: starts at the page holding it, ends at the end of the page holding the last byte.
    auto const span = mapped->page_span(page + 10, 5);
    EXPECT_EQ(span.data(), all.data() + page);
    EXPECT_EQ(span.size(), page);

    // Crossing a page boundary covers both pages.
    auto const two = mapped->page_span(page - 1, 2);
    EXPECT_EQ(two.data(), all.data());
    EXPECT_EQ(two.size(), 2 * page);

    // The tail page is clipped to the mapping.
    auto const tail = mapped->page_span(page * 3, 1000);
    EXPECT_EQ(tail.data(), all.data() + page * 3);
    EXPECT_EQ(tail.size(), size_t{17});

    // Past the end, or empty: nothing.
    EXPECT_TRUE(mapped->page_span(page * 3 + 17, 1).empty());
    EXPECT_TRUE(mapped->page_span(0, 0).empty());

    // The whole file.
    auto const whole = mapped->page_span(0, all.size());
    EXPECT_EQ(whole.data(), all.data());
    EXPECT_EQ(whole.size(), all.size());
}

TEST(mem_mapped_file, lock_range_locks_the_pages_and_unlock_range_frees_them)
{
#if defined(__linux__)
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 4};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    long const before = vm_lck_kb();
    EXPECT_TRUE(before >= 0);

    auto locked = mapped->lock_range(page, page * 2);
    if (!locked) {
        EXPECT_TRUE(errno_of(locked.error()) == ENOMEM || errno_of(locked.error()) == EPERM);
        SKIP("mlock is not permitted here (RLIMIT_MEMLOCK / CAP_IPC_LOCK)");
    }
    long const during = vm_lck_kb();
    EXPECT_EQ(during - before, static_cast<long>(2 * page / 1024));
    // The locked window reads without a fault having to be taken now.
    EXPECT_EQ(mapped->bytes()[page + 5], TempFile::byte_at(page + 5));

    EXPECT_TRUE(mapped->unlock_range(page, page * 2).has_value());
    EXPECT_EQ(vm_lck_kb(), before);
#else
    SKIP("VmLck is read from /proc/self/status (Linux only)");
#endif
}

TEST(mem_mapped_file, advise_accepts_every_advice)
{
    TempFile const file{MappedFile::page_size() * 2};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::normal).has_value());
    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::sequential).has_value());
    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::random).has_value());
    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::will_need).has_value());
    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::dont_need).has_value());
    EXPECT_TRUE(mapped->advise(mapped->size(), 10, MappedFile::Advice::will_need).has_value());  // past the end: nothing
}

TEST(mem_mapped_file, dont_need_drops_the_pages_from_the_process_and_they_read_back)
{
#if defined(__linux__)
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 8};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    auto const bytes = mapped->bytes();
    touch_pages(bytes);
    if (present_pages(bytes) < 0) {
        SKIP("/proc/self/pagemap is not readable here");
    }
    EXPECT_EQ(present_pages(bytes), 8L);
    EXPECT_TRUE(mapped->advise(page * 2, page * 4, MappedFile::Advice::dont_need).has_value());
    EXPECT_EQ(present_pages(bytes.subspan(page * 2, page * 4)), 0L);
    EXPECT_EQ(present_pages(bytes), 4L);
    EXPECT_EQ(bytes[page * 3 + 5], TempFile::byte_at(page * 3 + 5));  // faulted back in from the file
#else
    SKIP("the present bit is read from /proc/self/pagemap (Linux only)");
#endif
}

TEST(mem_mapped_file, dont_need_refuses_a_locked_range)
{
#if defined(__linux__)
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 2};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    if (!mapped->lock_range(0, page)) {
        SKIP("mlock is not permitted here (RLIMIT_MEMLOCK / CAP_IPC_LOCK)");
    }
    auto const advised = mapped->advise(0, page, MappedFile::Advice::dont_need);
    EXPECT_EQ(advised.has_value() ? 0 : errno_of(advised.error()), EINVAL);
    EXPECT_TRUE(mapped->unlock_range(0, page).has_value());
    EXPECT_TRUE(mapped->advise(0, page, MappedFile::Advice::dont_need).has_value());
#else
    SKIP("madvise(2) refuses DONTNEED on locked pages on Linux only");
#endif
}

TEST(mem_mapped_file, a_move_hands_the_mapping_over_and_the_source_is_empty)
{
    TempFile const file{512};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    auto const* data = mapped->bytes().data();

    MappedFile moved{std::move(*mapped)};
    EXPECT_TRUE(moved.valid());
    EXPECT_EQ(moved.bytes().data(), data);
    EXPECT_EQ(moved.size(), size_t{512});
    EXPECT_FALSE(mapped->valid());  // NOLINT(bugprone-use-after-move) the moved-from state is what is under test
    EXPECT_TRUE(mapped->bytes().empty());

    MappedFile assigned;
    EXPECT_FALSE(assigned.valid());
    assigned = std::move(moved);
    EXPECT_TRUE(assigned.valid());
    EXPECT_EQ(assigned.bytes().data(), data);
    EXPECT_FALSE(moved.valid());  // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(assigned.bytes()[511], TempFile::byte_at(511));
}

//
// Test Runner
//

TEST_MAIN(statusbar_mem, mem_mapped_file_test)
