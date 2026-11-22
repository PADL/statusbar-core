// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for MappedFile: mapping, the page arithmetic, range locking and advice,
// the error paths and the move semantics.

#include "statusbar/mem/mem_mapped_file.hpp"

#include "statusbar/test/test.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <bit>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
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
/// How many of the mapping's pages this process has a page-table entry for:
/// bit 63 of each /proc/self/pagemap word, readable without privilege (the
/// frame number is what needs it, and is not looked at). -1 when the file
/// cannot be read.
auto mapped_pages(std::span<uint8_t const> const bytes) -> long
{
    size_t const page = MappedFile::page_size();
    int const fd = ::open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    long count = 0;
    for (size_t offset = 0; offset < bytes.size() && count >= 0; offset += page) {
        uint64_t entry = 0;
        auto const index = std::bit_cast<uintptr_t>(bytes.data() + offset) / page;
        auto const got = ::pread(fd, &entry, sizeof(entry), static_cast<off_t>(index * sizeof(entry)));
        count = got == static_cast<ssize_t>(sizeof(entry)) ? count + static_cast<long>((entry >> 63U) & 1U) : -1;
    }
    (void)::close(fd);
    return count;
}

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
    if (statusbar::test::under_address_sanitizer) {
        SKIP("AddressSanitizer reports mlock success without locking anything");
    }
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

TEST(mem_mapped_file, advise_dont_need_drops_the_pages_from_the_mapping)
{
#if defined(__linux__)
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 4};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    // Read one byte of each page so each has an entry.
    uint8_t touched = 0;
    for (size_t p = 0; p < 4; ++p) {
        touched = static_cast<uint8_t>(touched + mapped->bytes()[p * page]);
    }
    EXPECT_TRUE(
        touched ==
        static_cast<uint8_t>(
            TempFile::byte_at(0) + TempFile::byte_at(page) + TempFile::byte_at(2 * page) + TempFile::byte_at(3 * page)));
    long const before = mapped_pages(mapped->bytes());
    if (before < 0) {
        SKIP("/proc/self/pagemap is not readable here");
    }
    EXPECT_EQ(before, 4L);

    EXPECT_TRUE(mapped->advise(0, mapped->size(), MappedFile::Advice::dont_need).has_value());
    // Through posix_madvise this stayed at 4: glibc and musl never make the
    // call for POSIX_MADV_DONTNEED.
    EXPECT_EQ(mapped_pages(mapped->bytes()), 0L);
    // The bytes are still the file's; they come back in on the next read.
    EXPECT_EQ(mapped->bytes()[page + 1], TempFile::byte_at(page + 1));
#else
    SKIP("/proc/self/pagemap is Linux only; posix_madvise is what the other platforms have");
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

TEST(mem_mapped_file, a_region_maps_at_its_offset)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{(page * 3) + 9};
    auto mapped = MappedFile::map(file.fd(), {.offset = page, .length = page});
    EXPECT_TRUE(mapped.has_value());
    EXPECT_EQ(mapped->size(), page);
    EXPECT_EQ(mapped->bytes()[0], TempFile::byte_at(page));
    EXPECT_EQ(mapped->bytes()[page - 1], TempFile::byte_at((page * 2) - 1));

    auto tail = MappedFile::map(file.fd(), {.offset = page * 2});  // no length: to the end
    EXPECT_TRUE(tail.has_value());
    EXPECT_EQ(tail->size(), page + 9);
    EXPECT_EQ(tail->bytes()[page + 8], TempFile::byte_at((page * 3) + 8));
}

TEST(mem_mapped_file, a_regions_ranges_count_from_its_own_start)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{(page * 4) + 9};
    auto mapped = MappedFile::map(file.fd(), {.offset = page * 2});
    EXPECT_TRUE(mapped.has_value());
    auto const all = mapped->bytes();
    auto const span = mapped->page_span(page + 10, 5);  // the region's second page, the file's fourth
    EXPECT_EQ(span.data(), all.data() + page);
    EXPECT_EQ(span.size(), page);
    EXPECT_EQ(mapped->page_span(page * 2, 100).size(), size_t{9});  // clipped to the region, not the file
#if defined(__linux__)
    if (statusbar::test::under_address_sanitizer) {
        SKIP("AddressSanitizer reports mlock success without locking anything");
    }
    long const before = vm_lck_kb();
    auto const locked = mapped->lock_range(page, page * 2);  // the region's second page and its 9-byte tail
    if (!locked) {
        SKIP("mlock is not permitted here (RLIMIT_MEMLOCK / CAP_IPC_LOCK)");
    }
    EXPECT_EQ(vm_lck_kb() - before, static_cast<long>(2 * page / 1024));
    EXPECT_EQ(mapped_pages(mapped->page_span(page, page * 2)), 2L);
    EXPECT_EQ(all[page + 1], TempFile::byte_at((page * 3) + 1));
    EXPECT_TRUE(mapped->unlock_range(page, page * 2).has_value());
    EXPECT_EQ(vm_lck_kb(), before);
#endif
}

TEST(mem_mapped_file, a_zero_length_region_is_a_valid_empty_mapping)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 2};
    auto mapped = MappedFile::map(file.fd(), {.offset = page, .length = 0});
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->valid());
    EXPECT_TRUE(mapped->bytes().empty());
    EXPECT_TRUE(mapped->page_span(0, 1).empty());
    EXPECT_TRUE(mapped->lock_range(0, page).has_value());  // nothing to lock
}

TEST(mem_mapped_file, a_writable_region_writes_through_to_the_file)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{page * 2};
    {
        auto mapped = MappedFile::map(file.fd(), {.offset = page, .length = page, .writable = true});
        EXPECT_TRUE(mapped.has_value());
        EXPECT_TRUE(mapped->writable());
        auto const bytes = mapped->writable_bytes();
        EXPECT_EQ(bytes.size(), page);
        bytes[3] = 0xA5;
    }
    uint8_t read_back = 0;
    EXPECT_EQ(::pread(file.fd(), &read_back, 1, static_cast<off_t>(page + 3)), ssize_t{1});
    EXPECT_EQ(read_back, uint8_t{0xA5});
}

TEST(mem_mapped_file, a_read_only_mapping_has_no_writable_bytes)
{
    TempFile const file{100};
    auto mapped = MappedFile::map(file.fd());
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(mapped->writable_bytes().empty());
}

TEST(mem_mapped_file, an_unaligned_offset_is_refused)
{
    TempFile const file{MappedFile::page_size() * 2};
    auto mapped = MappedFile::map(file.fd(), {.offset = 1, .length = 16});
    EXPECT_FALSE(mapped.has_value());
    EXPECT_EQ(mapped.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(mem_mapped_file, a_region_past_the_end_is_refused)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{page + 10};
    auto too_long = MappedFile::map(file.fd(), {.offset = page, .length = 11});
    EXPECT_FALSE(too_long.has_value());
    EXPECT_EQ(too_long.error(), std::make_error_code(std::errc::invalid_argument));
    auto too_far = MappedFile::map(file.fd(), {.offset = page * 2});
    EXPECT_FALSE(too_far.has_value());
    EXPECT_EQ(too_far.error(), std::make_error_code(std::errc::invalid_argument));
    auto exact = MappedFile::map(file.fd(), {.offset = page, .length = 10});
    EXPECT_TRUE(exact.has_value());
}

TEST(mem_mapped_file, a_zero_length_writable_region_still_checks_the_descriptor)
{
    TempFile const file{MappedFile::page_size()};
    int const fd = ::open(file.path().c_str(), O_RDONLY | O_CLOEXEC);
    EXPECT_TRUE(fd >= 0);
    auto refused = MappedFile::map(fd, {.length = 0, .writable = true});
    (void)::close(fd);
    EXPECT_FALSE(refused.has_value());
    EXPECT_EQ(errno_of(refused.error()), EACCES);
    int const write_only = ::open(file.path().c_str(), O_WRONLY | O_CLOEXEC);
    EXPECT_TRUE(write_only >= 0);
    auto const not_readable = MappedFile::map(write_only, {.length = 0});
    auto const not_read_write = MappedFile::map(write_only, {.length = 0, .writable = true});
    auto const sized = MappedFile::map(write_only, {.length = 16, .writable = true});
    (void)::close(write_only);
    EXPECT_EQ(errno_of(not_readable.error()), EACCES);  // as mmap refuses O_WRONLY, whatever the length
    EXPECT_EQ(errno_of(not_read_write.error()), EACCES);
    EXPECT_EQ(errno_of(sized.error()), EACCES);
    auto allowed = MappedFile::map(file.fd(), {.length = 0, .writable = true});
    EXPECT_TRUE(allowed.has_value());
    EXPECT_TRUE(allowed->writable_bytes().empty());
}

TEST(mem_mapped_file, a_moved_writable_mapping_stays_writable)
{
    size_t const page = MappedFile::page_size();
    TempFile const file{page};
    auto mapped = MappedFile::map(file.fd(), {.writable = true});
    EXPECT_TRUE(mapped.has_value());
    MappedFile moved{std::move(*mapped)};
    EXPECT_TRUE(moved.writable());
    EXPECT_FALSE(mapped->writable());  // NOLINT(bugprone-use-after-move) the moved-from state is what is under test
    EXPECT_TRUE(mapped->writable_bytes().empty());
    moved.writable_bytes()[7] = 0x5A;
    MappedFile assigned;
    assigned = std::move(moved);
    EXPECT_TRUE(assigned.writable());
    assigned.writable_bytes()[8] = 0xA5;
    std::array<uint8_t, 2> read_back{};
    EXPECT_EQ(::pread(file.fd(), read_back.data(), read_back.size(), 7), ssize_t{2});  // both writes reach the file
    EXPECT_EQ(read_back[0], uint8_t{0x5A});
    EXPECT_EQ(read_back[1], uint8_t{0xA5});
}

TEST(mem_mapped_file, a_writable_region_of_a_read_only_descriptor_is_refused)
{
    TempFile const file{MappedFile::page_size()};
    int const fd = ::open(file.path().c_str(), O_RDONLY | O_CLOEXEC);
    EXPECT_TRUE(fd >= 0);
    auto mapped = MappedFile::map(fd, {.writable = true});
    (void)::close(fd);
    EXPECT_FALSE(mapped.has_value());
    EXPECT_EQ(errno_of(mapped.error()), EACCES);
}

TEST(mem_mapped_file, an_offset_past_off_t_is_refused)
{
    int const fd = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
    EXPECT_TRUE(fd >= 0);
    uint64_t const page = MappedFile::page_size();
    auto mapped = MappedFile::map(fd, {.offset = (UINT64_MAX / page) * page, .length = MappedFile::page_size()});
    (void)::close(fd);
    EXPECT_FALSE(mapped.has_value());
    EXPECT_EQ(mapped.error(), std::make_error_code(std::errc::invalid_argument));
}

#if defined(__linux__)
// /dev/zero maps shared on Linux; other systems refuse it (ENODEV).
TEST(mem_mapped_file, a_file_that_is_not_regular_needs_a_length)
{
    int const fd = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
    EXPECT_TRUE(fd >= 0);
    auto no_length = MappedFile::map(fd);
    EXPECT_FALSE(no_length.has_value());
    EXPECT_EQ(no_length.error(), std::make_error_code(std::errc::invalid_argument));
    auto with_length = MappedFile::map(fd, {.length = MappedFile::page_size()});
    (void)::close(fd);
    EXPECT_TRUE(with_length.has_value());
    EXPECT_EQ(with_length->size(), MappedFile::page_size());
    EXPECT_EQ(with_length->bytes()[0], uint8_t{0});
}
#endif

//
// Test Runner
//

TEST_MAIN(statusbar_mem, mem_mapped_file_test)
