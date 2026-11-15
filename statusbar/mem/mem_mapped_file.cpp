// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/mem/mem_mapped_file.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <system_error>

#include <sys/mman.h>
#include <sys/stat.h>

namespace statusbar::mem {

namespace {

[[nodiscard]] auto errno_status() noexcept -> std::unexpected<std::error_code>
{
    return failure(std::error_code{errno, std::system_category()});
}

[[nodiscard]] auto madvise_flag(MappedFile::Advice const advice) noexcept -> int
{
    switch (advice) {
        case MappedFile::Advice::sequential:
            return POSIX_MADV_SEQUENTIAL;
        case MappedFile::Advice::random:
            return POSIX_MADV_RANDOM;
        case MappedFile::Advice::will_need:
            return POSIX_MADV_WILLNEED;
        case MappedFile::Advice::dont_need:
            return POSIX_MADV_DONTNEED;
        case MappedFile::Advice::normal:
            break;
    }
    return POSIX_MADV_NORMAL;
}

#if defined(__linux__)
// glibc's and musl's posix_madvise(3) drop POSIX_MADV_DONTNEED, so on Linux
// advise() calls madvise(2), whose advice values are the same.
static_assert(POSIX_MADV_NORMAL == MADV_NORMAL && POSIX_MADV_SEQUENTIAL == MADV_SEQUENTIAL);
static_assert(POSIX_MADV_RANDOM == MADV_RANDOM && POSIX_MADV_WILLNEED == MADV_WILLNEED);
static_assert(POSIX_MADV_DONTNEED == MADV_DONTNEED);

/// madvise(2) of the page-aligned range at start, the errno as Status.
[[nodiscard]] auto advise_pages(void* const start, size_t const length, int const advice) noexcept -> Status
{
    if (::madvise(start, length, advice) != 0) {
        return errno_status();
    }
    return success();
}
#else
/// posix_madvise(3) of the page-aligned range at start, which returns the
/// error number itself rather than setting errno.
[[nodiscard]] auto advise_pages(void* const start, size_t const length, int const advice) noexcept -> Status
{
    if (int const err = ::posix_madvise(start, length, advice); err != 0) {
        return failure(std::error_code{err, std::system_category()});
    }
    return success();
}
#endif

/// The size of a regular file open on fd, or the errno.
[[nodiscard]] auto file_size(int const fd) noexcept -> StatusValue<size_t>
{
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return errno_status();
    }
    if (!S_ISREG(st.st_mode)) {
        return failure(std::errc::invalid_argument);
    }
    return static_cast<size_t>(st.st_size);
}

/// A close that keeps the errno of the call before it.
void close_keeping_errno(int const fd) noexcept
{
    int const saved = errno;
    (void)::close(fd);
    errno = saved;
}

}  // namespace

auto MappedFile::map(int const fd) -> StatusValue<MappedFile>
{
    auto const size = file_size(fd);
    if (!size) {
        return failure(size.error());
    }
    if (*size == 0) {
        return MappedFile{nullptr, 0};  // mmap refuses a zero length; the empty file is valid all the same
    }
    void* const base = ::mmap(nullptr, *size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        return errno_status();
    }
    return MappedFile{base, *size};
}

namespace {

/// openat(2) of path, read-only, with the name copied to a NUL-terminated buffer.
[[nodiscard]] auto open_read_only(int const dir_fd, std::string_view const path) noexcept -> StatusValue<int>
{
    std::array<char, PATH_MAX> name{};
    if (path.empty() || path.size() >= name.size()) {
        return failure(std::errc::filename_too_long);
    }
    std::memcpy(name.data(), path.data(), path.size());
    int const fd = ::openat(dir_fd, name.data(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return errno_status();
    }
    return fd;
}

}  // namespace

auto MappedFile::open(int const dir_fd, std::string_view const path) -> StatusValue<MappedFile>
{
    auto const fd = open_read_only(dir_fd, path);
    if (!fd) {
        return failure(fd.error());
    }
    auto mapped = map(*fd);
    close_keeping_errno(*fd);
    return mapped;
}

auto MappedFile::operator=(MappedFile&& other) noexcept -> MappedFile&
{
    if (this != &other) {
        unmap();
        base_ = other.base_;
        size_ = other.size_;
        valid_ = other.valid_;
        other.forget();
    }
    return *this;
}

void MappedFile::unmap() noexcept
{
    if (base_ != nullptr) {
        (void)::munmap(base_, size_);
    }
    forget();
}

auto MappedFile::page_size() noexcept -> size_t
{
    static size_t const size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    return size;
}

auto MappedFile::page_span(size_t const offset, size_t const length) const noexcept -> std::span<uint8_t const>
{
    if (length == 0 || offset >= size_) {
        return {};
    }
    size_t const page = page_size();
    size_t const first = offset - (offset % page);
    size_t const last = offset + std::min(length, size_ - offset);  // one past the last byte asked for, clipped
    size_t const end = std::min(size_, last + ((page - (last % page)) % page));
    return bytes().subspan(first, end - first);
}

auto MappedFile::lock_range(size_t const offset, size_t const length) const noexcept -> Status
{
    auto const pages = page_span(offset, length);
    if (pages.empty()) {
        return success();
    }
    if (::mlock(pages.data(), pages.size()) != 0) {
        return errno_status();
    }
    return success();
}

auto MappedFile::unlock_range(size_t const offset, size_t const length) const noexcept -> Status
{
    auto const pages = page_span(offset, length);
    if (pages.empty()) {
        return success();
    }
    if (::munlock(pages.data(), pages.size()) != 0) {
        return errno_status();
    }
    return success();
}

auto MappedFile::advise(size_t const offset, size_t const length, Advice const advice) const noexcept -> Status
{
    auto const pages = page_span(offset, length);
    if (pages.empty()) {
        return success();
    }
    // The argument is the page-aligned start; the span is const only to us.
    void* const start = const_cast<uint8_t*>(pages.data());  // NOLINT(cppcoreguidelines-pro-type-const-cast)
    return advise_pages(start, pages.size(), madvise_flag(advice));
}

}  // namespace statusbar::mem
