// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/mem/mem_mapped_file.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <system_error>

#include <sys/mman.h>
#include <sys/stat.h>

namespace statusbar::mem {

namespace {

[[nodiscard]] auto errno_status() noexcept -> std::unexpected<std::error_code>
{
    return failure(std::error_code{errno, std::system_category()});
}

#if defined(__linux__)
// madvise(2)'s own flags: see MappedFile::advise() for why not the POSIX ones.
[[nodiscard]] auto madvise_flag(MappedFile::Advice const advice) noexcept -> int
{
    switch (advice) {
        case MappedFile::Advice::sequential:
            return MADV_SEQUENTIAL;
        case MappedFile::Advice::random:
            return MADV_RANDOM;
        case MappedFile::Advice::will_need:
            return MADV_WILLNEED;
        case MappedFile::Advice::dont_need:
            return MADV_DONTNEED;
        case MappedFile::Advice::normal:
            break;
    }
    return MADV_NORMAL;
}
#else
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
#endif

/// The size of the file open on fd, or nullopt when it is not a regular file; the errno on failure.
[[nodiscard]] auto file_size(int const fd) noexcept -> StatusValue<std::optional<uint64_t>>
{
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return errno_status();
    }
    if (!S_ISREG(st.st_mode)) {
        return std::optional<uint64_t>{};
    }
    return std::optional{static_cast<uint64_t>(st.st_size)};
}

/// The length of `options`' region of a regular file of `size` bytes: within the file, and within size_t.
[[nodiscard]] auto regular_region(MapOptions const& options, uint64_t const size) noexcept -> StatusValue<size_t>
{
    uint64_t const left = options.offset <= size ? size - options.offset : 0;
    uint64_t const length = options.length ? uint64_t{*options.length} : left;
    bool const fits = options.offset <= size && length <= left && static_cast<size_t>(length) == length;  // 32-bit size_t
    return fits ? StatusValue<size_t>{static_cast<size_t>(length)} : failure(std::errc::invalid_argument);
}

/// The region's length: `options` checked against the page size and off_t and, for a regular file, its `size`.
[[nodiscard]] auto region_length(MapOptions const& options, std::optional<uint64_t> const size, size_t const page) noexcept
    -> StatusValue<size_t>
{
    if (options.offset % page != 0 || options.offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        return failure(std::errc::invalid_argument);
    }
    if (!size) {
        return options.length ? StatusValue<size_t>{*options.length} : failure(std::errc::invalid_argument);
    }
    return regular_region(options, *size);
}

/// The shared read-only mapping of `length` bytes of fd at `options`' offset; the errno on failure.
[[nodiscard]] auto mmap_region(int const fd, size_t const length, MapOptions const& options) noexcept -> StatusValue<void*>
{
    void* const base = ::mmap(nullptr, length, PROT_READ, MAP_SHARED, fd, static_cast<off_t>(options.offset));
    if (base == MAP_FAILED) {
        return errno_status();
    }
    return base;
}

/// A close that keeps the errno of the call before it.
void close_keeping_errno(int const fd) noexcept
{
    int const saved = errno;
    (void)::close(fd);
    errno = saved;
}

}  // namespace

auto MappedFile::map(int const fd, MapOptions const& options) -> StatusValue<MappedFile>
{
    auto const length =
        file_size(fd).and_then([&](std::optional<uint64_t> const size) { return region_length(options, size, page_size()); });
    if (!length) {
        return failure(length.error());
    }
    if (*length == 0) {
        return MappedFile{nullptr, 0};  // mmap refuses a zero length; the empty region is valid
    }
    return mmap_region(fd, *length, options).transform([&](void* const base) { return MappedFile{base, *length}; });
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
#if defined(__linux__)
    // madvise(2), not posix_madvise(3). POSIX lets a hint be ignored, and
    // glibc and musl both answer POSIX_MADV_DONTNEED with 0 and no system
    // call, because Linux's MADV_DONTNEED is not a hint: it drops the pages
    // from the mapping. That is exactly what dont_need is for here - a
    // window slid over a large file must not keep every page it has passed
    // - so the kernel is asked directly. It sets errno.
    if (::madvise(start, pages.size(), madvise_flag(advice)) != 0) {
        return errno_status();
    }
    return success();
#else
    // posix_madvise returns the error number itself rather than setting errno.
    if (int const err = ::posix_madvise(start, pages.size(), madvise_flag(advice)); err != 0) {
        return failure(std::error_code{err, std::system_category()});
    }
    return success();
#endif
}

}  // namespace statusbar::mem
