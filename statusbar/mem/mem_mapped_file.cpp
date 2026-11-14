// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/mem/mem_mapped_file.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>
#include <utility>

#include <sys/mman.h>
#include <sys/stat.h>

namespace statusbar::mem {

namespace {

/// The calling thread's errno as a Status failure.
[[nodiscard]] auto errno_failure() noexcept -> std::unexpected<std::error_code>
{
    return failure(std::error_code{errno, std::generic_category()});
}

/// A status from a POSIX call returning 0 or -1 with errno.
[[nodiscard]] auto posix_status(int const result) noexcept -> Status
{
    if (result != 0) {
        return errno_failure();
    }
    return success();
}

[[nodiscard]] constexpr auto posix_advice(MapAdvice const advice) noexcept -> int
{
    switch (advice) {  // NOLINT(statusbar-block-statements): a table
        case MapAdvice::sequential:
            return POSIX_MADV_SEQUENTIAL;
        case MapAdvice::random:
            return POSIX_MADV_RANDOM;
        case MapAdvice::will_need:
            return POSIX_MADV_WILLNEED;
        case MapAdvice::dont_need:
            return POSIX_MADV_DONTNEED;
        case MapAdvice::normal:
            break;
    }
    return POSIX_MADV_NORMAL;
}

/// The size of open file `fd` (fstat(2)); a negative size reads as zero.
[[nodiscard]] auto file_size(int const fd) noexcept -> StatusValue<uint64_t>
{
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return errno_failure();
    }
    return st.st_size > 0 ? static_cast<uint64_t>(st.st_size) : 0;
}

/// Closes a descriptor on scope exit.
class ScopedFd
{
  public:
    explicit ScopedFd(int const fd) noexcept
        : fd_{fd}
    {}
    ~ScopedFd() { (void)::close(fd_); }
    ScopedFd(ScopedFd const&) = delete;
    auto operator=(ScopedFd const&) -> ScopedFd& = delete;
    ScopedFd(ScopedFd&&) = delete;
    auto operator=(ScopedFd&&) -> ScopedFd& = delete;

  private:
    int fd_;
};

}  // namespace

MappedFile::~MappedFile()
{
    reset();
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : data_{std::exchange(other.data_, nullptr)}
    , size_{std::exchange(other.size_, 0)}
{}

auto MappedFile::operator=(MappedFile&& other) noexcept -> MappedFile&
{
    if (this != &other) {
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

void MappedFile::reset() noexcept
{
    if (data_ != nullptr) {
        (void)::munmap(const_cast<uint8_t*>(data_), size_);  // NOLINT(cppcoreguidelines-pro-type-const-cast): munmap's signature
    }
    data_ = nullptr;
    size_ = 0;
}

auto MappedFile::map(int const fd) noexcept -> StatusValue<MappedFile>
{
    auto const size = file_size(fd);
    if (!size) {
        return forward_failure(size);
    }
    if (*size == 0) {
        return MappedFile{};
    }
    void* const data = ::mmap(nullptr, *size, PROT_READ, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {  // NOLINT(cppcoreguidelines-pro-type-cstyle-cast,performance-no-int-to-ptr): the POSIX macro
        return errno_failure();
    }
    return MappedFile{static_cast<uint8_t const*>(data), *size};
}

auto MappedFile::open(int const dir_fd, char const* const path) noexcept -> StatusValue<MappedFile>
{
    int const fd = ::openat(dir_fd, path, O_RDONLY | O_CLOEXEC);  // NOLINT(cppcoreguidelines-pro-type-vararg): openat(2)
    if (fd < 0) {
        return errno_failure();
    }
    ScopedFd const closer{fd};
    return map(fd);
}

auto MappedFile::page_size() noexcept -> uint64_t
{
    static uint64_t const size = static_cast<uint64_t>(::sysconf(_SC_PAGESIZE));
    return size;
}

auto MappedFile::page_span(uint64_t const offset, uint64_t const length) const noexcept -> std::span<uint8_t const>
{
    if (offset >= size_ || length == 0) {
        return {};
    }
    uint64_t const end = length > size_ - offset ? size_ : offset + length;
    uint64_t const first = offset - (offset % page_size());
    return bytes().subspan(first, end - first);
}

auto MappedFile::lock_range(uint64_t const offset, uint64_t const length) noexcept -> Status
{
    auto const pages = page_span(offset, length);
    if (pages.empty()) {
        return success();
    }
    return posix_status(::mlock(pages.data(), pages.size()));
}

auto MappedFile::unlock_range(uint64_t const offset, uint64_t const length) noexcept -> Status
{
    auto const pages = page_span(offset, length);
    if (pages.empty()) {
        return success();
    }
    return posix_status(::munlock(pages.data(), pages.size()));
}

auto MappedFile::advise(MapAdvice const advice) noexcept -> Status
{
    if (data_ == nullptr) {
        return success();
    }
    // posix_madvise returns the error number rather than setting errno.
    int const result = ::posix_madvise(
        const_cast<uint8_t*>(data_), size_, posix_advice(advice));  // NOLINT(cppcoreguidelines-pro-type-const-cast): its signature
    if (result != 0) {
        return failure(std::error_code{result, std::generic_category()});
    }
    return success();
}

}  // namespace statusbar::mem
