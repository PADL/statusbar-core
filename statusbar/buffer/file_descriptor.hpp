#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// RAII wrapper for POSIX file descriptors.
///
/// Single canonical type used by `net::FileDescriptor` (aliased) and
/// `bpf::FileDescriptor` (aliased) — promoted from those modules so the
/// implementation lives in one place. Lives in the `buffer` module
/// because both `net` and `bpf` already depend on `buffer`; the type
/// itself is not buffer-specific.
///
/// Move-only. Closes the underlying fd on destruction unless `release()`
/// transferred ownership first.

#include <unistd.h>

namespace statusbar {

class FileDescriptor
{
  public:
    /// Construct with optional file descriptor (default: invalid).
    /// @param fd Raw file descriptor to take ownership of (-1 for invalid).
    explicit FileDescriptor(int fd = -1) noexcept
        : fd_{fd}
    {}

    ~FileDescriptor() noexcept { close(); }

    FileDescriptor(FileDescriptor&& other) noexcept
        : fd_{other.fd_}
    {
        other.fd_ = -1;
    }

    auto operator=(FileDescriptor&& other) noexcept -> FileDescriptor&
    {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    FileDescriptor(FileDescriptor const&) = delete;
    auto operator=(FileDescriptor const&) -> FileDescriptor& = delete;

    /// Raw file descriptor value (-1 if invalid).
    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    /// True iff the descriptor is non-negative.
    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// Release ownership: return the descriptor and clear our copy
    /// so the destructor will not close it.
    [[nodiscard]] auto release() noexcept -> int
    {
        int const fd = fd_;
        fd_ = -1;
        return fd;
    }

    /// Close the descriptor if it is valid, then set to -1.
    /// Safe to call multiple times.
    ///
    /// The return value is ignored and EINTR is deliberately not retried:
    /// on Linux and XNU the descriptor is released before EINTR is reported,
    /// and close(2) warns that a retry could close a number another thread
    /// has already reused.
    void close() noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

  private:
    int fd_;
};

}  // namespace statusbar
