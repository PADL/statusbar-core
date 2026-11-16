#pragma once
// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
/// A durable file write: the bytes go to a temporary file beside the target,
/// are synced to the device, and the temporary is renamed over the target,
/// whose directory is then synced too. A reader sees either the old file or
/// the new one, never a half-written one, and once this returns success the
/// new one survives a crash or a power loss. For the files a process must
/// not lose or corrupt: a persisted entity model, a configuration it rewrites,
/// a counters file.
///
/// Lives in the `buffer` module beside FileDescriptor for the same reason
/// that does: `net`, `config` and the tools already depend on `buffer`, and
/// the function is not buffer-specific.
#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/status/status.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>

namespace statusbar {

namespace detail {

[[nodiscard]] inline auto errno_failure() noexcept -> std::unexpected<std::error_code>
{
    return failure(std::error_code{errno, std::system_category()});
}

/// Every byte of `bytes` to `fd`, however many write() calls it takes.
[[nodiscard]] inline auto write_all(int const fd, std::span<uint8_t const> bytes) noexcept -> Status
{
    while (!bytes.empty()) {
        ssize_t const written = ::write(fd, bytes.data(), bytes.size());
        if (written < 0) {
            return errno == EINTR ? success() : errno_failure();  // EINTR: try again
        }
        bytes = bytes.subspan(static_cast<size_t>(written));
    }
    return success();
}

/// The file's bytes to the device. fsync(2) on Linux; on Darwin fsync only
/// reaches the drive's cache and F_FULLFSYNC is what asks the drive to
/// write it through (fsync(2) there says so).
[[nodiscard]] inline auto sync_to_device(int const fd) noexcept -> Status
{
#if defined(__APPLE__)
    if (::fcntl(fd, F_FULLFSYNC) != 0 && ::fsync(fd) != 0) {
        return errno_failure();
    }
    return success();
#else
    return ::fsync(fd) == 0 ? success() : errno_failure();
#endif
}

/// The directory entry: the rename is durable only once the directory
/// holding it has been synced.
[[nodiscard]] inline auto sync_directory(int const dir_fd, std::string_view const path) noexcept -> Status
{
    auto const slash = path.rfind('/');
    std::string const dir = slash == std::string_view::npos ? std::string{"."}
        : slash == 0                                        ? std::string{"/"}
                                                            : std::string{path.substr(0, slash)};
    FileDescriptor const fd{::openat(dir_fd, dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (!fd.valid()) {
        return errno_failure();
    }
    return ::fsync(fd.get()) == 0 ? success() : errno_failure();
}

/// The temporary's name: the target's with a suffix no reader looks for and
/// this process's id, so two writers of one target in two processes do not
/// share it. Two writers in one process must not race either way.
[[nodiscard]] inline auto temporary_name(std::string_view const path) -> std::string
{
    return std::string{path} + ".tmp." + std::to_string(::getpid());
}

/// Write, sync and close the temporary, open for creation.
[[nodiscard]] inline auto fill_temporary(int const fd, std::span<uint8_t const> const bytes) noexcept -> Status
{
    if (auto const written = write_all(fd, bytes); !written) {
        return written;
    }
    return sync_to_device(fd);
}

}  // namespace detail

/// Write `bytes` to the file at `path` (relative to `dir_fd`, or absolute)
/// durably: via a temporary beside it that is synced, renamed over the
/// target, and whose directory is synced. The target's mode is `mode` for a
/// new file; an existing target is replaced, mode and all, since the rename
/// replaces the inode. A failure at any step removes the temporary and
/// leaves the target as it was; the error is the errno as Status.
/// @param dir_fd The directory `path` is relative to, or AT_FDCWD
/// @param path The target's path
/// @param bytes What the file is to hold
/// @param mode The mode of a newly created target, before the umask
[[nodiscard]] inline auto write_file_durably(
    int const dir_fd, std::string_view const path, std::span<uint8_t const> const bytes, mode_t const mode = 0644) noexcept
    -> Status
{
    std::string const temporary = detail::temporary_name(path);
    {
        FileDescriptor const fd{::openat(dir_fd, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode)};
        if (!fd.valid()) {
            return detail::errno_failure();
        }
        if (auto const filled = detail::fill_temporary(fd.get(), bytes); !filled) {
            (void)::unlinkat(dir_fd, temporary.c_str(), 0);
            return filled;
        }
    }
    std::string const target{path};
    if (::renameat(dir_fd, temporary.c_str(), dir_fd, target.c_str()) != 0) {
        auto const err = detail::errno_failure();
        (void)::unlinkat(dir_fd, temporary.c_str(), 0);
        return err;
    }
    return detail::sync_directory(dir_fd, path);
}

/// write_file_durably() with `path` relative to the working directory, or absolute.
[[nodiscard]] inline auto write_file_durably(
    std::string_view const path, std::span<uint8_t const> const bytes, mode_t const mode = 0644) noexcept -> Status
{
    return write_file_durably(AT_FDCWD, path, bytes, mode);
}

}  // namespace statusbar
