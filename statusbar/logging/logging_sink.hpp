#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file logging_sink.hpp
/// @brief Consumer-side output destinations for the deferred-formatting log.
///
/// A LogSink receives fully rendered lines (formatting happened in
/// LogCollector / render_line, on the consumer thread) plus the message level
/// so priority-aware sinks (syslog) can map it. Provided sinks: stderr, an
/// owned FILE, and — where <syslog.h> exists — syslog. All sink calls happen
/// on the single consumer thread; sinks may block (that is the point of
/// moving them off the producer).

#include "statusbar/logging/logging.hpp"

#include <cstdio>
#include <format>
#include <string>
#include <string_view>

#if __has_include(<syslog.h>)
#    include <syslog.h>
#    define STATUSBAR_LOGGING_HAS_SYSLOG 1
#endif

namespace statusbar::logging {

/// Output destination for rendered log lines (consumer thread only).
class LogSink
{
  public:
    LogSink() = default;
    LogSink(LogSink const&) = delete;
    auto operator=(LogSink const&) -> LogSink& = delete;
    virtual ~LogSink() = default;

    /// @p line is a complete rendered line including the trailing newline.
    virtual void write(LogLevel level, std::string_view line) = 0;
    virtual void flush() {}
};

/// Render one entry as the standard line:
///   `<seconds>.<micros> <level-char> [<channel>] <message>\n`
/// The timestamp is the channel clock's raw nanosecond count shown in seconds
/// (steady-clock by default, so it is time-since-boot-ish, matching the other
/// telemetry lines).
[[nodiscard]] inline auto render_line(char const* channel_name, LogEntry const& entry) -> std::string
{
    double const seconds = static_cast<double>(entry.timestamp_ns) / 1e9;
    return std::format("{:.6f} {} [{}] {}\n", seconds, level_char(entry.level), channel_name, entry.message());
}

/// Writes lines to stderr (unbuffered by default, so journald/terminals see
/// them immediately — same behavior as the std::print(stderr, ...) it
/// replaces).
class StderrSink final : public LogSink
{
  public:
    void write(LogLevel /*level*/, std::string_view const line) override { (void)std::fwrite(line.data(), 1, line.size(), stderr); }
};

/// Appends lines to a file the sink owns. flush() flushes the FILE buffer.
class FileSink final : public LogSink
{
  public:
    /// Opens @p path for append. is_open() reports failure (the sink then
    /// swallows writes rather than crashing the consumer).
    explicit FileSink(char const* path) noexcept
        : file_{std::fopen(path, "ae")}
    {}

    ~FileSink() override
    {
        if (file_ != nullptr) {
            (void)std::fclose(file_);
        }
    }

    [[nodiscard]] auto is_open() const noexcept -> bool { return file_ != nullptr; }

    void write(LogLevel /*level*/, std::string_view const line) override
    {
        if (file_ != nullptr) {
            (void)std::fwrite(line.data(), 1, line.size(), file_);
        }
    }

    void flush() override
    {
        if (file_ != nullptr) {
            (void)std::fflush(file_);
        }
    }

  private:
    std::FILE* file_;
};

#ifdef STATUSBAR_LOGGING_HAS_SYSLOG
/// Forwards lines to syslog with the level mapped to the matching priority.
/// The caller is responsible for openlog()/closelog() if it wants an ident.
class SyslogSink final : public LogSink
{
  public:
    void write(LogLevel const level, std::string_view const line) override
    {
        int priority = LOG_DEBUG;
        switch (level) {
            case LogLevel::Error:
                priority = LOG_ERR;
                break;
            case LogLevel::Warning:
                priority = LOG_WARNING;
                break;
            case LogLevel::Status:
                priority = LOG_INFO;
                break;
            default:
                break;
        }
        ::syslog(priority, "%.*s", static_cast<int>(line.size()), line.data());
    }
};
#endif

}  // namespace statusbar::logging
