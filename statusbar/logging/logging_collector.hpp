#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file logging_collector.hpp
/// @brief The single consumer that drains every log channel to a sink.
///
/// A LogCollector holds the consumer side of each registered LogChannel so ONE
/// thread does all the log formatting and output. poll() drains a bounded
/// batch from every channel (bounded so a chatty channel cannot starve the
/// others) and reports drop counts as synthesized warning lines; run() is a
/// convenience loop for a dedicated consumer thread, pairing with
/// itc::StopToken.
///
/// Threading: register channels (add()) before the consumer starts; poll()/
/// run() are single-consumer — one thread only, and it must be the only
/// consumer of every registered channel.

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/logging/logging.hpp"
#include "statusbar/logging/logging_sink.hpp"
#include "statusbar/sg14/inplace_vector.h"

#include <chrono>
#include <cstddef>
#include <format>
#include <thread>

namespace statusbar::logging {

template <size_t MaxChannels = 16>
class LogCollector
{
  public:
    /// Register a channel for draining. Returns false when full. The channel
    /// must outlive the collector's consumer loop.
    [[nodiscard]] auto add(LogChannelBase& channel) noexcept -> bool { return channels_.try_push_back(&channel) != nullptr; }

    [[nodiscard]] auto channel_count() const noexcept -> size_t { return channels_.size(); }

    /// Drain up to @p batch_per_channel entries from every channel into
    /// @p sink, oldest first per channel, then report any drops. Returns the
    /// number of lines written; 0 means everything was idle (callers use this
    /// to decide to sleep).
    auto poll(LogSink& sink, size_t const batch_per_channel = 64) -> size_t
    {
        size_t lines = 0;
        for (auto* const channel_ptr : channels_) {
            auto& channel = *channel_ptr;
            for (size_t n = 0; n < batch_per_channel; ++n) {
                auto const entry = channel.drain_one();
                if (!entry) {
                    break;
                }
                sink.write(entry->level, render_line(channel.name(), *entry));
                ++lines;
            }
            if (auto const dropped = channel.take_dropped(); dropped > 0) {
                sink.write(
                    LogLevel::Warning,
                    std::format("{} W [{}] log ring overflow: {} message(s) dropped\n", 0.0, channel.name(), dropped));
                ++lines;
            }
        }
        if (lines > 0) {
            sink.flush();
        }
        return lines;
    }

    /// Dedicated consumer-thread loop: poll all channels, sleeping
    /// @p idle_sleep whenever a pass finds nothing, until @p stop is
    /// requested. Performs a final drain pass on exit so shutdown messages
    /// are not lost.
    void run(itc::StopToken& stop, LogSink& sink, std::chrono::milliseconds const idle_sleep = std::chrono::milliseconds{10})
    {
        while (!stop.stop_requested()) {
            if (poll(sink) == 0) {
                std::this_thread::sleep_for(idle_sleep);
            }
        }
        (void)poll(sink);
    }

  private:
    sg14::inplace_vector<LogChannelBase*, MaxChannels> channels_;
};

}  // namespace statusbar::logging
