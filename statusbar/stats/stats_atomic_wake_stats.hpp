#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Thread-safe atomic wake timing statistics.
/// Tracks wake error timing and callback duration with histograms.

#include "statusbar/stats/stats_atomic_histogram.hpp"
#include "statusbar/stats/stats_atomic_time_stats.hpp"

#include <atomic>
#include <cmath>
#include <cstdint>
#include <format>

namespace statusbar::stats {

/// Non-template base class for AtomicWakeStats.
class AtomicWakeStatsBase
{
  public:
    AtomicWakeStatsBase() noexcept;
    ~AtomicWakeStatsBase() = default;

    AtomicWakeStatsBase(AtomicWakeStatsBase const&) = delete;
    auto operator=(AtomicWakeStatsBase const&) -> AtomicWakeStatsBase& = delete;
    AtomicWakeStatsBase(AtomicWakeStatsBase&&) = delete;
    auto operator=(AtomicWakeStatsBase&&) -> AtomicWakeStatsBase& = delete;

  protected:
    auto reset_skipped() noexcept -> void;
    auto add_skipped(int64_t counts) noexcept -> void;
    [[nodiscard]] auto load_skipped() const noexcept -> int64_t;

  private:
    std::atomic<int64_t> skipped_counts_{0};
};

/// Statistics tracker for wake timing (thread-safe).
class AtomicWakeStats : public AtomicWakeStatsBase
{
  public:
    static constexpr auto default_error_histogram_config() -> AtomicHistogramConfig
    {
        return AtomicHistogramConfig{.low_ns = -50'000, .high_ns = 50'000, .bin_width_ns = 1000};
    }

    static constexpr auto default_duration_histogram_config() -> AtomicHistogramConfig
    {
        return AtomicHistogramConfig{.low_ns = 0, .high_ns = 100'000, .bin_width_ns = 1000};
    }

    AtomicWakeStats() noexcept
        : error_histogram_{default_error_histogram_config()}
        , duration_histogram_{default_duration_histogram_config()}
    {
        reset();
    }

    explicit AtomicWakeStats(AtomicHistogramConfig error_histogram_config) noexcept
        : error_histogram_{error_histogram_config}
        , duration_histogram_{default_duration_histogram_config()}
    {
        reset();
    }

    AtomicWakeStats(AtomicHistogramConfig error_histogram_config, AtomicHistogramConfig duration_histogram_config) noexcept
        : error_histogram_{error_histogram_config}
        , duration_histogram_{duration_histogram_config}
    {
        reset();
    }

    void configure_error_histogram(AtomicHistogramConfig config) noexcept { error_histogram_.configure(config); }
    void configure_duration_histogram(AtomicHistogramConfig config) noexcept { duration_histogram_.configure(config); }

    void update(int64_t error_ns, int64_t skipped_counts = 0) noexcept
    {
        error_.update(error_ns);
        error_histogram_.update(error_ns);
        add_skipped(skipped_counts);
    }

    /// Record a duration (and skipped counts) for a wake whose error update()
    /// already recorded: for a duration only known after the wake's work.
    void update_duration(int64_t duration_ns, int64_t skipped_counts = 0) noexcept
    {
        duration_.update(duration_ns);
        duration_histogram_.update(duration_ns);
        add_skipped(skipped_counts);
    }

    void update_with_duration(int64_t error_ns, int64_t duration_ns, int64_t skipped_counts = 0) noexcept
    {
        error_.update(error_ns);
        duration_.update(duration_ns);
        error_histogram_.update(error_ns);
        duration_histogram_.update(duration_ns);
        add_skipped(skipped_counts);
    }

    void reset() noexcept
    {
        error_.reset();
        duration_.reset();
        error_histogram_.reset();
        duration_histogram_.reset();
        reset_skipped();
    }

    [[nodiscard]] auto count() const noexcept -> int64_t { return error_.count(); }
    [[nodiscard]] auto sum_ns() const noexcept -> int64_t { return error_.sum_ns(); }
    [[nodiscard]] auto min_ns() const noexcept -> int64_t { return error_.min_ns(); }
    [[nodiscard]] auto max_ns() const noexcept -> int64_t { return error_.max_ns(); }
    [[nodiscard]] auto skipped_counts() const noexcept -> int64_t { return load_skipped(); }

    struct Snapshot
    {
        AtomicTimeStats::Snapshot error;
        AtomicTimeStats::Snapshot duration;
        AtomicHistogram<128>::Snapshot error_histogram;
        AtomicHistogram<128>::Snapshot duration_histogram;
        int64_t skipped_counts = 0;

        [[nodiscard]] auto average_ns() const noexcept -> double { return error.average_ns(); }
        [[nodiscard]] auto stddev_ns() const noexcept -> double { return error.stddev_ns(); }

        template <typename OutputIt>
        auto format_status_to(OutputIt out) const -> OutputIt
        {
            return std::format_to(
                out,
                "Wakes: {:8}  Avg: {:+8.1f} ns  Min: {:+8} ns  Max: {:+8} ns  StdDev: {:7.1f} ns",
                error.count,
                error.average_ns(),
                error.min_ns,
                error.max_ns,
                error.stddev_ns());
        }

        template <typename OutputIt>
        auto format_report_to(OutputIt out, int64_t const compensation_ns = 0) const -> OutputIt
        {
            out = std::format_to(out, "=== Wake Statistics ===\n");
            out = std::format_to(out, "  Total wakes:     {}\n", error.count);
            if (compensation_ns != 0) {
                out = std::format_to(
                    out, "  Compensation:    {} ns ({:+.3f} us)\n", compensation_ns, static_cast<double>(compensation_ns) / 1000.0);
            }
            if (error.count > 0) {
                out = std::format_to(out, "  Skipped counts:  {}\n", skipped_counts);
                out = format_error_stats_to(out);
                out = format_duration_stats_to(out);
                out = format_suggested_compensation_to(out, compensation_ns);
                out = format_histograms_to(out);
            }
            out = std::format_to(out, "=======================\n");
            return out;
        }

      private:
        template <typename OutputIt>
        auto format_error_stats_to(OutputIt out) const -> OutputIt
        {
            double const avg = error.average_ns();
            double const sd = error.stddev_ns();
            out = std::format_to(out, "\n  --- Wake Error ---\n");
            out = std::format_to(out, "  Average:         {:+.1f} ns ({:+.3f} us)\n", avg, avg / 1000.0);
            out = std::format_to(
                out, "  Minimum:         {:+} ns ({:+.3f} us)\n", error.min_ns, static_cast<double>(error.min_ns) / 1000.0);
            out = std::format_to(
                out, "  Maximum:         {:+} ns ({:+.3f} us)\n", error.max_ns, static_cast<double>(error.max_ns) / 1000.0);
            out = std::format_to(out, "  Std deviation:   {:.1f} ns ({:.3f} us)\n", sd, sd / 1000.0);
            return out;
        }

        template <typename OutputIt>
        auto format_duration_stats_to(OutputIt out) const -> OutputIt
        {
            if (!duration.has_samples()) {
                return out;
            }
            double const avg = duration.average_ns();
            double const sd = duration.stddev_ns();
            out = std::format_to(out, "\n  --- Callback Duration ---\n");
            out = std::format_to(out, "  Average:         {:.1f} ns ({:.3f} us)\n", avg, avg / 1000.0);
            out = std::format_to(
                out, "  Minimum:         {} ns ({:.3f} us)\n", duration.min_ns, static_cast<double>(duration.min_ns) / 1000.0);
            out = std::format_to(
                out, "  Maximum:         {} ns ({:.3f} us)\n", duration.max_ns, static_cast<double>(duration.max_ns) / 1000.0);
            out = std::format_to(out, "  Std deviation:   {:.1f} ns ({:.3f} us)\n", sd, sd / 1000.0);
            return out;
        }

        template <typename OutputIt>
        auto format_suggested_compensation_to(OutputIt out, int64_t compensation_ns) const -> OutputIt
        {
            double const avg = error.average_ns();
            if (std::abs(avg) > 100.0) {
                int64_t const suggested = compensation_ns - static_cast<int64_t>(avg);
                out = std::format_to(
                    out, "\n  Suggested compensation: {} ns ({:+.3f} us)\n", suggested, static_cast<double>(suggested) / 1000.0);
            }
            return out;
        }

        template <typename OutputIt>
        auto format_histograms_to(OutputIt out) const -> OutputIt
        {
            if (error_histogram.num_bins > 0) {
                out = std::format_to(out, "\n  --- Error Distribution ---\n");
                out = error_histogram.format_to(out);
            }
            if (duration_histogram.num_bins > 0 && duration.has_samples()) {
                out = std::format_to(out, "\n  --- Duration Distribution ---\n");
                out = duration_histogram.format_to(out);
            }
            return out;
        }
    };

    [[nodiscard]] auto snapshot() const noexcept -> Snapshot
    {
        return Snapshot{
            .error = error_.snapshot(),
            .duration = duration_.snapshot(),
            .error_histogram = error_histogram_.snapshot(),
            .duration_histogram = duration_histogram_.snapshot(),
            .skipped_counts = load_skipped(),
        };
    }

  private:
    AtomicTimeStats error_;
    AtomicTimeStats duration_;
    AtomicHistogram<128> error_histogram_;
    AtomicHistogram<128> duration_histogram_;
};

}  // namespace statusbar::stats
