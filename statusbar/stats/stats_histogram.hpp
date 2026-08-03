#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Post-hoc histogram classification and ASCII bar chart formatting.
/// Templatized on value type (float, double, int64_t, etc.)

#include <algorithm>
#include <cstddef>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::stats {

/// A histogram bucket definition, templatized on value type.
template <typename T = double>
struct Bucket
{
    std::string_view label;
    T low;   ///< inclusive
    T high;  ///< exclusive
};

/// A histogram entry with count, templatized on value type.
template <typename T = double>
struct HistogramEntry
{
    std::string_view label;
    T low;
    T high;
    size_t count;
};

/// Result of classifying values into buckets.
template <typename T = double>
struct HistogramResult
{
    std::vector<HistogramEntry<T>> entries;
    size_t total_count{0};
};

/// Standard 8-bucket log-scale microsecond histogram (double)
[[nodiscard]] auto log_scale_us_buckets() -> std::span<Bucket<double> const>;

/// Classify values into buckets.
/// T is deduced from the Bucket type; values must be convertible to span<T const>.
template <typename T>
[[nodiscard]] auto histogram(std::span<T const> values, std::span<Bucket<T> const> buckets) -> HistogramResult<T>
{
    HistogramResult<T> result;
    result.entries.reserve(buckets.size());
    for (auto const& b : buckets) {
        result.entries.push_back(HistogramEntry<T>{b.label, b.low, b.high, 0});
    }
    for (auto const& v : values) {
        for (auto& e : result.entries) {
            if (v >= e.low && v < e.high) {
                e.count++;
                result.total_count++;
                break;
            }
        }
    }
    return result;
}

/// Convenience overload: classify a vector of values into buckets.
template <typename T>
[[nodiscard]] auto histogram(std::vector<T> const& values, std::span<Bucket<T> const> buckets) -> HistogramResult<T>
{
    return histogram(std::span<T const>{values}, buckets);
}

/// Format histogram as ASCII bar chart.
template <typename OutputIt, typename T = double>
auto format_histogram_to(OutputIt out, HistogramResult<T> const& hist, int bar_width = 40) -> OutputIt
{
    size_t max_count = 0;
    for (auto const& e : hist.entries) {
        max_count = std::max(max_count, e.count);
    }
    if (max_count == 0) {
        return out;
    }
    for (auto const& e : hist.entries) {
        if (e.count == 0) {
            continue;
        }
        auto const bar_len = static_cast<int>(((e.count * static_cast<size_t>(bar_width)) + max_count - 1) / max_count);
        std::string bar(static_cast<size_t>(bar_len), '#');
        out = std::format_to(out, "  {} {:>5}  {}\n", e.label, e.count, bar);
    }
    return out;
}

}  // namespace statusbar::stats
