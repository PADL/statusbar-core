// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_monotonic_raw_line.hpp"

#include "statusbar/realtime/realtime_base.hpp"

#include <cmath>
#include <cstdint>
#include <optional>

namespace statusbar::realtime {

namespace {

using Fit = MonotonicRawLine::RateOffset;

/// `(value * numerator) / denominator` without overflow for any uptime.
[[nodiscard]] auto scale(int64_t value, int64_t numerator, int64_t denominator) noexcept -> int64_t
{
    __int128 const product = static_cast<__int128>(value) * static_cast<__int128>(numerator);
    return static_cast<int64_t>(product / static_cast<__int128>(denominator));
}

using Sample = MonotonicRawTracker::Sample;
using Window = TimingSampleWindow<Sample>;

/// The line through one sample at rate 1.
[[nodiscard]] auto offset_only(Sample const& sample) noexcept -> Fit
{
    return Fit{.rate = 1.0, .offset_ns = sample.mono_ns - sample.raw_ns};
}

/// Least-squares sums over the window, centred on its first sample so the
/// arithmetic stays on small exact deltas.
struct Sums
{
    double n{0.0};
    double sx{0.0};
    double sy{0.0};
    double sxx{0.0};
    double sxy{0.0};
};

[[nodiscard]] auto accumulate(Window const& window, Sample const& first) noexcept -> Sums
{
    Sums sums{.n = static_cast<double>(window.size())};
    for (size_t i = 0; i < window.size(); ++i) {
        auto const dx = static_cast<double>(window[i].raw_ns - first.raw_ns);
        auto const dy = static_cast<double>(window[i].mono_ns - first.mono_ns);
        sums.sx += dx;
        sums.sy += dy;
        sums.sxx += dx * dx;
        sums.sxy += dx * dy;
    }
    return sums;
}

/// Solve the centred fit and put the intercept back on the absolute clocks
/// in integers: `mono = rate*raw + offset` passes through the first sample
/// plus the fitted delta. nullopt when the samples do not span any time.
[[nodiscard]] auto solve(Sums const& s, Sample const& first) noexcept -> std::optional<Fit>
{
    double const denominator = (s.n * s.sxx) - (s.sx * s.sx);
    if (denominator <= 0.0) {
        return std::nullopt;
    }
    double const rate = ((s.n * s.sxy) - (s.sx * s.sy)) / denominator;
    double const intercept_delta = (s.sy - (rate * s.sx)) / s.n;
    int64_t const offset = first.mono_ns + std::llround(intercept_delta) -
        scale(first.raw_ns, MonotonicRawLine::slope_numerator(rate), MonotonicRawLine::SLOPE_DENOMINATOR);
    return Fit{.rate = rate, .offset_ns = offset};
}

/// Empty = nothing; one sample, or samples that span no time = offset only.
[[nodiscard]] auto fit_window(Window const& window) noexcept -> std::optional<Fit>
{
    if (window.size() == 0) {
        return std::nullopt;
    }
    Sample const& first = window[0];
    if (window.size() == 1) {
        return offset_only(first);
    }
    auto const solved = solve(accumulate(window, first), first);
    return solved ? *solved : offset_only(first);
}

[[nodiscard]] auto rate_in_range(double rate) noexcept -> bool
{
    return std::fabs(rate - 1.0) <= MonotonicRawTracker::MAX_RATE_PPM * 1e-6;
}

}  // namespace

auto MonotonicRawLine::slope_numerator(double rate) noexcept -> int64_t
{
    return std::llround(rate * static_cast<double>(SLOPE_DENOMINATOR));
}

auto MonotonicRawLine::to_monotonic_ns(int64_t raw_ns) const noexcept -> int64_t
{
    auto const line = consume();
    return scale(raw_ns, slope_numerator(line.rate), SLOPE_DENOMINATOR) + line.offset_ns;
}

auto MonotonicRawLine::from_monotonic_ns(int64_t mono_ns) const noexcept -> int64_t
{
    auto const line = consume();
    return scale(mono_ns - line.offset_ns, SLOPE_DENOMINATOR, slope_numerator(line.rate));
}

auto MonotonicRawTracker::push(int64_t raw_ns, int64_t mono_ns) noexcept -> bool
{
    window_.push({.raw_ns = raw_ns, .mono_ns = mono_ns});
    auto const fit = fit_window(window_);
    if (!fit || !rate_in_range(fit->rate)) {
        return false;
    }
    line_->publish(*fit);
    return true;
}

auto MonotonicRawTracker::sample() noexcept -> int64_t
{
    int64_t const raw_before = read_monotonic_raw_ns();
    int64_t const mono = read_monotonic_ns();
    int64_t const raw_after = read_monotonic_raw_ns();
    (void)push(raw_before + ((raw_after - raw_before) / 2), mono);
    return raw_after - raw_before;
}

// MonotonicRawClockAdapter's line conversions (declared in realtime_clock.hpp).

auto MonotonicRawClockAdapter::to_monotonic_ns(int64_t raw_ns) const noexcept -> int64_t
{
    if (line_ != nullptr) {
        return line_->to_monotonic_ns(raw_ns);
    }
    return raw_ns + (read_monotonic_ns() - read_monotonic_raw_ns());
}

auto MonotonicRawClockAdapter::from_monotonic_ns(int64_t mono_ns) const noexcept -> int64_t
{
    if (line_ != nullptr) {
        return line_->from_monotonic_ns(mono_ns);
    }
    return mono_ns - (read_monotonic_ns() - read_monotonic_raw_ns());
}

}  // namespace statusbar::realtime
