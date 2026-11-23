// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_monotonic_raw_line.hpp"

#include <algorithm>
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
    // An offset between two clocks belongs to neither: a bare count.
    return Fit{.rate = 1.0, .offset_ns = MonotonicClock::to_ns(sample.mono) - MonotonicRawClock::to_ns(sample.raw)};
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
        auto const dx = static_cast<double>((window[i].raw - first.raw).count());
        auto const dy = static_cast<double>((window[i].mono - first.mono).count());
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
    int64_t const offset = MonotonicClock::to_ns(first.mono) + std::llround(intercept_delta) -
        scale(MonotonicRawClock::to_ns(first.raw), MonotonicRawLine::slope_numerator(rate), MonotonicRawLine::SLOPE_DENOMINATOR);
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

/// The furthest any sample of the window lies from the line, in whole
/// nanoseconds rounded up: the fit's worst case over what it was fitted to.
[[nodiscard]] auto worst_residual(Window const& window, MonotonicRawLine const& line) noexcept -> Nanoseconds
{
    int64_t worst = 0;
    for (size_t i = 0; i < window.size(); ++i) {
        int64_t const miss = MonotonicClock::to_ns(line.to_monotonic(window[i].raw)) - MonotonicClock::to_ns(window[i].mono);
        worst = std::max(worst, miss < 0 ? -miss : miss);
    }
    return Nanoseconds{worst};
}

/// The spread of the slope over the window's two halves, in parts per
/// billion: how far the rate the line now holds may be from the rate it
/// would be given next. Zero until both halves span some time.
[[nodiscard]] auto rate_spread_ppb(Window const& window) noexcept -> uint32_t
{
    size_t const half = window.size() / 2;
    if (half < 2) {
        return 0;
    }
    auto const slope_ppb = [&window](size_t const from, size_t const to) -> double {
        auto const dx = static_cast<double>((window[to].raw - window[from].raw).count());
        auto const dy = static_cast<double>((window[to].mono - window[from].mono).count());
        return dx > 0.0 ? (dy / dx) * 1e9 : 1e9;
    };
    double const spread = std::fabs(slope_ppb(0, half - 1) - slope_ppb(half, window.size() - 1));
    return spread >= 4e9 ? UINT32_MAX : static_cast<uint32_t>(std::ceil(spread));
}

/// The line's drift bound: the range of the system clock's frequency
/// correction, the line's own distance from rate one and the spread seen
/// in the window, all three together. Saturates.
[[nodiscard]] auto drift_bound_ppb(uint32_t const spread_ppb, int64_t const deviation_ppb) noexcept -> uint32_t
{
    int64_t const sum = int64_t{MonotonicRawTracker::DEFAULT_DRIFT_BOUND_PPB} + int64_t{spread_ppb} + deviation_ppb;
    return sum >= int64_t{UINT32_MAX} ? UINT32_MAX : static_cast<uint32_t>(sum);
}

}  // namespace

auto MonotonicRawLine::slope_numerator(double rate) noexcept -> int64_t
{
    return std::llround(rate * static_cast<double>(SLOPE_DENOMINATOR));
}

auto MonotonicRawLine::to_monotonic_ns(int64_t raw_ns) const noexcept -> int64_t
{
    auto const line = consume_fixed();
    return scale(raw_ns, line.slope_numerator, SLOPE_DENOMINATOR) + line.offset_ns;
}

auto MonotonicRawLine::from_monotonic_ns(int64_t mono_ns) const noexcept -> int64_t
{
    auto const line = consume_fixed();
    return scale(mono_ns - line.offset_ns, SLOPE_DENOMINATOR, line.slope_numerator);
}

auto MonotonicRawLine::sleep_margin(
    MonotonicRawClock::time_point const target_raw, MonotonicRawClock::time_point const raw_now) const noexcept -> Nanoseconds
{
    auto const slew_ppb = static_cast<uint32_t>(rate_deviation_ppb() + SLEEP_RATE_MARGIN_PPB);
    ClockQuality const known = quality();
    if (!known.is_bounded()) {
        return accumulated_drift(target_raw - raw_now, slew_ppb);
    }
    return known.bound_at_sync + accumulated_drift(target_raw - known.synced_at, slew_ppb);
}

auto MonotonicRawTracker::push(
    MonotonicRawClock::time_point const raw, MonotonicClock::time_point const mono, Nanoseconds const bracket) noexcept -> bool
{
    window_.push({.raw = raw, .mono = mono});
    auto const fit = fit_window(window_);
    if (!fit || !rate_in_range(fit->rate)) {
        return false;
    }
    line_->publish(*fit);
    // The quality of what was just published: fitted on the writer's side,
    // so that a reader's uncertainty() stays integer arithmetic.
    line_->publish_quality(
        {.synced_at = raw,
         .bound_at_sync = worst_residual(window_, *line_) +
             (bracket > Nanoseconds::zero() ? (bracket + Nanoseconds{1}) / 2 : Nanoseconds::zero()),
         .epoch = 0,
         .drift_bound_ppb = drift_bound_ppb(rate_spread_ppb(window_), line_->rate_deviation_ppb()),
         .time_source = TimeSource::internal_oscillator});
    return true;
}

auto MonotonicRawTracker::sample() noexcept -> Nanoseconds
{
    auto const raw_before = read_monotonic_raw();
    auto const mono = read_monotonic();
    auto const raw_after = read_monotonic_raw();
    Nanoseconds const bracket = raw_after - raw_before;
    (void)push(raw_before + (bracket / 2), mono, bracket);
    return bracket;
}

}  // namespace statusbar::realtime
