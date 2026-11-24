#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// One user's limit on one clock.
///
/// A clock source reports how well it knows its time as a ClockQuality: a
/// worst-case error that grows while the source is not being synchronized.
/// Whether that is good enough is not the source's to say. Each user of the
/// time has its own tolerance, set in its configuration, and compares the
/// two. AccuracyLimit is that comparison, together with a record of how the
/// clock has kept to the limit, for the user's report.
///
/// This is what replaces a "synchronized" flag driven by a protocol timeout.
/// A source that misses a few messages keeps its rate and offset and its
/// error grows slowly, so a user with a limit of 100 microseconds runs on
/// for seconds and a user with a limit of 10 milliseconds for minutes.

#include "statusbar/realtime/realtime_clock.hpp"

#include <cstdint>

namespace statusbar::realtime {

/// What a user concluded about a clock at one instant.
struct AccuracyVerdict
{
    /// The clock's worst-case error was bounded and within the limit.
    bool usable{false};

    /// The clock is on a different timeline from the one last judged (a new
    /// grandmaster, a time step): what the user built on the old one, an
    /// offset or a filter, does not carry over. True for one verdict.
    bool timeline_changed{false};

    /// The worst-case error at the instant judged.
    Nanoseconds accuracy{UNBOUNDED_ACCURACY};
};

/// How a clock has kept to a limit since the user started judging it.
struct AccuracyRecord
{
    /// Times the clock went from usable to not usable.
    uint64_t excursions{0};

    /// Changes of timeline seen.
    uint64_t timeline_changes{0};

    /// Time spent not usable after the clock was first usable.
    Nanoseconds outside{0};

    /// The largest error seen while usable.
    Nanoseconds worst_usable{0};
};

/// Judges a clock's quality against a configured limit. Told the time,
/// integers only, no allocation. Single-threaded: its owner judges, and
/// publishes what others need.
class AccuracyLimit
{
  public:
    /// The limit that any bounded clock meets.
    static constexpr Nanoseconds ANY_BOUNDED = UNBOUNDED_ACCURACY;

    AccuracyLimit() noexcept = default;

    /// @param limit The largest worst-case error the user tolerates
    explicit constexpr AccuracyLimit(Nanoseconds const limit) noexcept
        : limit_{limit}
    {}

    [[nodiscard]] constexpr auto limit() const noexcept -> Nanoseconds { return limit_; }

    /// Judge the clock at @p now and add the verdict to the record.
    /// @param quality What the clock's source reports
    /// @param now The CLOCK_MONOTONIC_RAW instant the verdict is for
    constexpr auto judge(ClockQuality const& quality, MonotonicRawClock::time_point const now) noexcept -> AccuracyVerdict
    {
        AccuracyVerdict const verdict{
            .usable = quality.within(limit_, now),
            .timeline_changed = judged_ && quality.epoch != epoch_,
            .accuracy = quality.uncertainty(now)};
        note(verdict, now);
        epoch_ = quality.epoch;
        judged_ = true;
        return verdict;
    }

    /// The last verdict's answer: false before the first.
    [[nodiscard]] constexpr auto usable() const noexcept -> bool { return usable_; }

    [[nodiscard]] constexpr auto record() const noexcept -> AccuracyRecord const& { return record_; }

  private:
    constexpr auto note(AccuracyVerdict const& verdict, MonotonicRawClock::time_point const now) noexcept -> void
    {
        if (verdict.timeline_changed) {
            ++record_.timeline_changes;
        }
        if (usable_ && !verdict.usable) {
            ++record_.excursions;
        }
        if (was_usable_ && !usable_ && now > last_) {
            record_.outside += now - last_;
        }
        if (verdict.usable && verdict.accuracy > record_.worst_usable) {
            record_.worst_usable = verdict.accuracy;
        }
        remember(verdict, now);
    }

    constexpr auto remember(AccuracyVerdict const& verdict, MonotonicRawClock::time_point const now) noexcept -> void
    {
        usable_ = verdict.usable;
        was_usable_ = was_usable_ || verdict.usable;
        last_ = now;
    }

    Nanoseconds limit_{ANY_BOUNDED};
    AccuracyRecord record_{};
    MonotonicRawClock::time_point last_{};
    uint64_t epoch_{0};
    bool judged_{false};
    bool usable_{false};
    bool was_usable_{false};
};

}  // namespace statusbar::realtime
