// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for realtime clock types
/// Verifies that each domain is its own type, that integers cross into a
/// domain only through from_ns/to_ns, and that the adapters convert with
/// the clock named on both sides.

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"

#include <chrono>
#include <concepts>
#include <cstdint>
#include <type_traits>

using namespace statusbar::realtime;

//
// Clock Type Tests
//

TEST(clock_types, every_clock_counts_signed_nanoseconds)
{
    static_assert(std::is_same_v<MonotonicRawClock::rep, int64_t>);
    static_assert(std::is_signed_v<MonotonicRawClock::rep>);
    static_assert(std::is_same_v<MonotonicRawClock::duration, std::chrono::duration<int64_t, std::nano>>);
    static_assert(std::is_same_v<GptpClock0::rep, int64_t>);
    static_assert(std::is_same_v<GptpClock<1>::rep, int64_t>);
}

TEST(clock_types, a_duration_is_the_same_type_on_every_clock)
{
    // A period is added to a gPTP schedule and to a RAW deadline alike.
    static_assert(std::is_same_v<MonotonicRawClock::duration, Nanoseconds>);
    static_assert(std::is_same_v<MonotonicClock::duration, Nanoseconds>);
    static_assert(std::is_same_v<GptpClock0::duration, Nanoseconds>);
    static_assert(std::is_same_v<TaiClock::duration, Nanoseconds>);
}

TEST(clock_types, each_domain_has_its_own_time_point)
{
    static_assert(!std::is_same_v<MonotonicRawClock::time_point, MonotonicClock::time_point>);
    static_assert(!std::is_same_v<GptpClock<0>::time_point, GptpClock<1>::time_point>);
    static_assert(!std::is_same_v<GptpClock<0>::time_point, MonotonicRawClock::time_point>);
    static_assert(!std::is_same_v<UtcClock::time_point, TaiClock::time_point>);
    static_assert(std::is_same_v<GptpClock0, GptpClock<0>>);

    // A time on one clock is not accepted where another clock's is wanted.
    static_assert(!std::is_convertible_v<MonotonicClock::time_point, MonotonicRawClock::time_point>);
    static_assert(!std::is_convertible_v<GptpClock0::time_point, MonotonicRawClock::time_point>);
    static_assert(!std::is_assignable_v<GptpClock<0>::time_point&, GptpClock<1>::time_point>);
    static_assert(!std::equality_comparable_with<MonotonicClock::time_point, MonotonicRawClock::time_point>);

    // Nor is a bare count: it has to say which clock it is on.
    static_assert(!std::is_convertible_v<int64_t, MonotonicRawClock::time_point>);
}

TEST(clock_types, the_gptp_tag_carries_its_domain)
{
    static_assert(GptpClock<0>::tag_type::domain_id == 0);
    static_assert(GptpClock<42>::tag_type::domain_id == 42);
}

TEST(clock_types, from_ns_to_ns)
{
    constexpr int64_t test_ns = 1'234'567'890'123LL;

    static_assert(MonotonicRawClock::to_ns(MonotonicRawClock::from_ns(test_ns)) == test_ns);
    static_assert(GptpClock0::to_ns(GptpClock0::from_ns(test_ns)) == test_ns);
    static_assert(std::is_same_v<decltype(GptpClock0::to_ns(GptpClock0::time_point{})), int64_t>);

    // A default time_point is the clock's zero.
    EXPECT_EQ(MonotonicClock::to_ns(MonotonicClock::time_point{}), int64_t{0});
    EXPECT_EQ(UtcClock::to_ns(UtcClock::time_point{}), int64_t{0});
}

TEST(clock_types, duration_arithmetic)
{
    auto const tp = MonotonicRawClock::from_ns(1'000'000'000LL);
    auto const later = tp + Nanoseconds{500'000'000LL};

    EXPECT_EQ(MonotonicRawClock::to_ns(later), int64_t{1'500'000'000LL});
    EXPECT_EQ((later - tp).count(), int64_t{500'000'000LL});
    static_assert(std::is_same_v<decltype(later - tp), Nanoseconds>);
}

TEST(clock_types, tai_is_a_constant_offset_from_utc)
{
    static_assert(TAI_MINUS_UTC == std::chrono::seconds{37});
    constexpr auto utc = UtcClock::from_ns(1'795'000'000'000'000'000LL);
    static_assert(std::is_same_v<decltype(to_tai(utc)), TaiClock::time_point>);
    static_assert(TaiClock::to_ns(to_tai(utc)) == 1'795'000'037'000'000'000LL);
    static_assert(to_utc(to_tai(utc)) == utc);
}

//
// Drift Over a Span
//

TEST(accumulated_drift, a_part_per_billion_is_a_nanosecond_per_second)
{
    static_assert(accumulated_drift(std::chrono::seconds{1}, 1) == Nanoseconds{1});
    static_assert(accumulated_drift(std::chrono::seconds{30}, 1'000) == Nanoseconds{30'000});     // 1 ppm for 30 s
    static_assert(accumulated_drift(std::chrono::milliseconds{375}, 1'000) == Nanoseconds{375});  // three Syncs at 1 ppm
    static_assert(accumulated_drift(std::chrono::hours{1}, 1) == Nanoseconds{3'600});
}

TEST(accumulated_drift, a_fraction_of_a_nanosecond_rounds_up)
{
    // A worst-case figure never understates.
    static_assert(accumulated_drift(Nanoseconds{1}, 1) == Nanoseconds{1});
    static_assert(accumulated_drift(std::chrono::milliseconds{1}, 1) == Nanoseconds{1});
    static_assert(accumulated_drift(Nanoseconds{1'000'000'001}, 1) == Nanoseconds{2});
    static_assert(accumulated_drift(std::chrono::milliseconds{1'500}, 3) == Nanoseconds{5});  // 4.5 rounds up
}

TEST(accumulated_drift, nothing_drifts_over_no_span_or_at_no_rate)
{
    static_assert(accumulated_drift(Nanoseconds{0}, 1'000) == Nanoseconds{0});
    static_assert(accumulated_drift(Nanoseconds{-5}, 1'000) == Nanoseconds{0});
    static_assert(accumulated_drift(std::chrono::hours{24}, 0) == Nanoseconds{0});
}

TEST(accumulated_drift, a_result_that_does_not_fit_saturates)
{
    constexpr uint32_t WORST_PPB = 0xFFFF'FFFFU;
    static_assert(accumulated_drift(Nanoseconds::max(), WORST_PPB) == Nanoseconds::max());
    static_assert(accumulated_drift(Nanoseconds::max(), 1'000'000'000) == Nanoseconds::max());
    // The largest span at 1 ppb still fits: 292 years drift 9.2 seconds.
    static_assert(accumulated_drift(Nanoseconds::max(), 1) == Nanoseconds{9'223'372'037});
    // The largest product of the sub-second part does not overflow.
    static_assert(accumulated_drift(Nanoseconds{999'999'999}, WORST_PPB) == Nanoseconds{4'294'967'291});
}

//
// ClockType Concept Tests
//

TEST(clock_concepts, clock_type_concept)
{
    static_assert(ClockType<MonotonicRawClock>);
    static_assert(ClockType<MonotonicClock>);
    static_assert(ClockType<GptpClock0>);
    static_assert(ClockType<GptpClock<7>>);
    static_assert(ClockType<UtcClock>);
    static_assert(ClockType<TaiClock>);

    static_assert(!ClockType<int>);
    static_assert(!ClockType<std::chrono::steady_clock>);
    static_assert(!ClockType<MonotonicRawClock::time_point>);
}

//
// Typed Clock Reads
//

TEST(clock_reads, the_raw_read_is_the_raw_clock)
{
    int64_t const before = read_monotonic_raw_ns();
    auto const now = read_monotonic_raw();
    int64_t const after = read_monotonic_raw_ns();

    static_assert(std::is_same_v<decltype(now), MonotonicRawClock::time_point const>);
    EXPECT_TRUE(MonotonicRawClock::to_ns(now) >= before);
    EXPECT_TRUE(MonotonicRawClock::to_ns(now) <= after);
}

TEST(clock_reads, the_monotonic_read_is_the_monotonic_clock)
{
    int64_t const before = read_monotonic_ns();
    auto const now = read_monotonic();
    int64_t const after = read_monotonic_ns();

    static_assert(std::is_same_v<decltype(now), MonotonicClock::time_point const>);
    EXPECT_TRUE(MonotonicClock::to_ns(now) >= before);
    EXPECT_TRUE(MonotonicClock::to_ns(now) <= after);
}

TEST(clock_reads, sleeping_to_a_monotonic_deadline_reaches_it)
{
    auto const deadline = read_monotonic() + Nanoseconds{2'000'000};
    EXPECT_EQ(sleep_until_monotonic(deadline), 0);
    EXPECT_TRUE(read_monotonic() >= deadline);

    // A deadline already passed returns at once.
    EXPECT_EQ(sleep_until_monotonic(read_monotonic() - Nanoseconds{1'000'000}), 0);
}

//
// ClockSource Concept Tests
//

namespace {

/// A source whose domain runs at RAW's rate, a fixed offset ahead of it.
struct MockClockSource
{
    int64_t current_time_ns{1'000'000'000LL};
    int64_t offset_ns{100'000'000LL};  // the domain is 100 ms ahead of RAW
    bool healthy{true};

    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return current_time_ns; }
    [[nodiscard]] auto to_raw_ns(int64_t domain_ns) const noexcept -> int64_t { return domain_ns - offset_ns; }
    [[nodiscard]] auto from_raw_ns(int64_t raw_ns) const noexcept -> int64_t { return raw_ns + offset_ns; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return healthy; }
};

/// Maps to CLOCK_MONOTONIC only: not a source any more.
struct MonotonicOnlySource
{
    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return 0; }
    [[nodiscard]] auto to_monotonic_ns(int64_t ns) const noexcept -> int64_t { return ns; }
    [[nodiscard]] auto from_monotonic_ns(int64_t ns) const noexcept -> int64_t { return ns; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return true; }
};

using MockGptpAdapter = ClockAdapter<GptpClock0, MockClockSource>;

/// Whether an adapter accepts a value in a conversion, asked in a way that
/// answers no where a plain call would be a compile error.
template <typename A, typename T>
concept ConvertsToRaw = requires(A const& a, T t) { a.to_raw(t); };

template <typename A, typename T>
concept ConvertsFromRaw = requires(A const& a, T t) { a.from_raw(t); };

template <typename A>
concept ReportsQuality = requires(A const& a) { a.quality(); };

}  // namespace

TEST(clock_source, a_source_maps_its_domain_to_and_from_raw)
{
    static_assert(ClockSource<MockClockSource>);
    static_assert(!ClockSource<MonotonicOnlySource>);
    static_assert(!ClockSource<int>);
}

//
// ClockAdapter Tests
//

TEST(clock_adapter, now_is_the_source_time_in_the_adapters_clock)
{
    MockClockSource source;
    source.current_time_ns = 5'000'000'000LL;
    MockGptpAdapter const adapter{source};

    static_assert(std::is_same_v<decltype(adapter.now()), GptpClock0::time_point>);
    EXPECT_EQ(GptpClock0::to_ns(adapter.now()), int64_t{5'000'000'000LL});
}

TEST(clock_adapter, conversions_name_the_clock_on_both_sides)
{
    MockClockSource const source;
    MockGptpAdapter const adapter{source};

    auto const raw = adapter.to_raw(GptpClock0::from_ns(1'100'000'000LL));
    static_assert(std::is_same_v<decltype(raw), MonotonicRawClock::time_point const>);
    EXPECT_EQ(MonotonicRawClock::to_ns(raw), int64_t{1'000'000'000LL});

    auto const gptp = adapter.from_raw(raw);
    static_assert(std::is_same_v<decltype(gptp), GptpClock0::time_point const>);
    EXPECT_EQ(GptpClock0::to_ns(gptp), int64_t{1'100'000'000LL});

    // A RAW instant is not accepted as the adapter's own domain, or the
    // other way about, and neither is a bare count.
    static_assert(ConvertsToRaw<MockGptpAdapter, GptpClock0::time_point>);
    static_assert(ConvertsFromRaw<MockGptpAdapter, MonotonicRawClock::time_point>);
    static_assert(!ConvertsToRaw<MockGptpAdapter, MonotonicRawClock::time_point>);
    static_assert(!ConvertsFromRaw<MockGptpAdapter, GptpClock0::time_point>);
    static_assert(!ConvertsToRaw<MockGptpAdapter, int64_t>);
}

TEST(clock_adapter, health_is_the_sources)
{
    MockClockSource source;
    MockGptpAdapter const adapter{source};
    EXPECT_TRUE(adapter.is_healthy());

    source.healthy = false;
    EXPECT_FALSE(adapter.is_healthy());
}

TEST(clock_adapter, a_copy_reads_the_same_source)
{
    static_assert(std::is_copy_constructible_v<MockGptpAdapter>);
    static_assert(std::is_copy_assignable_v<MockGptpAdapter>);
    // A temporary source would be gone before the adapter is used.
    static_assert(!std::is_constructible_v<MockGptpAdapter, MockClockSource>);
    static_assert(std::is_constructible_v<MockGptpAdapter, MockClockSource&>);

    MockClockSource source;
    MockGptpAdapter const adapter{source};
    MockGptpAdapter const copy{adapter};
    source.current_time_ns = 42;
    EXPECT_EQ(GptpClock0::to_ns(copy.now()), int64_t{42});
}

TEST(clock_adapter, the_same_source_can_be_bound_to_any_clock)
{
    static_assert(ClockAdapterType<ClockAdapter<GptpClock0, MockClockSource>>);
    static_assert(ClockAdapterType<ClockAdapter<GptpClock<1>, MockClockSource>>);
    static_assert(ClockAdapterType<ClockAdapter<TaiClock, MockClockSource>>);
    static_assert(std::is_same_v<ClockAdapter<TaiClock, MockClockSource>::clock_type, TaiClock>);
}

//
// ClockQuality Tests
//

namespace {

constexpr auto raw_s(int64_t seconds) -> MonotonicRawClock::time_point
{
    return MonotonicRawClock::from_ns(seconds * 1'000'000'000);
}

/// Synchronized at RAW second 100 to within 2 us, wandering at most 1 ppm since.
constexpr ClockQuality SYNCED{
    .synced_at = raw_s(100),
    .bound_at_sync = Nanoseconds{2'000},
    .epoch = 7,
    .drift_bound_ppb = 1'000,
    .time_source = TimeSource::ptp,
};

}  // namespace

TEST(clock_quality, a_default_quality_has_never_synchronized_and_bounds_nothing)
{
    constexpr ClockQuality never{};
    static_assert(!never.is_bounded());
    static_assert(never.uncertainty(raw_s(0)) == UNBOUNDED_ACCURACY);
    static_assert(never.uncertainty(raw_s(1'000'000)) == UNBOUNDED_ACCURACY);
    static_assert(!never.within(UNBOUNDED_ACCURACY, raw_s(5)));
    static_assert(never.time_source == TimeSource::internal_oscillator);
}

TEST(clock_quality, at_the_sync_the_uncertainty_is_the_bound_at_sync)
{
    static_assert(SYNCED.is_bounded());
    static_assert(SYNCED.age(raw_s(100)) == Nanoseconds::zero());
    static_assert(SYNCED.uncertainty(raw_s(100)) == Nanoseconds{2'000});
}

TEST(clock_quality, coasting_grows_the_uncertainty_by_the_drift_bound)
{
    // Three missed Syncs at 8 per second: 375 ms of age costs 375 ns at 1 ppm.
    constexpr auto three_syncs_later = raw_s(100) + std::chrono::milliseconds{375};
    static_assert(SYNCED.age(three_syncs_later) == std::chrono::milliseconds{375});
    static_assert(SYNCED.uncertainty(three_syncs_later) == Nanoseconds{2'375});

    // Thirty seconds without the master: 30 us more. Still inside 100 us.
    static_assert(SYNCED.uncertainty(raw_s(130)) == Nanoseconds{32'000});
    static_assert(SYNCED.within(std::chrono::microseconds{100}, raw_s(130)));
    // A hundred seconds: just past it.
    static_assert(SYNCED.uncertainty(raw_s(200)) == Nanoseconds{102'000});
    static_assert(!SYNCED.within(std::chrono::microseconds{100}, raw_s(200)));
}

TEST(clock_quality, an_instant_before_the_sync_has_age_zero)
{
    // Stamps taken on two threads can be a little out of order.
    static_assert(SYNCED.age(raw_s(99)) == Nanoseconds::zero());
    static_assert(SYNCED.uncertainty(raw_s(99)) == Nanoseconds{2'000});
}

TEST(clock_quality, a_bound_that_is_not_a_bound_claims_nothing)
{
    constexpr ClockQuality negative{.synced_at = raw_s(1), .bound_at_sync = Nanoseconds{-1}};
    static_assert(!negative.is_bounded());
    static_assert(negative.uncertainty(raw_s(2)) == UNBOUNDED_ACCURACY);
}

TEST(clock_quality, growth_saturates_and_never_wraps)
{
    constexpr ClockQuality fast{.synced_at = raw_s(0), .bound_at_sync = Nanoseconds{1}, .drift_bound_ppb = 0xFFFF'FFFFU};
    static_assert(fast.is_bounded());
    static_assert(fast.uncertainty(MonotonicRawClock::time_point::max()) == UNBOUNDED_ACCURACY);

    constexpr ClockQuality nearly{
        .synced_at = raw_s(0), .bound_at_sync = UNBOUNDED_ACCURACY - Nanoseconds{10}, .drift_bound_ppb = 1};
    static_assert(nearly.uncertainty(raw_s(5)) == UNBOUNDED_ACCURACY - Nanoseconds{5});
    static_assert(nearly.uncertainty(raw_s(60)) == UNBOUNDED_ACCURACY);
}

TEST(clock_quality, the_reference_read_as_itself_is_exact)
{
    static_assert(ClockQuality::exact().is_bounded());
    static_assert(ClockQuality::exact().uncertainty(raw_s(1'000'000)) == Nanoseconds::zero());
}

TEST(clock_quality, a_further_step_widens_the_bound)
{
    constexpr auto wider = SYNCED.widened_by(Nanoseconds{500});
    static_assert(wider.bound_at_sync == Nanoseconds{2'500});
    static_assert(wider.uncertainty(raw_s(130)) == Nanoseconds{32'500});
    static_assert(wider.epoch == SYNCED.epoch && wider.synced_at == SYNCED.synced_at);
    // A step cannot make a clock better, or give a bound to one that has none.
    static_assert(SYNCED.widened_by(Nanoseconds{-500}) == SYNCED);
    static_assert(!ClockQuality{}.widened_by(Nanoseconds{500}).is_bounded());
}

TEST(clock_quality, is_plain_integers)
{
    static_assert(std::is_trivially_copyable_v<ClockQuality>);
    static_assert(std::is_trivially_copyable_v<BoundedTime<GptpClock0>>);
    static_assert(sizeof(ClockQuality) <= 32);
    static_assert(sizeof(BoundedTime<GptpClock0>) == 16);
    static_assert(static_cast<uint8_t>(TimeSource::gnss) == 0x20);
    static_assert(static_cast<uint8_t>(TimeSource::internal_oscillator) == 0xA0);

    // The same arithmetic at run time, where a compiler could not have
    // folded it: a quality read from somewhere, an instant read from a clock.
    ClockQuality quality = SYNCED;
    quality.synced_at = read_monotonic_raw();
    auto const later = quality.synced_at + std::chrono::seconds{30};
    EXPECT_EQ(quality.uncertainty(later).count(), int64_t{32'000});
    EXPECT_TRUE(quality.within(std::chrono::microseconds{100}, later));
}

//
// BoundedTime Tests
//

TEST(bounded_time, a_default_bounded_time_claims_no_accuracy)
{
    constexpr BoundedTime<GptpClock0> unknown{};
    static_assert(!unknown.is_bounded());
    static_assert(!unknown.within(UNBOUNDED_ACCURACY));

    constexpr BoundedTime<GptpClock0> good{.time = GptpClock0::from_ns(5), .accuracy = Nanoseconds{40}};
    static_assert(good.is_bounded());
    static_assert(good.within(Nanoseconds{40}));
    static_assert(!good.within(Nanoseconds{39}));
    static_assert(!std::is_same_v<BoundedTime<GptpClock0>, BoundedTime<MonotonicRawClock>>);
}

//
// Adapters, with the Worst-Case Accuracy
//

namespace {

/// A source that reports its quality: a fixed offset ahead of RAW, synced
/// at a RAW instant the test sets.
struct QualifiedSource
{
    static constexpr int64_t OFFSET_NS = 100'000'000;
    ClockQuality reported{};
    int64_t current_time_ns{0};

    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return current_time_ns; }
    [[nodiscard]] auto to_raw_ns(int64_t domain_ns) const noexcept -> int64_t { return domain_ns - OFFSET_NS; }
    [[nodiscard]] auto from_raw_ns(int64_t raw_ns) const noexcept -> int64_t { return raw_ns + OFFSET_NS; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return reported.is_bounded(); }
    [[nodiscard]] auto quality() const noexcept -> ClockQuality { return reported; }
};

using QualifiedAdapter = ClockAdapter<GptpClock0, QualifiedSource>;

}  // namespace

TEST(bounded_adapter, a_source_may_report_its_quality_or_not)
{
    static_assert(QualifiedClockSource<QualifiedSource>);
    static_assert(ClockSource<MockClockSource>);
    static_assert(!QualifiedClockSource<MockClockSource>);

    static_assert(QualifiedClockAdapter<QualifiedAdapter>);
    static_assert(ClockAdapterType<MockGptpAdapter>);
    static_assert(!QualifiedClockAdapter<MockGptpAdapter>);
    static_assert(QualifiedClockAdapter<MonotonicRawClockAdapter>);
}

TEST(bounded_adapter, now_bounded_is_the_time_with_the_accuracy_at_that_instant)
{
    QualifiedSource source;
    source.reported = SYNCED;  // synced at RAW second 100
    source.current_time_ns =
        GptpClock0::to_ns(GptpClock0::from_ns(QualifiedSource::OFFSET_NS)) + 130'000'000'000;  // RAW second 130
    QualifiedAdapter const adapter{source};

    auto const now = adapter.now_bounded();
    static_assert(std::is_same_v<decltype(now), BoundedTime<GptpClock0> const>);
    EXPECT_TRUE(now.time == adapter.now());
    EXPECT_EQ(now.accuracy.count(), int64_t{32'000});
    EXPECT_TRUE(adapter.quality() == SYNCED);
    EXPECT_EQ(adapter.accuracy_at(raw_s(100)).count(), int64_t{2'000});
}

TEST(bounded_adapter, a_conversion_adds_its_own_accuracy_to_the_one_it_is_given)
{
    QualifiedSource source;
    source.reported = SYNCED;
    QualifiedAdapter const adapter{source};

    // A gPTP time known to 300 ns, which is RAW second 130: 2 us at sync,
    // 30 us of coasting, and the 300 ns it came with.
    BoundedTime<GptpClock0> const gptp{
        .time = GptpClock0::from_ns(130'000'000'000 + QualifiedSource::OFFSET_NS), .accuracy = Nanoseconds{300}};
    auto const raw = adapter.to_raw(gptp);
    static_assert(std::is_same_v<decltype(raw), BoundedTime<MonotonicRawClock> const>);
    EXPECT_TRUE(raw.time == raw_s(130));
    EXPECT_EQ(raw.accuracy.count(), int64_t{32'300});

    // And back: the mapping's error is counted again, because it is used again.
    auto const back = adapter.from_raw(raw);
    static_assert(std::is_same_v<decltype(back), BoundedTime<GptpClock0> const>);
    EXPECT_TRUE(back.time == gptp.time);
    EXPECT_EQ(back.accuracy.count(), int64_t{64'300});

    // The plain forms are untouched: a time in, a time out.
    static_assert(std::is_same_v<decltype(adapter.to_raw(gptp.time)), MonotonicRawClock::time_point>);
}

TEST(bounded_adapter, a_time_of_unknown_accuracy_stays_unknown)
{
    QualifiedSource source;
    source.reported = SYNCED;
    QualifiedAdapter const adapter{source};

    BoundedTime<GptpClock0> const unknown{.time = GptpClock0::from_ns(QualifiedSource::OFFSET_NS)};
    EXPECT_FALSE(adapter.to_raw(unknown).is_bounded());
    BoundedTime<GptpClock0> const nonsense{.time = GptpClock0::from_ns(QualifiedSource::OFFSET_NS), .accuracy = Nanoseconds{-1}};
    EXPECT_FALSE(adapter.to_raw(nonsense).is_bounded());
}

TEST(bounded_adapter, a_source_that_reports_no_quality_claims_no_accuracy)
{
    MockClockSource const source;
    MockGptpAdapter const adapter{source};

    EXPECT_FALSE(adapter.now_bounded().is_bounded());
    EXPECT_TRUE(adapter.accuracy_at(raw_s(1)) == UNBOUNDED_ACCURACY);
    BoundedTime<GptpClock0> const exact_in{.time = GptpClock0::from_ns(1'100'000'000LL), .accuracy = Nanoseconds::zero()};
    auto const raw = adapter.to_raw(exact_in);
    EXPECT_EQ(MonotonicRawClock::to_ns(raw.time), int64_t{1'000'000'000LL});
    EXPECT_FALSE(raw.is_bounded());
    // quality() itself is only there when the source has one.
    static_assert(!ReportsQuality<MockGptpAdapter>);
    static_assert(ReportsQuality<QualifiedAdapter>);
}

TEST(bounded_adapter, a_source_that_never_synchronized_is_unbounded_until_it_does)
{
    QualifiedSource source;  // reported{} : never synchronized
    QualifiedAdapter const adapter{source};
    EXPECT_FALSE(adapter.now_bounded().is_bounded());

    source.reported = SYNCED;
    EXPECT_TRUE(adapter.now_bounded().is_bounded());
}

TEST(bounded_adapter, the_raw_adapter_is_exact)
{
    static_assert(MonotonicRawClockAdapter::quality() == ClockQuality::exact());
    static_assert(MonotonicRawClockAdapter::accuracy_at(raw_s(5)) == Nanoseconds::zero());
    constexpr BoundedTime<MonotonicRawClock> in{.time = raw_s(5), .accuracy = Nanoseconds{17}};
    static_assert(MonotonicRawClockAdapter::to_raw(in) == in);
    static_assert(MonotonicRawClockAdapter::from_raw(in) == in);

    auto const before = read_monotonic_raw();
    auto const now = MonotonicRawClockAdapter::now_bounded();
    EXPECT_TRUE(now.time >= before);
    EXPECT_EQ(now.accuracy.count(), int64_t{0});
}

//
// MonotonicRawClockAdapter Tests
//

TEST(monotonic_raw_adapter, is_an_adapter_on_the_raw_clock)
{
    static_assert(ClockAdapterType<MonotonicRawClockAdapter>);
    static_assert(std::is_same_v<MonotonicRawClockAdapter::clock_type, MonotonicRawClock>);
    static_assert(std::is_default_constructible_v<MonotonicRawClockAdapter>);
}

TEST(monotonic_raw_adapter, now_reads_the_raw_clock_and_is_always_healthy)
{
    MonotonicRawClockAdapter const adapter{};
    EXPECT_TRUE(adapter.is_healthy());

    auto const before = read_monotonic_raw();
    auto const now = adapter.now();
    auto const after = read_monotonic_raw();
    EXPECT_TRUE(now >= before);
    EXPECT_TRUE(now <= after);
}

TEST(monotonic_raw_adapter, conversions_are_the_identity)
{
    auto const tp = MonotonicRawClock::from_ns(42);
    static_assert(MonotonicRawClockAdapter::to_raw(MonotonicRawClock::from_ns(42)) == MonotonicRawClock::from_ns(42));
    EXPECT_TRUE(MonotonicRawClockAdapter::to_raw(tp) == tp);
    EXPECT_TRUE(MonotonicRawClockAdapter::from_raw(tp) == tp);
}

//
// ClockAdapterType Concept Tests
//

namespace {

/// Converts to CLOCK_MONOTONIC, not RAW: a Timer cannot wait on it.
struct MonotonicReferenceAdapter
{
    using clock_type = GptpClock0;
    [[nodiscard]] auto now() const noexcept -> GptpClock0::time_point { return {}; }
    [[nodiscard]] auto to_raw(GptpClock0::time_point) const noexcept -> MonotonicClock::time_point { return {}; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return true; }
};

/// Speaks bare nanoseconds: not an adapter.
struct IntegerAdapter
{
    using clock_type = GptpClock0;
    [[nodiscard]] auto now() const noexcept -> int64_t { return 0; }
    [[nodiscard]] auto to_raw(int64_t ns) const noexcept -> int64_t { return ns; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return true; }
};

}  // namespace

TEST(clock_adapter_concept, an_adapter_speaks_typed_time_and_converts_to_raw)
{
    static_assert(!ClockAdapterType<MonotonicReferenceAdapter>);
    static_assert(!ClockAdapterType<IntegerAdapter>);
    static_assert(!ClockAdapterType<MockClockSource>);
    static_assert(!ClockAdapterType<int>);
}

TEST_MAIN(statusbar_realtime, realtime_clock_test)
