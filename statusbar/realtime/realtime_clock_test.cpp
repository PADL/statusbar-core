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
    static_assert(!std::is_same_v<GpsClock::time_point, TaiClock::time_point>);
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
    EXPECT_EQ(GpsClock::to_ns(GpsClock::time_point{}), int64_t{0});
}

TEST(clock_types, duration_arithmetic)
{
    auto const tp = MonotonicRawClock::from_ns(1'000'000'000LL);
    auto const later = tp + Nanoseconds{500'000'000LL};

    EXPECT_EQ(MonotonicRawClock::to_ns(later), int64_t{1'500'000'000LL});
    EXPECT_EQ((later - tp).count(), int64_t{500'000'000LL});
    static_assert(std::is_same_v<decltype(later - tp), Nanoseconds>);
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
    static_assert(ClockType<GpsClock>);
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
    // other way about.
    static_assert(!std::is_invocable_v<decltype(&MockGptpAdapter::to_raw), MockGptpAdapter const&, MonotonicRawClock::time_point>);
    static_assert(!std::is_invocable_v<decltype(&MockGptpAdapter::from_raw), MockGptpAdapter const&, GptpClock0::time_point>);
    static_assert(!std::is_invocable_v<decltype(&MockGptpAdapter::to_raw), MockGptpAdapter const&, int64_t>);
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
