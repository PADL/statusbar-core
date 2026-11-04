// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for realtime clock types
/// Verifies type safety, clock traits, and adapter functionality

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/tsn/tsn.hpp"

#include <chrono>
#include <optional>
#include <ratio>

using namespace statusbar::realtime;

//
// Clock Type Tests
//

TEST(clock_types, monotonic_clock_types)
{
    // Verify MonotonicClock has expected type aliases
    static_assert(std::is_same_v<MonotonicClock::rep, int64_t>);
    static_assert(std::is_same_v<MonotonicClock::duration, std::chrono::duration<int64_t, std::ratio<1, 1'000'000'000>>>);
    static_assert(!MonotonicClock::is_steady);  // Rate can theoretically change
}

TEST(clock_types, gptp_clock_types)
{
    // Verify GptpClock has expected type aliases
    static_assert(std::is_same_v<GptpClock0::rep, int64_t>);
    static_assert(std::is_same_v<GptpClock<0>::rep, int64_t>);
    static_assert(std::is_same_v<GptpClock<1>::rep, int64_t>);

    // Different domains produce different types
    static_assert(!std::is_same_v<GptpClock<0>::time_point, GptpClock<1>::time_point>);
    static_assert(!std::is_same_v<GptpClock<0>::time_point, MonotonicClock::time_point>);
}

TEST(clock_types, from_ns_to_ns)
{
    // Test from_ns and to_ns round-trip
    constexpr int64_t test_ns = 1'234'567'890'123LL;

    auto tp = MonotonicClock::from_ns(test_ns);
    auto ns = MonotonicClock::to_ns(tp);
    EXPECT_EQ(ns, test_ns);

    // Same for GptpClock
    auto gptp_tp = GptpClock0::from_ns(test_ns);
    auto gptp_ns = GptpClock0::to_ns(gptp_tp);
    EXPECT_EQ(gptp_ns, test_ns);
}

//
// Clock Traits Tests
//

TEST(clock_traits, is_clock)
{
    static_assert(is_clock_v<MonotonicClock>);
    static_assert(is_clock_v<GptpClock0>);
    static_assert(is_clock_v<GptpClock<1>>);
    static_assert(is_clock_v<GpsClock>);
    static_assert(is_clock_v<TaiClock>);

    // Non-clock types
    static_assert(!is_clock_v<int>);
    static_assert(!is_clock_v<std::chrono::steady_clock>);
}

TEST(clock_traits, is_gptp_clock)
{
    static_assert(is_gptp_clock_v<GptpClock0>);
    static_assert(is_gptp_clock_v<GptpClock<1>>);
    static_assert(is_gptp_clock_v<GptpClock<42>>);

    static_assert(!is_gptp_clock_v<MonotonicClock>);
    static_assert(!is_gptp_clock_v<GpsClock>);
    static_assert(!is_gptp_clock_v<TaiClock>);
}

TEST(clock_traits, is_monotonic_clock)
{
    static_assert(is_monotonic_clock_v<MonotonicClock>);

    static_assert(!is_monotonic_clock_v<GptpClock0>);
    static_assert(!is_monotonic_clock_v<GpsClock>);
    static_assert(!is_monotonic_clock_v<TaiClock>);
}

TEST(clock_traits, gptp_domain_id)
{
    static_assert(gptp_domain_id_v<GptpClock<0>> == 0);
    static_assert(gptp_domain_id_v<GptpClock<1>> == 1);
    static_assert(gptp_domain_id_v<GptpClock<42>> == 42);
}

//
// Clock Concepts Tests
//

TEST(clock_concepts, clock_type_concept)
{
    static_assert(ClockType<MonotonicClock>);
    static_assert(ClockType<GptpClock0>);
    static_assert(ClockType<GpsClock>);
    static_assert(ClockType<TaiClock>);
}

TEST(clock_concepts, gptp_clock_type_concept)
{
    static_assert(GptpClockType<GptpClock0>);
    static_assert(GptpClockType<GptpClock<1>>);

    static_assert(!GptpClockType<MonotonicClock>);
    static_assert(!GptpClockType<GpsClock>);
}

TEST(clock_concepts, monotonic_clock_type_concept)
{
    static_assert(MonotonicClockType<MonotonicClock>);

    static_assert(!MonotonicClockType<GptpClock0>);
    static_assert(!MonotonicClockType<GpsClock>);
}

//
// Time Point Type Safety Tests
//

TEST(type_safety, different_clocks_different_types)
{
    // These are compile-time checks - different clock time_points are incompatible
    MonotonicClock::time_point mono_tp{};
    GptpClock0::time_point gptp0_tp{};
    GptpClock1::time_point gptp1_tp{};
    GpsClock::time_point gps_tp{};

    // All are default constructed to epoch (0)
    EXPECT_EQ(MonotonicClock::to_ns(mono_tp), 0);
    EXPECT_EQ(GptpClock0::to_ns(gptp0_tp), 0);
    EXPECT_EQ(GptpClock1::to_ns(gptp1_tp), 0);
    EXPECT_EQ(GpsClock::to_ns(gps_tp), 0);

    // The following would be compile errors (type safety):
    // mono_tp = gptp0_tp;           // Error: different clock types
    // bool b = (mono_tp < gptp0_tp); // Error: cannot compare different clocks
    // gptp0_tp = gptp1_tp;          // Error: different gPTP domains
}

TEST(type_safety, duration_arithmetic)
{
    using namespace std::chrono_literals;

    // Durations can be added to time_points
    auto tp = MonotonicClock::from_ns(1'000'000'000LL);         // 1 second
    auto later = tp + MonotonicClock::duration{500'000'000LL};  // +500ms

    EXPECT_EQ(MonotonicClock::to_ns(later), 1'500'000'000LL);

    // Duration between time_points
    auto diff = later - tp;
    EXPECT_EQ(diff.count(), 500'000'000LL);
}

//
// TimeConversion Tests
//

TEST(time_conversion, healthy_conversion)
{
    TimeConversion<MonotonicClock> conv{.time = MonotonicClock::from_ns(1'234'567'890LL), .epoch = 5, .healthy = true};

    EXPECT_TRUE(static_cast<bool>(conv));
    EXPECT_EQ(MonotonicClock::to_ns(conv.time), 1'234'567'890LL);
    EXPECT_EQ(conv.epoch, 5U);
    EXPECT_TRUE(conv.healthy);

    // value() should return the time
    auto val = conv.value();
    EXPECT_EQ(MonotonicClock::to_ns(val), 1'234'567'890LL);
}

TEST(time_conversion, unhealthy_conversion)
{
    TimeConversion<GptpClock0> conv{.time = GptpClock0::from_ns(1'234'567'890LL), .epoch = 3, .healthy = false};

    EXPECT_FALSE(static_cast<bool>(conv));
    EXPECT_FALSE(conv.healthy);

    // value_or should return default
    auto default_tp = GptpClock0::from_ns(999LL);
    auto val = conv.value_or(default_tp);
    EXPECT_EQ(GptpClock0::to_ns(val), 999LL);
}

TEST(time_conversion, value_throws_when_unhealthy)
{
    TimeConversion<MonotonicClock> conv{.time = MonotonicClock::from_ns(0), .epoch = 0, .healthy = false};

    bool threw = false;
    try {
        (void)conv.value();
    } catch (std::runtime_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

//
// MonotonicClockAdapter Tests
//

TEST(monotonic_adapter, always_healthy)
{
    MonotonicClockAdapter adapter;

    EXPECT_TRUE(adapter.is_healthy());
    EXPECT_EQ(adapter.epoch(), 0U);
}

TEST(monotonic_adapter, now_returns_positive)
{
    MonotonicClockAdapter adapter;

    auto result = adapter.now();
    EXPECT_TRUE(result.healthy);
    EXPECT_EQ(result.epoch, 0U);

    // Time should be positive (system has been running for some time)
    auto ns = MonotonicClock::to_ns(result.time);
    EXPECT_TRUE(ns > 0);
}

TEST(monotonic_adapter, now_increases)
{
    MonotonicClockAdapter adapter;

    auto t1 = adapter.now();
    auto t2 = adapter.now();

    EXPECT_TRUE(MonotonicClock::to_ns(t2.time) >= MonotonicClock::to_ns(t1.time));
}

TEST(monotonic_adapter, identity_conversions)
{
    MonotonicClockAdapter adapter;

    auto tp = MonotonicClock::from_ns(1'234'567'890LL);

    // to_monotonic is identity
    auto to_result = adapter.to_monotonic(tp);
    EXPECT_TRUE(to_result.healthy);
    EXPECT_EQ(MonotonicClock::to_ns(to_result.time), 1'234'567'890LL);

    // from_monotonic is identity
    auto from_result = adapter.from_monotonic(tp);
    EXPECT_TRUE(from_result.healthy);
    EXPECT_EQ(MonotonicClock::to_ns(from_result.time), 1'234'567'890LL);

    // Raw ns conversions are identity
    EXPECT_EQ(adapter.to_monotonic_ns(1'234'567'890LL), 1'234'567'890LL);
    EXPECT_EQ(adapter.from_monotonic_ns(1'234'567'890LL), 1'234'567'890LL);
}

TEST(monotonic_adapter, satisfies_concept)
{
    static_assert(ClockAdapterType<MonotonicClockAdapter>);
}

//
// ClockSource Concept Tests
//

// Mock clock source for testing ClockAdapter
struct MockClockSource
{
    int64_t current_time_ns{1'000'000'000LL};
    double rate{1.0};
    int64_t offset_ns{100'000'000LL};  // PTP is 100ms ahead of monotonic
    bool healthy{true};
    uint64_t current_epoch{0};

    [[nodiscard]] auto now_ns() const -> int64_t { return current_time_ns; }

    [[nodiscard]] auto to_monotonic_ns(int64_t ptp_ns) const -> int64_t
    {
        // ptp_time = monotonic_time * rate + offset
        // monotonic_time = (ptp_time - offset) / rate
        return static_cast<int64_t>((static_cast<double>(ptp_ns) - static_cast<double>(offset_ns)) / rate);
    }

    [[nodiscard]] auto from_monotonic_ns(int64_t mono_ns) const -> int64_t
    {
        // ptp_time = monotonic_time * rate + offset
        return static_cast<int64_t>(static_cast<double>(mono_ns) * rate + static_cast<double>(offset_ns));
    }

    [[nodiscard]] auto is_healthy() const -> bool { return healthy; }
    [[nodiscard]] auto epoch() const -> uint64_t { return current_epoch; }
};

TEST(clock_source, mock_satisfies_concept)
{
    static_assert(ClockSource<MockClockSource>);
}

//
// ClockAdapter Tests with Mock Source
//

TEST(clock_adapter, now_returns_source_time)
{
    MockClockSource source;
    source.current_time_ns = 5'000'000'000LL;

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    auto result = adapter.now();
    EXPECT_TRUE(result.healthy);
    EXPECT_EQ(GptpClock0::to_ns(result.time), 5'000'000'000LL);
}

TEST(clock_adapter, to_monotonic_conversion)
{
    MockClockSource source;
    source.rate = 1.0;
    source.offset_ns = 100'000'000LL;  // PTP is 100ms ahead

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    // PTP time of 1100ms should map to monotonic 1000ms
    auto ptp_tp = GptpClock0::from_ns(1'100'000'000LL);
    auto result = adapter.to_monotonic(ptp_tp);

    EXPECT_TRUE(result.healthy);
    EXPECT_EQ(MonotonicClock::to_ns(result.time), 1'000'000'000LL);
}

TEST(clock_adapter, from_monotonic_conversion)
{
    MockClockSource source;
    source.rate = 1.0;
    source.offset_ns = 100'000'000LL;  // PTP is 100ms ahead

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    // Monotonic time of 1000ms should map to PTP 1100ms
    auto mono_tp = MonotonicClock::from_ns(1'000'000'000LL);
    auto result = adapter.from_monotonic(mono_tp);

    EXPECT_TRUE(result.healthy);
    EXPECT_EQ(GptpClock0::to_ns(result.time), 1'100'000'000LL);
}

TEST(clock_adapter, rate_difference)
{
    MockClockSource source;
    source.rate = 1.00005;  // PTP clock is 50ppm faster
    source.offset_ns = 0;

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    // After 1 second of monotonic time, PTP has advanced by 1.00005 seconds
    auto mono_tp = MonotonicClock::from_ns(1'000'000'000LL);
    auto result = adapter.from_monotonic(mono_tp);

    // Expected: 1'000'000'000 * 1.00005 = 1'000'050'000
    EXPECT_EQ(GptpClock0::to_ns(result.time), 1'000'050'000LL);
}

TEST(clock_adapter, unhealthy_source)
{
    MockClockSource source;
    source.healthy = false;

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    auto result = adapter.now();
    EXPECT_FALSE(result.healthy);
    EXPECT_FALSE(static_cast<bool>(result));

    EXPECT_FALSE(adapter.is_healthy());
}

TEST(clock_adapter, epoch_tracking)
{
    MockClockSource source;
    source.current_epoch = 42;

    ClockAdapter<GptpClock0, MockClockSource> adapter{source};

    EXPECT_EQ(adapter.epoch(), 42U);

    auto result = adapter.now();
    EXPECT_EQ(result.epoch, 42U);
}

TEST(clock_adapter, satisfies_concept)
{
    static_assert(ClockAdapterType<ClockAdapter<GptpClock0, MockClockSource>>);
    static_assert(ClockAdapterType<ClockAdapter<GptpClock<1>, MockClockSource>>);
    static_assert(ClockAdapterType<ClockAdapter<GpsClock, MockClockSource>>);
}

//
// gPTP Domain Info Tests
//

TEST(gptp_domain_info, default_values)
{
    GptpDomainInfo info{};

    EXPECT_FALSE(info.has_grandmaster());
    EXPECT_EQ(info.priority1, 255);
    EXPECT_EQ(info.priority2, 255);
    EXPECT_EQ(info.clock_class, 255);
    EXPECT_EQ(info.clock_accuracy, 0xFE);
    EXPECT_EQ(info.steps_removed, 0);
    EXPECT_FALSE(info.is_grandmaster);
    EXPECT_EQ(info.last_sync_mono_ns, 0);
}

TEST(gptp_domain_info, has_grandmaster)
{
    GptpDomainInfo info{};

    // Default GM ID is all zeros - no grandmaster
    EXPECT_FALSE(info.has_grandmaster());

    // Set a valid GM ID
    info.grandmaster_id = statusbar::tsn::ClockIdentity{0x0102030405060708ULL};
    EXPECT_TRUE(info.has_grandmaster());
}

TEST(gptp_domain_info, staleness_detection)
{
    GptpDomainInfo info{};

    // Never synced (last_sync_mono_ns = 0) is always stale
    EXPECT_TRUE(info.is_stale(1'000'000'000LL, default_staleness_threshold_ns));

    // Set a recent sync time
    info.last_sync_mono_ns = 900'000'000LL;

    // 100ms ago is not stale (threshold is 1 second)
    EXPECT_FALSE(info.is_stale(1'000'000'000LL, default_staleness_threshold_ns));

    // 1.5 seconds ago is stale
    EXPECT_TRUE(info.is_stale(2'400'000'000LL, default_staleness_threshold_ns));

    // Custom threshold of 500ms
    EXPECT_TRUE(info.is_stale(1'500'000'000LL, 500'000'000LL));   // 600ms ago, threshold 500ms
    EXPECT_FALSE(info.is_stale(1'200'000'000LL, 500'000'000LL));  // 300ms ago, threshold 500ms
}

TEST(gptp_domain_info, equality)
{
    GptpDomainInfo info1{};
    GptpDomainInfo info2{};

    // Default values should be equal
    EXPECT_TRUE(info1 == info2);

    // Different grandmaster IDs
    info1.grandmaster_id = statusbar::tsn::ClockIdentity{0x0102030405060708ULL};
    EXPECT_FALSE(info1 == info2);

    info2.grandmaster_id = statusbar::tsn::ClockIdentity{0x0102030405060708ULL};
    EXPECT_TRUE(info1 == info2);

    // Different last sync time
    info1.last_sync_mono_ns = 1000;
    EXPECT_FALSE(info1 == info2);
}

//
// GptpClockSource Concept Tests
//

// Extended mock that satisfies GptpClockSource concept
struct MockGptpClockSource
{
    int64_t current_time_ns{1'000'000'000LL};
    double rate{1.0};
    int64_t offset_ns{100'000'000LL};
    bool healthy{true};
    uint64_t current_epoch{0};
    std::optional<GptpDomainInfo> info{};  // nullopt = not yet synchronized
    int64_t staleness_threshold{default_staleness_threshold_ns};

    [[nodiscard]] auto now_ns() const -> int64_t { return current_time_ns; }

    [[nodiscard]] auto to_monotonic_ns(int64_t ptp_ns) const -> int64_t
    {
        return static_cast<int64_t>((static_cast<double>(ptp_ns) - static_cast<double>(offset_ns)) / rate);
    }

    [[nodiscard]] auto from_monotonic_ns(int64_t mono_ns) const -> int64_t
    {
        return static_cast<int64_t>(static_cast<double>(mono_ns) * rate + static_cast<double>(offset_ns));
    }

    [[nodiscard]] auto is_healthy() const -> bool { return healthy; }
    [[nodiscard]] auto epoch() const -> uint64_t { return current_epoch; }
    [[nodiscard]] auto domain_info() const -> std::optional<GptpDomainInfo> { return info; }
    [[nodiscard]] auto staleness_threshold_ns() const -> int64_t { return staleness_threshold; }
};

TEST(gptp_clock_source, mock_satisfies_concept)
{
    static_assert(ClockSource<MockGptpClockSource>);
    static_assert(GptpClockSource<MockGptpClockSource>);

    // Basic mock does NOT satisfy GptpClockSource
    static_assert(!GptpClockSource<MockClockSource>);
}

//
// ClockAdapter with GptpClockSource Tests
//

TEST(gptp_adapter, not_synchronized)
{
    MockGptpClockSource source;
    // info is nullopt by default - not yet synchronized

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    // domain_info() returns nullopt
    auto info = adapter.domain_info();
    EXPECT_FALSE(info.has_value());

    // grandmaster_id() returns nullopt
    auto gm_id = adapter.grandmaster_id();
    EXPECT_FALSE(gm_id.has_value());

    // is_synchronized() returns false
    EXPECT_FALSE(adapter.is_synchronized());

    // is_stale() returns true (not synchronized = stale)
    EXPECT_TRUE(adapter.is_stale());
}

TEST(gptp_adapter, domain_info_access)
{
    MockGptpClockSource source;
    GptpDomainInfo domain{};
    domain.grandmaster_id = statusbar::tsn::ClockIdentity{0xAABBCCDDEEFF1122ULL};
    domain.priority1 = 128;
    domain.steps_removed = 2;
    domain.is_grandmaster = false;
    source.info = domain;  // Now synchronized

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    auto info = adapter.domain_info();
    EXPECT_TRUE(info.has_value());
    EXPECT_EQ(info->grandmaster_id.to_uint64(), 0xAABBCCDDEEFF1122ULL);
    EXPECT_EQ(info->priority1, 128);
    EXPECT_EQ(info->steps_removed, 2);
    EXPECT_FALSE(info->is_grandmaster);

    EXPECT_TRUE(adapter.is_synchronized());
}

TEST(gptp_adapter, grandmaster_id_shortcut)
{
    MockGptpClockSource source;
    GptpDomainInfo domain{};
    domain.grandmaster_id = statusbar::tsn::ClockIdentity{0x1234567890ABCDEFULL};
    source.info = domain;

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    auto gm_id = adapter.grandmaster_id();
    EXPECT_TRUE(gm_id.has_value());
    EXPECT_EQ(gm_id->to_uint64(), 0x1234567890ABCDEFULL);
}

TEST(gptp_adapter, staleness_threshold)
{
    MockGptpClockSource source;
    source.staleness_threshold = 500'000'000LL;  // 500ms

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    EXPECT_EQ(adapter.staleness_threshold_ns(), 500'000'000LL);
}

TEST(gptp_adapter, grandmaster_change_detection)
{
    MockGptpClockSource source;

    // Initial GM
    GptpDomainInfo domain1{};
    domain1.grandmaster_id = statusbar::tsn::ClockIdentity{0x1111111111111111ULL};
    source.info = domain1;
    source.current_epoch = 1;

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    auto gm1 = adapter.grandmaster_id();
    auto epoch1 = adapter.epoch();
    EXPECT_TRUE(gm1.has_value());

    // GM changes (simulating what would happen in a real bridge)
    GptpDomainInfo domain2{};
    domain2.grandmaster_id = statusbar::tsn::ClockIdentity{0x2222222222222222ULL};
    source.info = domain2;
    source.current_epoch = 2;  // Epoch should increment on GM change

    auto gm2 = adapter.grandmaster_id();
    auto epoch2 = adapter.epoch();

    EXPECT_NE(gm1->to_uint64(), gm2->to_uint64());
    EXPECT_NE(epoch1, epoch2);

    // GM changes back to original (epoch should still increment)
    source.info = domain1;
    source.current_epoch = 3;  // Epoch increments even when returning to previous GM

    auto gm3 = adapter.grandmaster_id();
    auto epoch3 = adapter.epoch();

    EXPECT_EQ(gm1->to_uint64(), gm3->to_uint64());  // Same GM ID
    EXPECT_NE(epoch2, epoch3);                      // But different epoch
}

TEST(gptp_adapter, synchronization_lost)
{
    MockGptpClockSource source;

    // Start synchronized
    GptpDomainInfo domain{};
    domain.grandmaster_id = statusbar::tsn::ClockIdentity{0x1111111111111111ULL};
    source.info = domain;
    source.current_epoch = 1;

    ClockAdapter<GptpClock0, MockGptpClockSource> adapter{source};

    EXPECT_TRUE(adapter.is_synchronized());
    EXPECT_TRUE(adapter.grandmaster_id().has_value());

    // GM disappears (lost synchronization)
    source.info = std::nullopt;
    source.current_epoch = 2;  // Epoch increments on loss of sync

    EXPECT_FALSE(adapter.is_synchronized());
    EXPECT_FALSE(adapter.grandmaster_id().has_value());
    EXPECT_FALSE(adapter.domain_info().has_value());
    EXPECT_TRUE(adapter.is_stale());
}

//
// Test Runner
//

//
// MonotonicRawClock and MonotonicRawClockAdapter Tests
//

TEST(monotonic_raw_clock, is_its_own_clock_type)
{
    static_assert(is_clock_v<MonotonicRawClock>);
    static_assert(is_monotonic_raw_clock_v<MonotonicRawClock>);
    static_assert(!is_monotonic_raw_clock_v<MonotonicClock>);
    static_assert(!is_monotonic_clock_v<MonotonicRawClock>);
    static_assert(MonotonicRawClockType<MonotonicRawClock>);
    static_assert(!std::is_same_v<MonotonicRawClock::time_point, MonotonicClock::time_point>);
    static_assert(std::is_signed_v<MonotonicRawClock::rep>);
}

TEST(monotonic_raw_adapter, satisfies_the_adapter_concept_and_says_it_is_raw)
{
    static_assert(ClockAdapterType<MonotonicRawClockAdapter>);
    static_assert(reference_is_raw_v<MonotonicRawClockAdapter>);
    static_assert(!reference_is_raw_v<MonotonicClockAdapter>);
    static_assert(std::is_same_v<MonotonicRawClockAdapter::clock_type, MonotonicRawClock>);
}

TEST(monotonic_raw_adapter, now_reads_the_raw_clock_and_is_always_healthy)
{
    MonotonicRawClockAdapter adapter;
    EXPECT_TRUE(adapter.is_healthy());
    EXPECT_EQ(adapter.epoch(), 0U);
    auto const before = read_monotonic_raw_ns();
    auto const now = adapter.now();
    auto const after = read_monotonic_raw_ns();
    EXPECT_TRUE(now.healthy);
    EXPECT_TRUE(MonotonicRawClock::to_ns(now.time) >= before);
    EXPECT_TRUE(MonotonicRawClock::to_ns(now.time) <= after);
    EXPECT_EQ(adapter.to_raw_ns(42), int64_t{42});
    EXPECT_EQ(adapter.from_raw_ns(42), int64_t{42});
}

TEST(monotonic_raw_adapter, converts_to_monotonic_through_the_line_it_is_given)
{
    MonotonicRawLine line;
    line.publish({.rate = 1.0, .offset_ns = 1'000});
    MonotonicRawClockAdapter adapter{&line};
    EXPECT_EQ(adapter.to_monotonic_ns(10), int64_t{1'010});
    EXPECT_EQ(adapter.from_monotonic_ns(1'010), int64_t{10});
    auto const mono = adapter.to_monotonic(MonotonicRawClock::from_ns(10));
    static_assert(std::is_same_v<decltype(mono), TimeConversion<MonotonicClock> const>);
    EXPECT_EQ(MonotonicClock::to_ns(mono.time), int64_t{1'010});
}

TEST(monotonic_raw_adapter, without_a_line_it_applies_the_live_offset)
{
    MonotonicRawClockAdapter adapter;
    int64_t const raw_now = read_monotonic_raw_ns();
    int64_t const mono_now = read_monotonic_ns();
    // Converting "now" gives "now" on the other clock, give or take the reads.
    EXPECT_TRUE(std::llabs(adapter.to_monotonic_ns(raw_now) - mono_now) < 1'000'000);
    EXPECT_TRUE(std::llabs(adapter.from_monotonic_ns(mono_now) - raw_now) < 1'000'000);
}

namespace {

/// A gPTP source that says it maps to RAW: a ClockAdapter on it forwards
/// to_raw_ns/from_raw_ns and reports reference_is_raw.
struct RawGptpSource
{
    static constexpr bool reference_is_raw = true;
    [[nodiscard]] auto now_ns() const noexcept -> int64_t { return 5'000; }
    [[nodiscard]] auto to_monotonic_ns(int64_t ns) const noexcept -> int64_t { return ns + 100; }
    [[nodiscard]] auto from_monotonic_ns(int64_t ns) const noexcept -> int64_t { return ns - 100; }
    [[nodiscard]] auto to_raw_ns(int64_t ns) const noexcept -> int64_t { return ns + 1; }
    [[nodiscard]] auto from_raw_ns(int64_t ns) const noexcept -> int64_t { return ns - 1; }
    [[nodiscard]] auto is_healthy() const noexcept -> bool { return true; }
    [[nodiscard]] auto epoch() const noexcept -> uint64_t { return 0; }
};

}  // namespace

TEST(clock_adapter, forwards_a_raw_reference_source)
{
    static_assert(RawReferenceClockSource<RawGptpSource>);
    static_assert(!RawReferenceClockSource<MockClockSource>);
    RawGptpSource source;
    ClockAdapter<GptpClock0, RawGptpSource> adapter{source};
    static_assert(reference_is_raw_v<decltype(adapter)>);
    EXPECT_EQ(adapter.to_raw_ns(10), int64_t{11});
    EXPECT_EQ(adapter.from_raw_ns(11), int64_t{10});
    static_assert(!reference_is_raw_v<ClockAdapter<GptpClock0, MockClockSource>>);
}

TEST_MAIN(statusbar_realtime, realtime_clock_test)