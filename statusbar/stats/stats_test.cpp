// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/stats/stats.hpp"

#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar::stats;

// ---------------------------------------------------------------------------
// stats_analyze - analyze() tests
// ---------------------------------------------------------------------------

TEST(stats_analyze, empty_input)
{
    std::vector<double> measurements;
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 0);
    EXPECT_EQ(s.mean, 0.0);
    EXPECT_EQ(s.median, 0.0);
    EXPECT_EQ(s.stddev, 0.0);
}

TEST(stats_analyze, single_value)
{
    std::vector<double> measurements{42.0};
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 1);
    EXPECT_EQ(s.mean, 42.0);
    EXPECT_EQ(s.median, 42.0);
    EXPECT_EQ(s.min, 42.0);
    EXPECT_EQ(s.max, 42.0);
    EXPECT_EQ(s.stddev, 0.0);
}

TEST(stats_analyze, two_values)
{
    std::vector<double> measurements{100.0, 200.0};
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 2);
    EXPECT_EQ(s.mean, 150.0);
    EXPECT_EQ(s.median, 150.0);
    EXPECT_EQ(s.min, 100.0);
    EXPECT_EQ(s.max, 200.0);
}

TEST(stats_analyze, odd_count)
{
    std::vector<double> measurements{10.0, 20.0, 30.0};
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 3);
    EXPECT_EQ(s.mean, 20.0);
    EXPECT_EQ(s.median, 20.0);
    EXPECT_EQ(s.min, 10.0);
    EXPECT_EQ(s.max, 30.0);
}

TEST(stats_analyze, known_dataset)
{
    // Values: 2, 4, 4, 4, 5, 5, 7, 9
    // Mean = 5, Variance = 4, StdDev = 2
    std::vector<double> measurements{2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 8);
    EXPECT_EQ(s.mean, 5.0);
    EXPECT_TRUE(s.stddev > 1.9 && s.stddev < 2.1);
    EXPECT_EQ(s.min, 2.0);
    EXPECT_EQ(s.max, 9.0);
    // median of [2,4,4,4,5,5,7,9] = (4+5)/2 = 4.5
    EXPECT_TRUE(s.median > 4.4 && s.median < 4.6);
}

TEST(stats_analyze, percentiles_large_dataset)
{
    // 100 values: 1..100
    std::vector<double> measurements;
    for (int i = 1; i <= 100; ++i) {
        measurements.push_back(static_cast<double>(i));
    }
    auto s = analyze(std::move(measurements));
    EXPECT_EQ(s.sample_count, 100);
    EXPECT_EQ(s.min, 1.0);
    EXPECT_EQ(s.max, 100.0);
    // p95 index = 100*0.95 = 95 -> measurements[95] = 96
    EXPECT_EQ(s.p95, 96.0);
    // p99 index = 100*0.99 = 99 -> measurements[99] = 100
    EXPECT_EQ(s.p99, 100.0);
}

// ---------------------------------------------------------------------------
// stats_percentile - percentile() tests
// ---------------------------------------------------------------------------

TEST(stats_percentile, empty_input)
{
    std::span<double const> empty;
    EXPECT_EQ(percentile(empty, 0.5), 0.0);
}

TEST(stats_percentile, zeroth_percentile)
{
    std::vector<double> data{10.0, 20.0, 30.0, 40.0, 50.0};
    EXPECT_EQ(percentile(data, 0.0), 10.0);
}

TEST(stats_percentile, fiftieth_percentile)
{
    std::vector<double> data{10.0, 20.0, 30.0, 40.0, 50.0};
    // index = 5*0.5 = 2 -> data[2] = 30
    EXPECT_EQ(percentile(data, 0.5), 30.0);
}

TEST(stats_percentile, hundredth_percentile)
{
    std::vector<double> data{10.0, 20.0, 30.0, 40.0, 50.0};
    // index = 5*1.0 = 5, clamped to 4 -> data[4] = 50
    EXPECT_EQ(percentile(data, 1.0), 50.0);
}

TEST(stats_percentile, small_dataset)
{
    std::vector<double> data{5.0};
    EXPECT_EQ(percentile(data, 0.0), 5.0);
    EXPECT_EQ(percentile(data, 0.5), 5.0);
    EXPECT_EQ(percentile(data, 1.0), 5.0);
}

// ---------------------------------------------------------------------------
// stats_histogram - histogram tests
// ---------------------------------------------------------------------------

TEST(stats_histogram, empty_input)
{
    auto buckets = log_scale_us_buckets();
    std::span<double const> empty;
    auto result = histogram(empty, buckets);
    EXPECT_EQ(result.total_count, 0);
    EXPECT_EQ(result.entries.size(), buckets.size());
}

TEST(stats_histogram, log_scale_bucket_count)
{
    auto buckets = log_scale_us_buckets();
    EXPECT_EQ(buckets.size(), 8);
}

TEST(stats_histogram, values_in_different_buckets)
{
    auto buckets = log_scale_us_buckets();
    std::vector<double> values{
        100.0,    // 0-500us bucket
        750.0,    // 500-1000us bucket
        1500.0,   // 1000-2000us bucket
        3000.0,   // 2000-5000us bucket
        7000.0,   // 5-10ms bucket
        20000.0,  // 10-50ms bucket
    };
    auto result = histogram(values, buckets);
    EXPECT_EQ(result.total_count, 6);
    EXPECT_EQ(result.entries[0].count, 1);  // 0-500us
    EXPECT_EQ(result.entries[1].count, 1);  // 500-1000us
    EXPECT_EQ(result.entries[2].count, 1);  // 1000-2000us
    EXPECT_EQ(result.entries[3].count, 1);  // 2000-5000us
    EXPECT_EQ(result.entries[4].count, 1);  // 5-10ms
    EXPECT_EQ(result.entries[5].count, 1);  // 10-50ms
    EXPECT_EQ(result.entries[6].count, 0);  // 50-250ms
    EXPECT_EQ(result.entries[7].count, 0);  // >250ms
}

TEST(stats_histogram, multiple_values_same_bucket)
{
    auto buckets = log_scale_us_buckets();
    std::vector<double> values{100.0, 200.0, 300.0, 400.0};
    auto result = histogram(values, buckets);
    EXPECT_EQ(result.total_count, 4);
    EXPECT_EQ(result.entries[0].count, 4);  // all in 0-500us
}

TEST(stats_histogram, format_histogram_to_output)
{
    auto buckets = log_scale_us_buckets();
    std::vector<double> values{100.0, 750.0};
    auto result = histogram(values, buckets);
    std::string output;
    format_histogram_to(std::back_inserter(output), result);
    // Should contain some '#' characters for the bar chart
    EXPECT_TRUE(output.find('#') != std::string::npos);
    // Should contain count "1"
    EXPECT_TRUE(output.find('1') != std::string::npos);
}

// ---------------------------------------------------------------------------
// stats_format - format_duration tests
// ---------------------------------------------------------------------------

TEST(stats_format, nanosecond_range)
{
    std::string result = format_duration(500.0);
    EXPECT_TRUE(result.find("ns") != std::string::npos);
}

TEST(stats_format, microsecond_range)
{
    std::string result = format_duration(5000.0);
    EXPECT_TRUE(result.find("s") != std::string::npos);
}

TEST(stats_format, millisecond_range)
{
    std::string result = format_duration(5'000'000.0);
    EXPECT_TRUE(result.find("ms") != std::string::npos);
}

TEST(stats_format, second_range)
{
    std::string result = format_duration(5'000'000'000.0);
    EXPECT_TRUE(result.find(" s") != std::string::npos);
}

TEST(stats_format, timestamp_ns_zero)
{
    std::string result = format_timestamp_ns(0);
    EXPECT_EQ(result, std::string{"[  0.000]"});
}

TEST(stats_format, timestamp_ns_sub_ms)
{
    // 500 microseconds = 500_000 ns -> 0 ms integer part, 0 ms fractional
    std::string result = format_timestamp_ns(500'000);
    EXPECT_EQ(result, std::string{"[  0.000]"});
}

TEST(stats_format, timestamp_ns_ms_range)
{
    // 1500 ms = 1_500_000_000 ns -> "[  1.500]"
    std::string result = format_timestamp_ns(1'500'000'000);
    EXPECT_EQ(result, std::string{"[  1.500]"});
}

TEST(stats_format, timestamp_ns_seconds_range)
{
    // 12_345 ms = 12_345_000_000 ns -> "[ 12.345]"
    std::string result = format_timestamp_ns(12'345'000'000);
    EXPECT_EQ(result, std::string{"[ 12.345]"});
}

TEST(stats_format, report_smoke_writes_output)
{
    // report() writes to stdout. Redirect to a pipe and confirm the
    // benchmark label and at least one stat line appear. This is a
    // smoke test — we just verify the function can be called without
    // crashing and produces non-empty output that includes the name.
    fflush(stdout);
    int pipefd[2]{};
    EXPECT_EQ(pipe(pipefd), 0);
    int const saved_stdout = dup(STDOUT_FILENO);
    EXPECT_NE(saved_stdout, -1);
    EXPECT_NE(dup2(pipefd[1], STDOUT_FILENO), -1);
    close(pipefd[1]);

    DescriptiveStats const stats{
        .mean = 150.0, .median = 149.0, .stddev = 10.0, .min = 100.0, .max = 200.0, .p95 = 190.0, .p99 = 198.0, .sample_count = 42};
    report(std::string_view{"smoke-test"}, stats);
    fflush(stdout);

    EXPECT_NE(dup2(saved_stdout, STDOUT_FILENO), -1);
    close(saved_stdout);

    std::string captured;
    captured.resize(4096);
    ssize_t const n = read(pipefd[0], captured.data(), captured.size());
    close(pipefd[0]);
    if (n > 0) {
        captured.resize(static_cast<size_t>(n));
    } else {
        captured.clear();
    }
    EXPECT_TRUE(captured.find("smoke-test") != std::string::npos);
    EXPECT_TRUE(captured.find("Samples") != std::string::npos);
}

//
// AtomicHistogram tests
//

TEST(stats_atomic_histogram, configure_honors_bin_width_and_narrows_range)
{
    // low=0, high=300ms, requested bin_width=250ns. That requests
    // 1.2M bins but storage holds only 1024. configure() honors the
    // requested bin_width and narrows high_ns to fit exactly
    // MaxBins bins worth of range (here 256µs). Values beyond the
    // truncated high_ns route to the overflow bin — this is the
    // explicit "I want fine resolution, accept a smaller window"
    // contract.
    AtomicHistogram<1024> h;
    h.configure(AtomicHistogramConfig{.low_ns = 0, .high_ns = 300'000'000, .bin_width_ns = 250});

    auto const& cfg = h.config();
    EXPECT_EQ(cfg.bin_width_ns, int64_t{250});
    EXPECT_EQ(cfg.high_ns, int64_t{1024} * 250);  // 256000 = 256µs
    EXPECT_EQ(h.num_bins(), size_t{1024});

    // 100ns lands in bin 0; 200µs lands in the last bin; 1.8ms is
    // beyond the truncated range and routes to overflow.
    h.update(100);
    h.update(200'000);
    h.update(1'800'000);

    auto snap = h.snapshot();
    EXPECT_EQ(snap.total_count(), int64_t{3});
    EXPECT_EQ(snap.bins[0], int64_t{1});
    EXPECT_EQ(snap.overflow, int64_t{1});
    EXPECT_EQ(snap.underflow, int64_t{0});
}

TEST(stats_atomic_histogram, configure_keeps_user_bin_width_when_it_fits)
{
    // (high - low) / bin_width_ns ≤ MaxBins → range stays as
    // configured. Here 1024 bins of 1µs cover 1ms.
    AtomicHistogram<1024> h;
    h.configure(AtomicHistogramConfig{.low_ns = 0, .high_ns = 1'000'000, .bin_width_ns = 1000});
    auto const& cfg = h.config();
    EXPECT_EQ(cfg.bin_width_ns, int64_t{1000});
    EXPECT_EQ(cfg.high_ns, int64_t{1'000'000});
    EXPECT_EQ(h.num_bins(), size_t{1000});
}

TEST(stats_atomic_histogram, in_range_still_lands_in_correct_bin)
{
    AtomicHistogram<1024> h;
    h.configure(AtomicHistogramConfig{.low_ns = 0, .high_ns = 1'000'000, .bin_width_ns = 1000});
    h.update(500);      // bin 0
    h.update(1500);     // bin 1
    h.update(999'500);  // bin 999
    auto snap = h.snapshot();
    EXPECT_EQ(snap.total_count(), int64_t{3});
    EXPECT_EQ(snap.overflow, int64_t{0});
    EXPECT_EQ(snap.underflow, int64_t{0});
    EXPECT_EQ(snap.bins[0], int64_t{1});
    EXPECT_EQ(snap.bins[1], int64_t{1});
    EXPECT_EQ(snap.bins[999], int64_t{1});
}

TEST(stats_atomic_histogram, underflow_routed)
{
    AtomicHistogram<1024> h;
    h.configure(AtomicHistogramConfig{.low_ns = 0, .high_ns = 1'000'000, .bin_width_ns = 1000});
    h.update(-500);
    auto snap = h.snapshot();
    EXPECT_EQ(snap.underflow, int64_t{1});
    EXPECT_EQ(snap.overflow, int64_t{0});
}

// ---------------------------------------------------------------------------
// stats_atomic_time - AtomicTimeStats tests
// ---------------------------------------------------------------------------

namespace {

// The framework has no EXPECT_NEAR; compare with an absolute tolerance.
[[nodiscard]] auto near(double a, double b, double eps = 1e-6) -> bool
{
    return std::fabs(a - b) < eps;
}

}  // namespace

TEST(stats_atomic_time, initial_state_and_reset)
{
    AtomicTimeStats stats;
    EXPECT_EQ(stats.count(), 0);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_FALSE(stats.snapshot().has_samples());
    EXPECT_EQ(stats.snapshot().average_ns(), 0.0);
    EXPECT_EQ(stats.snapshot().stddev_ns(), 0.0);

    stats.update(100);
    EXPECT_EQ(stats.count(), 1);
    stats.reset();
    EXPECT_EQ(stats.count(), 0);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_FALSE(stats.snapshot().has_samples());
}

TEST(stats_atomic_time, tracks_count_sum_min_max)
{
    AtomicTimeStats stats;
    stats.update(300);
    stats.update(-100);
    stats.update(200);

    EXPECT_EQ(stats.count(), 3);
    EXPECT_EQ(stats.sum_ns(), 400);
    EXPECT_EQ(stats.min_ns(), -100);
    EXPECT_EQ(stats.max_ns(), 300);
}

TEST(stats_atomic_time, average_and_stddev)
{
    AtomicTimeStats stats;
    stats.update(1);
    stats.update(2);
    stats.update(3);
    stats.update(4);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, 4);
    EXPECT_EQ(snap.sum_ns, 10);
    EXPECT_EQ(snap.sum_sq, 30);  // 1 + 4 + 9 + 16
    EXPECT_TRUE(near(snap.average_ns(), 2.5));
    // Population variance = 30/4 - 2.5^2 = 1.25
    EXPECT_TRUE(near(snap.stddev_ns(), std::sqrt(1.25)));
}

TEST(stats_atomic_time, huge_sample_does_not_overflow_square)
{
    // Regression: value_ns * value_ns was a plain signed multiply — any
    // sample beyond ~3.037 s (sqrt(INT64_MAX) ns) was signed-overflow UB.
    // Magnitudes are now clamped before squaring and the accumulator
    // saturates instead of wrapping.
    AtomicTimeStats stats;
    stats.update(5'000'000'000);  // 5 s
    stats.update(std::numeric_limits<int64_t>::max());
    stats.update(std::numeric_limits<int64_t>::min());

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, 3);
    EXPECT_EQ(snap.sum_sq, std::numeric_limits<int64_t>::max());  // saturated
    EXPECT_TRUE(snap.stddev_ns() >= 0.0);
    EXPECT_TRUE(std::isfinite(snap.stddev_ns()));

    stats.reset();
    EXPECT_EQ(stats.snapshot().sum_sq, 0);  // reset clears saturation
}

TEST(stats_atomic_time, sum_sq_saturates_instead_of_wrapping)
{
    // Two squares each near INT64_MAX must pin the accumulator at
    // INT64_MAX (previously they wrapped to a garbage negative value).
    AtomicTimeStats stats;
    stats.update(3'000'000'000);
    stats.update(3'000'000'000);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.sum_sq, std::numeric_limits<int64_t>::max());
    EXPECT_TRUE(snap.stddev_ns() >= 0.0);
}

TEST(stats_atomic_time, exact_below_clamp_threshold)
{
    // Samples up to floor(sqrt(INT64_MAX)) = 3'037'000'499 square exactly.
    AtomicTimeStats stats;
    stats.update(3'037'000'499);
    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.sum_sq, int64_t{3'037'000'499} * int64_t{3'037'000'499});
}

// ---------------------------------------------------------------------------
// stats_atomic_wake - AtomicWakeStats tests
// ---------------------------------------------------------------------------

TEST(stats_atomic_wake, tracks_error_duration_and_skips)
{
    AtomicWakeStats stats;
    stats.update(-500, 1);
    stats.update_with_duration(500, 2'000, 2);

    EXPECT_EQ(stats.count(), 2);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_EQ(stats.min_ns(), -500);
    EXPECT_EQ(stats.max_ns(), 500);
    EXPECT_EQ(stats.skipped_counts(), 3);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.error.count, 2);
    EXPECT_EQ(snap.duration.count, 1);
    EXPECT_EQ(snap.duration.max_ns, 2'000);
    EXPECT_EQ(snap.skipped_counts, 3);
    EXPECT_TRUE(near(snap.average_ns(), 0.0));
    EXPECT_TRUE(near(snap.stddev_ns(), 500.0));

    stats.reset();
    EXPECT_EQ(stats.count(), 0);
    EXPECT_EQ(stats.skipped_counts(), 0);
}

//
// Test Runner
//

TEST_MAIN(statusbar_stats, stats_test)
