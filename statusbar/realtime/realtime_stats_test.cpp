// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime.hpp"
#include "statusbar/stats/stats.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <vector>

using namespace statusbar::realtime;
using namespace statusbar::stats;

//
// Static Assertions - Compile-time Verification
//

// Verify max_timing_sample_window_size constant
static_assert(max_timing_sample_window_size == 512, "Expected max timing sample window size of 512");
static_assert(max_timing_sample_window_size > 0, "Window size must be positive");

// Verify AtomicHistogramConfig is_valid() is constexpr
static_assert(
    AtomicHistogramConfig{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 1000}.is_valid(), "Valid config should return true");
static_assert(
    !AtomicHistogramConfig{.low_ns = 10000, .high_ns = -10000, .bin_width_ns = 1000}.is_valid(),
    "Inverted range should be invalid");
static_assert(
    !AtomicHistogramConfig{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 0}.is_valid(), "Zero bin width should be invalid");

// Verify AtomicHistogramConfig num_bins() is constexpr
static_assert(
    AtomicHistogramConfig{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 1000}.num_bins() == 20,
    "20 bins for -10k to 10k with 1k width");
static_assert(
    AtomicHistogramConfig{.low_ns = 0, .high_ns = 100000, .bin_width_ns = 5000}.num_bins() == 20,
    "20 bins for 0 to 100k with 5k width");

// Verify AtomicTimeStats::Snapshot is default constructible with expected values
static_assert(AtomicTimeStats::Snapshot{}.count == 0, "Default snapshot count should be 0");
static_assert(AtomicTimeStats::Snapshot{}.sum_ns == 0, "Default snapshot sum should be 0");
static_assert(AtomicTimeStats::Snapshot{}.min_ns == std::numeric_limits<int64_t>::max(), "Default min should be max int64");
static_assert(AtomicTimeStats::Snapshot{}.max_ns == std::numeric_limits<int64_t>::min(), "Default max should be min int64");

//
// Tests: AtomicWakeStats - Construction and reset
//

TEST(wake_stats_construct, default_constructor_initializes)
{
    AtomicWakeStats stats;

    EXPECT_EQ(stats.count(), 0);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_EQ(stats.min_ns(), std::numeric_limits<int64_t>::max());
    EXPECT_EQ(stats.max_ns(), std::numeric_limits<int64_t>::min());
}

TEST(wake_stats_construct, reset_clears_all_values)
{
    AtomicWakeStats stats;

    // Add some samples
    stats.update(100);
    stats.update(-50);
    stats.update(200);

    // Reset
    stats.reset();

    EXPECT_EQ(stats.count(), 0);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_EQ(stats.min_ns(), std::numeric_limits<int64_t>::max());
    EXPECT_EQ(stats.max_ns(), std::numeric_limits<int64_t>::min());
}

//
// Tests: AtomicWakeStats - Single sample update
//

TEST(wake_stats_update, single_positive_sample)
{
    AtomicWakeStats stats;
    stats.update(1000);

    EXPECT_EQ(stats.count(), 1);
    EXPECT_EQ(stats.sum_ns(), 1000);
    EXPECT_EQ(stats.min_ns(), 1000);
    EXPECT_EQ(stats.max_ns(), 1000);
}

TEST(wake_stats_update, single_negative_sample)
{
    AtomicWakeStats stats;
    stats.update(-500);

    EXPECT_EQ(stats.count(), 1);
    EXPECT_EQ(stats.sum_ns(), -500);
    EXPECT_EQ(stats.min_ns(), -500);
    EXPECT_EQ(stats.max_ns(), -500);
}

TEST(wake_stats_update, single_zero_sample)
{
    AtomicWakeStats stats;
    stats.update(0);

    EXPECT_EQ(stats.count(), 1);
    EXPECT_EQ(stats.sum_ns(), 0);
    EXPECT_EQ(stats.min_ns(), 0);
    EXPECT_EQ(stats.max_ns(), 0);
}

//
// Tests: AtomicWakeStats - Multiple sample updates
//

TEST(wake_stats_update, multiple_samples_count)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);
    stats.update(400);
    stats.update(500);

    EXPECT_EQ(stats.count(), 5);
}

TEST(wake_stats_update, multiple_samples_sum)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(-150);

    EXPECT_EQ(stats.sum_ns(), 150);  // 100 + 200 - 150 = 150
}

TEST(wake_stats_update, multiple_samples_min)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(-200);
    stats.update(50);
    stats.update(-300);
    stats.update(0);

    EXPECT_EQ(stats.min_ns(), -300);
}

TEST(wake_stats_update, multiple_samples_max)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(-200);
    stats.update(500);
    stats.update(-300);
    stats.update(250);

    EXPECT_EQ(stats.max_ns(), 500);
}

TEST(wake_stats_update, min_max_same_value)
{
    AtomicWakeStats stats;
    stats.update(42);
    stats.update(42);
    stats.update(42);

    EXPECT_EQ(stats.min_ns(), 42);
    EXPECT_EQ(stats.max_ns(), 42);
}

//
// Tests: AtomicWakeStats::Snapshot - average_ns()
//

TEST(wake_stats_snapshot, average_ns_zero_count)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 0;

    EXPECT_TRUE(std::abs(snapshot.average_ns()) < 1e-9);
}

TEST(wake_stats_snapshot, average_ns_single_sample)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 1;
    snapshot.error.sum_ns = 1000;

    EXPECT_TRUE(std::abs(snapshot.average_ns() - 1000.0) < 1e-9);
}

TEST(wake_stats_snapshot, average_ns_multiple_samples)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 4;
    snapshot.error.sum_ns = 400;  // Average = 100

    EXPECT_TRUE(std::abs(snapshot.average_ns() - 100.0) < 1e-9);
}

TEST(wake_stats_snapshot, average_ns_negative_sum)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 5;
    snapshot.error.sum_ns = -250;  // Average = -50

    EXPECT_TRUE(std::abs(snapshot.average_ns() - (-50.0)) < 1e-9);
}

//
// Tests: AtomicWakeStats::Snapshot - stddev_ns()
//

TEST(wake_stats_snapshot, stddev_ns_zero_count)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 0;

    EXPECT_TRUE(std::abs(snapshot.stddev_ns()) < 1e-9);
}

TEST(wake_stats_snapshot, stddev_ns_one_sample)
{
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 1;
    snapshot.error.sum_ns = 100;
    snapshot.error.sum_sq = 10000;

    EXPECT_TRUE(std::abs(snapshot.stddev_ns()) < 1e-9);
}

TEST(wake_stats_snapshot, stddev_ns_identical_values)
{
    // If all values are the same, stddev should be 0
    // 4 samples of 100: sum = 400, sum_sq = 40000
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 4;
    snapshot.error.sum_ns = 400;    // mean = 100
    snapshot.error.sum_sq = 40000;  // sum of 100^2 * 4

    // variance = (sum_sq / n) - mean^2 = 10000 - 10000 = 0
    EXPECT_TRUE(std::abs(snapshot.stddev_ns()) < 1e-9);
}

TEST(wake_stats_snapshot, stddev_ns_varying_values)
{
    // Values: 0, 100 -> sum = 100, sum_sq = 10000
    // mean = 50, variance = 10000/2 - 2500 = 5000 - 2500 = 2500
    // stddev = sqrt(2500) = 50
    AtomicWakeStats::Snapshot snapshot{};
    snapshot.error.count = 2;
    snapshot.error.sum_ns = 100;
    snapshot.error.sum_sq = 10000;  // 0^2 + 100^2

    double const stddev = snapshot.stddev_ns();
    EXPECT_TRUE(std::abs(stddev - 50.0) < 1.0);
}

//
// Tests: AtomicWakeStats - snapshot() integration
//

TEST(wake_stats_snapshot, snapshot_captures_state)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);

    auto snapshot = stats.snapshot();

    EXPECT_EQ(snapshot.error.count, 3);
    EXPECT_EQ(snapshot.error.sum_ns, 600);
    EXPECT_EQ(snapshot.error.min_ns, 100);
    EXPECT_EQ(snapshot.error.max_ns, 300);
}

TEST(wake_stats_snapshot, snapshot_average_from_stats)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);
    stats.update(400);

    auto snapshot = stats.snapshot();

    // Average of 100, 200, 300, 400 = 250
    EXPECT_TRUE(std::abs(snapshot.average_ns() - 250.0) < 1e-9);
}

TEST(wake_stats_snapshot, snapshot_stddev_from_stats)
{
    AtomicWakeStats stats;
    // Values centered around 0: -100, -50, 0, 50, 100
    // Sum = 0, mean = 0
    // Sum of squares = 10000 + 2500 + 0 + 2500 + 10000 = 25000
    // Variance = 25000/5 - 0 = 5000
    // Stddev = sqrt(5000) ≈ 70.7
    stats.update(-100);
    stats.update(-50);
    stats.update(0);
    stats.update(50);
    stats.update(100);

    auto snapshot = stats.snapshot();

    double const expected_stddev = std::sqrt(5000.0);
    EXPECT_TRUE(std::abs(snapshot.stddev_ns() - expected_stddev) < 1.0);
}

//
// Tests: AtomicWakeStats - Large values
//

TEST(wake_stats_large, handles_large_positive_values)
{
    AtomicWakeStats stats;
    int64_t const large_value = 1'000'000'000LL;  // 1 second in ns
    stats.update(large_value);
    stats.update(large_value);

    EXPECT_EQ(stats.count(), 2);
    EXPECT_EQ(stats.sum_ns(), 2 * large_value);
    EXPECT_EQ(stats.min_ns(), large_value);
    EXPECT_EQ(stats.max_ns(), large_value);
}

TEST(wake_stats_large, handles_large_negative_values)
{
    AtomicWakeStats stats;
    int64_t const large_negative = -1'000'000'000LL;
    stats.update(large_negative);

    EXPECT_EQ(stats.min_ns(), large_negative);
    EXPECT_EQ(stats.max_ns(), large_negative);
}

//
// Tests: AtomicWakeStats::Snapshot - format_status_to()
//

TEST(wake_stats_format, format_status_to_produces_output)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(-50);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_status_to(std::back_inserter(output));

    // Check that output contains expected substrings
    EXPECT_TRUE(output.find("Wakes:") != std::string::npos);
    EXPECT_TRUE(output.find("Avg:") != std::string::npos);
    EXPECT_TRUE(output.find("Min:") != std::string::npos);
    EXPECT_TRUE(output.find("Max:") != std::string::npos);
    EXPECT_TRUE(output.find("StdDev:") != std::string::npos);
}

//
// Tests: AtomicWakeStats::Snapshot - format_report_to()
//

TEST(wake_stats_format, format_report_to_produces_output)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output));

    EXPECT_TRUE(output.find("Wake Statistics") != std::string::npos);
    EXPECT_TRUE(output.find("Total wakes:") != std::string::npos);
    EXPECT_TRUE(output.find("Wake Error") != std::string::npos);
    EXPECT_TRUE(output.find("Average:") != std::string::npos);
}

TEST(wake_stats_format, format_report_with_compensation)
{
    AtomicWakeStats stats;
    stats.update(100);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output), -50000);

    EXPECT_TRUE(output.find("Compensation:") != std::string::npos);
}

TEST(wake_stats_format, format_report_suggests_compensation)
{
    AtomicWakeStats stats;
    // Add samples with large average error (> 100ns)
    stats.update(500);
    stats.update(600);
    stats.update(700);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output), 0);

    // Should suggest compensation when average error > 100ns
    EXPECT_TRUE(output.find("Suggested compensation:") != std::string::npos);
}

TEST(wake_stats_format, format_report_no_suggestion_for_small_error)
{
    AtomicWakeStats stats;
    // Add samples with small average error (< 100ns)
    stats.update(10);
    stats.update(20);
    stats.update(30);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output), 0);

    // Should not suggest compensation when average error < 100ns
    EXPECT_TRUE(output.find("Suggested compensation:") == std::string::npos);
}

//
// Tests: AtomicWakeStats - Edge cases
//

TEST(wake_stats_edge, reset_after_samples_works)
{
    AtomicWakeStats stats;
    stats.update(100);
    stats.update(200);
    stats.reset();
    stats.update(50);

    EXPECT_EQ(stats.count(), 1);
    EXPECT_EQ(stats.sum_ns(), 50);
    EXPECT_EQ(stats.min_ns(), 50);
    EXPECT_EQ(stats.max_ns(), 50);
}

TEST(wake_stats_edge, min_max_with_mixed_sign)
{
    AtomicWakeStats stats;
    stats.update(-1000);
    stats.update(1000);
    stats.update(-500);
    stats.update(500);

    EXPECT_EQ(stats.min_ns(), -1000);
    EXPECT_EQ(stats.max_ns(), 1000);
    EXPECT_EQ(stats.sum_ns(), 0);
}

//
// Tests: AtomicWakeStats - Duration tracking
//

TEST(wake_stats_duration, update_with_duration_tracks_both)
{
    AtomicWakeStats stats;
    stats.update_with_duration(100, 5000);  // 100ns error, 5000ns duration
    stats.update_with_duration(200, 3000);
    stats.update_with_duration(-50, 7000);

    auto snapshot = stats.snapshot();

    // Error stats
    EXPECT_EQ(snapshot.error.count, 3);
    EXPECT_EQ(snapshot.error.sum_ns, 250);  // 100 + 200 - 50
    EXPECT_EQ(snapshot.error.min_ns, -50);
    EXPECT_EQ(snapshot.error.max_ns, 200);

    // Duration stats
    EXPECT_EQ(snapshot.duration.count, 3);
    EXPECT_EQ(snapshot.duration.sum_ns, 15000);  // 5000 + 3000 + 7000
    EXPECT_EQ(snapshot.duration.min_ns, 3000);
    EXPECT_EQ(snapshot.duration.max_ns, 7000);
}

TEST(wake_stats_duration, legacy_update_no_duration)
{
    AtomicWakeStats stats;
    stats.update(100);  // Legacy update without duration
    stats.update(200);

    auto snapshot = stats.snapshot();

    // Error stats populated
    EXPECT_EQ(snapshot.error.count, 2);

    // Duration stats should be empty (no samples)
    EXPECT_EQ(snapshot.duration.count, 0);
    EXPECT_FALSE(snapshot.duration.has_samples());
}

TEST(wake_stats_duration, format_report_shows_duration)
{
    AtomicWakeStats stats;
    stats.update_with_duration(100, 5000);
    stats.update_with_duration(200, 3000);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output));

    // Should show both error and duration sections
    EXPECT_TRUE(output.find("Wake Error") != std::string::npos);
    EXPECT_TRUE(output.find("Callback Duration") != std::string::npos);
}

TEST(wake_stats_duration, format_report_hides_duration_when_empty)
{
    AtomicWakeStats stats;
    stats.update(100);  // Legacy update without duration
    stats.update(200);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output));

    // Should show error section but NOT duration section
    EXPECT_TRUE(output.find("Wake Error") != std::string::npos);
    EXPECT_TRUE(output.find("Callback Duration") == std::string::npos);
}

//
// Tests: AtomicTimeStats - Basic functionality
//

TEST(time_measurement, basic_update)
{
    AtomicTimeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);

    EXPECT_EQ(stats.count(), 3);
    EXPECT_EQ(stats.sum_ns(), 600);
    EXPECT_EQ(stats.min_ns(), 100);
    EXPECT_EQ(stats.max_ns(), 300);
}

TEST(time_measurement, snapshot_average)
{
    AtomicTimeStats stats;
    stats.update(100);
    stats.update(200);
    stats.update(300);
    stats.update(400);

    auto snapshot = stats.snapshot();
    EXPECT_TRUE(std::abs(snapshot.average_ns() - 250.0) < 1e-9);
}

TEST(time_measurement, snapshot_stddev)
{
    AtomicTimeStats stats;
    // Values: 0, 100 -> stddev = 50
    stats.update(0);
    stats.update(100);

    auto snapshot = stats.snapshot();
    EXPECT_TRUE(std::abs(snapshot.stddev_ns() - 50.0) < 1.0);
}

//
// Tests: AtomicHistogramConfig - Configuration
//

TEST(histogram_config, num_bins_calculation)
{
    AtomicHistogramConfig config{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 1000};
    EXPECT_EQ(config.num_bins(), 20);
}

TEST(histogram_config, is_valid_check)
{
    AtomicHistogramConfig valid{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 1000};
    EXPECT_TRUE(valid.is_valid());

    AtomicHistogramConfig invalid_width{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 0};
    EXPECT_FALSE(invalid_width.is_valid());

    AtomicHistogramConfig invalid_range{.low_ns = 10000, .high_ns = -10000, .bin_width_ns = 1000};
    EXPECT_FALSE(invalid_range.is_valid());
}

//
// Tests: Histogram - Basic functionality
//

TEST(histogram_basic, unconfigured_histogram)
{
    AtomicHistogram<64> hist;
    EXPECT_FALSE(hist.is_configured());
    EXPECT_EQ(hist.num_bins(), 0);

    // Updates should be no-ops
    hist.update(1000);
    auto snapshot = hist.snapshot();
    EXPECT_EQ(snapshot.total_count(), 0);
}

TEST(histogram_basic, configured_histogram)
{
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogram<64> hist(config);

    EXPECT_TRUE(hist.is_configured());
    EXPECT_EQ(hist.num_bins(), 10);  // (-5000 to 5000) / 1000 = 10 bins
}

TEST(histogram_basic, update_in_range)
{
    // 10 bins: [-5000,-4000), [-4000,-3000), ..., [4000,5000)
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogram<64> hist(config);

    // Value in first bin [-5000, -4000)
    hist.update(-4500);
    // Value in last bin [4000, 5000)
    hist.update(4500);
    // Value in middle bin [0, 1000)
    hist.update(500);

    auto snapshot = hist.snapshot();
    EXPECT_EQ(snapshot.total_count(), 3);
    EXPECT_EQ(snapshot.underflow, 0);
    EXPECT_EQ(snapshot.overflow, 0);
    EXPECT_EQ(snapshot.bins.at(0), 1);  // [-5000, -4000)
    EXPECT_EQ(snapshot.bins.at(5), 1);  // [0, 1000)
    EXPECT_EQ(snapshot.bins.at(9), 1);  // [4000, 5000)
}

TEST(histogram_basic, underflow_overflow)
{
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogram<64> hist(config);

    // Underflow: values < -5000
    hist.update(-10000);
    hist.update(-5001);

    // Overflow: values >= 5000
    hist.update(5000);
    hist.update(10000);

    auto snapshot = hist.snapshot();
    EXPECT_EQ(snapshot.underflow, 2);
    EXPECT_EQ(snapshot.overflow, 2);
    EXPECT_EQ(snapshot.total_count(), 4);
}

TEST(histogram_basic, bin_edges)
{
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogram<64> hist(config);

    auto snapshot = hist.snapshot();
    EXPECT_EQ(snapshot.bin_low(0), -5000);
    EXPECT_EQ(snapshot.bin_high(0), -4000);
    EXPECT_EQ(snapshot.bin_low(5), 0);
    EXPECT_EQ(snapshot.bin_high(5), 1000);
    EXPECT_EQ(snapshot.bin_low(9), 4000);
    EXPECT_EQ(snapshot.bin_high(9), 5000);
}

TEST(histogram_basic, reset)
{
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogram<64> hist(config);

    hist.update(-10000);  // underflow
    hist.update(0);       // bin 5
    hist.update(10000);   // overflow

    hist.reset();

    auto snapshot = hist.snapshot();
    EXPECT_EQ(snapshot.total_count(), 0);
    EXPECT_EQ(snapshot.underflow, 0);
    EXPECT_EQ(snapshot.overflow, 0);
}

TEST(histogram_basic, reconfigure)
{
    AtomicHistogram<64> hist;

    // Initially not configured
    EXPECT_FALSE(hist.is_configured());

    // Configure
    hist.configure({.low_ns = -1000, .high_ns = 1000, .bin_width_ns = 100});
    EXPECT_TRUE(hist.is_configured());
    EXPECT_EQ(hist.num_bins(), 20);

    // Add some data
    hist.update(0);
    EXPECT_EQ(hist.snapshot().total_count(), 1);

    // Reconfigure (should reset)
    hist.configure({.low_ns = -500, .high_ns = 500, .bin_width_ns = 100});
    EXPECT_EQ(hist.num_bins(), 10);
    EXPECT_EQ(hist.snapshot().total_count(), 0);
}

//
// Tests: AtomicWakeStats - Histogram integration
//

TEST(wake_stats_histogram, default_histogram)
{
    AtomicWakeStats stats;
    stats.update(0);
    stats.update(10000);
    stats.update(-10000);

    auto snapshot = stats.snapshot();
    // Default error histogram is configured (-50us to +50us, 1us bins)
    EXPECT_EQ(snapshot.error_histogram.num_bins, 100);
    EXPECT_EQ(snapshot.error_histogram.total_count(), 3);
}

TEST(wake_stats_histogram, custom_error_histogram)
{
    AtomicHistogramConfig config{.low_ns = -10000, .high_ns = 10000, .bin_width_ns = 2000};
    AtomicWakeStats stats(config);

    stats.update(0);      // Middle bin
    stats.update(5000);   // Later bin
    stats.update(-5000);  // Earlier bin

    auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.error_histogram.num_bins, 10);
    EXPECT_EQ(snapshot.error_histogram.total_count(), 3);
}

TEST(wake_stats_histogram, histogram_with_duration)
{
    AtomicWakeStats stats;
    stats.update_with_duration(1000, 500);
    stats.update_with_duration(2000, 600);
    stats.update_with_duration(-1000, 400);

    auto snapshot = stats.snapshot();
    // Error histogram should track error values
    EXPECT_EQ(snapshot.error_histogram.total_count(), 3);
    // Duration histogram should track duration values
    EXPECT_EQ(snapshot.duration_histogram.total_count(), 3);
    // Duration stats should also be tracked
    EXPECT_EQ(snapshot.duration.count, 3);
}

TEST(wake_stats_histogram, format_report_includes_histogram)
{
    AtomicHistogramConfig config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicWakeStats stats(config);

    stats.update(0);
    stats.update(1000);
    stats.update(2000);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output));

    // Should include histogram section
    EXPECT_TRUE(output.find("Error Distribution") != std::string::npos);
}

TEST(wake_stats_histogram, duration_histogram_tracking)
{
    // Custom duration histogram: 0-10us, 1us bins
    AtomicHistogramConfig error_config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogramConfig duration_config{.low_ns = 0, .high_ns = 10000, .bin_width_ns = 1000};
    AtomicWakeStats stats(error_config, duration_config);

    stats.update_with_duration(0, 500);       // duration in bin 0 [0-1000)
    stats.update_with_duration(1000, 5500);   // duration in bin 5 [5000-6000)
    stats.update_with_duration(-1000, 9500);  // duration in bin 9 [9000-10000)
    stats.update_with_duration(2000, 15000);  // duration overflow (>= 10000)

    auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.duration_histogram.num_bins, 10);
    EXPECT_EQ(snapshot.duration_histogram.total_count(), 4);
    EXPECT_EQ(snapshot.duration_histogram.overflow, 1);
    EXPECT_EQ(snapshot.duration_histogram.bins.at(0), 1);
    EXPECT_EQ(snapshot.duration_histogram.bins.at(5), 1);
    EXPECT_EQ(snapshot.duration_histogram.bins.at(9), 1);
}

TEST(wake_stats_histogram, format_report_includes_duration_histogram)
{
    AtomicHistogramConfig error_config{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 1000};
    AtomicHistogramConfig duration_config{.low_ns = 0, .high_ns = 10000, .bin_width_ns = 1000};
    AtomicWakeStats stats(error_config, duration_config);

    stats.update_with_duration(0, 1000);
    stats.update_with_duration(1000, 2000);
    stats.update_with_duration(2000, 3000);

    auto snapshot = stats.snapshot();
    std::string output;
    snapshot.format_report_to(std::back_inserter(output));

    // Should include both histogram sections
    EXPECT_TRUE(output.find("Error Distribution") != std::string::npos);
    EXPECT_TRUE(output.find("Duration Distribution") != std::string::npos);
}

//
// Tests: TimingSampleWindow - Edge cases
//

TEST(timing_window, empty_window)
{
    TimingSampleWindow<int64_t> window(8);

    EXPECT_TRUE(window.empty());
    EXPECT_EQ(window.size(), 0U);
}

TEST(timing_window, zero_max_size_is_safe)
{
    // max_size 0 would divide by zero in push()/operator[] (`% max_size_`); the
    // constructor clamps to 1 so the ring degrades to holding the newest sample.
    TimingSampleWindow<int64_t> window(0);
    window.push(42);
    window.push(43);
    EXPECT_EQ(window.size(), 1U);
    EXPECT_EQ(window[0], 43);
}

TEST(timing_window, single_sample)
{
    TimingSampleWindow<int64_t> window(8);

    window.push(42);

    EXPECT_FALSE(window.empty());
    EXPECT_EQ(window.size(), 1U);
    EXPECT_EQ(window[0], 42);
}

TEST(timing_window, fill_to_capacity)
{
    TimingSampleWindow<int64_t> window(4);

    window.push(1);
    window.push(2);
    window.push(3);
    window.push(4);

    EXPECT_EQ(window.size(), 4U);
    EXPECT_EQ(window[0], 1);  // oldest
    EXPECT_EQ(window[3], 4);  // newest
}

TEST(timing_window, wrap_around)
{
    TimingSampleWindow<int64_t> window(4);

    // Fill
    window.push(1);
    window.push(2);
    window.push(3);
    window.push(4);

    // Push one more - should wrap, dropping oldest (1)
    window.push(5);

    EXPECT_EQ(window.size(), 4U);
    EXPECT_EQ(window[0], 2);  // oldest is now 2
    EXPECT_EQ(window[1], 3);
    EXPECT_EQ(window[2], 4);
    EXPECT_EQ(window[3], 5);  // newest
}

TEST(timing_window, multiple_wraps)
{
    TimingSampleWindow<int64_t> window(3);

    // Push 10 values, should only keep last 3
    for (int i = 1; i <= 10; ++i) {
        window.push(i);
    }

    EXPECT_EQ(window.size(), 3U);
    EXPECT_EQ(window[0], 8);  // oldest
    EXPECT_EQ(window[1], 9);
    EXPECT_EQ(window[2], 10);  // newest
}

TEST(timing_window, clear_resets)
{
    TimingSampleWindow<int64_t> window(4);

    window.push(1);
    window.push(2);
    window.push(3);

    window.clear();

    EXPECT_TRUE(window.empty());
    EXPECT_EQ(window.size(), 0U);

    // Can push again after clear
    window.push(100);
    EXPECT_EQ(window.size(), 1U);
    EXPECT_EQ(window[0], 100);
}

TEST(timing_window, clamped_to_max)
{
    // Request more than max_timing_sample_window_size (512)
    TimingSampleWindow<int64_t> window(1000);

    // Fill up to clamped max
    for (size_t i = 0; i < max_timing_sample_window_size + 10; ++i) {
        window.push(static_cast<int64_t>(i));
    }

    // Should be clamped to max_timing_sample_window_size
    EXPECT_EQ(window.size(), max_timing_sample_window_size);
}

TEST(timing_window, struct_sample_type)
{
    struct Sample
    {
        int64_t time;
        double value;
    };

    TimingSampleWindow<Sample> window(4);

    window.push({.time = 1000, .value = 1.5});
    window.push({.time = 2000, .value = 2.5});

    EXPECT_EQ(window.size(), 2U);
    EXPECT_EQ(window[0].time, 1000);
    EXPECT_EQ(window[1].value, 2.5);
}

//
// Tests: AtomicTimeStats - direct (not via AtomicWakeStats)
//

TEST(atomic_time_stats, default_snapshot_is_empty)
{
    AtomicTimeStats stats;
    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, 0);
    EXPECT_EQ(snap.sum_ns, 0);
    EXPECT_FALSE(snap.has_samples());
    EXPECT_EQ(snap.average_ns(), 0.0);
    EXPECT_EQ(snap.stddev_ns(), 0.0);
}

TEST(atomic_time_stats, update_then_reset_clears_state)
{
    AtomicTimeStats stats;
    stats.update(100);
    stats.update(-50);
    EXPECT_EQ(stats.count(), 2);

    stats.reset();
    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, 0);
    EXPECT_EQ(snap.sum_ns, 0);
    EXPECT_EQ(snap.min_ns, std::numeric_limits<int64_t>::max());
    EXPECT_EQ(snap.max_ns, std::numeric_limits<int64_t>::min());
}

TEST(atomic_time_stats, snapshot_stddev_matches_variance_formula)
{
    AtomicTimeStats stats;
    // Samples 10, 20, 30: mean=20, variance = ((100+400+900)/3) - 400 = 466.67 - 400 = 66.67
    stats.update(10);
    stats.update(20);
    stats.update(30);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, 3);
    EXPECT_EQ(snap.sum_ns, 60);
    EXPECT_EQ(snap.min_ns, 10);
    EXPECT_EQ(snap.max_ns, 30);
    EXPECT_TRUE(std::abs(snap.average_ns() - 20.0) < 1e-9);
    EXPECT_TRUE(std::abs(snap.stddev_ns() - std::sqrt(200.0 / 3.0)) < 1e-6);
}

TEST(atomic_time_stats, concurrent_updates_produce_consistent_count_and_sum)
{
    constexpr int num_threads = 4;
    constexpr int per_thread = 5000;

    AtomicTimeStats stats;
    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (int t = 0; t < num_threads; ++t) {
        workers.emplace_back([&stats, t] {
            for (int i = 0; i < per_thread; ++i) {
                int64_t const value = (int64_t{t} * per_thread) + i + 1;
                stats.update(value);
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }

    int64_t const total_samples = int64_t{num_threads} * int64_t{per_thread};
    int64_t const expected_sum = (total_samples * (total_samples + 1)) / 2;

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.count, total_samples);
    EXPECT_EQ(snap.sum_ns, expected_sum);
    EXPECT_EQ(snap.min_ns, 1);
    EXPECT_EQ(snap.max_ns, total_samples);
}

//
// Tests: AtomicWakeStats - custom config constructors and runtime configure
//

TEST(wake_stats_config, single_arg_constructor_uses_default_duration_config)
{
    AtomicHistogramConfig const error_cfg{.low_ns = -1000, .high_ns = 1000, .bin_width_ns = 100};
    AtomicWakeStats stats{error_cfg};

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.error_histogram.num_bins, error_cfg.num_bins());
    EXPECT_EQ(snap.duration_histogram.num_bins, AtomicWakeStats::default_duration_histogram_config().num_bins());
}

TEST(wake_stats_config, two_arg_constructor_uses_both)
{
    AtomicHistogramConfig const error_cfg{.low_ns = -2000, .high_ns = 2000, .bin_width_ns = 100};
    AtomicHistogramConfig const dur_cfg{.low_ns = 0, .high_ns = 50'000, .bin_width_ns = 500};
    AtomicWakeStats stats{error_cfg, dur_cfg};

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.error_histogram.num_bins, error_cfg.num_bins());
    EXPECT_EQ(snap.duration_histogram.num_bins, dur_cfg.num_bins());
}

TEST(wake_stats_config, configure_error_histogram_at_runtime)
{
    AtomicWakeStats stats;
    AtomicHistogramConfig const new_cfg{.low_ns = -5000, .high_ns = 5000, .bin_width_ns = 500};
    stats.configure_error_histogram(new_cfg);

    // After reconfigure, histogram bin count should reflect the new config.
    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.error_histogram.num_bins, new_cfg.num_bins());
}

TEST(wake_stats_config, configure_duration_histogram_at_runtime)
{
    AtomicWakeStats stats;
    AtomicHistogramConfig const new_cfg{.low_ns = 0, .high_ns = 20'000, .bin_width_ns = 200};
    stats.configure_duration_histogram(new_cfg);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.duration_histogram.num_bins, new_cfg.num_bins());
}

TEST(wake_stats_skipped, update_accumulates_skipped_counts)
{
    AtomicWakeStats stats;
    EXPECT_EQ(stats.skipped_counts(), 0);

    stats.update(100, 2);
    stats.update(200, 3);
    EXPECT_EQ(stats.skipped_counts(), 5);

    stats.update_with_duration(50, 1000, 7);
    EXPECT_EQ(stats.skipped_counts(), 12);

    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.skipped_counts, 12);
}

TEST(wake_stats_skipped, reset_zeroes_skipped_counts)
{
    AtomicWakeStats stats;
    stats.update(100, 9);
    EXPECT_EQ(stats.skipped_counts(), 9);

    stats.reset();
    EXPECT_EQ(stats.skipped_counts(), 0);
}

TEST(wake_stats_concurrency, concurrent_updates_consistent_count_and_skipped)
{
    constexpr int num_threads = 4;
    constexpr int per_thread = 4000;

    AtomicWakeStats stats;
    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (int t = 0; t < num_threads; ++t) {
        workers.emplace_back([&stats] {
            for (int i = 0; i < per_thread; ++i) {
                stats.update_with_duration(10, 100, 1);
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }

    int64_t const total = static_cast<int64_t>(num_threads) * per_thread;
    auto const snap = stats.snapshot();
    EXPECT_EQ(snap.error.count, total);
    EXPECT_EQ(snap.duration.count, total);
    EXPECT_EQ(snap.skipped_counts, total);
    EXPECT_EQ(snap.error.sum_ns, total * 10);
    EXPECT_EQ(snap.duration.sum_ns, total * 100);
}

//
// Main test runner
//

TEST_MAIN(statusbar_realtime, realtime_stats_test)