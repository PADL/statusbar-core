[← back to module index](README.md)

# stats

Descriptive statistics, histograms, and lock-free atomic accumulators
for benchmarks, realtime timing analysis, and human-readable reporting.

## Overview

The `stats` module covers two complementary use cases:

1. **Post-hoc analysis** of a finished measurement vector — compute
   mean, median, standard deviation, percentiles (`p95`, `p99`), and
   bucket counts; then format the result for stdout or a string buffer.
2. **Live, lock-free accumulation** from realtime threads —
   `AtomicTimeStats` and `AtomicHistogram` use `std::atomic<int64_t>`
   counters so any thread can call `update()` without locking, and a
   consumer thread pulls a `snapshot()` for display. The snapshot's
   fields are loaded individually (not as one atomic unit), so under
   concurrent updates the fields may be mutually slightly out of step —
   fine for display, not a linearizable point-in-time view.

The post-hoc side operates on `std::vector<double>` and `std::span`
inputs (typically nanoseconds). `analyze()` sorts in place and returns
a `DescriptiveStats` aggregate; `histogram()` classifies values into a
caller-supplied bucket list and `format_histogram_to()` writes an
ASCII bar chart through any output iterator.

The live side is built on fixed-size atomic arrays — no heap, no
mutexes. `AtomicWakeStats` composes an `AtomicTimeStats` with two
`AtomicHistogram`s (error and duration) and ships a
`Snapshot::format_report_to()` that produces a full wake-statistics
report. This module is what [`benchmark`](BENCHMARK_MODULE.md)
delegates to — `BenchmarkStats` is `stats::DescriptiveStats`.

## Key types

- `DescriptiveStats` — POD with `mean`, `median`, `stddev`, `min`,
  `max`, `p95`, `p99`, `sample_count`. Output of `analyze()`.
- `analyze(measurements)` / `percentile(sorted, p)` — post-hoc
  reduction. `analyze` sorts its argument in place; `percentile`
  expects ascending input.
- `Bucket<T>` / `HistogramResult<T>` / `histogram()` /
  `log_scale_us_buckets()` / `format_histogram_to()` — templated
  bucket classification, the built-in 8-bucket log-scale microsecond
  layout, and an ASCII bar-chart formatter.
- `format_duration(ns)` / `format_timestamp_ns(ns)` / `report(name, stats)` —
  human-readable formatting. `format_duration` picks ns/µs/ms/s;
  `report` writes to stdout.
- `AtomicHistogramConfig` / `AtomicHistogram<MaxBins>` — uniform-bin
  lock-free histogram. `configure()`, `update(value_ns)`, `snapshot()`,
  plus `Snapshot::format_to()`. Underflow/overflow tracked separately.
- `AtomicTimeStats` — lock-free count/sum/min/max/sum-of-squares
  accumulator. `snapshot()` yields a `Snapshot` with `average_ns()`
  and `stddev_ns()`.
- `AtomicWakeStats` — composite tracker: error `AtomicTimeStats`,
  duration `AtomicTimeStats`, matching histograms, and a
  `skipped_counts` counter. `format_report_to()` / `format_status_to()`
  for full and one-line outputs.

## Quick example

```cpp
#include "statusbar/stats/stats.hpp"

#include <vector>

using namespace statusbar::stats;

int main()
{
    // Post-hoc reduction.
    std::vector<double> measurements{2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
    auto s = analyze(std::move(measurements));
    report("demo", s);  // writes Samples / Mean / StdDev / ... to stdout

    // Live lock-free accumulator (e.g. from a realtime callback).
    AtomicTimeStats live;
    live.update(120);   // 120 ns
    live.update(180);
    auto snap = live.snapshot();  // .average_ns(), .stddev_ns(), .min_ns, .max_ns

    // Bucket classification with the built-in log-scale layout.
    std::vector<double> samples{100.0, 750.0, 1500.0};
    auto h = histogram(samples, log_scale_us_buckets());
    return h.total_count == 3 ? 0 : 1;
}
```

## Headers

- `statusbar/stats/stats.hpp` — module header. This is what
  consumers should `#include`; it pulls in all six feature headers.
- `stats_descriptive.hpp` — `DescriptiveStats`, `analyze()`,
  `percentile()`.
- `stats_histogram.hpp` — `Bucket`, `HistogramResult`, `histogram()`,
  `log_scale_us_buckets()`, `format_histogram_to()`.
- `stats_format.hpp` — `format_duration()`, `format_timestamp_ns()`,
  `report()`.
- `stats_atomic_histogram.hpp` — `AtomicHistogramConfig`,
  `AtomicHistogram<MaxBins>`.
- `stats_atomic_time_stats.hpp` — `AtomicTimeStats`.
- `stats_atomic_wake_stats.hpp` — `AtomicWakeStats`.

## Dependencies

- **Statusbar modules:** none. `stats` is a leaf module — every header
  it pulls in is either internal or part of the standard library.
- **System / external:** `<atomic>`, `<array>`, `<span>`, `<vector>`,
  `<cmath>`, `<format>`, `<string>`, `<string_view>`, `<cstdint>`,
  `<algorithm>`, `<limits>` from C++20/23.

## Notes & caveats

- `analyze()` takes its `std::vector<double>` *by value* and sorts in
  place — pass with `std::move` when the original order is no longer
  needed.
- `percentile()` requires ascending-sorted input; it does not sort
  for you. Index is `floor(size * p)`, clamped to `size - 1`.
- `AtomicHistogram` storage is a fixed `MaxBins` array
  (`MaxBins ≤ 1024`). `configure()` honors the requested
  `bin_width_ns` exactly and narrows `high_ns` to fit when the request
  needs more bins than storage; values beyond the truncated range
  route to overflow. Raise `MaxBins` if you need wide range with fine
  resolution.
- `AtomicTimeStats::Snapshot::stddev_ns()` uses the population
  formula `sqrt(E[X²] − E[X]²)` (no Bessel correction) and clamps
  negative variance from float cancellation to zero; fewer than two
  samples returns `0.0`.
- `AtomicWakeStats` defaults the error histogram to ±50 µs at 1 µs
  and the duration histogram to 0–100 µs at 1 µs; override via
  constructor or `configure_error_histogram()` /
  `configure_duration_histogram()`.
- `report()` writes to `stdout` directly. For buffered output use
  `format_histogram_to()` / `Snapshot::format_to()` with a
  `std::back_inserter`.

## Further reading

- [`benchmark`](BENCHMARK_MODULE.md) — delegates statistical reporting
  here; `BenchmarkStats` is `stats::DescriptiveStats`.
- [`realtime`](REALTIME_MODULE.md) — typical producer of
  `AtomicWakeStats` updates from RT threads.
