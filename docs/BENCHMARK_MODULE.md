[← back to module index](README.md)

# benchmark

Micro-benchmark harness with optimization barriers, two timer backends
(`steady_clock` and CPU performance counter), and warmup + statistical
analysis loops.

## Overview

The `benchmark` module is the toolkit for writing performance
benchmarks that survive contact with an optimizing compiler. It
provides three pieces:

1. **Optimization barriers** (`do_not_optimize`) — inline-assembly
   sinks modeled on Google Benchmark that force the compiler to
   materialize a value and treat memory as clobbered. Without these,
   a loop computing a result nothing observes gets deleted.

2. **High-resolution timers** — `Timer` wraps `std::chrono::steady_clock`
   and is the safe default. `HardwareTimer` reads `rdtscp` on x86_64
   or `cntvct_el0` on aarch64 directly; its sampling path stores raw
   tick deltas only, deferring tick→ns conversion until after the
   measurement loop. Use it when `steady_clock::now()`'s ~20 ns vDSO
   overhead dominates the operation being measured.

3. **Benchmark runners** — `run()` and `run_hw()` drive a user lambda
   through a warmup phase followed by a measured phase, feed samples
   to `stats::analyze`, and return a `BenchmarkStats`
   (`stats::DescriptiveStats`). A `BenchmarkConfig` controls warmup
   count, measurement count, batch size, and verbosity.

`run()` accepts any callable; if the lambda returns a value, the runner
threads it through `do_not_optimize` automatically. `run_hw()` takes a
slightly different shape — its lambda receives the inner-iteration
count `n` and runs the operation `n` times inside its own loop, so a
single barrier covers the whole batch and the compiler can keep state
in registers across calls.

Statistical reporting itself is delegated to the [`stats`](STATS_MODULE.md)
module via `using` declarations.

## Key types

- `do_not_optimize(value)` — optimization barrier. Two overloads: const-ref
  (read-only sink) and mutable-ref (read-write sink that prevents even
  more reordering).
- `Timer` — `steady_clock`-backed stopwatch. `start()`, `elapsed()`,
  `elapsed_ns()` / `elapsed_us()` / `elapsed_ms()` / `elapsed_s()`,
  `reset()`. It is `BasicTimer<std::chrono::steady_clock>`;
  `BasicTimer<ClockT>` takes any clock with a static `now()`, so a test
  can drive it.
- `HardwareTimer` — CPU-counter-backed stopwatch with the same shape as
  `Timer` plus `elapsed_ticks()`, `start_tick()`, `ticks_per_second()`,
  and `ticks_to_ns()` for callers doing their own batch conversion.
- `BenchmarkConfig` — `warmup_iterations`, `measurement_iterations`,
  `batch_size`, `verbose`.
- `BenchmarkStats` — alias for `stats::DescriptiveStats`.
- `run(name, func, config)` — runs `func()` through warmup +
  measurement loops; returns `BenchmarkStats`.
- `run_hw(name, func, config)` — same shape, but `func(n)` is expected
  to loop `n` times internally and the harness samples the hardware
  counter instead of `steady_clock`.
- `analyze(measurements)`, `format_duration(ns)`, `report(name, stats)` —
  re-exports of `stats::analyze` / `stats::format_duration` /
  `stats::report`.

## Quick example

```cpp
#include "statusbar/benchmark/benchmark.hpp"

using namespace statusbar::benchmark;

int main()
{
    BenchmarkConfig config;
    config.warmup_iterations = 100;
    config.measurement_iterations = 1000;
    config.batch_size = 1;

    int counter = 0;
    auto stats = run(
        "increment",
        [&counter]() {
            counter++;
            do_not_optimize(counter);
        },
        config);

    report("increment", stats);
    return 0;
}
```

## Headers

- `statusbar/benchmark/benchmark.hpp` — module header. Pulls in
  `hardware_timer.hpp` transitively. This is what consumers should
  `#include`.
- `statusbar/benchmark/hardware_timer.hpp` — `HardwareTimer` class and
  the `hw_detail` calibration / counter-read internals.

## Dependencies

- **Statusbar modules:** [`stats`](STATS_MODULE.md) (`run()` and
  `run_hw()` feed measurements through `stats::analyze`, returning a
  `stats::DescriptiveStats`; `format_duration` and `report` are
  re-exported for caller convenience).
- **System / external:**
  - `<chrono>` for `steady_clock` (the `Timer` backend and the fallback
    counter on platforms without `rdtscp` / `cntvct_el0`).
  - `<print>`, `<vector>`, `<cstdint>`, `<string_view>`,
    `<type_traits>`, `<utility>`, `<cstdlib>` from the standard
    library.
  - Inline assembly — the optimization barriers and `HardwareTimer`'s
    counter read use GCC/Clang `asm volatile`. On MSVC and unknown
    compilers there is a `volatile`-pointer fallback for
    `do_not_optimize` and a `steady_clock` fallback for the counter.

## Notes & caveats

- `do_not_optimize` is the load-bearing piece of any real benchmark.
  If your lambda computes a value that nothing observes, apply the
  barrier — otherwise the optimizer will delete the work.
- `run()` auto-applies `do_not_optimize` to non-void return values.
  Void-returning lambdas are responsible for applying barriers to
  their own state.
- `run_hw()`'s lambda takes the batch size `n` as a parameter and
  loops internally. This is intentional: one timer sample and one
  barrier per batch means the compiler can register-allocate across
  the inner loop. Don't write `run_hw("...", []{ ... })` — the
  signature mismatch will not compile.
- `HardwareTimer::ticks_per_second()` is lazily calibrated on first
  use. On x86_64 the first call busy-waits ~10 ms against
  `steady_clock` to measure TSC frequency; on aarch64 it just reads
  `cntfrq_el0`. Trigger the calibration once before timing-sensitive
  code if the latency on first use would skew results.
- `rdtscp` requires an invariant TSC (post-Nehalem / post-Bulldozer);
  older x86 hardware will produce nonsense, prefer `Timer` there.
- `batch_size` divides elapsed time per sample, so the returned
  statistics are always *per-call* nanoseconds.

## Further reading

- [`stats`](STATS_MODULE.md) — descriptive statistics and the
  `report()` / `format_duration()` helpers re-exported here.
