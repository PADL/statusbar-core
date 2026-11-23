[← back to module index](README.md)

# realtime

Utilities for hard-realtime programming: memory locking, SCHED_FIFO
scheduling, CPU affinity, deadline-driven periodic timers, multi-domain
clock types, and a tripwire framework for wake-latency / callback-
duration overruns.

## Overview

The module header groups four layers:

1. **System setup** (`realtime_base.hpp`) — `mlockall` memory locking,
   `SCHED_FIFO` / `SCHED_RR`, CPU affinity, capability diagnostics,
   shutdown-signal wiring. Each operation has a `bool` legacy form, an
   `_ex` form returning `RealtimeResult`, and a `_logged` form.
2. **Clock types** (`realtime_clock.hpp`, `realtime_monotonic_raw_line.hpp`)
   — `MonotonicRawClock` (`CLOCK_MONOTONIC_RAW`, the timing reference:
   stamps, deadlines, measurements), `MonotonicClock` (`CLOCK_MONOTONIC`,
   the clock the kernel sleeps on, slewed, so for sleeping only),
   `GptpClock<DomainId>`, `UtcClock`, `TaiClock`, all built on
   `Clock<Tag>`. Each yields a distinct `time_point`; cross-domain mixing
   is a compile error, and a bare nanosecond count enters or leaves a
   domain only through `Clock::from_ns()` / `Clock::to_ns()`. A
   `ClockAdapter` binds a clock type to a source of bare nanoseconds (a
   bridge) and converts to and from `MonotonicRawClock`, with the clock
   named on both sides. `ClockQuality` says how well a domain is known,
   as a worst-case accuracy that grows from the last synchronization, and
   `BoundedTime` carries a time with that accuracy. The clock header
   includes no operating-system header; the platform's clock code is in
   `realtime_clock.cpp`. `MonotonicRawLine` is the published
   `monotonic = rate * raw + offset` line a sleeper uses to reach a RAW
   deadline through a `CLOCK_MONOTONIC` sleep. The policy behind the
   split is in [TIME_POLICY.md](TIME_POLICY.md).
3. **Periodic timer** (`realtime_timer.hpp`, `realtime_anytimer.hpp`)
   — `Timer<ClockAdapterT>` runs in its own thread with absolute
   deadline scheduling, optional busy-wait, configurable CPU/priority,
   and atomic histograms. Its schedule is in the adapter's clock domain;
   it always waits and measures on `CLOCK_MONOTONIC_RAW`. `AnyTimer` is
   the type-erased holder.
4. **Tripwire** (`realtime_tripwire.hpp`,
   `realtime_timer_event_tripwire.hpp`) — first-wins latch that fires
   on wake-latency / duration overrun, monitor thread consuming
   coherent snapshots through `itc::AtomicTripleBuffer`, optional
   ftrace `TraceController`.

`RealtimeResult` is separate from `Status` so RT / signal-handler
error reporting stays allocation-free (raw `errno` + static
`error_message`).

## Key types

- `RealtimeResult` — allocation-free result with `errno`, static `error_message`, `log_if_failed()`.
- `RealtimeCapabilities` — snapshot from `check_realtime_capabilities()` (root, PREEMPT_RT, isolated CPUs).
- `MonotonicRawClock` / `MonotonicClock` / `GptpClock<DomainId>` / `UtcClock` / `TaiClock` — distinct `Clock<Tag>` instantiations; `ClockType` concept gates templates. `MonotonicRawClock` is the timing reference; `MonotonicClock` exists to sleep on.
- `Nanoseconds` — the one duration type every clock counts in, so a period can be added to a schedule in any domain.
- `read_monotonic_raw()` / `read_monotonic()` / `sleep_until_monotonic()` — the typed clock reads and the typed sleep; the `_ns` forms beside them in `realtime_clock.hpp` are the bare counts underneath.
- `ClockSource` — concept for a domain mapped onto `CLOCK_MONOTONIC_RAW` in bare nanoseconds: `now_ns()`, `to_raw_ns()`, `from_raw_ns()`, `is_healthy()`.
- `ClockAdapter<ClockT, Source>` — gives a `ClockSource` its clock type: `now()`, `to_raw()`, `from_raw()` take and return typed `time_point`s. A copyable pointer to the source.
- `MonotonicRawClockAdapter` — reads `CLOCK_MONOTONIC_RAW` directly; the adapter a `Timer` uses unless it is given another.
- `ClockAdapterType` — concept for what a `Timer` needs of its clock: `clock_type`, `now()`, `to_raw()`, `is_healthy()`.
- `ClockQuality` — how well a domain is known: `synced_at`, `bound_at_sync`, `drift_bound_ppb`, `epoch`, `time_source`. `uncertainty(now)` is the worst-case error at a told instant, in integers only. A default one has never synchronized and bounds nothing.
- `BoundedTime<ClockT>` — a `time` with its worst-case `accuracy`. `adapter.now_bounded()` returns one; `adapter.to_raw()` and `from_raw()` take one and return one with the mapping's own accuracy added.
- `QualifiedClockSource` / `QualifiedClockAdapter` — a source or adapter that reports a `ClockQuality`. One that does not is still accepted and claims no accuracy.
- `accumulated_drift(elapsed, ppb)` — `elapsed * ppb / 1e9`, rounded up, saturating, no floating point.
- `UtcClock` / `TaiClock`, `to_tai()` / `to_utc()`, `TAI_MINUS_UTC` — the system clock's timescale and the constant 37 s to TAI. What disciplines the system clock is a `ClockQuality::time_source`, not a type.
- `read_utc()` / `read_system_clock_error()` — the system clock as a `UtcClock` time, and what the operating system says of its synchronization (`synchronized`, `max_error`, `estimated_error`).
- `UtcClockQualityTracker` — the system clock's `ClockQuality`. It takes the operating system's worst-case error at each update by the time daemon as the bound and grows it at the deployment's own drift figure, so the clock coasts through a lost time server where the system's 500 ppm growth would write it off in seconds. `observe(raw, utc, reported)` is the told form, `sample()` the asking one. A step of the system clock is a new `epoch`.
- `AccuracyLimit` — one user's limit on one clock. `judge(quality, now)` returns an `AccuracyVerdict` (`usable`, `timeline_changed`, `accuracy`) and keeps an `AccuracyRecord` of excursions, time spent outside the limit and changes of timeline. Told the time, integers only, `constexpr`. This is what a user of a clock writes in place of an `is_synchronized()` check.
- `DEFAULT_HOLDOVER_DRIFT_PPB` — 15 ppm, the drift a source assumes while it coasts when its deployment has configured nothing.
- `MonotonicRawLine` / `MonotonicRawRateOffset` — the RAW<->MONOTONIC line: one writer samples both clocks and publishes `rate`/`offset_ns` through a seqlock; any sleeper reads it without a lock (a reader retries while the writer is mid-update) to convert a RAW deadline into a coarse MONOTONIC one. `quality()` says how well the line is known: the fit's worst residual plus half the read bracket, growing while it is not sampled.
- `TimerConfig` — period, compensation, CPU, SCHED_FIFO priority, the early-wake guard (`raw_spin_guard_ns`, or `busy_wait_threshold_ns` with `busy_wait`), how often the RAW↔MONOTONIC line is sampled (`raw_line_sample_interval_ns`), memory locking (`lock_memory`), stack-prefault size, first-wake offset (`start_offset_cycles`), resync interval, per-tick histograms.
- `Timer<ClockAdapterT>` — periodic timer thread keyed on a clock adapter (`MonotonicRawClockAdapter` by default).
- `TimerSchedule<ClockAdapterT>` / `WaitResult` — the schedule a `Timer` keeps, apart from its thread: the grid, each deadline on two clocks, the resync, readiness and the accuracy of each wake. It is told the time (`begin(now)`, `advance(wait)`, `event(wait)`) and reads no clock.
- `TimerEvent<ClockT>` — what a callback is told: `scheduled_time` on the schedule's clock, `error` as a duration, `wake_raw`, the `CLOCK_MONOTONIC_RAW` instant the callback was entered (zero for an event built by hand), and `accuracy`, the worst-case accuracy of the schedule at this wake (`UNBOUNDED_ACCURACY` when the adapter reports no quality).
- `AnyTimer` / `AnyTimerStart` — type-erased holder and RAII start/stop guard usable across clock domains.
- `Tripwire` / `TripwireMonitor` / `TripwireEvent` — fire latch, monitor thread, coherent event payload.
- `TraceConfig` / `TraceController` — ftrace wiring that captures kernel traces on fire.
- `ScopedTripwireObserver<ClockT>` — RAII observer; throws `TripwireFiredException` on wake-latency trip.
- `TimingSampleWindow<T>` — fixed-size ring buffer (≤ `max_timing_sample_window_size`); single-threaded.

## Quick example

```cpp
#include "statusbar/realtime/realtime.hpp"
using namespace statusbar;

int main()
{
    // Best-effort; both accept EPERM on unprivileged hosts.
    (void)realtime::lock_memory();
    (void)realtime::set_realtime_priority();

    realtime::TimerConfig cfg{.name = "rt-1ms", .period_ns = 1'000'000, .cpu = 3};
    auto timer = realtime::AnyTimer::create(cfg,
        [](realtime::TimerEvent<realtime::MonotonicRawClock> const& ev,
           stats::AtomicWakeStats::Snapshot const& /*wake_stats*/) {
            (void)ev.wake_count;  // RT thread — keep allocation-free.
        });

    auto& token = realtime::shutdown_token();
    realtime::AnyTimerStart guard{timer, &token};
    while (!token.stop_requested()) {
        (void)token.wait_for_stop(std::chrono::seconds{1});
    }
}
```

## Headers

- `statusbar/realtime/realtime.hpp` — module header; consumers `#include` this.
- `realtime_base.hpp` — `RealtimeResult`, memory locking, scheduling, affinity, diagnostics, shutdown signals.
- `realtime_clock.hpp` — `Clock<Tag>`, concrete clock aliases, `Nanoseconds`, the `ClockType` concept, the declarations of the clock reads and the sleep, `ClockQuality`, `BoundedTime`, `ClockSource`, `ClockAdapter`, `MonotonicRawClockAdapter`, `ClockAdapterType`. No operating-system includes.
- `realtime_clock.cpp` — the platform's clock reads and sleep; the one file to port.
- `realtime_utc_clock.hpp` — `UtcClockQualityTracker`.
- `realtime_accuracy_limit.hpp` — `AccuracyLimit`, `AccuracyVerdict`, `AccuracyRecord`.
- `realtime_monotonic_raw_line.hpp` — `MonotonicRawLine`, `MonotonicRawRateOffset`, `MonotonicRawTracker` (told one typed reading of each clock per sample).
- `realtime_timer_schedule.hpp` — `TimerSchedule<ClockAdapterT>`, `WaitResult`, `wait_result()`, the cycle-number helpers.
- `realtime_timer.hpp` (+ `_base.hpp` / `_config.hpp` / `_event.hpp`) — `Timer<ClockAdapterT>`, `TimerBase`, `TimerConfig`, `TimerEvent<ClockT>`, `TimerCallback<ClockT>`.
- `realtime_anytimer.hpp` — `AnyTimer`, `AnyTimerStart`, `start_timers()`.
- `realtime_tripwire.hpp` — `Tripwire`, `TripwireMonitor`, `TripwireEvent`, `TraceConfig`, `TraceController`.
- `realtime_timer_event_tripwire.hpp` — `observe_wake_and_handle_tripwire`, `observe_duration_and_handle_tripwire`, `ScopedTripwireObserver`.
- `realtime_timing_sample_window.hpp` — `TimingSampleWindow<T>` ring buffer.

## Dependencies

- **Statusbar modules:** [`args`](ARGS_MODULE.md) (`build_timer_arg_specs` / `build_trace_arg_specs`), [`itc`](ITC_MODULE.md) (`StopToken`, `AtomicTripleBuffer<TripwireEvent>`), [`stats`](STATS_MODULE.md) (`AtomicWakeStats`, `AtomicHistogramConfig`), `safe_arith` (saturating bound arithmetic), `container`.
- **System / external:** POSIX (`mlockall`, `pthread_setschedparam`, `sched_setaffinity`, `clock_gettime`, `clock_nanosleep`), the kernel's clock error figure (`adjtimex` on Linux, `ntp_gettime` on macOS); on macOS, Mach (`thread_policy_set`, `mach_absolute_time`, `mach_wait_until`); `<chrono>`, `<atomic>`, `<thread>`, `<print>`.

## Notes & caveats

- **RT-priority requirements.** `lock_memory()` needs `CAP_IPC_LOCK`; `set_realtime_priority()` / `set_realtime_affinity()` need `CAP_SYS_NICE`. Unprivileged hosts get `error_code = EPERM` — handle it. `check_realtime_capabilities()` is safe as non-root.
- **Blocking vs non-blocking.** `Timer::start()` returns immediately; the callback runs on the RT thread. Inside it, never block on locks, allocate, or call APIs that can page-fault.
- **Allocation behaviour.** `RealtimeResult` stores the raw `char const*` from `strerror` — allocation-free, but `strerror`'s static buffer is not thread-safe (nor async-signal-safe), so treat `error_message` as best-effort diagnostic text and consume it promptly on the thread that produced it; `Tripwire` publishes through a pre-allocated `AtomicTripleBuffer`; `TimingSampleWindow<T>` is a `std::array` capped at 512. `AnyTimer::create()` calls `std::make_unique` — construct timers off the RT path.
- **MCL_FUTURE.** `lock_memory(false)` (default) locks only currently-mapped pages; touch required pages first. `lock_memory(true)`, for memory-constrained hosts, reads in and locks what is mapped now and then locks every later mapping as its pages fault in (`MCL_ONFAULT`), so a large file mapped afterwards pins only the pages it touches.
- **Stack prefault.** `prefault_stack(bytes)` grows and writes the calling thread's stack so the loop after it faults on none of it. `Timer` does this for its thread (`TimerConfig::stack_prefault_bytes`); a real-time thread of your own calls it before its loop, with a size that fits its stack.
- **Timer memory locking.** By default every `Timer::start()` calls `mlockall(MCL_CURRENT)` from its thread (`TimerConfig::lock_memory`, flag `--<timer>.lock_memory`). The lock is process-wide: it reads in and locks every mapping of the moment, a large mapped file included, and overrides any page-range locking the process does for itself. A process that maps files sets `lock_memory = false` on its timers and locks once at startup with `lock_memory()` or `prepare_realtime_system()`.
- **Busy-wait.** Every `Timer` sleeps early on `CLOCK_MONOTONIC` and spins on RAW to its deadline. `TimerConfig::busy_wait` only widens the spin: the early-wake guard is `busy_wait_threshold_ns` (200 µs) in place of `raw_spin_guard_ns` (50 µs) — more of a CPU for more margin against a late kernel wake.
- **Scheduling assumptions.** Absolute deadlines on `CLOCK_MONOTONIC_RAW`; the sleep to each one goes through the `MonotonicRawLine` to a coarse `CLOCK_MONOTONIC` target, wakes early by a guard sized from the line's rate, and spins on RAW to the deadline. `compensation_ns` offsets each target. `resync_interval_cycles` re-bases the deadline against the adapter domain (0 disables). `start_offset_cycles` must be ≥ 2 to avoid a startup race.
- **Told the time.** A timer callback is told its wake; it does not read a clock. Everything it calls is told the wake in turn, typed per domain (`TimePoint`, `MonotonicRawClock::time_point`). See [TIME_POLICY.md](TIME_POLICY.md) for the rule and its forms.
- **Tripwire ordering.** `trigger()` / `observe()` run on the RT thread; the monitor reads coherent snapshots via `consume_event()`. First-wins latch — do not poll `has_fired()` from the monitor.
- **ftrace.** `TraceController` touches `/sys/kernel/tracing` and needs root; with `TraceConfig::enable_tracing = false` the tripwire still fires but no kernel trace is captured.
- **Shutdown wiring.** `realtime::shutdown_token()` returns the same `itc::StopToken&` as `itc::install_stop_signal()`. `setup_shutdown_signal_handlers()` wires `SIGINT`/`SIGTERM`/`SIGPIPE` into it; `handle_shutdown_signal()` is signal-safe.
- **Clock domains do not implicitly convert.** Conversion needs a `ClockAdapter` and a runtime time-bridge, or the `MonotonicRawLine` between the two local clocks. `MonotonicRawClock` and `MonotonicClock` are the clocks readable without a bridge, and only the former is for timing.
- **Every timer waits on RAW.** There is no `CLOCK_MONOTONIC`-scheduled timer: `CLOCK_MONOTONIC` appears only inside the wait, as the clock the coarse sleep is made on.
- **Coasting, not a health flag.** A source that has lost its master keeps its rate and offset, and its `ClockQuality` grows from the last sync at its drift bound. A timer waits for the first sync only; after that it keeps its schedule and tells each wake the accuracy. The user of the time compares the accuracy with its own limit. Two things stay hard events: a source that never synchronized is unbounded, and a new timeline changes the `epoch`.
- **Tests run on made-up time.** The timer's arithmetic is `TimerSchedule`, the wait's is `TimerBase::wake_target()` / `early_wake()` / `wait_outcome()`, and each tracker has a told form. Their tests tell them instants and do not wait. A few tests still touch the real clocks for a millisecond or two (the clock reads, the sleep primitive, one timer thread's first wake) and assert only what load cannot change. A test that sleeps for its result, or that asserts how long something took, fails on a loaded build host for no fault of the code.
- **The limit belongs to the user of the time.** A source never says it is good enough. Each user holds an `AccuracyLimit` set from its own configuration and asks it at the instants it cares about. A latency meter stops measuring at a tenth of a millisecond; a media clock follows the system clock up to ten. A user that built something on the clock (an offset, a filter) starts it over when the verdict says `timeline_changed`.
- **Accuracy is a worst case.** Bounds add through conversions, are rounded up, and saturate to `UNBOUNDED_ACCURACY`. A negative or unbounded input is never made to look bounded, and an uncertainty that has grown to the ceiling is inside no limit.

## Further reading

- [TIME_POLICY.md](TIME_POLICY.md) — the clock domains and the "told the time" rule this module's types exist to serve.
- [`itc`](ITC_MODULE.md) — `StopToken` and `AtomicTripleBuffer<T>` underpin shutdown and tripwire publication.
- [`stats`](STATS_MODULE.md) — `AtomicWakeStats` / `AtomicHistogramConfig` used by `Timer` and `TimerConfig`.
- [`args`](ARGS_MODULE.md) — `build_timer_arg_specs` / `build_trace_arg_specs` expose timer/trace config as CLI options.
