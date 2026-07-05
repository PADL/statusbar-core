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
2. **Clock types** (`realtime_clock.hpp`) — `MonotonicClock`,
   `GptpClock<DomainId>`, `GpsClock`, `TaiClock` built on `Clock<Tag>`.
   Each yields a distinct `time_point`; cross-domain mixing is a
   compile error.
3. **Periodic timer** (`realtime_timer.hpp`, `realtime_anytimer.hpp`)
   — `Timer<ClockAdapterT>` runs in its own thread with absolute
   deadline scheduling, optional busy-wait, configurable CPU/priority,
   and atomic histograms. `AnyTimer` is the type-erased holder.
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
- `MonotonicClock` / `GptpClock<DomainId>` / `GpsClock` / `TaiClock` — distinct `Clock<Tag>` instantiations; `ClockType` concept gates templates.
- `TimerConfig` — period, compensation, CPU, SCHED_FIFO priority, busy-wait threshold, stack-prefault size, resync interval, per-tick histograms.
- `Timer<ClockAdapterT>` — periodic timer thread keyed on a clock adapter (`MonotonicClockAdapter` by default).
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
        [](realtime::TimerEvent<realtime::MonotonicClock> const& ev,
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
- `realtime_clock.hpp` — `Clock<Tag>`, concrete clock aliases, `ClockType` concepts, `TimeConversion<Clock>`.
- `realtime_timer.hpp` (+ `_base.hpp` / `_config.hpp` / `_event.hpp`) — `Timer<ClockAdapterT>`, `TimerBase`, `TimerConfig`, `TimerEvent<ClockT>`, `TimerCallback<ClockT>`.
- `realtime_anytimer.hpp` — `AnyTimer`, `AnyTimerStart`, `start_timers()`.
- `realtime_tripwire.hpp` — `Tripwire`, `TripwireMonitor`, `TripwireEvent`, `TraceConfig`, `TraceController`.
- `realtime_timer_event_tripwire.hpp` — `observe_wake_and_handle_tripwire`, `observe_duration_and_handle_tripwire`, `ScopedTripwireObserver`.
- `realtime_timing_sample_window.hpp` — `TimingSampleWindow<T>` ring buffer.

## Dependencies

- **Statusbar modules:** [`args`](ARGS_MODULE.md) (`build_timer_arg_specs` / `build_trace_arg_specs`), [`itc`](ITC_MODULE.md) (`StopToken`, `AtomicTripleBuffer<TripwireEvent>`), [`stats`](STATS_MODULE.md) (`AtomicWakeStats`, `AtomicHistogramConfig`), [`tsn`](TSN_MODULE.md) (via clock adapters for gPTP).
- **System / external:** POSIX (`mlockall`, `pthread_setschedparam`, `sched_setaffinity`, `clock_gettime`); on macOS, Mach (`thread_policy_set`, `mach_absolute_time`); `<chrono>`, `<atomic>`, `<thread>`, `<print>`.

## Notes & caveats

- **RT-priority requirements.** `lock_memory()` needs `CAP_IPC_LOCK`; `set_realtime_priority()` / `set_realtime_affinity()` need `CAP_SYS_NICE`. Unprivileged hosts get `error_code = EPERM` — handle it. `check_realtime_capabilities()` is safe as non-root.
- **Blocking vs non-blocking.** `Timer::start()` returns immediately; the callback runs on the RT thread. Inside it, never block on locks, allocate, or call APIs that can page-fault.
- **Allocation behaviour.** `RealtimeResult` stores the raw `char const*` from `strerror` — allocation-free, but `strerror`'s static buffer is not thread-safe (nor async-signal-safe), so treat `error_message` as best-effort diagnostic text and consume it promptly on the thread that produced it; `Tripwire` publishes through a pre-allocated `AtomicTripleBuffer`; `TimingSampleWindow<T>` is a `std::array` capped at 512. `AnyTimer::create()` calls `std::make_unique` — construct timers off the RT path.
- **MCL_FUTURE.** `lock_memory(false)` (default) locks only currently-mapped pages; pass `true` only on memory-constrained hosts. Touch required pages first.
- **Busy-wait.** `TimerConfig::busy_wait` switches `Timer` to a hybrid sleep-then-spin loop governed by `busy_wait_threshold_ns` — trades a CPU for lower jitter (see deep-dive below).
- **Scheduling assumptions.** Absolute deadlines. `compensation_ns` offsets each target. `resync_interval_cycles` re-bases the monotonic deadline against the adapter domain (0 disables). `start_offset_cycles` must be ≥ 2 to avoid a startup race.
- **Tripwire ordering.** `trigger()` / `observe()` run on the RT thread; the monitor reads coherent snapshots via `consume_event()`. First-wins latch — do not poll `has_fired()` from the monitor.
- **ftrace.** `TraceController` touches `/sys/kernel/tracing` and needs root; with `TraceConfig::enable_tracing = false` the tripwire still fires but no kernel trace is captured.
- **Shutdown wiring.** `realtime::shutdown_token()` returns the same `itc::StopToken&` as `itc::install_stop_signal()`. `setup_shutdown_signal_handlers()` wires `SIGINT`/`SIGTERM`/`SIGPIPE` into it; `handle_shutdown_signal()` is signal-safe.
- **Clock domains do not implicitly convert.** Conversion needs a `ClockAdapter` and a runtime time-bridge. `MonotonicClock` is the only clock readable without one.

## Further reading

- [`itc`](ITC_MODULE.md) — `StopToken` and `AtomicTripleBuffer<T>` underpin shutdown and tripwire publication.
- [`stats`](STATS_MODULE.md) — `AtomicWakeStats` / `AtomicHistogramConfig` used by `Timer` and `TimerConfig`.
- [`args`](ARGS_MODULE.md) — `build_timer_arg_specs` / `build_trace_arg_specs` expose timer/trace config as CLI options.
