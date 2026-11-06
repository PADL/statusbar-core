[← back to module index](README.md)

# Time handling policy

How statusbar code reads, carries and compares time. The rules here apply
across every statusbar repository (core, avb, audio, atdecc-control); the
types they name live in core's [`realtime`](REALTIME_MODULE.md),
[`net`](NET_MODULE.md) and [`sm`](SM_MODULE.md) modules.

## The clocks

| Domain | Type | What it is for |
|---|---|---|
| `CLOCK_MONOTONIC_RAW` | `realtime::MonotonicRawClock` | **The timing reference.** Every stamp, deadline, interval and measurement. The raw hardware counter: NTP and phc2sys slew `CLOCK_MONOTONIC`, never this one, so two readings a second apart are a second apart. |
| `CLOCK_MONOTONIC` | `realtime::MonotonicClock` | **Sleeping only.** The kernel can only sleep on this clock, so a sleep to a RAW deadline goes through `realtime::MonotonicRawLine` (`monotonic = rate * raw + offset`), wakes early by a guard, then spins on RAW to the exact deadline. Never time anything with it. |
| `std::chrono::steady_clock` | `sm::Clock` / `sm::TimePoint` | **The control plane.** Protocol state machines (ADP, ACMP, AECP, MRP, gPTP port state) and the `net::MessageReactor` that drives them. Timers here are hundreds of milliseconds, so slew is harmless. It is `CLOCK_MONOTONIC` on Linux and stays that way on purpose: do not "fix" it to RAW. |
| gPTP / PHC | `realtime::GptpClock<N>`, PHC nanoseconds | The network's media time: AVTP presentation times, CRF, launch times. Reached from RAW through a bridge (`gptp::GptpTimeBridge`, `ptpclient::PtpTimeBridge`), never read directly on a hot path. |
| GPS, TAI | `realtime::GpsClock`, `realtime::TaiClock` | Media-clock rate tracking and TAI arithmetic. |
| `CLOCK_REALTIME` | plain `int64_t` | Wall-clock output only (log lines, LTC, scene stamps). Never compared with the clocks above. |

The first two rows mean the same thing on macOS as on Linux: both are read
with `clock_gettime`, both keep counting through a system sleep, and only
`CLOCK_MONOTONIC` is slewed. The one platform difference is the sleep
primitive, and it lives in a single place, `realtime::sleep_until_monotonic_ns()`:
`clock_nanosleep(TIMER_ABSTIME)` on Linux, a relative `mach_wait_until` on
macOS, because Mach's own counter (`mach_absolute_time`, which is
`CLOCK_UPTIME_RAW`) stops while the machine sleeps and must never carry an
absolute deadline. `std::chrono::steady_clock` is `CLOCK_MONOTONIC_RAW` on
macOS libc++, so it is not a `CLOCK_MONOTONIC` value there either: a
"monotonic" nanosecond count for a sleep or a line comes from
`realtime::read_monotonic_ns()`, never from `steady_clock`.

Each domain is a distinct `Clock<Tag>` with its own `time_point`, so mixing
two domains is a compile error. Crossing a domain is an explicit conversion
through an adapter or a bridge, done once, at the edge.

## Told the time

**A bounded function is told the time by its caller. It never asks a clock.**

"Bounded" means anything with a latency budget: a media tick, an RX drain, a
state-machine action, a frame handler, a conversion. The caller owns the tick
and reads the clock once; everything it calls receives that reading as a
typed `time_point` of the right domain, signed, and passes it on.

Why: a clock read is a syscall or a vDSO call and a cache miss. One per tick
is the budget. Reads scattered through callees are unbudgeted, make the
"now" of one tick disagree with itself, and are invisible to a test, which
cannot inject the time it wants. A function that is told its time is
deterministic and its cost is its own.

The surface a told function presents:

- **The told form is the API.** `rx_start(RxTimePoint now)`,
  `drain_rx(GptpClock0::time_point gptp_now, RxTimePoint rx_now)`,
  `process_audio(TimePoint time, MonotonicRawClock::time_point raw_now)`,
  `handle_event(ctx, event, TimePoint now)`.
- **An asking twin, only where a real caller owns no tick.** `rx_start()`
  reads the RX clock once and forwards. A reactor adapter that drains a port
  from `on_ready` reads RAW once per pass, at that one call site. The
  asking form is documented as the convenience it is, never as the API.
- **Default-argument form for setup and edge calls.** `start(reactor,
  TimePoint now = sm::Clock::now())`, `register_vlan(vid, now =
  sm::Clock::now())`, `connect(talker, ..., now = TimePoint::clock::now())`.
  A caller with a time in hand tells it; a tool reacting to a keypress takes
  the default. Allowed only where the default needs no member state, and
  never on a virtual function.
- **Callbacks fired from inside a state machine carry the time.** An
  action runs with the `TimePoint` the machine was told; a handler that
  fires hooks from its actions stashes that time at its told entry
  (`last_event_time_`) and tells it to each hook, so `on_connect(idx,
  stream, mac, now)`, `on_talker_listener(id, ready, now)`,
  `AemCommandResult::at` all carry the receive or tick that caused them.
- **A wake is told on every clock its consumer needs.** A timer reports
  its wake as `TimerWakeInfo{actual_time_ns (gPTP), actual_raw
  (MonotonicRawClock::time_point)}`; the media tick tells gPTP to the
  talkers and RAW to the transmit gate and the RX drain, and nothing under
  it reads a clock.
- **Control-plane adapters take the reactor's count.** `net::Pollable`
  hands `on_ready(int64_t now_ns)` / `tick(int64_t now_ns)` on the reactor's
  `steady_clock`; a handler wraps that once into `sm::TimePoint` at its
  entry and tells it down. The `int64_t` form is the reactor adapter, the
  `TimePoint` form is the API.

## Contracts worth knowing by name

- **RX timestamps** (`net_ethernet_port.hpp`): `RxClock` is
  `CLOCK_MONOTONIC_RAW` and is not configurable. A backend whose kernel
  stamps the frame (`PACKET_MMAP`, the macOS BPF reader, Zephyr) keeps that
  stamp and falls back to the told `RxTimePoint` only when the kernel gave
  none. A drain loop reads `rx_clock_now()` once per pass and tells it to
  every `rx_start(now)` of the pass.
- **Deadlines are RAW, sleeps are MONO.** `realtime::Timer` and
  `PtpTimeBridge::sleep_until_ptp` plan a sleep as a RAW deadline, convert it
  to a coarse `CLOCK_MONOTONIC` target through the `MonotonicRawLine`, sleep
  early, and spin on RAW to the deadline.
- **The gPTP time bridge is told its anchor.** `GptpTimeBridge::update_from_anchor(sync_rx_app_ns,
  tx_master_ns, rate_ratio)` takes the Sync's arrival on the app clock (read
  once in the receive path, carried with the Sync to its FollowUp) and the
  master time the FollowUp carried. Reading the app clock at the call would
  pair the Sync's master time with the FollowUp's processing time. The
  conversions (`to_gptp`, `from_gptp_rated`) are told an instant and read
  nothing; udptun's wire timeline is RAW straight through them.
- **The gPTP slave's bridge clock is RAW.** `--bridge-clock=monotonic_raw`
  is the policy value and udptun refuses any other.

## Known outliers

- `bpf::BpfDevice` on Linux stamps each `recv()` with one user-space
  `CLOCK_MONOTONIC` reading (Darwin pairs the kernel `bh_tstamp` with
  `CLOCK_MONOTONIC_RAW`). The capture tools that use it compare stamps only
  with each other. It predates the policy and is the one RAW exception left
  in core.
- Transitional net shims, kept on purpose while an external tree written
  against the earlier API catches up: `AnyEthernetPort::rx_start(int64_t
  now_ns)`, `net::software_rx_timestamp_ns(clock_id)` and the
  `AnyEthernetPortConfig::rx_clock_id` field (refused unless RAW). Each
  says "Transitional" in its comment and goes when that tree has rebased.

## Checklist for new code

1. Which domain is this time in? Name it with the typed `time_point`, not
   an `int64_t`, unless it is leaving the process or the reactor handed it.
2. Who owns the tick? That caller reads the clock once. Everything below it
   is told.
3. Does the function fire callbacks from inside a state machine? Stash the
   told time and pass it to them.
4. Is a clock read left in a bounded path? Either it is the one read of the
   tick owner, or it is the documented asking twin of a told form.
5. Does a sleep target a RAW deadline? Go through the `MonotonicRawLine`,
   wake early, spin on RAW.
6. Test it by telling it a time. If the test needs to mock a clock, the
   function is asking.
