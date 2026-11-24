<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->
<!-- SPDX-License-Identifier: MIT -->

# statusbar 3.0.0

Released 2026-11-24. What the release contains, what changed on the wire
and in the public APIs, how it was built and verified, and where the
per-repository detail is.

3.0.0 is a major release because core's realtime clock API changed. Every
clock is a type, `CLOCK_MONOTONIC_RAW` is the one timing reference, and a
timer tells each wake how accurate its time is. avb follows through the
gPTP and PHC bridges, the PTP timer and the AVTP stream times. On top of
that the release carries MSRP as the AVnu end station tests and Milan
v1.3 have it, a clock-quality gate on the inter-site tunnel and the
latency tool, an HTTP engine that runs with no socket, a split of every
test suite into unit tests and functional tests, a fix for millisecond
stalls of the real-time threads on a host short of memory, mapped files
that can be a region of a device and can be written, and a PHC
cross-timestamp, servo and follower for steering one PHC onto another.
The figures behind every clock accuracy are set at run time. crypto
carries only the version bump.

Things that change what goes on the wire:

- **MSRP.** A first declaration is sent as New. A listener attached
  before its talker's attribute is registered declares nothing, where
  2.15.0 declared Listener Asking Failed, and is withdrawn when the
  talker's attribute has gone. JoinTime is 200 ms (was 100 ms) and the
  leavealltimer runs 10 to 15 s (was 5 to 15 s); under the Milan profile
  LeaveTime is 5 s. A re-declared Talker Advertise with a changed value
  waits two LeaveAll periods after its Leave.
- **Presentation time.** A Milan entity's talker stamps 2 ms ahead by
  default (Milan v1.3 5.3.7.6), where 2.15.0 stamped 1 ms. Other
  entities keep 1 ms. A configured value is used as given.
- **Tunnel.** Tunnel packets carry the AVTPDU `tu` bit while the sender
  does not know TAI to within its limit (3 ms by default). A 2.15.0
  receiver ignores the bit, so mixed versions interoperate.

## The tags

| Repository       | Tag(s)                        | Commit    | Previous |
|------------------|-------------------------------|-----------|----------|
| core             | `3.0.0`                       | `87c8e8a` | `639a9bf` (2.15.0) |
| crypto           | `3.0.0`                       | `7149f1f` | `35fcafa` (2.15.0) |
| audio            | `3.0.0`                       | `20a66fe` | `2bd434c` (2.15.0) |
| avb              | `3.0.0`, `wireshark-v3.0.0`   | `55eb799` | `743ea80` (2.15.0) |
| atdecc-control   | `3.0.0`                       | `9d614c6` | `d67f43a` (2.15.0) |
| umbrella         | `3.0.0`                       | `b727829` | `620d9c1` (2.15.0) |

The mains and the tags are on the staging remote and on all three public
mirrors (opensource, Codeberg, GitHub), verified ref-for-ref after the
push.

## What changed

Each item names the commit on main. Every commit carries the tests that
pin it.

### core (2.15.0 to 3.0.0, 24 commits including the version bump)

- **Typed clocks, RAW the only reference** (`8ef6bc7`, `a78a4cc`).
  `realtime_clock.hpp` no longer needs an OS header. `Timer<>` is
  scheduled on `CLOCK_MONOTONIC_RAW`: it sleeps early on
  `CLOCK_MONOTONIC`, which is the clock the kernel sleeps on, and spins
  on RAW to the deadline. `MonotonicClockAdapter`, `TimeConversion` and
  the bare-count adapter calls are gone; a `ClockSource` maps to RAW
  only. `GpsClock` is replaced by `UtcClock`, the system clock on the
  1970 UTC scale, with `to_tai()` and `to_utc()`.
- **Clock quality** (`b5c9c49`, `66ace4c`, `d6d6a9c`, `a148e5e`).
  `ClockQuality` says how a clock knows the time (its source, a
  worst-case error, the age of the last measurement, the timeline it is
  on) and `BoundedTime` carries a time with its bound. Sources report
  their quality, and a `TimerEvent` has the `accuracy` of that wake and
  its `timeline`. `AccuracyLimit` is one user's limit on one clock: it
  judges each reading and keeps the record of excursions.
  `UtcClockQualityTracker` reads the kernel's own error estimate for
  the system clock.
- **A timer follows its clock** (`80c8eab`, `709ab00`). When a clock
  moves to a new timeline (a new grandmaster, a step) the timer lays
  its grid again on the new one. `stop()` returns within 100 ms
  whatever the period.
- **`TimerSchedule`** is the schedule arithmetic on its own, told the
  time, so the timer's logic is tested with no thread and no sleep.
- **HTTP engine and transport seam** (`5a96e8d`, `09d17ec`,
  `ab1fda3`). `HttpEngine` holds the HTTP and WebSocket logic on a
  `ConnectionTransport`; `HttpServer` is that engine on a
  `TcpConnectionPool`, with the same public calls as before.
  `ToldConnectionTransport` is a transport made of memory for unit
  tests.
- **A refused WebSocket send leaves nothing staged** (`29110fa`). In
  2.15.0 a `ws_send()` refused for size left the slot looking busy, so
  every later send to that connection was refused until its drop
  timeout.
- **Unit tests and functional tests** (`edfdbcb`, `ac3b1d0`,
  `36d92e7`, `ce8ca27`). No unit test sleeps or opens a socket. Tests
  that need a real socket or a real kernel are functional tests:
  `statusbar_add_module()` takes `FUNCTIONAL_TESTS` and
  `FUNCTIONAL_TEST_DATA`, each package builds
  `<package>-functional-test`, ctest labels them `functional`, and the
  development package installs the binary so the tests run on a
  target. `local-build.sh` runs the unit tests and then the functional
  tests; `STATUSBAR_SKIP_FUNCTIONAL_TESTS=1` leaves the second run out.
- **`MappedFile` maps a region, and maps writable** (`119575e`,
  `87c8e8a`). `MappedFile::map()` takes a `MapOptions`: a page-aligned
  region in place of the whole file, of a regular file or of a device
  that can be mapped (a device has no size, so its region is given a
  length), and `writable` for `PROT_READ | PROT_WRITE` with
  `writable_bytes()`. A device's or shared memory's mapping may be
  written from a real-time thread; a file on a disk filesystem may not,
  and the header says why.
- **Logging** (`3cdb72e`). A log line's timestamp is formatted in
  integers; no absolute time goes through a double.
- **The figures behind an accuracy are set at run time** (`04a61c5`).
  How well a clock is known depends on the hardware and the operating
  system, so nothing about it is compiled in.
  `UtcClockQualityTracker::Config` gains `fixed_error`, an error the
  system's own report cannot show (a receiver's pulse offset, a path
  taken as symmetric), added to the bound at every update, and the
  operating system's figures (`system_growth_per_second`,
  `step_rate_ppb`, `step_margin`). `MonotonicRawLineConfig` carries the
  figures of the line between the two local clocks, and `TimerConfig`
  passes them through (`raw_line_drift_bound_ppb`,
  `raw_line_sleep_rate_margin_ppb`). Every default is the value that
  was a constant before.
- **Documents** (`db6d4c0`, `b509441`, `5dd9819`). A new
  guide, `docs/REALTIME_CLOCK.md`: the clock API's theory of operation,
  its use by example, and what depends on the hardware. The README,
  build, test, net and HTTP documents and the timer options' help text
  follow the code.

### crypto (2.15.0 to 3.0.0, 1 commit)

The version bump.

### audio (2.15.0 to 3.0.0, 3 commits including the version bump)

- `MockOutputStream::wait_until_stopped()` and
  `MockInputStream::wait_until_stopped()` (`6f669d2`): a test waits for
  the mock to stop and does not sleep.

### avb (2.15.0 to 3.0.0, 41 commits including the version bump)

- **Typed bridges** (`11ff086`, `eee9ea9`, `02e8f5e`, `338467c`,
  `cae07cb`). `gptp::GptpTimeBridge` is kept against
  `CLOCK_MONOTONIC_RAW` only and converts typed time points.
  `ptpclient::PtpTimeBridge` plans a sleep and reports a wake in typed
  time; its `convert_*` calls and `TimeConvertResult` are gone.
  `TimerWakeInfo` carries typed times and the spin headroom of the
  wake. `statusbar-gptp-slave --bridge-clock` is replaced by
  `--no-bridge`.
- **The bridges report quality and coast** (`25f8119`, `136d950`). A
  bridge that misses Syncs widens its bound at a stated drift
  (`holdover_drift_ppb`, 15 ppm by default) and stays usable until the
  bound passes its user's limit. A new grandmaster is unbounded until
  the bridge has fitted it.
- **No absolute time in a double** (`b5f06ff`). The PHC bridge's line
  fit works on differences in 64-bit integers.
- **Users of a clock judge it against their own limit** (`ed9b968`,
  `e5ec4cf`, `9a1cc6c`). `udptun::ClockGate` gates the latency tool and
  the tunnel session on the master link's worst-case error
  (`--max-clock-error-us`, 100 µs). The entity's media clock follows
  the system clock only while its error is inside
  `--media.max_utc_error_us`, and the tunnel's talker sets `tu` outside
  `--udptun.max_tai_error_us`.
- **The ratio filter corrects itself** (`16b68bc`). A bad early sample
  could seed the GPS-to-TAI rate filter with a wrong frequency that its
  own gate then defended. Eight gated samples in a row now widen the
  filter.
- **AVTP stream time as `avtp::Nanoseconds`** (`7ca7b33`, `edcd640`,
  `a763375`, `08c643e`). A signed nanosecond count that is never below
  zero, added beside the `uint64_t` calls, which stay. The two
  timestamp reconstructions agree everywhere.
- **MSRP and MVRP** (`b3e704d`, `950afae`, `f12519d`, `9ec6105`,
  `fc1fa76`). The changes on the wire are listed at the top. Also:
  `srp::mrp::TimerConfig` on both participants and
  `nanoavb::MILAN_MRP_TIMERS`; a changed Listener declaration type is a
  Join with no Leave (802.1Q 35.2.6); an observer hears of a
  registration and of a Leave once; decoding stops at the first invalid
  field (Milan v1.3 4.2.7.1.2); the entity's control loop no longer
  sleeps past an MRP timer. Against an AVB interface with a built-in
  bridge, the time from Listener Ready to the first stream frame went
  from 19 to 39 s to 1.2 s.
- **Presentation offset by profile** (`8f97e45`).
  `presentation_offset_ns` defaults to 0, which takes the profile's
  value: 2 ms under Milan, 1 ms otherwise.
- **A timer thread locks the memory it brought** (`5a67aa5`). The
  process locked its memory before its timer threads existed, so their
  stacks and allocator arenas stayed unlocked. On a 1 GB host the
  kernel's compaction moved those pages, and a media thread that
  touched one waited 0.2 to 2.6 ms in a page fault. That was enough to
  put stream frames past their presentation time. Each `PtpTimer`
  thread now allocates once and locks again before its loop
  (`PtpTimer::set_lock_memory()`).
- **Each clock source is told its hardware's fixed error**
  (`5773f41`). A bridge bounds its error by what it measures, and a
  constant error (PHY latency asymmetry, timestamp granularity, the
  PHC's offset from its master) is invisible to a fit.
  `--ptp.fixed_error_ns`, `--fixed-error-ns` on the gPTP slave,
  `--utc-fixed-error-ns` on the latency tool and
  `--media.utc_fixed_error_ns` on the entity add the stated figure to
  the bound at every sync. All default to 0.
- **PHC cross-timestamps, a PHC servo and a follower** (`a79bfd3` to
  `f24fee1`, `55eb799`). `PhcDevice` reads a `/dev/ptpN` against
  `CLOCK_MONOTONIC_RAW` by the best method the device and kernel offer.
  `PhcCrossTimestamp` pairs two PHCs. `PhcServo` is linuxptp's PI servo
  as arithmetic, with `estimated()`. `PhcFollower` steers one PHC onto
  another, or onto a `PhcLine` over it, as phc2sys does between two
  PHCs. The loop is tested on a fake port. The tests that open real
  devices are functional tests and skip without them; they have not
  been run on hardware here, where each node has one PHC.
- **The entity can be told its interface MAC** (`85c4230`), for a model
  built before the interface is opened.
- **Tests** (`0c88cf4`, `8fca77c`, `f7be01b`, `b85968e`). The bridges'
  tests are told the time; socket and kernel tests are functional
  tests.
- **Documents** (`6e6b8e5`, `3cbd03d`). Review fixes for the clock
  changes, and the README, tools, MRP, PTP, tunnel and kit documents
  brought to the code.

### atdecc-control (2.15.0 to 3.0.0, 6 commits including the version bump)

- Tests wait for the fake device's event and do not sleep (`7c0ca5d`);
  tests that open a socket are functional tests (`e75a14d`);
  `local-build.sh` runs both kinds (`f1f75cf`, `3293814`).

### umbrella

- `local-build.sh`, the CMake presets and the integration build run the
  unit tests and then the functional tests; `install-hooks.sh
  --functional` adds an opt-in functional step to the pre-commit hook.

## Downstream: what a tree built on 2.15.0 must change

**core, `statusbar/realtime`**

- `GpsClock` and `GpsClockTag` are removed. `UtcClock` is the system
  clock on the UTC scale; it is a different clock, so check each use.
  `GptpClock1` is removed: write `GptpClock<1>`.
- `TimeConversion<Clock>` is removed. A conversion returns a plain
  `time_point`; validity is `is_healthy()` or a `ClockQuality`.
- `ClockAdapter`: `to_monotonic()` and `from_monotonic()` become
  `to_raw()` and `from_raw()` on `MonotonicRawClock::time_point`;
  `now()` returns a `time_point`; the `*_ns()` calls, `epoch()`,
  `reference_is_raw`, `domain_info()`, `grandmaster_id()`,
  `is_synchronized()` and `is_stale()` are removed. A `ClockSource`
  provides `now_ns()`, `to_raw_ns()`, `from_raw_ns()` and
  `is_healthy()`.
- `MonotonicClockAdapter` is removed and `MonotonicRawClockAdapter` is a
  stateless struct. `Timer<>`, `TimerEvent<>`, `TimerCallback<>` and
  `AnyTimer::create()` default to `MonotonicRawClock`: a callback taking
  `TimerEvent<MonotonicClock> const&` no longer converts.
- The traits `is_clock`, `is_gptp_clock`, `is_monotonic_clock`,
  `is_monotonic_raw_clock`, `reference_is_raw`, `gptp_domain_id` and the
  concepts `GptpClockType`, `MonotonicClockType`,
  `MonotonicRawClockType`, `RawReferenceClockSource`, `GptpClockSource`
  are removed. `ClockType` stays.
- `MonotonicRawTracker::push()` and `Sample` take typed time points.
- A subclass of `TimerBase` or `Timer`: the protected waits take typed
  time points, and `wait_until_busy()` and `wait_until_deadline()` are
  removed.
- `read_monotonic_ns()`, `read_monotonic_raw_ns()` and
  `sleep_until_monotonic_ns()` keep their signatures but live in
  `realtime_clock.hpp` and are no longer inline: link
  `statusbar-realtime`.
- `statusbar-realtime` no longer brings `statusbar-tsn` with it. A
  target that used tsn through realtime names it itself.
- Behaviour: every timer spins on RAW for at least `raw_spin_guard_ns`
  (50 µs) before each wake, and its `scheduled_time`, error and
  statistics are RAW. `busy_wait` only widens that spin.

**core, elsewhere**

- `benchmark::Timer` is an alias of `BasicTimer<steady_clock>`; a
  forward declaration `class Timer;` no longer matches.
- `MappedFile::map(fd)` of an empty file refuses a write-only or
  `O_PATH` descriptor (EACCES, EBADF), as mmap refuses a non-empty file
  on one. It used to return an empty mapping.
- ctest names: socket and kernel suites moved from `<x>_test` to
  `<x>_functional_test` in `statusbar/net` and `statusbar/http`. A
  script that ran `net_linux_xdp_test` as root wants
  `net_linux_xdp_functional_test`.
- The package config still accepts any newer version, so a
  `find_package(statusbar-core 2.15)` takes 3.0.0 without complaint.
  Pin by tag.

**avb**

- `PtpTimeBridge`: `convert_ptp_to_raw()`, `convert_raw_to_ptp()`,
  `convert_ptp_to_monotonic()`, `convert_monotonic_to_ptp()` and
  `TimeConvertResult` are removed; use `to_raw_ns()` and `from_raw_ns()`
  with `is_healthy()`, or a `realtime::ClockAdapter<GptpClock0,
  PtpTimeBridge>`. `to_monotonic_ns()` and `from_monotonic_ns()` become
  typed `to_monotonic()` and `from_monotonic()`. `prepare_sleep()`,
  `finalize_wake()`, `sleep_until_ptp()`, `SleepPlan` and `WakeTimes`
  take and hold typed time points.
- `TimerWakeInfo`: `scheduled_time`, `actual_time` and `error` are
  typed; the old names are member functions, so `info->error_ns`
  becomes `info->error_ns()`.
- `GptpTimeBridge`: `update_from_anchor()`, `to_gptp()`, `from_gptp()`
  and the `_rated` forms take typed time points (`anchor_at()` is the
  bare-count form); `app_now()` is `raw_now()`. `get_app_time_ns` must
  return `CLOCK_MONOTONIC_RAW`. `SlaveSessionConfig::bridge_clock`
  becomes `bool bridge`.
- `ptp_to_monotonic()` and `monotonic_to_ptp()` with a `double` slope
  are removed; use the `_precise` forms.
- `ListenerReservationState` gains `Waiting`, and
  `MsrpHandler::listener_attach()` can return it.
  `talker_advertise_registered()` is true only while the Advertise is
  registered and no Talker Failed is.
- `AvbEntityAudioIOConfig::presentation_offset_ns` defaults to 0: code
  that reads the value in use calls
  `effective_presentation_offset_ns(config)`.
- `ListenerStreams::drain_frames()` and the per-format frame helpers
  take `avtp::Nanoseconds`. The stream input contexts' `last_pts_ns`
  and `last_gptp_time_ns` are `int64_t`.
- `TimerScheduler::JOIN_TIME` is 200 ms.
- Options removed: `--bridge-clock` on `statusbar-gptp-slave` (use
  `--no-bridge` for none) and on `statusbar-owlm-tool`.
- ctest names: `nanoavb_components_test`, `stun_loopback_test` and
  `stun_rendezvous_test` end in `_functional_test`.

**atdecc-control**

- ctest names: `galaxy_client_test`, `galaxy_proxy_loopback_test`,
  `nadia_proxy_loopback_test` and `offline_scenes_test` end in
  `_functional_test`.

## Not changed

- The `uint64_t` AVTP stream-time calls and `HttpServer`'s public calls.
- **Our own LeaveAll does not age our Registrars.** A received LeaveAll
  and a received Leave retire registrations. This departure from 802.1Q
  Table 10-4 is kept and is described in
  `avb/docs/MRP_STATE_MACHINES.md`.
- **Milan v1.3 4.3.3.1**: a talker still declares its Talker Advertise
  without waiting to be probed or listened to. The presentation offset
  is set by configuration; there is no per-stream AECP SET for it.
- `mlockall(MCL_FUTURE)` stays unused.
- `TAI_MINUS_UTC` is a constant, 37 s. No further leap second is
  expected.
- AM824 SYT and the low findings carried from 2.7.0.

## Build, test and verify

- The change from 2.15.0 breaks the build between repositories at every
  intermediate point, so it could not land one repository at a time.
  The whole set was built and tested together on the CI host with the
  cron's three gates (local build, cross container, arm64 container),
  and each main was then fast-forwarded to the tested commit. Everything
  after that, the document corrections, the version bumps, the guide,
  the run-time figures, the mapped-file regions and the PHC family,
  landed through the CI branch flow, each run building and testing all
  five packages on Linux x86-64 and arm64.
- Before push, each branch was formatted with the pinned clang-format,
  gated by the block-statement plugin, scrubbed, and built and tested
  on macOS arm64 against Homebrew LLVM 23.1.5 and on arm64 Linux.
  Suites at the tags, unit and functional together: core 120 and avb
  185 on macOS, avb 186 and atdecc-control 36 on arm64 Linux.
- MSRP was checked against the AVnu end station test suite (tests
  35.e1.1, e2.1 to e2.7, e3.1 to e3.6) and Milan v1.3 4.2.7, and on the
  wire against two AVB interfaces with built-in bridges.
- Two sites, each a Raspberry Pi 5 with its own grandmaster and an AVB
  audio interface, exchanged 96 kHz audio through the tunnel for 15
  minutes on the installed packages: no missed media cycle at either
  site, the worst wake 4.8 µs late, every stream locked with no
  sequence error. The site whose node has 1 GB of memory stalled in
  each 15-minute run before the memory-lock fix.
- Packages: eleven arm64 Debian packages (six runtime, five dev)
  cross-built with podman as 3.0.0-20261124132549 and installed on four
  Raspberry Pi nodes. The avb package's `entity.toml` changed, so an
  upgrade over an edited one needs `dpkg --force-confold` to keep it
  without a prompt.

## Where the detail is

- `core/docs/REALTIME_CLOCK.md`: the clock API in long form, with the
  theory of operation, examples and the hardware figures.
- `core/docs/TIME_POLICY.md` and `core/docs/REALTIME_MODULE.md`: the
  clocks, what each is for, clock quality and the timer.
- `core/docs/TEST_MODULE.md` and `core/docs/BUILD_SYSTEM.md`: unit and
  functional tests.
- `core/docs/HTTP_PLAN.md` and `core/docs/NET_MODULE.md`: the HTTP
  engine and the connection transport.
- `avb/docs/MRP_STATE_MACHINES.md`: MSRP and MVRP, the timers and the
  departure kept.
- `avb/docs/PTP_WAKE_TIMING.md`: the PHC bridge, the PTP timer and
  memory locking.
- `avb/docs/GPS_MEDIA_CLOCK.md`, `avb/docs/UDPTUN.md` and
  `avb/docs/OWLM.md`: the media clock, the tunnel and the clock gate.
- `avb/docs/ENTITY_CONSTRUCTION_KIT.md`: what the profile decides.
- `RELEASE_2_5_0.md` and `RELEASE_2_4_0.md` (this folder): the previous releases.
