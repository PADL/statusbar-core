<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->
<!-- SPDX-License-Identifier: MIT -->

# statusbar 2.4.0

Released 2026-11-05. What the release contains,
what changed in the public APIs, how it was built, verified and deployed,
and where the per-repository detail is.

2.4.0 is the "told the time" release. Every bounded real-time function in
core and avb is now handed the instant it acts at, as a typed time point on
the clock that instant was read from, instead of reading a clock itself.
The policy that drove the work is written up once, in
`core/docs/TIME_POLICY.md`; this document only summarises it.

## The tags

| Repository       | Tag(s)                        | Commit    | Previous |
|------------------|-------------------------------|-----------|----------|
| core             | `2.4.0`                       | `bf8883d` | `680fb44` (2.3.2) |
| crypto           | `2.4.0`                       | `625f70a` | `e94209b` (2.3.2) |
| audio            | `2.4.0`                       | `d0d4da7` | `b6a111c` (2.3.2) |
| avb              | `2.4.0`, `wireshark-v2.4.0`   | `34cf00f` | `ebc1d6d` (2.3.2) |
| atdecc-control   | `2.4.0`                       | `651b9cb` | `d738704` (2.3.2) |
| umbrella         | `2.4.0`                       | `5242e28` | `adb8bfa` (2.3.2) |

crypto, audio and atdecc-control carry only the version bump. The mains and
the tags are on the staging remote and on all three public mirrors
(opensource, Codeberg, GitHub), verified ref-for-ref after the push.

## What changed

### The policy (core `TIME_POLICY.md`)

- **`CLOCK_MONOTONIC_RAW` is the timing reference.** It is the unslewed
  hardware counter, so it is the clock to time by and to stamp received
  frames with. `CLOCK_MONOTONIC` is the clock to sleep on, because the
  kernel's sleep primitives run on it, and nothing else.
- **A bounded function is told the time.** It takes a typed
  `Clock<Tag>::time_point` (signed nanoseconds) for the instant it acts at,
  and reads no clock. The caller that owns the tick or the receive reads a
  clock once and tells every callee the same instant. A time on the wrong
  clock does not compile.
- **Two forms at most.** The told form is the API. Where a caller owns no
  tick (a tool's main, a setup edge), the asking twin reads once and
  forwards, or the told form takes a defaulted `now` read at the call site.
  Defaults never appear on virtuals and never read member state.
- **Wakes are told on both clocks.** A timer wake carries its gPTP time and
  its RAW time, so the media and RX paths each get the clock they run on
  without converting the other.

### core (2.3.2 to 2.4.0, 6 commits)

- **Wave 0, the clock foundation.** `realtime::MonotonicRawClock` and
  `read_monotonic_raw_ns()`. `MonotonicRawLine` is the seqlocked
  `monotonic = rate * raw + offset` line between the two clocks, exact to
  the nanosecond at any uptime, written by a `MonotonicRawTracker` fit with
  the rate clamped at plus or minus 20 percent. `TimerBase` gains
  `wait_until_raw_deadline`: sleep early on `CLOCK_MONOTONIC`, spin on RAW.
  The old `detail::now_monotonic_raw_ns()` read `CLOCK_MONOTONIC` despite
  its name; it reads RAW now.
- **Wave 1, the net RX path.** Every `EthernetPort` gains
  `rx_start(RxTimePoint now)`. A drain reads the RX clock once per pass and
  tells each receive, where the rawnet, AF_PACKET, XDP and test ports used
  to read a clock per frame. `RxTimePoint` is the RAW clock's time point,
  so the RX clock is no longer configurable and `rx_clock_id` is retired
  from the port configs. A backend whose kernel stamps the frame keeps that
  stamp and uses the told time only when the kernel gave none.
- **Transitional shims, kept on purpose.** `AnyEthernetPort::rx_start(int64_t)`,
  `AnyEthernetPortConfig::rx_clock_id` (accepted, refused unless RAW) and
  `net::software_rx_timestamp_ns()` stay so that the PADL trees compile
  against this core. They are marked transitional at their definitions and
  come out once that tree has rebased. See "Downstream" below.
- **`sm::Clock` stays `std::chrono::steady_clock`** by design, and the
  header now says why: the control plane does not need the RAW counter.
- **Docs.** The new `TIME_POLICY.md`, and the realtime, net, sm and bpf
  module docs rewritten to match it.

### avb (2.3.2 to 2.4.0, 10 commits)

- **Wave 0b, the PTP bridge's reference clock is RAW.** `PtpTimeBridge`
  declares `reference_is_raw`; its PHC-to-RAW line gets honest names and
  its MONOTONIC conversions go through core's `MonotonicRawLine`. A real
  bug fell out: udptun's ptp4l translator added the current MONOTONIC
  minus RAW offset to a RAW instant and handed that to a line that already
  mapped PHC to RAW. The slave now refuses a bridge clock other than RAW.
- **Wave 2, the RX drain is told the wake.** `sleep_until_ptp` returns the
  wake as the one RAW read it took plus the PTP time that read converts
  to; `TimerWakeInfo::actual_raw` is typed RAW. `ListenerStreams::drain_rx`
  and the entities' `drain_stream_rx` take the wake on both clocks.
  Talker presentation times are typed gPTP time points.
- **Wave 3, the control plane.** MSRP, ACMP listener, MAAP and ADP hooks
  carry the time of the receive or tick that fired them. The talker gate's
  grace window moved to the media thread on RAW: the reactor only sets the
  Listener Ready flag, and no thread converts the reactor's time to the
  media clock. The MVRP VID is now registered in `start()`.
- **Shim removal (avb side).** The one-argument `process_audio` and the
  int64 drain forms are gone. The ACMP and AEM controllers' command methods
  take a trailing `TimePoint now`, defaulted for the tools, so the state
  machines are told the command time instead of reading it inside
  `send_command`. `AvbInfoMirror` tells its tick's time down.
- **Wave 4, controllers and the gPTP time bridge.** The nanoavb controllers
  are `TimePoint`-primary, with the int64 forms as reactor adapters.
  `on_unsolicited`, the ACMP response and timeout hooks and
  `AemCommandResult::at` carry the told time. The important fix:
  `GptpTimeBridge::update_from_anchor` is told the Sync's arrival instant
  on the app clock, read once per received frame in the slave session.
  Before, it paired the Sync's master time with the FollowUp's processing
  time, a bias of the whole Sync-to-FollowUp gap.
- **ptpclient.** The startup clock print shows `CLOCK_MONOTONIC_RAW` and
  the PTP-minus-RAW difference, matching the clock the timer runs on.
- **Docs.** `PTP_WAKE_TIMING.md`, `ACMP_STATE_MACHINES.md`,
  `NANOAVB_ARCHITECTURE.md`, `TOOLS.md` and the README follow the policy.

## Downstream: what a tree built on 2.3.x must change

For code on the typed API nothing changes. Code written against 2.3.x
patterns hits these:

- `rx_start(int64_t)` on a concrete port: use `rx_start(RxTimePoint)`;
  `realtime::MonotonicRawClock::from_ns()` converts a bare count. The
  int64 form survives only on `AnyEthernetPort`, transitionally.
- `rx_clock_id` in a port config: delete it. The field on
  `AnyEthernetPortConfig` still exists but any value other than
  `CLOCK_MONOTONIC_RAW` is refused at `open()`.
- `process_audio(gptp_now)` with one argument: pass the RAW wake as well.
- `drain_rx(int64_t)` / `drain_stream_rx(int64_t)`: pass both clocks.
- ACMP/AEM controller hooks and `AcmpControllerCallbacks` gained a trailing
  `sm::TimePoint now`.
- `GptpTimeBridge::rate_ratio()` is gone; `update_from_anchor` takes the
  Sync's app-clock arrival and the FollowUp's master time.

The PADL `padl` branches were built against this release on Linux
(podman, native arm64, `-Werror`): core at its padl head plus our waves
cherry-picked, avb at its padl head unchanged, with our crypto and audio.
Both compile and package. The avb tree needs no edit while the three core
shims remain.

## Build, test and deploy

- Each repository landed through the CI branch flow (`ci/<name>` built and
  cherry-picked onto main by the cron, result tag per branch); the version
  bumps were the last four branches. avb's full suite is 168 tests.
- Packages: suite `2.4.0-20261105082331`, cross-built in podman from the
  tagged trees with the umbrella's `container-build-cross.sh` and
  atdecc-control's, one `STATUSBAR_DEB_REVISION` for all six runtime
  packages (core, crypto, audio, avb, avb-wireshark, atdecc-control).
- Fleet: all five Raspberry Pi 5 nodes (jdk01a, jdk01b, jdk01c, jdk01d,
  jdk01f) upgraded in parallel with `dpkg -i`, rc 0 everywhere. The
  tone-generator service restarted through postinst on jdk01f and jdk01c.
  On jdk01c the device proxies and the widget bridge were restarted by
  pidfile afterwards and came back healthy.

## Where the detail is

- `core/docs/TIME_POLICY.md`: the policy, the clock table, the named
  contracts, the known outliers and the checklist for new code.
- `core/docs/REALTIME_MODULE.md`, `NET_MODULE.md`, `SM_MODULE.md`,
  `BPF_MODULE.md`: the module docs as rewritten for 2.4.0.
- `avb/docs/PTP_WAKE_TIMING.md`: the wake told on both clocks, the RAW
  regression and the startup print.
- `avb/docs/NANOAVB_ARCHITECTURE.md` and `ACMP_STATE_MACHINES.md`: the
  told controller and state-machine surfaces.
- `REPORT_2_3_0_PI5.md` (this folder): the previous release's rig and
  measurements, which 2.4.0 does not repeat.
