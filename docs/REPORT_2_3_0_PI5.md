<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->
<!-- SPDX-License-Identifier: MIT -->

# statusbar-core 2.3.0: what is new, and how it behaved on a Raspberry Pi 5

A reference for the work that reached `main` between the 2.1.0 release and
2.3.0, with the results of running it on the Raspberry Pi 5 rig. The sibling
reports in `statusbar-avb/docs/REPORT_2_3_0_PI5.md` and the umbrella's
`docs/REPORT_2_3_0_PI5.md` cover the entity data path and the rig itself.

## The rig, in one paragraph

Raspberry Pi 5 Model B (Rev 1.1), four cores, on-board Ethernet through the
RP1's `macb` driver. Kernel: the umbrella's `rtkernel` build
`6.12.90-nohzfull-rt+` (package 1.0-2) with `CONFIG_XDP_SOCKETS=y` and the
CBS, ETF and TAPRIO qdiscs as modules, booted with
`isolcpus=2-3 nohz_full=2-3 rcu_nocbs=2-3 irqaffinity=0-1`, so cores 2 and 3
are free of housekeeping for the realtime threads. `macb` takes an XDP program
in generic mode only (no native attach, no zero-copy) and has no launch-time
support. Builds are cross-compiled on a Mac in a podman container
(`scripts/container-build-cross.sh`, clang, libc++, `-O3`), the x86 CI host
runs the unit tests on every landing, and the Pi runs the arm64 test binary,
as root for the tests that need a kernel.

## New in the net module

### A runtime-selected Ethernet port

`AnyEthernetPort` (`net_any_ethernet_port.hpp`) opens one of three backends
behind a single API: `rawnet` (AF_PACKET, two sockets, TX with qdisc bypass),
`mmap` (PACKET_MMAP rings) or `xdp` (AF_XDP with the embedded filter). The
caller picks by `EthernetBackend` at open time; `describe()` says what was
opened; `tx_rx_independent()` tells a caller whether TX and RX may be driven
from two threads without a lock. `RawnetPort` is the AF_PACKET pair behind it.

**On the Pi:** all three backends carried AVTP streams in both directions.
Transmit rate from the NIC's own counter was the same 8,514 frames/s for
each; receive of 104,000 injected frames arrived 104,000 times with zero
sequence errors on each. XDP attaches in generic mode with copy; that is what
`macb` offers.

### AF_XDP: ownership, pinning, adoption and counters

- The XDP program is pinned under `/sys/fs/bpf/statusbar/<ifname>/` so it
  outlives the process, and a later open adopts it back if the pin is from the
  same build (`XdpProgram::owner()`, `adopt()`, the identity map). A pin from a
  different build of ours is replaced; a stranger's pin is left alone and the
  open is refused with `foreign_program`.
- A program on the interface is recognised as ours by the name the kernel
  recorded for it, so an orphan a crash left behind is cleared, while a program
  somebody else attached stays.
- The kernel's own AF_XDP socket counters (`xdp_statistics`) are read, so a
  frame the kernel dropped on an invalid descriptor stops looking sent. The
  fill ring is filled by what it has free, and UMEM frames are kept back for
  transmit so the fill ring cannot take them all.
- The bind and attach modes are the caller's choice, with a documented
  fallback; a queue that the last process has not finished giving back is
  waited out instead of failing with `EBUSY`.
- The TX pending flag is atomic, so a kicker thread on one core can flush
  what the media thread committed on another.
- RSS steering is put back by an RAII guard.
- The AVTP stream rule set (`avtp_stream_rules()`) steers only the stream
  subtypes to the socket, so a control plane keeps its raw socket.

**On the Pi:** the XDP integration suite (`net_linux_xdp_test`, 119 tests)
passes as root over a veth pair and loopback, including pin/adopt across
processes, the orphan replacement, the stranger-left-alone refusal, the
queue-rebind wait and the kernel counters. The atomic pending flag was
exercised by the avb TX kicker at 50 µs for hours with zero refused kicks.

### Launch time and the qdiscs under it

`net_tc_launch_time.hpp` lays an `mqprio` root and an offloaded `etf` on the
socket's own TX queue so an AF_XDP socket can put a launch time in its TX
metadata (`XdpConfig::launch_time`), with PTP on a queue of its own where
the NIC has one to spare. `settle_launch_time_queue()` is idempotent: what is
already ours is read and kept, because replacing a root takes an `igb` link
down. The driver is asked whether it honours launch time first, and a launch
time the NIC cannot act on is refused at open instead of silently ignored.

The rtnetlink traffic-control client (`net_tc_qdisc.hpp`) that does the work
builds `mqprio`, `cbs` and `etf` requests on the stack, reads
`NETLINK_EXT_ACK` so the kernel's reason survives, drains late
acknowledgements, and treats a dump the kernel abandoned as the error it
names. `net_vlan_link.hpp` creates and deletes 802.1Q links the same way, and
`net_interface_info.hpp` reports the index, TX queue count, driver, link
speed and MTU the launch-time layout needs.

**On the Pi:** `macb` reports no launch-time support, so the mode resolves to
`unsupported` and nothing is asked of the kernel; the qdisc request sequences
are proven with the recorder (`TcRecorder`) and the netlink client's dump and
refusal paths against the Pi's kernel (49 tests, root and unprivileged). The
VLAN link lifecycle runs in a private network namespace (39 tests). The etf
offload itself needs an `igb`/`igc` NIC, which the rig has not got.

### Smaller additions

- `TcpConnectionPool` listens on AF_UNIX stream and seqpacket sockets, and
  `SocketAddress` speaks filesystem paths; a local listener bound but never
  served unlinks its socket file.
- UDP multicast helpers, on the named interface on every platform.
- `ip`: a dotted quad is parsed in one pass, refusing leading-zero octets.
- `toml`: a quoted key keeps its dots through the parser and back out; a table
  header under an array of tables attaches to the last element.
- `pcap`: a snapped capture records the length the frame had on the wire;
  short frames are written instead of dropped in silence.
- `stats`: a wake's duration and skipped ticks are recorded without inventing
  an error; `realtime`: `cpu_relax()` and `set_current_thread_name()`.
- `test`: a test that cannot run says `SKIP("reason")` and is counted apart
  from the passes; a failure outranks a skip.
- Build: version 2.2.0 then 2.3.0; a target property opts one tool out of the
  `statusbar-` prefix; the block-statements house check runs as a pre-commit
  gate on the lines a change touches.

## Fixed before the public mirror

The review of the above before publishing found two defects, both fixed on
`main`:

- **A stale `mqprio` root could never be replaced.** A root under our own
  handle whose layout was not the one a run wanted was replaced with one
  `RTM_NEWQDISC` under the same handle. The kernel treats that as a change to
  the existing qdisc, `mqprio` has no change operation, and the request fails
  with `EINVAL`. The root's state is now `missing`, `ours`, `stale` or
  `foreign`; a stale root is deleted first and then laid, a foreign one is
  grafted over in one request.
- **A daemon without `CAP_SYS_ADMIN` could not replace its own pinned
  program.** Reading a program's name by id needs `CAP_SYS_ADMIN`; a service
  with only `CAP_BPF` and `CAP_NET_ADMIN` got `EPERM` for its own program and
  read it as foreign. The kernel's answer is now `ours`, `foreign` or
  `unknown`; an unknown program is ours when its id is the one pinned in our
  own directory, and otherwise refused as `program_unidentifiable`, whose
  message names the privilege.

**On the Pi:** verified as root with `CAP_SYS_ADMIN` dropped from the
bounding set (`setpriv --bounding-set=-sys_admin`): a pin from a different
build of ours is now replaced, where before it was refused. What cannot be
known without the privilege (an unpinned orphan, a stranger's program, a
detach told to leave the pins alone) is reported as unidentifiable rather than
silently passed over. With the privilege, all 119 XDP tests pass; without
it, those three cases are the only differences.

## Test results on the Pi, 2026-11-02

| Run                                   | Result                                              |
|---------------------------------------|-----------------------------------------------------|
| every section, as root                | 81 sections, 0 failures, exit 0                     |
| `net_linux_xdp_test`, root            | 119 passed, 0 skipped                               |
| `net_linux_xdp_test`, unprivileged    | 20 skipped (each says "needs root"), rest pass      |
| `net_rawnet_test`, unprivileged       | 5 skipped "needs CAP_NET_RAW", 5 pass               |
| `net_xdp_equiv_test`, unprivileged    | 2 skipped "needs CAP_BPF, or the kernel refused…"   |
| `net_tc_qdisc_test`, `net_vlan_link_test` | 49 and 39 pass, root and unprivileged alike      |
| bpffs and veths after the run         | nothing left behind                                 |

The skips are the point of the test-accounting change: before it, those
tests printed a line and returned, and the runner counted them as passes.

## Known limits and follow-ups

- An unpinned daemon that crashes leaves an attachment only `CAP_SYS_ADMIN`
  can identify. Pinning, or a `bpf_link`-based attach that dies with the
  process, would remove the case; the entity daemons do not pin today.
- `macb` cannot time frames, so the launch-time path has only been run against
  the recorder and the netlink client, not an offloading NIC.
- The TOML parser and `Config` disagree on bare digit keys; `NLMSG_DONE`
  replies are not sequence-matched; `.clang-tidy` never selects the
  `statusbar-*` checks. None affects the Pi rig; all are noted for a later
  pass.
