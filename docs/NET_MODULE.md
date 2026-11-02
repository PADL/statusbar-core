[← back to module index](README.md)

# net

Non-blocking async TCP, UDP, and raw Ethernet networking with zero
runtime allocations, built around a `poll()`-driven reactor.

## Overview

A single-threaded `MessageReactor` owns a set of `Pollable` ports,
calls `poll()` once per cycle, and dispatches `on_ready` /
`on_writable` / `tick` callbacks with a nanosecond timestamp from
an injected clock. Buffers and queue capacities are fixed at
construction — nothing on the hot path allocates.

The socket layer adds RAII (`FileDescriptor`), an IPv4/IPv6 address
abstraction (`SocketAddress`) including link-local scope, factory
helpers (`create_udp_socket` / `create_tcp_socket` /
`create_tcp_listener`) that pre-configure DSCP/QoS and address reuse
(call `set_nonblocking()` yourself — the factories return blocking
sockets, as the Quick example shows), and a `NotificationPipe` for
cross-thread reactor wakeup. For Layer-2 work `RawnetContext` wraps `AF_PACKET`
(Linux) and `BPF` (macOS); the `EthernetPort` concept unifies
zero-copy backends `TestPortContext`, paired `LoopbackPortContext`,
`BpfPortContext` (`AF_PACKET` on Linux / `/dev/bpfN` on macOS),
`MmapContext` (`PACKET_MMAP`), and `XdpContext` (AF_XDP via
libbpf/libxdp). `TapBridge` connects the reactor to a kernel TAP
device, `TrafficClassifier` / `TcamClassifier` steer frames by
linear or `CompiledRule<N>`-based match, and `net_cbpf_emit.hpp`
emits cBPF for kernel-side filtering.

## Key types

- `Pollable` — base every reactor port implements: `fd()`, `poll_events()`, `on_ready`, `on_writable`, `tick`, `finished()`.
- `MessageReactor` — single-threaded `poll()` loop; built from a `StopToken`, a `ClockFn` (e.g. `monotonic_ns`), and a poll timeout; `add()` takes `unique_ptr<Pollable>`, `run()` drives the loop.
- `SocketAddress` — sockaddr_storage wrapper with `from_string`, `ipv4` / `ipv4_any` / `ipv4_loopback`, `ipv6` / `ipv6_any` / `ipv6_loopback` / `ipv6_link_local`, `sockaddr()`, `length()`, `family()`, `to_string()`.
- `FileDescriptor` — move-only RAII fd close; `create_udp_socket` / `create_tcp_socket` / `create_tcp_listener` return `StatusValue<FileDescriptor>`.
- `ServerConfig` — `bind_host` / `port` / `max_clients` / `dscp` from a `config::Config` via `from_config()`; `is_valid_dscp(dscp)` validates the QoS field.
- `NotificationPipe` — pipe-based reactor wakeup; `notify(code)` is safe from any thread.
- `RawnetContext` — Layer-2 socket; `open(iface, ethertype, multicast_mac)` configures `AF_PACKET` (Linux) or BPF (macOS); `MAX_ETHERNET_FRAME_SIZE` / `MAX_ETHERNET_PAYLOAD` / `VLAN_TAG_SIZE` live in this header.
- `EthernetPort` (concept) — zero-copy TX/RX contract satisfied by `TestPortContext`, `LoopbackPortContext`, `BpfPortContext`, `MmapContext`, `XdpContext`; `EthernetTxGuard` / `EthernetRxGuard` provide scoped slot acquisition.
- `RssIndirection` — a NIC's RSS indirection table; `rss_indirection(iface)` reads it (`ethtool -x`), `set_rss_indirection(iface, table)` writes it (an empty table restores the driver default), and `set_rss_indirection_all(iface, queue)` steers every bucket to one queue and returns the previous table to put back (`ethtool -X iface weight 1 0 0 0`). `rss_indirection_all` / `rss_steered_to` build and test tables.
- `netdev::NetdevClient` — generic netlink client for the kernel's netdev family: `features(ifindex)` returns `DeviceFeatures` (`xdp_features`, `xsk` as `XskFeatures` with `launch_time()`); `netdev::query_xsk_features(ifindex)` does a single query, `netdev::launch_time_supported(ifindex)` one for launch time alone (ask once, hand the answer to every user). The builders and parsers are pure functions and work on crafted bytes.
- `netdev::NapiClient` — the netdev family's queue and NAPI commands: `queue_napis(ifindex, queue)` finds the NAPIs behind a queue index (its RX queue's, and its TX queue's when another), `napi(id)` reports one (its kthread `pid`, its `threaded` mode), `set_threaded(id, mode)` sets `NapiThreaded::disabled`, `enabled` or `busy_poll`. `netdev::set_queue_threaded()` does all three for one queue and pins each kthread SCHED_OTHER to a CPU (`pin_napi_thread()`).
- `CarrierWatch` — a reactor `Pollable` on a NETLINK_ROUTE socket in RTMGRP_LINK: each RTM_NEWLINK of one ifindex reaches its callback as `LinkCarrier` (`IFLA_CARRIER`, `IFLA_CARRIER_DOWN_COUNT`). Event-driven, unlike `LinkMonitor`'s carrier poll, and the down count shows a carrier lost and regained before linkwatch sent the notification.
- `LaunchOrder` — the launch times one AF_XDP socket's frames carry, in commit order (igc's launch-time queue is a FIFO): `next(requested_ns, now)` returns at least the last time given, an untimed frame (0) or one wanted at or before `now()` (`tai_now_ns`; a tick that overran) at now, and a time more than `STEP_NS` (1 ms) behind the last is a clock step that drops the floor; `clamped()`, `max_clamp_ns()`, `steps()`, `launched_late()`, `max_late_ns()` count. `launch_time_support(driver)` / `plan_launch_time(wanted, driver)` say whether frames can carry launch times given the driver's one answer and this build (`LaunchTimePlan`).
- `tc::LaunchTimeMode` / `tc::launch_time_mode(wanted, driver)` — what a host does with etf on its socket's queue (unsupported / off / on); `tc::LaunchTimeQueue`, `tc::launch_time_mqprio`, `tc::launch_time_etf` and `tc::settle_launch_time_queue(tc, ifindex, queue, mode)` keep one TX queue for a socket's timed frames on an interface no other qdisc shapes (`net_tc_launch_time.hpp`).
- `TrafficClassifier` / `TcamClassifier` — rule-based steering; `ClassifierRule` for the linear matcher, `CompiledRule<32>` / `CompiledRule<64>` for the TCAM matcher (built via `ClassifierRuleBuilder`).

## Quick example

```cpp
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/net/net.hpp"
using namespace statusbar::net;
struct EchoUdp : Pollable {
    int fd_{-1};
    explicit EchoUdp(SocketAddress const& a) {
        if (auto r = create_udp_socket(a, true)) { fd_ = r->release(); (void)set_nonblocking(fd_); }
    }
    ~EchoUdp() override { if (fd_ >= 0) ::close(fd_); }
    auto fd() const noexcept -> int override { return fd_; }
    auto finished() const noexcept -> bool override { return false; }
    void tick(int64_t) override {}
    void on_ready(int64_t) override {
        SocketAddress src; src.reset_length();
        std::array<uint8_t, 1500> buf{};
        auto n = ::recvfrom(fd_, buf.data(), buf.size(), 0, src.sockaddr(), src.length_ptr());
        if (n > 0) ::sendto(fd_, buf.data(), n, 0, src.sockaddr(), src.length());
    }
};
int main() {
    auto& stop = statusbar::itc::install_stop_signal();
    MessageReactor reactor{stop, monotonic_ns, 100};
    reactor.add(std::make_unique<EchoUdp>(SocketAddress::ipv4_any(8080)));
    reactor.run();
}
```

## Headers

- `statusbar/net/net.hpp` — module header; pulls in everything below (with `net_linux_*.hpp` gated on `__linux__`). Consumers should `#include` this.
- `statusbar/net/net_message_reactor.hpp` — `Pollable`, `MessageReactor`, `ClockFn`, `monotonic_ns`.
- `statusbar/net/net_address.hpp` — `SocketAddress` plus `create_udp_socket` / `create_tcp_socket` / `create_tcp_listener`.
- `statusbar/net/net_socket.hpp` — `FileDescriptor`, `set_nonblocking`, `set_reuse_addr`, `set_dscp`, `set_tos`, `would_block`.
- `statusbar/net/net_server_config.hpp`, `net_notify.hpp`, `net_error.hpp` — `ServerConfig`, `NotificationPipe`, `NetError`.
- `statusbar/net/net_rawnet.hpp`, `net_ethernet_port.hpp` — `RawnetContext` and the `EthernetPort` concept + slot/guard types.
- `statusbar/net/net_traffic_classifier.hpp`, `net_tcam_classifier.hpp`, `net_compiled_rule.hpp`, `net_cbpf_emit.hpp` — classification and cBPF emission.
- `statusbar/net/net_test_port.hpp`, `net_loopback_port.hpp`, `net_bpf_port.hpp`, `net_tap_bridge.hpp` — `EthernetPort` backends.
- `statusbar/net/net_rss.hpp` — `RssIndirection` and the `ETHTOOL_GRXFHINDIR` / `ETHTOOL_SRXFHINDIR` helpers (the ioctls Linux-only).
- `statusbar/net/net_linux_mmap.hpp`, `net_linux_xdp.hpp` — Linux `PACKET_MMAP` and AF_XDP contexts (Linux-only).
- `statusbar/net/net_netdev_features.hpp` — `netdev::NetdevClient`, the netdev generic netlink builders and parsers (Linux-only; not in `net.hpp`).
- `statusbar/net/net_netdev_napi.hpp` — `netdev::NapiClient`, `netdev::set_queue_threaded()` and the queue and NAPI builders and parsers (Linux-only; not in `net.hpp`).
- `statusbar/net/net_carrier_watch.hpp` — `CarrierWatch`, `LinkCarrier`, `parse_link_carrier()`: one interface's carrier from rtnetlink link notifications (Linux-only; not in `net.hpp`).
- `statusbar/net/net_launch_order.hpp` — `LaunchOrder` and `tai_now_ns()`.
- `statusbar/net/net_tc_launch_time.hpp` — `tc::LaunchTimeMode`, `tc::LaunchTimeQueue` and `tc::settle_launch_time_queue` (the queue part Linux-only; not in `net.hpp`).
- `statusbar/net/net_netlink.hpp` — `netlink::Socket` and the netlink framing helpers shared by `TcClient` and `NetdevClient` (Linux-only).

## Dependencies

- **Statusbar modules:** [`status`](STATUS_MODULE.md) (factories return `Status` / `StatusValue`), [`buffer`](BUFFER_MODULE.md) (frame buffers, span utilities), [`ieee`](IEEE_MODULE.md) (`Eui48`, EtherType constants), [`ip`](IP_MODULE.md) (`ip::Ipv4Address` / `ip::Ipv6Address`), [`itc`](ITC_MODULE.md) (`StopToken` drives `MessageReactor::run`), [`config`](CONFIG_MODULE.md) (`ServerConfig::from_config`).
- **System / external:**
  - `<poll.h>`, `<sys/socket.h>`, `<netinet/in.h>` — POSIX socket / `poll()` API.
  - `AF_PACKET` (`<linux/if_packet.h>`) on Linux, `BPF` (`<net/bpf.h>`) on macOS, for `RawnetContext`.
  - `PACKET_MMAP` for `MmapContext`; **libbpf** and **libxdp** (`<bpf/libbpf.h>`, `<xdp/xsk.h>`) for `XdpContext` / AF_XDP — Linux-only, optional.
  - `sg14::inplace_function` from `statusbar/sg14/inplace_function.h` for `ClockFn` and bounded-capture handlers.
  - `<chrono>`, `<expected>`, `<memory_resource>`, `<span>`, `<system_error>` from the C++20/23 standard library.

## Notes & caveats

- `MessageReactor` is single-threaded; only `NotificationPipe::notify()` and the `StopToken` are safe across threads.
- `Pollable::fd()` may return `-1` for tick-only ports — `tick(now_ns)` still fires each cycle. `poll_events()` defaults to `POLLIN`; override for `POLLOUT` / `on_writable`.
- `set_dscp` writes IPv4 TOS or IPv6 traffic-class based on `family`; `is_valid_dscp` accepts `-1` (unset) or `0..63`.
- `RawnetContext` needs `CAP_NET_RAW` on Linux; root or BPF device access on macOS. AF_XDP needs kernel ≥ 5.4, libbpf, libxdp, and an XDP-capable driver — otherwise `XdpContext` compiles as a stub.
- An AF_XDP socket binds one RX queue, and RSS spreads received IP flows (multicast UDP included) over all of them: steer every bucket to the socket's queue with `set_rss_indirection_all` (needs `CAP_NET_ADMIN`; NICs without RSS, such as `lo` and `veth`, report `operation_not_supported`). Non-IP frames such as AVTP are not hashed and land on queue 0 on most NICs (igb, igc).
- A zero-copy driver sizes each RX buffer from the UMEM frame less `XDP_PACKET_HEADROOM` (256 octets), rounded down to its granularity; igb programs SRRCTL.BSIZEPACKET in 1 KiB steps, so 2048-octet frames give 1 KiB buffers and a longer frame reaches XDP cut to its first buffer. `XdpConfig::umem_frame_size` defaults to 4096 (3 KiB buffers); the UMEM is `umem_frame_count` × that, locked: the default 1024 frames are 4 MiB, 2048 are 8 MiB, which is the whole of a common default `RLIMIT_MEMLOCK` (8 MiB). Without `CAP_IPC_LOCK` raise the limit (`ulimit -l`, `LimitMEMLOCK=`) or use fewer frames.
- Launch time over AF_XDP (Documentation/networking/xsk-tx-metadata.rst): with `XdpConfig::tx_launch_time`, the UMEM reserves `struct xsk_tx_metadata` (24 octets) between `umem_headroom` and each frame's data. `tx_start(launch_time_ns)` writes `XDP_TXMD_FLAGS_LAUNCH_TIME` and the time (ns on the NIC's PHC, which is TAI when ptp4l disciplines it) for `launch_time_ns > 0`, or no request otherwise. `tx_commit` sets `XDP_TX_METADATA` only on timed frames. The headroom also delays received data by 24 octets, so a 4096-octet frame still gives 3 KiB RX buffers.
- `tx_launch_time` needs `xsk_umem__create_opts` from libxdp ≥ 1.5 (fd left 0, so libxdp opens the socket). CMake compiles the `xsk_umem_opts` initializer the code uses and defines `HAVE_XSK_TX_METADATA` if it builds. Without it, `open()` fails with `XdpError::tx_metadata_not_supported` before it closes or attaches anything. A kernel before 6.11 refuses `XDP_UMEM_TX_METADATA_LEN` with `EINVAL`. `open()` reports that as `tx_metadata_not_supported` too, but only when the geometry is otherwise one the kernel takes (`detail::valid_umem_geometry`); any other failure is `umem_creation_failed`. Kernels 6.11 to 6.14 accept the UMEM but reject `XDP_TXMD_FLAGS_LAUNCH_TIME` as an invalid descriptor when a timed frame is sent; launch time needs Linux ≥ 6.15.
- `open()` decides only whether the metadata can be reserved. Whether the driver honours the time is a separate question: `XdpContext::launch_time_supported()` / `netdev::query_xsk_features()` report the netdev `tx-launch-time-fifo` xsk-feature, set by drivers with `tmo_request_launch_time` (igc, stmmac; not igb). Copy mode works without it, for example on veth. Copy mode sends through `__dev_direct_xmit` and bypasses the qdisc, so the time reaches the driver as `skb->skb_mstamp_ns`; zero copy hands it to the driver directly. Either way the driver honours it only when the TX queue is in offloaded launch-time mode, which an offloaded ETF qdisc (`etf ... offload`) sets; otherwise the frame goes out at once.
- A frame taken ahead of time (a pool filled by `tx_start()`) gets its launch time from `tx_set_launch_time(handle, ns)` before `tx_commit`. `tc::build_replace_etf` / `TcControl::replace_etf` install the ETF qdisc that puts a queue in launch-time mode (`EtfQdisc::offload`; the kernel takes only `CLOCK_TAI`). etf has no change operation: replacing an etf already on that parent fails with `EINVAL`, so read it with `get()` and delete it first. igc estimates the launch cycle from the system's `CLOCK_TAI`, so the system clock must follow the PHC (phc2sys).
- On a socket with launch time every frame is timed: igc writes a launch-time context descriptor only for a frame that asks and may otherwise reuse the previous one, so an untimed frame goes at `tai_now_ns()`. igc's launch-time queue is a FIFO, so `LaunchOrder` raises each time to at least the last committed on the socket; a time more than `LaunchOrder::STEP_NS` behind is a clock step and drops the floor. A time already past when the frame is committed (a tick that overran) is stamped now and counted (`launched_late`, `max_late_ns`): igc would send it at once anyway, and the floor then follows now rather than a past time. igc places a time in a 1 s cycle it estimates from `CLOCK_TAI`: a past time goes at once, one more than a cycle ahead lands in the wrong cycle.
- `tc::settle_launch_time_queue` serves a socket on an interface with no other shaping (an AES67 port): `launch_time_mqprio` lays an mqprio root (`hw 0`: the driver is not involved) whose class for the socket's queue no skb priority maps to, so the kernel's frames, which an etf would hold or drop untimed, take the other queues, and `launch_time_etf` an offloaded etf (`CLOCK_TAI`, `skip_sock_check`) on that class. igc places a frame by CLOCK_TAI's offset in its cycle against its own PHC, so a queue may be in launch-time mode only while the system clock follows that NIC's PHC: the host's contract is `off` before the socket opens (an etf a crashed run left goes, one igc reset before anything streams), `on` once the clock agrees (the first etf switches the transmit mode, legacy to TSN, and resets the adapter, `igc_tsn_offload_apply`), `off` again when it no longer does or at exit (removing the last etf resets too). A settle that finds what it would lay is `kept` (idempotent: a second `on`, no request beyond the reads); `off` with nothing of ours is `none`; `unsupported` sends nothing. A refused etf (`EOPNOTSUPP`) is the result, the root left for the host to take away with `off`.
- `LaunchTimeQueue::ptp_queue` gives PTP event traffic a queue of its own past the socket's: `launch_time_mqprio` maps `ptp_priority` (default `tc::PTP_PRIORITY`, 7, ptp4l's `socket_priority`) to its class, every other priority to the queues past it, and leaves any queue between the two idle (on a 4-queue i210 or I226: socket 0, idle 1, PTP 2, the rest 3, the order of avb's shaper). `persistent_root` keeps the root without launch time: `off` lays or keeps it and deletes only an etf on the socket's class (`removed`), so the kernel's frames stay off the socket's queue and PTP on its own whatever the clock does. 7 is the kernel's TC_PRIO_CONTROL: IGMP and MLD reports share PTP's queue.
- An mqprio root never replaces another mqprio in place: the new root's init sets the device's traffic classes and the old root's destroy then clears them (`mqprio_destroy`: `netdev_set_num_tc(dev, 0)`), so every queue takes the kernel's hash until the next change; `taprio_destroy` resets them too (`netdev_reset_tc`). `remove_other_tc_root(tc, ifindex, root, major)` deletes an mqprio or taprio root under another handle first; `settle_launch_time_queue` and avb's shaper call it, and leave a root of another kind to the replace.
- The launch-time PTP layout assumes the lowest queue has the highest priority (igb, igc: I210 Datasheet Section 7.2.7.4, `igc_tsn_tx_arb`); a driver of the other order wants the socket and PTP at the top.
- `netdev::NetdevClient` resolves the netdev family with `CTRL_CMD_GETFAMILY` and sends `NETDEV_CMD_DEV_GET` for one ifindex. A kernel before 6.8 sends no xsk-features, which reads as none. `net_netlink.hpp` holds the plumbing it shares with `NapiClient`, `tc::TcClient` and `vlan::VlanLinkClient`: `netlink::Socket::request` builds a request under the socket's next sequence number, sends it with extended and capped acks requested, hands each reply addressed to it (sequence and port id) to the caller, and ends at the NLMSG_ERROR ack (its extended-ack text in `last_message()`) or a dump's NLMSG_DONE; the header also writes, walks and finds attributes. Each client owns a fixed receive buffer: 32 KiB for tc dumps, 4 KiB for the others. CMake detects the netdev uapi constants (`HAVE_NETDEV_XSK_FEATURES`, `HAVE_NETDEV_XSK_LAUNCH_TIME`) so the mirrors are asserted only against headers that have them.
- Threaded busy poll (`NETDEV_NAPI_THREADED_BUSY_POLL`, Linux 7.1; `Documentation/networking/napi.rst`): a kthread polls the NAPI without stopping and leaves its interrupt masked. Support is found at run time, not build time: `napi-set` answers EOPNOTSUPP before 6.13 and EINVAL where the kernel lacks the mode, so a caller falls back to interrupts (`HAVE_NETDEV_QUEUE_NAPI` and `HAVE_NETDEV_NAPI_BUSY_POLL` only gate the mirrors' asserts). Keep the kthread SCHED_OTHER on a CPU of its own: at a real-time policy it never yields and, on PREEMPT_RT, starves that CPU's `rcuc` thread. `napi_disable()` clears the mode; a driver that registers its NAPIs with `netif_napi_add_config()` (igb) gets it back on `napi_enable()`, one with `netif_napi_add()` (igc) does not, and its NAPI ids change, so after a reset a caller resolves the queue again and re-applies it.
- `XdpSocket::set_napi_busy_poll(true)` says the socket's queue is busy polled: in zero-copy mode `tx_flush()` then skips the kick (`detail::tx_kick_needed()`) once one more kick has gone through (`detail::NapiBusyPoll`), since setting the mode does not wake the kthread, an interrupt or a kick does; from then the polling kthread sends what the TX ring holds; igb and igc set the TX `need_wakeup` flag after every clean, so the kick would be made, and wasted, every tick. Copy mode still kicks: its frames are sent by the `sendto()` itself. The flag is a relaxed atomic, set from any thread; `close()` clears it. A queue that stops busy polling without the host noticing (an adapter reset, `ethtool -L`) would then never be kicked, so `tx_flush()` kicks anyway, counted in `tx_flush_stalled`, when descriptors left at the last flush are still pending and neither the TX consumer nor the completion producer has moved since (`detail::TxProgress`); the sum of the two keeps a full hardware ring that still completes from counting as a stall. A lost carrier is counted the same way.
- `CarrierWatch` sends one `RTM_GETLINK` for its ifindex when it opens and reports the `RTM_NEWLINK` reply through the same callback as the `RTMGRP_LINK` notifications that follow, so a carrier already down is seen at once. After an overrun (`ENOBUFS`) it asks again, but only once a read has drained the queue: while a netlink socket is congested the kernel drops every unicast to it, the reply included, and clears that state only when the queue empties. An error reply (`ENODEV` for an unknown index) finishes the watch.
- Raw sockets (`RawnetContext`, Linux): a receiving socket is opened on `ETH_P_ALL`, not `htons(ethertype)`, so it sits in the kernel's `ptype_all` list and receives frames this host sends as well as wire frames through the egress tap (`dev_queue_xmit_nit`), which feeds only `ETH_P_ALL` sockets; an L2 switch never reflects a frame to its source port, so this is what lets an on-box controller hear a co-located entity. A cBPF filter (`rawnet_filter`) narrows delivery to the ethertype in the kernel, and `join_multicast` binds with `ETH_P_ALL` for the same reason. A transmit-only socket is opened with protocol 0 instead: it is never hooked into delivery, while `sendto` still names the frame's protocol in `sll_protocol`. Opened on `ETH_P_ALL` and never read, it would be handed, and drop, a clone of every frame of its ethertype on every interface; joining a group would bind it and hook it in, so `join_multicast`, `leave_multicast` and `set_subtype_filter` refuse on it.
- `set_subtype_filter` replaces the ethertype filter with one that also requires the first payload byte (the AVTP subtype for 0x22F0, at 14, or 18 under one 802.1Q tag) to be in a set of up to `rawnet_filter::MAX_SUBTYPES`; on a shared ethertype it keeps, for example, an ATDECC socket from being woken by every stream frame. Frames already queued are not refiltered, so a receiver still checks the subtype. Frames whose tag the NIC stripped into metadata (RX VLAN offload) are seen untagged; a frame this host sends with a software tag reaches the egress tap tagged.
- `set_priority` sets `SO_PRIORITY`, the `skb->priority` of every frame sent. A `PACKET_QDISC_BYPASS` frame skips every software qdisc, and the kernel picks its TX queue from that priority through the netdev's priority-to-traffic-class map (which an mqprio root installs, even in software mode) and the class's queue range; at priority 0 it lands on a best-effort queue whatever PCP its VLAN tag carries. Priorities 0-6 need no privilege, 7 and above `CAP_NET_ADMIN`.
- AF_UNIX listeners (`TcpConnectionPool` with `SocketAddress::local(path)`): a stale socket file at the path, one nobody listens on (a probe connect is refused), is unlinked before bind; a live socket or any other kind of entry makes the pool invalid and is left alone (the probe shows up as a connect-then-EOF on the live listener). The socket is bound, given `unix_mode` and set listening inside a private (0700) directory beside the path, then hard-linked into place: the mode never reaches anything but our own socket file, whatever is swapped in at the path, `link()` like `bind()` never follows or replaces what is there, and nobody can connect before the socket is at the path with its final mode. The staged name `<dir>/.XXXXXX/s` must fit `sun_path`, and the directory must not be writable by others. The pool owns the file at the path and unlinks it when destroyed, if it is still the same file. Accepted peers are usually unnamed: `peer(slot)` is AF_UNIX with an empty `path()`.
- With `unix_seqpacket` the listener is `SOCK_SEQPACKET`: `write()` sends one whole message or, when the peer's queue is full, nothing (0); `read()` returns one message. A message longer than the buffer is discarded and reported as `NetError::buffer_full` (`recvmsg` `MSG_TRUNC`), the connection still usable. A read of 0 is EOF only when the peer has shut down (`POLLRDHUP`/`POLLHUP`) and nothing is queued (`FIONREAD` 0); otherwise it was an empty message, which is skipped. Messages queued before the peer's close are read first, unless the peer closed with unread data of its own, which the kernel reports as `ECONNRESET`.
- `tc::build_dump` asks for a dump rather than a single get: `tc_get_qdisc` answers through `rtnetlink_send`, which with `NLM_F_ECHO` also tells every `RTNLGRP_TC` listener (`tc monitor`) of a "new" qdisc. The kernel dumps every qdisc of every device in the namespace (`tc_dump_qdisc` ignores `tcm_ifindex`) and the caller filters. The builders write `struct tcmsg` and `tc_mqprio_qopt` / `tc_cbs_qopt` / `tc_etf_qopt` field by field with iproute2's framing (`q_mqprio.c`, `q_cbs.c`, `q_etf.c`): mqprio's `TCA_OPTIONS` is the flat `tc_mqprio_qopt`, cbs's and etf's nest `TCA_CBS_PARMS` / `TCA_ETF_PARMS`. Netlink is host byte order, and the .cpp static_asserts the kernel's sizes and offsets. `TcClient` returns the kernel's errno as a `Status` and keeps the extended-ack text (`last_message()`).
- `vlan::VlanLinkClient` creates a VLAN link to register its VID with a NIC's receive VLAN filter: a NIC with rx-vlan-filter on (igb's is fixed on) drops frames tagged with a VID nobody registered, before any socket sees them. The kernel registers a VID (`ndo_vlan_rx_add_vid`) when a VLAN link on it is registered, up or not, and unregisters it with the last such link. Left down, the link takes no addresses and only the real device's `ETH_P_ALL` taps see its frames; brought up with no address (`bring_up()`), it lets a socket join an IP group on it, so the kernel reports the membership tagged with the VID (IGMP snooping on that VLAN, RFC 4541). The 8021q module is loaded on demand (rtnl-link-vlan).
- `SocketAddress::from_string` takes host *and* port plus a socket type (`SocketStream` / `SocketDatagram`) — the type drives `getaddrinfo` hints.
- `NetError::would_block` is the expected end-of-drain on nonblocking `recv` / `send` — treat as success, not failure.

## Further reading

- [`ieee`](IEEE_MODULE.md) — wire types (`Eui48`, `EthernetFrame`, EtherType constants) used by `RawnetContext` and the classifiers.
- [`itc`](ITC_MODULE.md) — `StopToken` / `install_stop_signal()` that stops `MessageReactor::run`.
- [`bpf`](BPF_MODULE.md) — historical pointer; the working libbpf / libxdp / XDP code now lives here under `net_linux_xdp.*` and `net_cbpf_emit.hpp`.
