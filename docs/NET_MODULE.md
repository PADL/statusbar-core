[← back to module index](README.md)

# net

Non-blocking async TCP, UDP, and raw Ethernet networking with zero
runtime allocations, built around a `poll()`-driven reactor.

## Overview

A single-threaded `MessageReactor` owns a set of `Pollable` ports,
calls `poll()` once per cycle, and dispatches `on_ready` /
`on_writable` / `tick` callbacks with a nanosecond timestamp from
an injected clock: the control-plane clock (`monotonic_ns` is
`std::chrono::steady_clock`, the same clock as `sm::Clock`), read once
per cycle and told to every port. Buffers and queue capacities are
fixed at construction — nothing on the hot path allocates.

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
- `EthernetPort` (concept) — zero-copy TX/RX contract satisfied by `TestPortContext`, `LoopbackPortContext`, `BpfPortContext`, `MmapContext`, `XdpContext`, `RawnetPort` and `AnyEthernetPort`; `EthernetTxGuard` / `EthernetRxGuard` provide scoped slot acquisition. `MmapContext`, `XdpContext` and `RawnetPort` also `leave_multicast()`. The RX clock is `RxClock` = `realtime::MonotonicRawClock` (`CLOCK_MONOTONIC_RAW`), not configurable: `rx_start(RxTimePoint now)` is told it and stamps the frame from it where the kernel gave no stamp (mmap, the macOS BPF reader and Zephyr keep the kernel's); `rx_start()` reads it once and forwards. A drain loop reads `rx_clock_now()` once per pass and tells every `rx_start(now)` of the pass. `AnyEthernetPort::tx_set_launch_time()` times a frame after its `tx_start()` (xdp, and the test port, which records it). `TestPortContext::holds()` tells a test whether bytes lie in one of the port's frame buffers, i.e. were written or read in place.
- `RawnetPort` — the `EthernetPort` shape of a `RawnetContext` pair: a transmit-only socket with `PACKET_QDISC_BYPASS` and a receive socket, as the stream entities have always run them. Copy-based, one syscall per frame; its TX and RX are independent sockets and may be driven from two threads. The RX frame comes back with a rebuilt 14-byte header (the socket strips it, and any 802.1Q tag).
- `AnyEthernetPort` — one `EthernetPort` whose backend is chosen at runtime: `EthernetBackend::rawnet`, `mmap` or `xdp`, parsed from a config string by `parse_ethernet_backend` (`ETHERNET_BACKEND_CHOICES` is the usage text). Holds the chosen backend in a variant and forwards every operation of the concept; `tx_rx_independent()` says whether a sender thread and a receiver thread may share it without serialising (only rawnet), `describe()` is the startup-log line ("xdp (native, zero-copy)"), `as<XdpContext>()` reaches the backend for what only it offers. A backend this platform lacks fails to open with its own `not_supported_on_platform`.
- `netdev::NetdevClient` — generic-netlink client for the kernel's netdev family: `features(ifindex)` returns `DeviceFeatures` (`xsk` with `launch_time()`); `netdev::launch_time_supported(ifindex)` is the one answer a host asks once and hands to `tc::launch_time_mode()` and every socket. `probe_tx_launch_time()` asks through it.
- `netdev::NapiClient` — the netdev family's queue and NAPI commands: `queue_napis(ifindex, queue)`, `napi(id)`, `set_threaded(id, mode)`; `netdev::set_queue_threaded()` does all three for one queue and pins each kthread SCHED_OTHER to a CPU.
- `CarrierWatch` — a reactor `Pollable` on rtnetlink link notifications for one ifindex, reporting `LinkCarrier` (`IFLA_CARRIER`, `IFLA_CARRIER_DOWN_COUNT`): event-driven, unlike `LinkMonitor`'s poll, and the down count shows a carrier lost and regained between notifications.
- `LinkWatch` / `LinkReadiness` — a blocking rtnetlink watch of one interface's carrier, IPv4 addresses and qdisc changes; opened before a qdisc change, `await_reset()` waits out the adapter reset igb and igc schedule when an offload switches the transmit mode (`RESET_SETTLE_NS`: 2 s with no carrier loss means none came, else the carrier back within `RESET_TIMEOUT_NS`, 30 s, with an IPv4 address too when `ResetWaitPolicy::ipv4` asks).
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
- `statusbar/net/net_rawnet_port.hpp`, `net_any_ethernet_port.hpp` — `RawnetPort`, and `AnyEthernetPort` with `EthernetBackend` / `parse_ethernet_backend`.
- `statusbar/net/net_traffic_classifier.hpp`, `net_tcam_classifier.hpp`, `net_compiled_rule.hpp`, `net_cbpf_emit.hpp` — classification and cBPF emission.
- `statusbar/net/net_test_port.hpp`, `net_loopback_port.hpp`, `net_bpf_port.hpp`, `net_tap_bridge.hpp` — `EthernetPort` backends.
- `statusbar/net/net_linux_mmap.hpp`, `net_linux_xdp.hpp` — Linux `PACKET_MMAP` and AF_XDP contexts (Linux-only). `XdpConfig` chooses the bind mode (`auto_` / `zero_copy` / `copy`) and attach mode (`native` / `generic`, native first with a fall back to generic unless zero-copy was demanded), retries a bind refused with EBUSY while the previous socket's queue is still being released, and with a `pin_path` pins the program and its maps under `/sys/fs/bpf/statusbar/<interface>` so a restart adopts the running program instead of re-attaching (`XdpProgram::pin_path_for`, `query`, `owner`, `detach`). `socket_stats()` counts the user-space side of the rings; `kernel_stats()` reads the kernel's `XDP_STATISTICS`.
- `statusbar/net/net_xdp_avtp_rules.hpp` — the TCAM rules that steer an AVTP stream ID into AF_XDP, tagged and untagged, and `avtp_payload_offset`.
- `statusbar/net/net_rss.hpp` — ethtool RSS indirection: read a NIC's table, steer every bucket to one queue (`RssSteering` puts the table back when it goes out of scope), with a recorder double for tests.
- `statusbar/net/net_ethtool_stats.hpp` — a driver's statistics (`ethtool -S`: `ethtool_stats`) and the per-queue packet counters among them (`queue_packets`), under igb/igc/ixgbe/ice's, i40e's and mlx5's names.
- `statusbar/net/net_rx_flow.hpp` — ethtool RX flow rules (`ethtool -N <if> flow-type ether`): an EtherType or a VLAN priority steered to an RX queue, and `RxFlowSteering`, which installs a set of them with an RSS table that keeps the other traffic off their queues and removes both again; `net_rx_flow_recorder.hpp` is its test double.
- `statusbar/net/net_netlink.hpp` — `netlink::Socket` and the attribute helpers the netdev clients and the carrier watch share (Linux-only).
- `statusbar/net/net_netdev_features.hpp`, `net_netdev_napi.hpp`, `net_carrier_watch.hpp`, `net_link_readiness.hpp` — `netdev::NetdevClient`, `netdev::NapiClient`, `CarrierWatch` and `LinkWatch` (Linux-only; not in `net.hpp`).

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
- `join_group()` is an any-source join; `join_source_group()` joins for one source (an IGMPv3 INCLUDE join, RFC 4607
  Section 4.1) through `MCAST_JOIN_SOURCE_GROUP` (RFC 3678), which takes the interface by index on Linux, Darwin and
  the BSDs. A switch running source-specific multicast drops an any-source join to 232/8 (`is_source_specific_group()`);
  `open_source_group_membership()` holds such a join for an AF_XDP receiver as `open_group_membership()` holds the other.
- `RawnetContext` needs `CAP_NET_RAW` on Linux; root or BPF device access on macOS. AF_XDP needs a kernel with `CONFIG_XDP_SOCKETS` (≥ 5.4), libbpf, libxdp, and an XDP-capable driver — otherwise `XdpContext` compiles as a stub. A driver without native XDP (the Raspberry Pi 5's `macb`, for one) gets generic attach and a copy-mode bind, which `attach_mode()` and `zero_copy()` report.
- Threaded busy poll (`NETDEV_NAPI_THREADED_BUSY_POLL`, Linux 6.19; Documentation/networking/napi.rst) is found at run time: `napi-set` answers EOPNOTSUPP before 6.13 and EINVAL where the kernel lacks the mode. Keep the kthread SCHED_OTHER on a CPU of its own: at a real-time policy it never yields and, on PREEMPT_RT, starves that CPU's `rcuc` thread. A driver that registers its NAPIs with `netif_napi_add()` (igc) loses the mode and its NAPI ids across a reset, so a caller resolves the queue again and re-applies it.
- TX kicks: `XdpContext::tx_flush()` skips the kick when nothing was committed since the last one got through ("nothing submitted" is the one thing always safe to skip on, and the common case for a sender ticking faster than it sends, so a low skip ratio in the counters is a signal in itself); the socket is bound with `XDP_USE_NEED_WAKEUP`, and a kick is sent whenever frames are pending, which costs a syscall and never a frame. A kick refused with EAGAIN leaves the frames pending for the next call. A kicker thread may flush for the committing thread: the pending flag is claimed before the kick and re-armed on a refusal, so a commit between the claim and the syscall is carried by the next kick; the flag and the TX ring's indexes (read with acquire) are all the two share, and the flush counters and busy-poll progress are the flusher's alone.
- `XdpContext::set_napi_busy_poll(true)`: in zero-copy mode `tx_flush()` skips the kick once one kick has scheduled the kthread, and kicks again, counted in `tx_flush_stalled`, when the TX ring has made no progress since the last flush.
- An mqprio root never replaces another mqprio or taprio in place: the old root's destroy runs after the new root's init and clears the device's traffic classes. `tc::remove_other_tc_root()` deletes it first; `settle_launch_time_queue()` does. A replace under a handle the interface already has is a change to the qdisc holding it, which mqprio has no operation for (EINVAL), so a stale root of ours is deleted first as well.
- An AF_UNIX listener with `unix_seqpacket`: `read()` refuses (`buffer_full`) and discards a message longer than its buffer and skips empty messages; 0 is EOF only once the peer has shut down and nothing is queued.
- `RxFlowSteering` owns a run of classifier slots (`RxFlowRange`): any rule found there is a previous owner's leftover, removed before its own go in. The RSS table is read after that sweep and written back on restore; when leftovers were found, the restore writes the driver's default instead. A plan with `ntuple` set turns the flag on if it is off and never off again: igb and igc reset the adapter on any change (igb also resets its PHC from `CLOCK_REALTIME`), so turn it on while the link is down. igb needs it for VLAN priority rules in promiscuous mode; igc honours rules without it. Assigning a guard over a live one restores the old one first, so steer a held range again only after restoring its guard: the old guard's restore would remove the new rules at the same locations. igb and igc match an ETHER_FLOW rule on a whole EtherType (an ETQF filter) or on the VLAN priority alone (VLAPQF / VLANPQF), one of the two per rule; igb has three ETQF filters for rules (the fourth is its PTP timestamp filter). Rules sit ahead of RSS, so a frame a rule matches is not hashed.
- `SocketAddress::from_string` takes host *and* port plus a socket type (`SocketStream` / `SocketDatagram`) — the type drives `getaddrinfo` hints.
- `NetError::would_block` is the expected end-of-drain on nonblocking `recv` / `send` — treat as success, not failure.
- **Two clocks, told.** The reactor's `now_ns` is control-plane time (`steady_clock`); an `EthernetRxSlot::timestamp_ns` is on `CLOCK_MONOTONIC_RAW`. Neither is read by the code that handles a frame: the reactor tells its ports, a drain tells its port. See [TIME_POLICY.md](TIME_POLICY.md).

## Further reading

- [TIME_POLICY.md](TIME_POLICY.md) — the RX-stamp contract and the reactor's clock in the wider time-handling policy.
- [`ieee`](IEEE_MODULE.md) — wire types (`Eui48`, `EthernetFrame`, EtherType constants) used by `RawnetContext` and the classifiers.
- [`itc`](ITC_MODULE.md) — `StopToken` / `install_stop_signal()` that stops `MessageReactor::run`.
- [`bpf`](BPF_MODULE.md) — historical pointer; the working libbpf / libxdp / XDP code now lives here under `net_linux_xdp.*` and `net_cbpf_emit.hpp`.
