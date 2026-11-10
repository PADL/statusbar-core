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
- `AnyEthernetPort` — one `EthernetPort` whose backend is chosen at runtime: `EthernetBackend::rawnet`, `mmap` or `xdp`, parsed from a config string by `parse_ethernet_backend` (`ETHERNET_BACKEND_CHOICES` is the usage text). Holds the chosen backend in a variant and forwards every operation of the concept; `tx_rx_independent()` says whether a sender thread and a receiver thread may share it without serialising (only rawnet), `describe()` is the startup-log line ("xdp (native, zero-copy)"), `as<XdpContext>()` reaches the backend for what only it offers. A backend this platform lacks fails to open with its own `not_supported_on_platform`. `rawnet_config_from` / `mmap_config_from` / `xdp_config_from` are the translations open() applies, public for a caller that opens a backend itself from the same config.
- `netdev::NetdevClient` — generic-netlink client for the kernel's netdev family: `features(ifindex)` returns `DeviceFeatures` (`xdp_features`, `xsk` with `launch_time()`); `netdev::launch_time_supported(ifindex)` is the one answer a host asks once and hands to `tc::launch_time_mode()` and every socket. `probe_tx_launch_time()` asks through it.
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
- `statusbar/net/net_socket.hpp` — `FileDescriptor`, `set_nonblocking`, `set_reuse_addr`, `set_dscp`, `set_tos`, `would_block`; the IPv4 endpoint pair `ipv4_sockaddr_in(address, port)` / `ipv4_endpoint(sockaddr_in)` (`IPv4Endpoint`); `set_multicast_all(fd, on)` (Linux's IP_MULTICAST_ALL; a receiver turns it off so it hears only the groups it joined; Darwin and the BSDs filter per socket and have no such option); `set_receive_pktinfo(fd)`, `pktinfo_of(msghdr)` and `destined_for(msghdr, address, ifindex)`, which checks the IP_PKTINFO control message says the datagram was sent to that address on that interface (0: any).
- `statusbar/net/net_server_config.hpp`, `net_notify.hpp`, `net_error.hpp` — `ServerConfig`, `NotificationPipe`, `NetError`.
- `statusbar/net/net_rawnet.hpp`, `net_ethernet_port.hpp` — `RawnetContext` and the `EthernetPort` concept + slot/guard types.
- `statusbar/net/net_rawnet_port.hpp`, `net_any_ethernet_port.hpp` — `RawnetPort`, and `AnyEthernetPort` with `EthernetBackend` / `parse_ethernet_backend`.
- `statusbar/net/net_dpll.hpp`, `net_phc.hpp` — `dpll::DpllClient` / `dpll::DpllWatch` (the kernel's DPLLs and their lock status), `phc::PhcDevice` (a PTP hardware clock's pins and periodic outputs).
- `statusbar/net/net_traffic_classifier.hpp`, `net_tcam_classifier.hpp`, `net_compiled_rule.hpp`, `net_cbpf_emit.hpp` — classification and cBPF emission.
- `statusbar/net/net_test_port.hpp`, `net_loopback_port.hpp`, `net_bpf_port.hpp`, `net_tap_bridge.hpp` — `EthernetPort` backends.
- `statusbar/net/net_linux_mmap.hpp`, `net_linux_xdp.hpp` — Linux `PACKET_MMAP` and AF_XDP contexts (Linux-only). `XdpConfig` chooses the bind mode (`auto_` / `zero_copy` / `copy`) and attach mode (`native` / `generic`, native first with a fall back to generic unless zero-copy was demanded; under `auto_` the program is attached before the socket binds and a generic attach, fresh or adopted, binds copy, since a zero-copy queue is driven only by a native program; under an explicit `copy` or `zero_copy` the bind goes first, so a bind the driver refuses costs no attach and detach), retries a bind refused with EBUSY while the previous socket's queue is still being released, and with a `pin_path` pins the program and its maps under `/sys/fs/bpf/statusbar/<interface>` so a restart adopts the running program instead of re-attaching (`XdpProgram::pin_path_for`, `query`, `owner`, `detach`); the identity that decides adoption is a hash of the embedded object, which is compiled with its directories mapped to fixed names so that the same source and compiler give the same identity in every tree, and an upgrade built elsewhere adopts rather than resets the adapter. When the program did change, the new one is put in place of the pinned one in a single request (`XDP_FLAGS_REPLACE`, the old program named by its pin's descriptor): igb and ice swap programs without the reset that a detach and an attach each cost, the kernel refuses the swap if anything else was attached in between, and `program().swapped()` says it happened. `socket_stats()` counts the user-space side of the rings; `kernel_stats()` reads the kernel's `XDP_STATISTICS`. `set_napi_busy_poll(true)` tells a zero-copy context that its queue's NAPI thread busy polls: once a kick has scheduled the thread, `tx_flush()` skips the kick and leaves the pending flag set, so a kick is still owed if busy poll stops. A busy-polled queue with frames pending and no progress since the last flush is kicked anyway, counted in `tx_flush_stalled`.
- `statusbar/net/net_xdp_avtp_rules.hpp` — the TCAM rules that steer an AVTP stream ID into AF_XDP, tagged and untagged, and `avtp_payload_offset`.
- `statusbar/net/net_netlink.hpp` — the netlink framing (`netlink::put_header`, `put_attribute`, `walk_messages`, `walk_attributes`, `find_attribute`, `ack_status`, `end_status`) and, on Linux, `netlink::Socket`, the blocking request/reply socket the netlink clients share.
- `statusbar/net/net_netdev_features.hpp` — the netdev generic-netlink family: `netdev::NetdevClient`, `DeviceFeatures` / `XskFeatures`, `query_xsk_features`, `launch_time_supported` (Linux); the framing and parsers build everywhere.
- `statusbar/net/net_rss.hpp` — ethtool RSS indirection: read a NIC's table, steer every bucket to one queue (`RssSteering` puts the table back when it goes out of scope), with a recorder double for tests.
- `statusbar/net/net_rx_flow.hpp` — ethtool RX classifier rules: one EtherType or one VLAN priority steered to an RX queue (`RxFlowRule`, `RxFlowPlan`), and `RxFlowSteering`, which installs a plan's rules with an RSS table that keeps the other traffic off their queues and removes both again; `RxFlowControl` is the seam, `RxFlowEthtool` the NIC, `RxFlowRecorder` (`net_rx_flow_recorder.hpp`) the test double.
- `statusbar/net/net_netdev_napi.hpp`, `net_carrier_watch.hpp`, `net_link_readiness.hpp` — `netdev::NapiClient`, `CarrierWatch` and `LinkWatch` (Linux-only; not in `net.hpp`).
- `statusbar/net/net_ethtool_stats.hpp` — a driver's statistics (`ethtool -S`: `ethtool_stats`) and the per-queue packet counters among them (`queue_packets`), under igb/igc/ixgbe/ice's, i40e's and mlx5's names.

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
- `RawnetContext` needs `CAP_NET_RAW` on Linux; root or BPF device access on macOS. AF_XDP needs a kernel with `CONFIG_XDP_SOCKETS` (≥ 5.4), libbpf, libxdp, and an XDP-capable driver — otherwise `XdpContext` compiles as a stub. A driver without native XDP (the Raspberry Pi 5's `macb`, for one) gets generic attach and a copy-mode bind, which `attach_mode()` and `zero_copy()` report.
- Threaded busy poll (`NETDEV_NAPI_THREADED_BUSY_POLL`, Linux 6.19; Documentation/networking/napi.rst) is found at run time: `napi-set` answers EOPNOTSUPP before 6.13 and EINVAL where the kernel lacks the mode. Keep the kthread SCHED_OTHER on a CPU of its own: at a real-time policy it never yields and, on PREEMPT_RT, starves that CPU's `rcuc` thread. A driver that registers its NAPIs with `netif_napi_add()` (igc) loses the mode and its NAPI ids across a reset, so a caller resolves the queue again and re-applies it.
- An mqprio root never replaces another mqprio or taprio in place: the old root's destroy runs after the new root's init and clears the device's traffic classes. `tc::remove_other_tc_root()` deletes it first; `settle_launch_time_queue()` does. A replace under a handle the interface already has is a change to the qdisc holding it, which mqprio has no operation for (EINVAL), so a stale root of ours is deleted first as well.
- An AF_UNIX listener with `unix_seqpacket`: `read()` refuses (`buffer_full`) and discards a message longer than its buffer and skips empty messages; 0 is EOF only once the peer has shut down and nothing is queued.
- `SocketAddress::from_string` takes host *and* port plus a socket type (`SocketStream` / `SocketDatagram`) — the type drives `getaddrinfo` hints.
- `NetError::would_block` is the expected end-of-drain on nonblocking `recv` / `send` — treat as success, not failure.
- **RX flow steering.** `RxFlowSteering::steer(flows, rss, iface, plan)` owns a range of classifier slots: it removes a dead owner's leftovers from that range, turns the ntuple filters on when the plan asks (igb needs them for a VLAN priority rule; they are never turned off again, as igb and igc reset the adapter for it), inserts the plan's rules and spreads the RSS table over the queues the rules leave alone. Its destructor and `restore()` take the rules out and put the table back — the table read before, or the driver's default when leftovers showed the table found was another run's. A NIC without RSS keeps the rules alone; one without a classifier answers `operation_not_supported`. Needs `CAP_NET_ADMIN`.
- **Interface facts** (`net_interface_info.hpp`, Linux): index, MTU, TX queue count, driver name, link speed and, from `ETHTOOL_GRINGPARAM`, the descriptor ring sizes (`ring_params`). `set_rx_ring` sizes the RX ring alone - so it can match an AF_XDP fill ring - leaving the TX, mini and jumbo rings as they are, and writes nothing when the ring is already the size wanted, since most drivers reset the adapter for the write. `CAP_NET_ADMIN` for the write; none of the reads need one.
- **LinkMonitor** polls the carrier every 500 ms and reports transitions. Two ways in besides the poll: `recheck(now)` reads the carrier at once, for a caller that reset the adapter, resized a ring or attached a program on a driver that bounces the link and has no message to say so; `told(up, now)` takes the caller's word for the state, reported when it is a transition and remembered so the next poll says nothing more.
- **Two clocks, told.** The reactor's `now_ns` is control-plane time (`steady_clock`); an `EthernetRxSlot::timestamp_ns` is on `CLOCK_MONOTONIC_RAW`. Neither is read by the code that handles a frame: the reactor tells its ports, a drain tells its port. See [TIME_POLICY.md](TIME_POLICY.md).

### The netdev family

`netdev::launch_time_supported(ifindex)` asks the kernel's netdev generic-netlink family (Linux 6.3; `Documentation/netlink/specs/netdev.yaml`) whether the device's driver acts on an AF_XDP launch time: `NETDEV_CMD_DEV_GET`'s `xsk-features`, bit `NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO` (6.15; igc and stmmac set it). A kernel without the family answers ENOENT, one without the attribute answers no features, and both send untimed frames anyway. Ask once per device and hand the answer to every user of its queues; `XdpContext::open()` asks the same question for its own `XdpConfig::tx_launch_time`. The queue still needs an offloaded ETF qdisc (`net_tc_launch_time.hpp`) for the NIC to hold a frame until its launch time. `NetdevClient` keeps the socket open across several `features()` queries; `netlink::Socket` beneath it is what any other request/reply netlink client in this module builds on: one request under its own sequence number, every reply addressed to it handed over, the acknowledgement (or a dump's `NLMSG_DONE`) its result, a one-second timeout so a dropped request does not hang its caller.

### The dpll family and the PTP hardware clock's pins

`dpll::DpllClient` lists the kernel's digital PLLs (`Documentation/netlink/specs/dpll.yaml`, Linux 6.7: the E810's PPS DPLL, an EEC for SyncE) and reads one - its type, mode, lock status and why it is not locked. `dpll::DpllWatch` joins the family's `monitor` multicast group as a reactor `Pollable` and hands every device notification to a callback with the reactor time, so a daemon follows a lock without polling; read the devices once through the client, then watch. Notifications are not replayed, so the watch says when some were lost: a socket overrun (ENOBUFS), a datagram larger than its buffer (dropped whole), or a lasting error (after which it is `finished()` and opened again) each reach the optional `on_loss()` callback and the `losses()` count, and the caller reads the devices again. Both resolve the family through the generic-netlink controller, which is also where the group's id comes from (`parse_family` reads the nested `CTRL_ATTR_MCAST_GROUPS`). A kernel without the family answers ENOENT; one with no driver registering a device lists none; the family's requests and its monitor group are for `CAP_NET_ADMIN`, and without it a query is refused with EPERM.

The client reads the family's pins too: `pins()` dumps them and `pin(id)` reads one, each a `dpll::Pin` with its labels (the E810's `SMA1`, `U.FL2`), type, capabilities, frequency and the ranges it may take, phase-adjustment range and value, and how each device it is wired to sees it (`on_devices`: direction, state, priority, phase offset in femtoseconds) or, behind a mux, how each mux pin does (`on_pins`). `set_pin(id, PinChange)` is `DPLL_CMD_PIN_SET`: a frequency and a phase adjustment belong to the pin, while a state, a priority or a direction belong to the pin on one device and go in a `parent-device` nest, which is how the kernel frames them and why the change names the device; `set_frequency()`, `set_phase_adjust()`, `set_state()`, `set_priority()` and `set_direction()` each ask for one thing. A word clock out of an SMA is a frequency the pin supports and `connected` as an `output` on the PPS device. The kernel refuses a frequency outside the ranges and a phase adjustment outside its range or off its granularity with EINVAL, and what the hardware cannot do with EOPNOTSUPP, the reason in `last_message()`. `DpllWatch::on_pin()` takes a callback for the pin notifications (create, change, delete), which the watch otherwise passes over. The framing (`build_pin_dump`, `build_pin_get`, `build_pin_set`, `parse_pin`, `PinDump`) builds everywhere, is checked against `linux/dpll.h` where the headers have it, and is tested against hand-laid E810 replies and request bytes; `parse_pin` is under the fuzzer with `parse_device`.

`phc::PhcDevice` opens a `/dev/ptpN` (`phc_index(ifname)` finds the N behind an interface) and drives what the clock then drives: `set_pin()` gives a pin a function and a channel (`PTP_PIN_SETFUNC2`), `periodic_output()` puts a period, a start or a phase, an optional duty cycle and the one-shot flag on a channel (`PTP_PEROUT_REQUEST2`), `capabilities()` says how many of each the clock has and `pin()` reads one back. A phase instead of a start aligns the edges to the clock's seconds whenever the output is enabled, which is what a PPS wants. Reading needs read access to the node, setting needs write access; a device opened read-only says so through `writable()` and refuses the writes with `operation_not_permitted`. `perout_flags()` and `clock_time_from_ns()` are the pure parts, checked and tested without a clock.

## Further reading

- [TIME_POLICY.md](TIME_POLICY.md) — the RX-stamp contract and the reactor's clock in the wider time-handling policy.
- [`ieee`](IEEE_MODULE.md) — wire types (`Eui48`, `EthernetFrame`, EtherType constants) used by `RawnetContext` and the classifiers.
- [`itc`](ITC_MODULE.md) — `StopToken` / `install_stop_signal()` that stops `MessageReactor::run`.
- [`bpf`](BPF_MODULE.md) — historical pointer; the working libbpf / libxdp / XDP code now lives here under `net_linux_xdp.*` and `net_cbpf_emit.hpp`.
