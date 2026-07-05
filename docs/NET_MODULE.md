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
- `statusbar/net/net_linux_mmap.hpp`, `net_linux_xdp.hpp` — Linux `PACKET_MMAP` and AF_XDP contexts (Linux-only).

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
- `SocketAddress::from_string` takes host *and* port plus a socket type (`SocketStream` / `SocketDatagram`) — the type drives `getaddrinfo` hints.
- `NetError::would_block` is the expected end-of-drain on nonblocking `recv` / `send` — treat as success, not failure.

## Further reading

- [`ieee`](IEEE_MODULE.md) — wire types (`Eui48`, `EthernetFrame`, EtherType constants) used by `RawnetContext` and the classifiers.
- [`itc`](ITC_MODULE.md) — `StopToken` / `install_stop_signal()` that stops `MessageReactor::run`.
- [`bpf`](BPF_MODULE.md) — historical pointer; the working libbpf / libxdp / XDP code now lives here under `net_linux_xdp.*` and `net_cbpf_emit.hpp`.
