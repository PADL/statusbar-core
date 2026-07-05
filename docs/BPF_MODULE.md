[← back to module index](README.md)

# bpf

Raw Ethernet frame capture with kernel-side EtherType filtering,
exposed through a platform-neutral `BpfDevice` type alias.

## Overview

The `bpf` module wraps each operating system's preferred mechanism for
delivering raw Ethernet frames to user space and presents a single
callback-driven interface. On Darwin/macOS the backend is the
`/dev/bpf*` character-device family with kernel BPF filters; on Linux
it is an `AF_PACKET` socket created with the desired EtherType, which
moves the protocol filter into socket creation itself.

A device is constructed with a network interface name and a
`FilterParams` describing the EtherType, optional buffer size, optional
read timeout, and a promiscuous-mode flag. The caller installs a
`BpfPacketCallback` via `set_callback()` and then calls `receive_pdus()`
to read and dispatch packets. On Darwin one call may deliver a batch
of frames from a single `read()`; on Linux each call performs one
`recv()` and delivers at most one frame. Every delivered frame carries
an `AcquisitionTimeAssociation`: on Darwin the per-packet kernel BPF
timestamp (`bh_tstamp`) paired with a per-batch user-space
`CLOCK_MONOTONIC_RAW` reading; on Linux a single user-space
`CLOCK_MONOTONIC` reading written into both fields (no kernel-side
timestamp).

Both backends derive from `BpfDeviceBase`, which owns the file
descriptor, callback, and `BpfStatistics` counters. Failures surface as
`Status` / `StatusValue<T>` from [`status`](STATUS_MODULE.md), backed
by a dedicated `BpfError` enum plugged into `std::error_code`. The
module header `statusbar/bpf/bpf.hpp` selects the backend at compile
time and exports `BpfDevice`.

## Key types

- `BpfDevice` — platform-selected alias: `BpfDeviceLinux` on Linux,
  `BpfDeviceDarwin` elsewhere.
- `BpfDeviceBase` — abstract base owning the file descriptor, callback,
  and `BpfStatistics`. `receive_pdus()` is pure virtual; `get_mtu()`,
  `get_mac_address()`, `set_blocking()`, and `is_blocking()` are
  overridable.
- `BpfDeviceLinux` / `BpfDeviceDarwin` — `final`, non-copyable,
  non-movable concrete backends.
- `FilterParams` — `{ ethertype, promiscuous, buffer_size, read_timeout }`.
- `BpfPacketCallback` — `std::function<void(std::span<uint8_t const>,
  AcquisitionTimeAssociation const)>` installed via `set_callback()`.
- `AcquisitionTimeAssociation` — `{ bpf_time_ns, monotonic_clock_time_ns }`;
  see the Overview for per-platform semantics.
- `BpfStatistics` — counters (`packets_received`, `packets_dropped`,
  `read_errors`, `callback_errors`, `buffer_overflows`); read via
  `statistics()`, zero via `reset_statistics()`.
- `BpfError` / `bpf_error_category()` / `make_error_code()` — error
  taxonomy plugged into `std::error_code`.
- `FileDescriptor` — move-only RAII wrapper that closes the held `int`
  on destruction; `release()` relinquishes ownership.

## Quick example

```cpp
#include "statusbar/bpf/bpf.hpp"
#include <chrono>
#include <span>

using namespace statusbar::bpf;

int main()
{
    FilterParams params{
        .ethertype = 0x88F7,  // IEEE 802.1AS / gPTP
        .promiscuous = true,
        .read_timeout = std::chrono::milliseconds{50},
    };
    BpfDevice device{"eth0", params};
    if (!device.is_valid()) {
        return 1;  // open failed; statistics() still readable
    }
    device.set_callback([](std::span<uint8_t const> frame,
                           AcquisitionTimeAssociation const time) {
        (void)frame; (void)time;
    });
    auto status = device.receive_pdus();
    return status.has_value() ? 0 : 1;
}
```

## Headers

- `statusbar/bpf/bpf.hpp` — module header; picks the platform backend
  and exports `BpfDevice`. Consumers `#include` this.
- `statusbar/bpf/bpf_base.hpp` — constants (`ETHERNET_HEADER_MIN_SIZE`,
  `bpf_buffer_size`, `bpf_max_device_num`, `bpf_filter_max_packet`),
  `BpfError`, `BpfErrorCategory`, `AcquisitionTimeAssociation`,
  `BpfStatistics`, `BpfPacketCallback`, `FilterParams`, `FileDescriptor`.
- `statusbar/bpf/bpf_device_base.hpp` — `BpfDeviceBase` abstract class.
- `statusbar/bpf/bpf_device_linux.hpp` — `BpfDeviceLinux` (AF_PACKET).
- `statusbar/bpf/bpf_device_darwin.hpp` — `BpfDeviceDarwin` (`/dev/bpf*`).

## Dependencies

- **Statusbar modules:** [`status`](STATUS_MODULE.md) — fallible
  methods return `Status` / `StatusValue<T>`.
- **System / external:**
  - Linux: `AF_PACKET` / `SOCK_RAW` sockets via `<sys/socket.h>` and
    `<net/if.h>`. No libbpf, no libxdp — the BPF name is historical;
    the XDP / libbpf bindings live in [`net`](NET_MODULE.md).
  - Darwin: `<net/bpf.h>` `/dev/bpf*` character devices.
  - POSIX: `<unistd.h>`, `<fcntl.h>`, `<sys/ioctl.h>`, `<sys/time.h>`.
  - Standard library: `<chrono>`, `<functional>`, `<optional>`,
    `<span>`, `<string>`, `<system_error>`.

## Notes & caveats

- Requires elevated privileges: Linux needs `CAP_NET_RAW` (or root);
  Darwin needs read/write access to `/dev/bpf*`. Check `is_valid()`
  before `receive_pdus()` — a `-1` fd means open failed.
- Not thread-safe; serialize `receive_pdus()` externally. The class is
  non-copyable and non-movable since callbacks typically capture `this`.
- For timing-sensitive use on Darwin, prefer the per-packet
  `bpf_time_ns` (`bh_tstamp`) over the per-batch
  `monotonic_clock_time_ns`. On Linux the two fields are identical and
  only as precise as one user-space `clock_gettime` per `recv()`.
- The Linux backend filters by EtherType at socket-creation time;
  changing the EtherType requires a new device.
- `bpf_filter_max_packet` (512 KiB) exceeds the 16 KiB `bpf_buffer_size`
  default, so jumbo frames stay visible if you raise `buffer_size`.
- Callback exceptions are caught, counted in
  `callback_errors`, and surfaced as `BpfError::callback_exception`.

## Further reading

- [`NET_MODULE`](NET_MODULE.md) — higher-level networking and the
  libbpf / libxdp XDP path in the `net` module.
