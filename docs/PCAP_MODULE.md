[← back to module index](README.md)

# pcap

Standalone read/write support for the Wireshark **pcap** and **pcapng**
capture-file formats, plus a deterministic synthetic-time replay driver.

## Overview

Despite the name, this module does **not** depend on `libpcap` — it
does not `#include <pcap.h>` and links no system capture library.
Everything is implemented in-house against the published file-format
specs (pcap from the libpcap wiki, pcapng from the IETF draft). All I/O
goes through C stdio `FILE*` wrapped in a `FilePtr`. The module
reads/writes capture *files*; live-interface capture is a separate
concern (see [`netdump`](NET_MODULE.md)).

Both formats are supported. Legacy pcap is handled by `FileReader` /
`FileWriter` (`FileHeader` + `RecordHeader` + frame bytes). Pcapng is
handled by `PcapngReader` / `PcapngFileWriter`, which parse Section
Header, Interface Description, and Enhanced/Simple Packet Blocks
(SHB/IDB/EPB/SPB) and detect endianness from the magic numbers.

Readers normalise timestamps to **microseconds relative to the first
packet** so consumers don't have to track an epoch baseline. Writers
accept either an absolute microsecond timestamp or call
`get_current_time_in_microseconds()`. The zero-allocation
`std::span<uint8_t const>` overloads are the preferred runtime API;
`Packet` (`= std::vector<uint8_t>`) overloads exist for convenience.

`PcapReplayDriver` sits on top of `PcapngReader` as a pull-based replay
engine, handing each packet to the caller as a `ReplayEvent` (synthetic
`steady_clock` time + parsed `ieee::EthernetFrame` + payload span) with
the first packet pinned at `ReplayTime{}` and later packets offset by
their pcapng-relative timestamps, so state-machine tests run
deterministically without wall-clock drift.

## Key types

- `Packet` — alias for `std::vector<uint8_t>` holding an Ethernet frame.
- `FileHeader`, `RecordHeader` — 24-byte and 16-byte on-disk pcap structures.
- `FileReader`, `FileWriter` — legacy pcap I/O; auto-detect byte order on read, append on write.
- `PcapngBlockType`, `LinkType` — pcapng block-type codes and link-layer types (Ethernet, PPP, Raw, IEEE 802.11, Linux SLL, …).
- `PcapngBlockHeader`, `PcapngSectionHeaderBody`, `PcapngInterfaceDescBody`, `PcapngEnhancedPacketBody`, `PcapngSimplePacketBody` — on-disk pcapng block layouts.
- `InterfaceInfo` — per-IDB record: `link_type`, `snap_length`, `ts_resol`.
- `PcapngReader`, `PcapngFileWriter` — pcapng I/O; the writer emits one Ethernet IDB plus EPBs in native byte order.
- `ReplayEvent`, `ReplayTime`, `PcapReplayDriver` — synthetic-time replay over a pcapng capture; use `for_each` or pull with `next`.
- `for_each_packet(Reader&, cb)` — function template (overloaded for both readers) that loops to EOF, calling `cb` with parsed Ethernet fields.

## Quick example

```cpp
#include "statusbar/pcap/pcap.hpp"
#include <array>
#include <print>

using namespace statusbar::pcap;

int main()
{
    // 14-byte Ethernet header + small payload.
    std::array<uint8_t, 20> frame{
        0x00,0x11,0x22,0x33,0x44,0x55, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x08,0x00, 'H','i','!',0,0,0};
    {
        auto writer = FileWriter::open("/tmp/example.pcap");
        if (!writer) {
            return 1;
        }
        (void)writer->write_packet(1'000'000ULL, frame);  // span overload, 1s
        writer->flush();
    }
    // Timestamps come back relative to the first packet.
    auto reader = FileReader::open("/tmp/example.pcap");
    if (!reader) {
        return 1;
    }
    uint64_t ts_us = 0;
    Packet pkt;
    // read_packet returns StatusValue<bool>: success(true) = packet read,
    // success(false) = clean EOF, failure = read error. Check the value,
    // not just the status, or the loop never terminates.
    while (true) {
        auto more = reader->read_packet(&ts_us, pkt);
        if (!more || !*more) {
            break;
        }
        std::println("ts={}us size={}", ts_us, pkt.size());
    }
}
```

## Headers

- `statusbar/pcap/pcap.hpp` — module header; pulls in everything below.
- `statusbar/pcap/pcap_base.hpp` — `Packet`, `FileHeader`, `RecordHeader`, magic numbers, `swap_bytes`, `FilePtr`, `make_file`, `get_current_time_in_microseconds`.
- `statusbar/pcap/pcap_reader.hpp` / `pcap_writer.hpp` — `FileReader` / `FileWriter` plus the `FileReader` overload of `for_each_packet`.
- `statusbar/pcap/pcapng_base.hpp` — pcapng enums, block-body structs, `swap_bytes16` / `swap_bytes32` / `swap_bytes64`, `align_to_4`.
- `statusbar/pcap/pcapng_reader.hpp` / `pcapng_writer.hpp` — `PcapngReader`, `InterfaceInfo`, `PcapngFileWriter`.
- `statusbar/pcap/pcap_replay.hpp` — `ReplayEvent`, `ReplayTime`, `PcapReplayDriver`.

## Dependencies

- **Statusbar modules:** [`ieee`](IEEE_MODULE.md) (`Eui48`, `EthernetFrame` parsing); [`buffer`](BUFFER_MODULE.md) (helpers used inside the readers/writers).
- **System / external:** C stdio (`<cstdio>` — `fopen`/`fread`/`fwrite`), `<chrono>`, `<span>`, `<memory_resource>` (PMR allocator for the pcapng interface table). **No `libpcap`.**

## Notes & caveats

- No header or link dependency on system libpcap — `grep '#include' statusbar/pcap/*.{hpp,cpp}` shows no `pcap.h` / `pcap/pcap.h`; the formats are reimplemented from spec.
- Error reporting is via `statusbar::Status` / `StatusValue` with `PcapError` codes — nothing throws. Constructors are private; open files through the static `open()` factories (`FileReader::open`, `FileWriter::open`, `PcapngReader::open`), which return `StatusValue<T>`. `read_packet` returns `StatusValue<bool>`: `success(true)` = packet read, `success(false)` = clean EOF, `failure(...)` = read error — test the contained `bool`, not just the status.
- `FileWriter` opens existing files in **append mode** — *adds* frames to existing captures. `PcapngFileWriter` **truncates** on construction.
- `FileWriter::write_packet` silently drops frames smaller than 14 bytes. See the `write_too_small_ignored` test.
- Reader timestamps are relative to the first packet — `read_packet` returns `0` for the first call, then deltas. Don't expect Unix-epoch microseconds out.
- `PcapngReader` only parses SHB, IDB, EPB, SPB; NRB / ISB / DSB / custom blocks are skipped.
- `PcapngFileWriter` always writes one Ethernet IDB in native byte order; readers use the SHB magic for endianness.
- `ReplayEvent::payload` aliases driver-owned storage that is invalidated on the next iteration — copy if you need to keep it.
- `pcap_dump_tool.cpp` is a small command-line dumper executable, not part of the library surface.

## Further reading

- [`ieee`](IEEE_MODULE.md) — `Eui48` / `EthernetFrame` used by the component overloads and `ReplayEvent`.
- [`buffer`](BUFFER_MODULE.md) — helpers used inside the readers.
- [`netdump`](NET_MODULE.md) — on-wire capture / dump utilities.
