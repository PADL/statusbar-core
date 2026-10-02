[← back to module index](README.md)

# checksum

Header-only integrity arithmetic shared by the protocol stacks: the
ones-complement 16-bit "Internet checksum" of RFC 1071, and a
compile-time-tabled reflected CRC-32 with the IEEE 802.3 and AUTOSAR
CRC32P4 parameter sets ready-made.

## Overview

The `checksum` module (namespace `statusbar::checksum`) has no
dependencies beyond the standard library and every routine is
`constexpr`, so a checksum or CRC of a constant wire image can be a
`static_assert`. It exists so that the IPv4/ICMP/IGMP/UDP header
checksums and the IEEE 1722-2025 ACF_CHECKSUM / ACF_CRC messages
(Clause 9.4.20 and 9.4.21) share one implementation instead of each
protocol carrying its own fold loop.

## Key types

- `ones_complement_fold(uint32_t sum) -> uint16_t` — end-around-carry
  fold of a running sum to 16 bits.
- `ones_complement_sum16(std::span<uint8_t const> data, uint32_t initial = 0) -> uint16_t`
  — sums big-endian 16-bit words; an odd trailing octet is the high
  octet of a zero-padded final word. `initial` carries the folded sum of
  preceding pieces so a message can be summed piecewise (every piece but
  the last must be even-length).
- `internet_checksum16(data) -> uint16_t` — the checksum *field value*:
  the ones-complement of the sum, computed with the field itself zeroed.
- `internet_checksum_ok(data_with_checksum) -> bool` — true when the sum
  over data that carries its checksum field is `0xFFFF`.
- `Crc32Reflected<ReflectedPoly, Init, XorOut>` — a reflected
  (LSB-first) CRC-32 parameter set with a 256-entry table generated at
  compile time. `update(data, state = Init)` advances the register (chain
  calls to CRC piecewise), `finalize(state)` applies the xor-out, and
  `compute(data)` does both.
- `Crc32Ethernet` — IEEE 802.3 FCS: polynomial 0x04C11DB7 (reflected
  0xEDB88320), init/xor-out 0xFFFFFFFF; check `"123456789"` → `0xCBF43926`.
- `Crc32P4` — AUTOSAR CRC32P4: polynomial 0xF4ACFB13 (reflected
  0xC8DF352F), init/xor-out 0xFFFFFFFF; check `"123456789"` → `0x1697D06A`.
- `crc32_ethernet(data)`, `crc32_p4(data)` — one-call conveniences.

## Usage

```cpp
#include "statusbar/checksum/checksum_crc32.hpp"
#include "statusbar/checksum/checksum_ones_complement.hpp"

using namespace statusbar::checksum;

// A UDP-style header: zero the field, compute, store.
header.checksum = internet_checksum16(span_of(header));
// ... on receive:
bool const intact = internet_checksum_ok(received_bytes);

// IEEE 1722 ACF_CRC trailer for the preceding ACF message:
uint32_t const fcs = crc32_ethernet(preceding_message_bytes);

// Piecewise, e.g. header then payload from separate buffers:
auto state = Crc32P4::update(header_bytes);
state = Crc32P4::update(payload_bytes, state);
uint32_t const crc = Crc32P4::finalize(state);
```

## Notes

- Zero is a legal checksum value here. UDP's "zero means no checksum"
  convention, and ACF_CHECKSUM's "zero is validated like any other
  value", are both policy of the caller; the arithmetic is the same.
- The test suite pins the published check values (the `"123456789"`
  catalogue value for both CRCs, the AUTOSAR specification's seven
  CRC32P4 vectors, the textbook IPv4 header checksum `0xB861`) and the
  piecewise forms against the one-shot forms.
