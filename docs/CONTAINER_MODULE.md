[← back to module index](README.md)

# container

Generic bounded, zero-heap containers used across protocol state machines
and other modules.

## Overview

`container` collects fixed-capacity data structures whose storage is fully
embedded in the object — no heap allocation after construction, no global
allocator dependency, and a compile-time ceiling on size. They are
intended for code paths where allocation is either forbidden (real-time,
interrupt-adjacent) or simply undesirable (small, bounded protocol state).

Two containers ship today, both header-only templates parameterised on
their element type and a compile-time capacity:

- `SlotTable<Entry, MaxN>` — an unordered bag for tracking a small set of
  outstanding work items that are added, searched by predicate, and
  removed in arbitrary order. Removal is O(1) swap-with-last. Backed by
  `statusbar::sg14::inplace_vector`.
- `PresentationSlotMap<Payload, Capacity>` — a time-keyed slot ring where
  each slot owns a quantized timestamp window and one payload.
  Stale-vs-live discrimination happens at read time by comparing the
  requested time's quantized boundary to the slot's stored timestamp;
  there is no sweep or retire step. Backed by `std::array`.

Both types are single-threaded. Neither uses atomics or memory ordering;
if you need cross-thread access, copy out at the boundary.

## Key types

- `SlotTable<Entry, MaxN>` — bounded bag. `add()` returns `bool` (false
  when full). `remove(index)` is O(1) swap-with-last. `find_if(pred)`
  returns `capacity()` as the not-found sentinel. `max_capacity` is the
  compile-time ceiling; the constructor optionally accepts a runtime
  soft cap in `[0, MaxN]` (primarily for tests that want to exercise
  full-slot behaviour at a smaller bound).
- `PresentationSlotMap<Payload, Capacity>` — time-keyed slot ring. The
  slot index for `time_ns` is `(time_ns / slot_width_ns) % Capacity`.
  `store()` overwrites unconditionally; `store_if_absent()` writes only
  if the slot's stored timestamp doesn't already match the requested
  time. `load()` returns `std::optional<Payload>`, populated only when
  the stored timestamp matches the requested time's quantized boundary.
  `empty_slot` (= `INT64_MIN`) is the never-written sentinel; `capacity`
  is the compile-time slot count.

## Quick example

```cpp
#include "statusbar/container/container.hpp"
#include <cstdint>

using namespace statusbar;

int main()
{
    // 8 slots × 1 ms = 8 ms window before wraparound.
    constexpr int64_t kSlotNs = 1'000'000;
    container::PresentationSlotMap<uint32_t, 8> map{kSlotNs};

    map.store(3'000'000, 42);                          // primary
    map.store_if_absent(3'000'000, 99);                // rejected: primary wins
    auto p = map.load(3'500'000);                      // engaged, *p == 42

    map.store(11'000'000, 7);                          // wraps slot for T=3ms
    bool stale = map.has_payload_at(3'000'000);        // false
    (void)p; (void)stale;
    return 0;
}
```

## Headers

- `statusbar/container/container.hpp` — module header. Pulls in every
  container type in the module; this is what consumers should
  `#include`.
- `statusbar/container/container_slot_table.hpp` — `SlotTable`.
- `statusbar/container/container_presentation_slot_map.hpp` —
  `PresentationSlotMap`.

There are no `.cpp` files; the module is header-only.

## Dependencies

- **Statusbar modules:** none. `container` is a leaf module — nothing
  inside it `#include`s another first-party statusbar module.
- **System / external:**
  - `statusbar::sg14::inplace_vector` from
    `statusbar/sg14/inplace_vector.h` — backing storage for `SlotTable`.
  - `<array>`, `<algorithm>`, `<cassert>`, `<cstddef>`, `<cstdint>`,
    `<limits>`, `<optional>`, `<utility>` from the C++ standard library.

> **Convention:** `statusbar/sg14/` holds vendored third-party headers
> with their own [README](../statusbar/sg14/README.md); it is *not* a
> first-party statusbar module. The types there live in the
> `statusbar::sg14::` namespace only to avoid colliding with any other
> vendored copy of SG14 a downstream consumer might pull in. That is why
> `inplace_vector` appears under "System / external" rather than
> "Statusbar modules" — the same convention is followed in
> [`ARGS_MODULE.md`](ARGS_MODULE.md) for `inplace_function`.

## Notes & caveats

- `SlotTable` indices and pointers are **not stable** across `add` /
  `remove` / `clear`. Removal swaps the last entry into the removed
  slot, so both change identity. Don't cache an index across mutations.
- `SlotTable::find_if` returns `capacity()` (the runtime soft cap), not
  `size()`, as its not-found sentinel — so `index >= table.capacity()`
  is a uniform not-found check whether or not a soft cap was set.
- `SlotTable::operator[]` is unchecked; use `get(index)` for a nullable
  pointer if the index might be out of range.
- `PresentationSlotMap` is read-side stale-aware: there is no separate
  retire/sweep step. A slot holds whatever was last written until
  overwritten, and `load`/`has_payload_at` check the stored timestamp
  against the requested time's quantized boundary.
- `PresentationSlotMap` requires `slot_width_ns > 0` and non-negative
  `time_ns` (debug-asserted). Real presentation times in the codebase
  are gPTP / unix nanoseconds and always positive.
- The ring covers exactly `slot_width_ns * Capacity` ns before index
  reuse. Choose `Capacity` so the consumer's worst-case lag plus the
  producer's worst-case lead fit inside that window.
- `store()` is the canonical write; `store_if_absent()` is the
  fallback-source write that must not displace a primary that already
  arrived for the same quantized time.
- `live_count()` is a linear scan intended for tests and diagnostics —
  not the hot path.

## Further reading

- [`statusbar/sg14/README.md`](../statusbar/sg14/README.md) — vendored
  `inplace_vector` / `inplace_function` headers and import provenance.
