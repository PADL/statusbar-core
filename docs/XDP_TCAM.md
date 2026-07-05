<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->

# XDP TCAM

**Status**: complete. The shared `net_tcam_bpf_abi.h` ABI header, the
userspace `TcamClassifier`
(`statusbar/net/net_tcam_classifier.{hpp,_test.cpp}`), and the
kernel-side TCAM interpreter are all in place: `xdp_filter.bpf.c` reads
`tcam_rule` entries out of `rules_map`, and the userspace loader
installs them via `detail::BpfState::install_tcam_rules(std::span<CompiledRule<32> const>)`
(`net_linux_xdp.cpp`). The pre-migration `filter_key` /
`populate_filter_map` / `XdpFilterRule` machinery described below no
longer exists. The rest of this document is the design and migration
plan as written before the work shipped, kept as the rationale record.

## Migration plan (completed)

Migrate the kernel-side XDP packet classifier (`statusbar/net/xdp_filter.bpf.c`
plus its C++ userspace wrapper) from a hand-rolled semantic-lookup design to
a TCAM interpreter driven by the same `CompiledRule<N>` the userspace
`TcamClassifier` already consumes.

## Context

### Before the migration (two parallel matchers)

- **Userspace:** `statusbar::net::TcamClassifier<N, Capacity>` evaluates
  a `std::span<CompiledRule<N> const>` against the first *N* bytes of a
  frame. First-match-wins, rules produced by a constexpr
  `ClassifierRuleBuilder`.
- **Kernel (XDP):** `xdp_filter.bpf.c` parses the Ethernet/VLAN/IP/UDP
  header, builds a composite `struct filter_key`, and does a hash-map
  lookup per "match profile" (tagged-any, tagged-exact, L3+L4, ...). The
  C++ side populates the map through
  `detail::BpfState::populate_filter_map(std::span<XdpFilterRule const>)`.

The two engines encode the same rule types (`XdpFilterRule` and
`ClassifierRule` carry identical fields) but express matching
differently. Keeping them in sync is a maintenance burden; AVB features
that need MAC or Stream-ID matching cannot be expressed in the current
BPF at all.

### Goal

One rule representation (`CompiledRule<N>`), one semantic builder
(`ClassifierRuleBuilder<N>`), two execution engines that read the same
bytes:

- Userspace `TcamClassifier` — unchanged, already in place.
- Kernel `xdp_filter.bpf.c` — rewritten as a TCAM interpreter that
  reads `CompiledRule`-sized entries out of a BPF array map and runs
  a bounded unrolled loop of *N/8* AND+CMP pairs per rule.

## Design

### Shared ABI header

Create `statusbar/net/net_tcam_bpf_abi.h`, valid C and valid C++,
included by both `xdp_filter.bpf.c` and the userspace installer. Holds
a single struct layout that matches `CompiledRule<32>` byte-for-byte
and a small number of compile-time constants.

```c
// net_tcam_bpf_abi.h  (valid in both C and C++)
#pragma once
#include <stdint.h>

#define TCAM_WINDOW_BYTES 32
#define TCAM_MAX_RULES    16

struct tcam_rule {
    uint8_t  mask[TCAM_WINDOW_BYTES];
    uint8_t  match[TCAM_WINDOW_BYTES];
    uint64_t result_flags;
    uint16_t min_frame_size;
    uint8_t  priority;
    uint8_t  _pad;
};  // 80 bytes (72 + 4 tail fields padded to 8-byte alignment), same as CompiledRule<32>

// Reserved low bits of result_flags interpreted by the BPF program
// itself. Must stay in sync with statusbar::net::flag::* at bits 0..15.
#define TCAM_FLAG_PROCESS      (1ULL << 0)
#define TCAM_FLAG_FORWARD_TAP  (1ULL << 1)
#define TCAM_FLAG_DROP         (1ULL << 2)
```

A `static_assert` in the C++ side proves byte-for-byte identity to
`CompiledRule<32>`.

### Rewritten BPF program

`xdp_filter.bpf.c` becomes:

```c
#include "statusbar/net/net_tcam_bpf_abi.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TCAM_MAX_RULES);
    __type(key, __u32);
    __type(value, struct tcam_rule);
} rules_map SEC(".maps");

// XSKMAP + DEVMAP stay unchanged (used for redirect actions).

SEC("xdp")
int tcam_classify(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;
    if (data + TCAM_WINDOW_BYTES > end) return XDP_PASS;

    __u64 w[TCAM_WINDOW_BYTES / 8];
    __builtin_memcpy(w, data, TCAM_WINDOW_BYTES);

    #pragma unroll
    for (__u32 i = 0; i < TCAM_MAX_RULES; i++) {
        struct tcam_rule *r = bpf_map_lookup_elem(&rules_map, &i);
        if (!r) break;

        __u64 m[4], c[4];
        __builtin_memcpy(m, r->mask,  TCAM_WINDOW_BYTES);
        __builtin_memcpy(c, r->match, TCAM_WINDOW_BYTES);

        if (((w[0] & m[0]) == c[0]) &&
            ((w[1] & m[1]) == c[1]) &&
            ((w[2] & m[2]) == c[2]) &&
            ((w[3] & m[3]) == c[3])) {
            if (r->result_flags & TCAM_FLAG_DROP)        return XDP_DROP;
            if (r->result_flags & TCAM_FLAG_FORWARD_TAP) return bpf_redirect_map(&devmap, 0, XDP_PASS);
            if (r->result_flags & TCAM_FLAG_PROCESS)     return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}
```

Verifier notes:
- `__builtin_memcpy` of exactly 32 bytes lowers to four 64-bit loads;
  acceptable to recent verifiers. If a target kernel rejects it, fall
  back to four explicit `__u64` loads with bounds checks.
- `#pragma unroll` on a bounded loop with `TCAM_MAX_RULES = 16` is
  fine on Linux 5.3+.
- Empty slots break the loop early (`bpf_map_lookup_elem` returns 0
  for uninitialised entries? no — it returns the zeroed struct; use
  a sentinel bit in `result_flags` or check `min_frame_size != 0`
  to detect "inactive rule").

### Userspace wrapper

Replace `XdpFilterRule` / `populate_filter_map` / `update_filter_rules`
with:

```cpp
class XdpTcamInstaller {
  public:
    auto install(std::span<CompiledRule<32> const> rules) -> Status;
};
```

Internally it just does, for each rule *i*:
```cpp
bpf_map_update_elem(rules_map_fd_, &i, &rules[i], BPF_ANY);
```
followed by writing sentinel-zero entries for the remaining slots so
stale rules from a previous install don't match.

`XdpContext::update_filter_rules(std::span<XdpFilterRule const>)` is
deleted; `XdpContext::set_rules(std::span<CompiledRule<32> const>)`
takes its place with the same error-path shape.

### Flag-to-XDP-action mapping

The BPF program inspects only the system-reserved bits
(`flag::SYSTEM_MASK`, bits 0..15) to pick an XDP verdict. The user
slice (bits 16..63) rides through in the map entry but is never
inspected by the kernel — only relevant to userspace readers of the
same rule set. This lets one rule carry both "the action" and "the
tag" the userspace `TcamClassifier` can use when the packet
eventually reaches userspace via XSK.

Mapping:
| Library flag          | XDP verdict                                      |
| --------------------- | ------------------------------------------------ |
| `flag::process`       | `bpf_redirect_map(&xsk_map, rx_queue, XDP_PASS)` |
| `flag::forward_tap`   | `bpf_redirect_map(&devmap, 0, XDP_PASS)`         |
| `flag::drop`          | `XDP_DROP`                                       |
| (no flags set)        | `XDP_PASS`                                       |

## Files

| File | Action | Notes |
| :--- | :----- | :---- |
| `statusbar/net/net_tcam_bpf_abi.h` | **create** | Shared C/C++ ABI struct + action bits. |
| `statusbar/net/xdp_filter.bpf.c` | **rewrite** | TCAM interpreter, ~80 lines (vs 221 today). |
| `statusbar/net/net_linux_xdp.hpp` | **modify** | Delete `XdpFilterRule`; add `set_rules(span<CompiledRule<32> const>)`. |
| `statusbar/net/net_linux_xdp.cpp` | **modify** | Replace `populate_filter_map` with `install_tcam_rules`. |
| `statusbar/net/net_linux_xdp_test.cpp` | **modify** | Rewrite tests to use `ClassifierRuleBuilder<>`. |
| `statusbar/net/net_example_xdp.cpp` | **modify** | Adopt new API. |
| `statusbar/rttest/rttest_send_avtp.cpp` | **modify (if any)** | Any other `XdpFilterRule` caller. |
| `statusbar/net/CMakeLists.txt` | **modify** | No new dep; clang-bpf already wired. |

Estimated net diff: **–150 lines** (the BPF program shrinks by ~100, `XdpFilterRule` and its map-key struct disappear, the installer is shorter).

## Dependencies Re-used (not re-invented)

- `statusbar::net::CompiledRule<32>` — already layout-stable POD.
- `statusbar::net::ClassifierRuleBuilder<>` — already constexpr, produces `CompiledRule<32>` values.
- `statusbar::net::flag::*` — bit-flag contract, already defines system vs user slice.
- `statusbar::net::TcamClassifier<32>` — will naturally consume the same rules in userspace tests/fallback paths.
- libbpf / libxdp detection in `statusbar/net/CMakeLists.txt` — unchanged, Linux-only block.
- BPF toolchain (clang `-target bpf`) — already a build dependency.

## Implementation Phases

1. **ABI header + compile-time equivalence proof.**
   Add `net_tcam_bpf_abi.h`. Add a `static_assert(sizeof(tcam_rule) == sizeof(CompiledRule<32>))` and a `static_assert(offsetof(tcam_rule, match) == offsetof(CompiledRule<32>, match))` in a C++ translation unit that includes both.

2. **Rewrite `xdp_filter.bpf.c` as a TCAM interpreter.**
   Keep the XSKMAP and DEVMAP intact; replace `filter_map` with `rules_map`.

3. **Rewire `net_linux_xdp.cpp`.**
   Delete `populate_filter_map` and `update_filter_rules`, add
   `install_tcam_rules(std::span<CompiledRule<32> const>)` that does a
   direct `bpf_map_update_elem` per rule, zeroes trailing slots, and
   returns `Status`.

4. **Replace `XdpFilterRule` with `CompiledRule<32>` at call sites.**
   Grep for `XdpFilterRule`; every hit either converts to a builder
   expression or feeds a `CompiledRule<32>` span directly.

5. **Delete `XdpFilterRule`.**
   Once call sites compile, the struct is unused; remove it and its
   `populate_filter_map` helper.

6. **Tests.**
   `net_linux_xdp_test.cpp` rewritten to build rules through
   `ClassifierRuleBuilder<>` and pass them to `install_tcam_rules`. Add
   one end-to-end test: craft a frame, run it through both
   `TcamClassifier<32>` in the test process and (on Linux) the loaded
   BPF program via `BPF_PROG_TEST_RUN`, assert they produce the same
   XDP verdict.

## Verification

### Unit tests (platform-independent)

- The existing `net_compiled_rule_test`, `net_tcam_classifier_test`,
  `net_cbpf_emit_test` suites continue to pass — they already verify
  the userspace side of the shared format.
- `net_xdp_abi_test` confirms `tcam_rule` and `CompiledRule<32>`
  have identical layout (struct size + every field offset).

### Linux build

On a machine with libbpf + libxdp + clang-bpf (Debian 13 Trixie or
newer Ubuntu):
```
make build
```
Should pick up the changed `xdp_filter.bpf.c`, recompile it to
`.bpf.o`, re-embed via `#embed` into the userspace binary.

### Linux runtime

```
# Load the program onto a test interface.
sudo statusbar-net-example-xdp veth0 \
  --rule 'ethertype=0x88F7,vlan=any,action=process' \
  --rule 'ethertype=0x22F0,vlan=tagged_exact:2,avtp_subtype=0x02,action=process'

# Replay a pcap of crafted frames into veth0 and watch XDP stats:
sudo xdp-loader stats veth0
```
Expected: counters for "passed to XSK" increment by the number of
matching frames; unrelated frames increase the "passed to kernel"
counter.

### `BPF_PROG_TEST_RUN` (hermetic)

Once the BPF program is loaded, `bpf_prog_test_run_opts` lets us feed
a single frame buffer and receive the XDP return code without any
actual NIC. Pair with a matrix of crafted frames to prove the BPF
program's verdicts match `TcamClassifier<32>::classify_first` frame-
by-frame. This runs as a Linux-only test, guarded behind the same
`LIBBPF_FOUND && LIBXDP_FOUND` CMake block that already gates the XDP
bits.

## Constraints and Open Questions

- **Linux kernel version**: 5.3+ for `__builtin_memcpy` of 32 bytes
  inside a BPF program; earlier kernels need an explicit byte-at-a-
  time or four `__u64` loads. CLAUDE.md suggests this project targets
  Debian 13 Trixie / Raspberry Pi 5 / Fedora 42, all well inside that
  window.

- **Empty rule slots**: the array map always returns a zeroed
  `tcam_rule` for uninitialised indices, which (with zero mask) would
  "match" every frame spuriously. Use `min_frame_size != 0` as the
  "rule active" sentinel — the installer writes 0 there for vacant
  slots and the BPF program treats `min_frame_size == 0` as
  "done, stop iterating". Cheaper than a separate count map.

- **`max_entries` sizing**: `TCAM_MAX_RULES = 16` matches
  `TCAM_DEFAULT_CAPACITY`. Bump if users need more; each entry adds
  80 bytes of map memory.

- **Future: larger windows**: if we later want an XDP path that also
  matches IPv6 UDP destination port, we'd need a second program
  compiled from the same BPF source with `TCAM_WINDOW_BYTES = 64`.
  That's a simple `#define` change plus a second compilation rule in
  CMake. Defer until a callsite actually asks for it.

## Estimated Size / Time

- ~300 lines changed, net -150. Single sitting of focused work.
- Requires a Linux box with libbpf-dev + libxdp-dev + clang-bpf to
  compile and verify. Plan to do the work there once hardware is
  ready.
