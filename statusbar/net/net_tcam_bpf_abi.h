/* Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> */
/* SPDX-License-Identifier: MIT */

/*
 * Shared ABI between the XDP BPF program (xdp_filter.bpf.c) and the
 * userspace installer in net_linux_xdp.cpp. Valid as both C and C++.
 *
 * One rule slot (`struct tcam_rule`) is byte-for-byte identical to
 * statusbar::net::CompiledRule<TCAM_WINDOW_BYTES>; net_xdp_abi_test.cpp
 * asserts this at compile time so the two sides never drift.
 */

#ifndef STATUSBAR_NET_TCAM_BPF_ABI_H
#define STATUSBAR_NET_TCAM_BPF_ABI_H

#ifdef __bpf__
// clang -target bpf defines __LP64__ but not __x86_64__, so on x86_64
// glibc's <gnu/stubs.h> falls through to <gnu/stubs-32.h>, which is
// only shipped with gcc-multilib. Avoid <stdint.h> entirely here and
// reuse the kernel __u8/__u16/__u64 types from <linux/types.h>, which
// the BPF program includes before this header.
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u64 uint64_t;
#elif defined(__cplusplus)
#    include <cstdint>
#else
#    include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Sizing constants exposed as an enum so the macro-usage lint is quiet
 * while still remaining integer-constant-expressions in C. The BPF
 * program's __uint(max_entries, TCAM_MAX_RULES) accepts them just like
 * a #define would. */
enum
{
    /* Window size matched by the BPF program. 32 bytes covers
     * Ethernet + optional VLAN + AVTP common header + Stream ID.
     * Keep in sync with statusbar::net::tcam_default_window_bytes. */
    TCAM_WINDOW_BYTES = 32,

    /* Maximum number of rules the BPF program evaluates per frame.
     * Matches statusbar::net::tcam_default_capacity. */
    TCAM_MAX_RULES = 16,

    /* xsk_map's capacity: one slot per NIC receive queue, keyed by
     * rx_queue_index. Part of the ABI because a pinned map is adopted
     * only when its declared capacity still matches. */
    TCAM_XSK_MAP_ENTRIES = 64,

    /* devmap's capacity. One entry, at key 0. */
    TCAM_DEVMAP_ENTRIES = 1
};

/* One slot in the BPF rules_map. Byte-for-byte identical to
 * statusbar::net::CompiledRule<TCAM_WINDOW_BYTES>.
 *
 * Slot activity is indicated by min_frame_size != 0. The userspace
 * installer zeroes vacant slots; the BPF program treats such a slot
 * as an early-exit sentinel. */
struct tcam_rule
{
    uint8_t mask[TCAM_WINDOW_BYTES];
    uint8_t match[TCAM_WINDOW_BYTES];
    uint64_t result_flags;
    uint16_t min_frame_size;
    uint8_t priority;
    uint8_t _pad;
};

/* Action bits inspected by the BPF program. Must stay aligned with
 * statusbar::net::flag::process/forward_tap/drop — kept as macros
 * because an enum can't portably hold the 1ULL suffix needed for
 * 64-bit bit-flag arithmetic in C.
 *
 * Mutually exclusive, and evaluated in the order DROP, FORWARD_TAP,
 * PROCESS: a rule carrying several gets the first one only. So
 * PROCESS|FORWARD_TAP diverts to the tap and the AF_XDP socket never
 * sees the frame — see verdict_for() in xdp_filter.bpf.c. */

/* NOLINTBEGIN(cppcoreguidelines-macro-usage) */
#define TCAM_FLAG_PROCESS (1ULL << 0)
#define TCAM_FLAG_FORWARD_TAP (1ULL << 1)
#define TCAM_FLAG_DROP (1ULL << 2)
/* NOLINTEND(cppcoreguidelines-macro-usage) */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* STATUSBAR_NET_TCAM_BPF_ABI_H */
