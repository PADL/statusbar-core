// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>

// XDP TCAM classifier for AF_XDP lockless polling.
// Matches the first TCAM_WINDOW_BYTES bytes of each frame against a
// bounded table of (mask, match) rules, first-match-wins, and maps the
// matching rule's system flag bits to an XDP verdict.
//
// The rule slot layout and flag bits are shared with userspace via
// net_tcam_bpf_abi.h.
//
// Compiled with: clang -target bpf -O2 -g -c xdp_filter.bpf.c -o xdp_filter.bpf.o

#include <linux/bpf.h>
#include <linux/types.h>

// linux headers must come before the bpf helpers.
#include "net_tcam_bpf_abi.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Rules table. Userspace writes the rules into slots 0..N-1 and zeroes
// the rest; the first slot with min_frame_size == 0 is the end of the
// table, where the evaluator stops.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TCAM_MAX_RULES);
    __type(key, __u32);
    __type(value, struct tcam_rule);
} rules_map SEC(".maps");

// XSK redirect map — keyed by rx_queue_index, populated by the
// userspace XDP context after binding its AF_XDP socket.
struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

// DEVMAP for TAP-style forwarding (single entry at key 0).
struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} devmap SEC(".maps");

static __always_inline int verdict_for(struct xdp_md* ctx, __u64 flags)
{
    if (flags & TCAM_FLAG_DROP) {
        return XDP_DROP;
    }
    if (flags & TCAM_FLAG_FORWARD_TAP) {
        return bpf_redirect_map(&devmap, 0, XDP_PASS);
    }
    if (flags & TCAM_FLAG_PROCESS) {
        return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_filter_prog(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (data + TCAM_WINDOW_BYTES > data_end) {
        // Frame shorter than the TCAM window; pass it up to the stack
        // rather than drop so ARP, MLD, etc. keep working.
        return XDP_PASS;
    }

    __u64 const frame_size = (__u64)((long)data_end - (long)data);

    __u64 w[TCAM_WINDOW_BYTES / 8];
    __builtin_memcpy(w, data, TCAM_WINDOW_BYTES);

#pragma unroll
    for (__u32 i = 0; i < TCAM_MAX_RULES; i++) {
        __u32 key = i;
        struct tcam_rule* r = bpf_map_lookup_elem(&rules_map, &key);
        if (!r) {
            continue;  // Verifier-required NULL check; array maps never actually return NULL for in-range keys.
        }
        if (r->min_frame_size == 0) {
            break;  // The first vacant slot: the installer fills slots 0..N-1 and zeroes the rest.
        }
        if (frame_size < r->min_frame_size) {
            continue;  // Frame too short for this rule.
        }

        __u64 m[TCAM_WINDOW_BYTES / 8];
        __u64 c[TCAM_WINDOW_BYTES / 8];
        __builtin_memcpy(m, r->mask, TCAM_WINDOW_BYTES);
        __builtin_memcpy(c, r->match, TCAM_WINDOW_BYTES);

        if (((w[0] & m[0]) == c[0]) && ((w[1] & m[1]) == c[1]) && ((w[2] & m[2]) == c[2]) && ((w[3] & m[3]) == c[3])) {
            return verdict_for(ctx, r->result_flags);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
