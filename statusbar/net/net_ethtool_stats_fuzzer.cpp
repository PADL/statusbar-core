// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the driver statistics' names: parse_stat_names on arbitrary bytes, then each
/// name through queue_packets, must not crash or read out of bounds. The first octet is the name count.

#include "statusbar/net/net_ethtool_stats.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {
uint64_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    using namespace statusbar::net;
    auto const input = std::span<uint8_t const>(data, size);
    if (input.empty()) {
        return 0;
    }
    auto const names = parse_stat_names(input.subspan(1), input[0]);
    if (!names) {
        return 0;
    }
    std::vector<EthtoolStat> stats;
    for (auto const& name : *names) {
        stats.push_back({.name = name, .value = name.size()});
    }
    for (auto const& queue : queue_packets(stats)) {
        g_sink = g_sink + queue.queue + queue.rx.value_or(0) + queue.tx.value_or(0);
    }
    return 0;
}
