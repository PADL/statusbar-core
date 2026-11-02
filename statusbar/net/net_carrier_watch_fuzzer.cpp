// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for parse_link_carrier: arbitrary bytes must not crash or read out of bounds.
/// The first input octet picks the ifindex it expects; the rest is the message.

#include "statusbar/net/net_carrier_watch.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {
uint64_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    auto const input = std::span<uint8_t const>(data, size);
    if (input.empty()) {
        return 0;
    }
    if (auto const link = statusbar::net::parse_link_carrier(input.subspan(1), input[0]); link && *link) {
        g_sink = g_sink + (*link)->down_count + ((*link)->carrier ? 1U : 0U);
    }
    return 0;
}
