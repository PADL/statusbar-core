// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for parse_ipv4_address and LinkReadiness::apply: arbitrary bytes must not crash or read out of
/// bounds. The first input octet picks the ifindex they expect; the rest is the message.

#include "statusbar/net/net_link_readiness.hpp"

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
    if (auto const change = statusbar::net::parse_ipv4_address(input.subspan(1), input[0]); change && *change) {
        g_sink = g_sink + (*change)->address[3] + ((*change)->added ? 1U : 0U);
    }
    statusbar::net::LinkReadiness link{input[0]};
    (void)link.apply(input.subspan(1), 0);
    g_sink = g_sink + (link.carrier() ? 1U : 0U) + (link.has_ipv4() ? 2U : 0U) + (link.last_qdisc_change_ns() ? 4U : 0U);
    return 0;
}
