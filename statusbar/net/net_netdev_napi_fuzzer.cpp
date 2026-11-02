// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the netdev queue and NAPI reply parsers: parse_queue and parse_napi on
/// arbitrary bytes must not crash or read out of bounds. The first two input octets pick the
/// family id both expect; the rest is the message.

#include "statusbar/net/net_netdev_napi.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {
uint64_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    using namespace statusbar::net::netdev;
    auto const input = std::span<uint8_t const>(data, size);
    if (input.size() < 2) {
        return 0;
    }
    auto const family_id = static_cast<uint16_t>(input[0] | (input[1] << 8U));
    auto const message = input.subspan(2);
    if (auto const queue = parse_queue(message, family_id)) {
        g_sink = g_sink + queue->id + queue->napi_id.value_or(0);
    }
    if (auto const napi = parse_napi(message, family_id)) {
        g_sink = g_sink ^ napi->id ^ napi->pid.value_or(0) ^ static_cast<uint64_t>(napi->threaded.value_or(NapiThreaded::disabled));
    }
    return 0;
}
