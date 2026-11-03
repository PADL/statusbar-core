// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the tc reply parsers (parse_qdisc with its cbs, mqprio and etf options, and
/// parse_ack): arbitrary bytes must not crash or read out of bounds.

#include "statusbar/net/net_tc_qdisc.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {
uint64_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    namespace tc = statusbar::net::tc;
    auto const message = std::span<uint8_t const>(data, size);
    if (auto const info = tc::parse_qdisc(message); info) {
        g_sink = g_sink + info->handle + info->kind_name().size() + static_cast<uint64_t>(info->etf.delta_ns) +
            (info->has_etf_params ? 1U : 0U) + (info->has_cbs_params ? 1U : 0U) + info->mqprio.num_tc;
    }
    if (auto const ack = tc::parse_ack(message); ack) {
        g_sink = g_sink + static_cast<uint64_t>(ack->error) + ack->message.size();
    }
    return 0;
}
