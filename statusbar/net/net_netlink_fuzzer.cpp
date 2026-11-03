// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the netlink reply parsers: arbitrary bytes must not crash or read out of bounds.
/// The first two input octets are the request's flags and size for ack_status; the rest is the message.

#include "statusbar/net/net_netlink.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include <linux/netlink.h>

namespace {
uint64_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    namespace netlink = statusbar::net::netlink;
    auto const input = std::span<uint8_t const>(data, size);
    if (input.size() < 2) {
        return 0;
    }
    auto const message = input.subspan(2);
    std::string text;
    auto const flags = static_cast<uint16_t>(input[0] << 4U);  // NLM_F_CAPPED and NLM_F_ACK_TLVS among them
    g_sink = g_sink + (netlink::ack_status(message, flags, input[1], text) ? 1U : 0U) + text.size();
    g_sink = g_sink + (netlink::dump_status(message) ? 1U : 0U);
    for (uint16_t const type : {uint16_t{NLMSG_ERROR}, uint16_t{NLMSG_DONE}}) {
        if (auto const end = netlink::end_status(message, type, flags, input[1], text); end) {
            g_sink = g_sink + (*end ? 1U : 0U);
        }
    }
    if (auto const found = netlink::find_attribute(message, input[1]); found && *found) {
        g_sink = g_sink + (*found)->size();
    }
    return 0;
}
