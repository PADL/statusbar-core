// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the netdev generic-netlink reply parsers: parse_family_id and
/// parse_dev on arbitrary bytes must not crash or read out of bounds. The first two
/// input octets pick the family id parse_dev expects; the rest is the message.

#include "statusbar/net/net_netdev_features.hpp"

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
    if (auto const id = parse_family_id(message)) {
        g_sink = g_sink + *id;
    }
    if (auto const device = parse_dev(message, family_id)) {
        g_sink = g_sink ^ device->xdp_features ^ device->xsk.flags ^ static_cast<uint64_t>(device->ifindex);
    }
    return 0;
}
