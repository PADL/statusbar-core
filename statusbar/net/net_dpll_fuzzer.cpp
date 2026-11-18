// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the dpll generic-netlink readers: parse_family,
/// parse_device and parse_pin read a reply at the offsets it states, so
/// arbitrary bytes must never crash them or read out of bounds; any input
/// may be refused. The first two input octets are the family id the device
/// and pin parsers expect, the rest the message.

#include "statusbar/net/net_dpll.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {

std::uint64_t volatile g_sink = 0;

void consume(std::uint64_t const value) noexcept
{
    g_sink = g_sink ^ value;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
    using namespace statusbar::net::dpll;
    auto const input = std::span<std::uint8_t const>(data, size);
    if (input.size() < 2) {
        return 0;
    }
    auto const family_id = static_cast<std::uint16_t>(input[0] | (input[1] << 8U));
    auto const message = input.subspan(2);
    if (auto const family = parse_family(message)) {
        consume(family->id ^ family->monitor_group);
    }
    if (auto const device = parse_device(message, family_id)) {
        consume(device->device.clock_id ^ device->device.id ^ static_cast<std::uint64_t>(device->device.lock_status));
    }
    if (auto const pin = parse_pin(message, family_id)) {
        consume(pin->pin.id ^ pin->pin.clock_id ^ pin->pin.parents.size() ^ pin->pin.frequencies.size());
    }
    return 0;
}
