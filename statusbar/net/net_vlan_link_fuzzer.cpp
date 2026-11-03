// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the VLAN link module's netlink acknowledgement
/// parser. The input is one netlink message; parse_ack reads it as an
/// NLMSG_ERROR, finding the extended-ack TLVs after an echoed request whose
/// length the message itself states, or right after the nlmsgerr when the
/// kernel capped it. It may refuse any input; it may not crash or read out
/// of bounds on one. ASan and UBSan are what the run looks for.
///
/// Linux only, as the parser is: elsewhere the harness accepts every input
/// and does nothing.

#include <cstddef>
#include <cstdint>

#if defined(__linux__)

#    include "statusbar/net/net_vlan_link.hpp"

#    include <span>

namespace {
std::uint8_t volatile g_sink = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
    auto const message = std::span<std::uint8_t const>(data, size);
    if (auto const ack = statusbar::net::vlan::parse_ack(message)) {
        for (auto const c : ack->message) {
            g_sink = static_cast<std::uint8_t>(g_sink ^ static_cast<std::uint8_t>(c));
        }
        g_sink = static_cast<std::uint8_t>(g_sink ^ static_cast<std::uint8_t>(ack->error));
    }
    return 0;
}

#else

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* /*data*/, std::size_t /*size*/)
{
    return 0;
}

#endif  // __linux__
