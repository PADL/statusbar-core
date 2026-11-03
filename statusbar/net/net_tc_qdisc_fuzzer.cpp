// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the rtnetlink traffic-control reply parsers. The
/// input is one netlink message as the kernel would hand it over, so it is
/// read by both: parse_qdisc, which walks a dump reply's attributes and
/// their option nests (cbs, mqprio) at the lengths the reply itself states,
/// and parse_ack, whose extended-ack offset depends on whether the kernel
/// capped the echoed request. Neither may crash or read out of bounds on
/// any input; either may refuse it. ASan and UBSan are what the run looks
/// for.
///
/// Linux only, as the parsers are: elsewhere the harness accepts every
/// input and does nothing.

#include <cstddef>
#include <cstdint>

#if defined(__linux__)

#    include "statusbar/net/net_tc_qdisc.hpp"

#    include <span>

namespace {

std::uint8_t volatile g_sink = 0;

/// Touch what a parse produced, so the compiler keeps the read and ASan
/// sees the whole of it.
void consume(statusbar::net::tc::QdiscInfo const& info) noexcept
{
    std::uint8_t x = static_cast<std::uint8_t>(info.handle ^ info.parent ^ static_cast<std::uint32_t>(info.ifindex));
    for (auto const c : info.kind_name()) {
        x = static_cast<std::uint8_t>(x ^ static_cast<std::uint8_t>(c));
    }
    if (info.has_cbs_params) {
        x = static_cast<std::uint8_t>(x ^ static_cast<std::uint8_t>(info.cbs.idleslope_kbps));
    }
    if (info.has_mqprio_params) {
        x = static_cast<std::uint8_t>(x ^ info.mqprio.num_tc);
    }
    g_sink = static_cast<std::uint8_t>(g_sink ^ x);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
    using namespace statusbar::net::tc;
    auto const message = std::span<std::uint8_t const>(data, size);

    if (auto const qdisc = parse_qdisc(message)) {
        consume(*qdisc);
    }
    if (auto const ack = parse_ack(message)) {
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
