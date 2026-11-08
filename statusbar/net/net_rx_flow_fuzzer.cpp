// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for the ETHTOOL_GRXCLSRULE reply decoder: rule_of on an arbitrary
/// ethtool_rx_flow_spec must not crash, and a rule it reads cleanly must encode back to itself.

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/net/net_rx_flow.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    using namespace statusbar::net;
    auto const input = std::span<uint8_t const>(data, size);
    ethtool_rx_flow_spec spec{};
    if (input.size() < sizeof(spec)) {
        return 0;
    }
    statusbar::span_copy(statusbar::make_span(spec), input.first<sizeof(spec)>());
    auto const rule = detail::rule_of(spec);
    if (!rule.other_fields && detail::rule_of(detail::flow_spec_of(rule)) != rule) {
        std::abort();
    }
    return 0;
}
