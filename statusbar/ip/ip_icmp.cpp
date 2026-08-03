// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ip/ip_icmp.hpp"

#include <string_view>

namespace statusbar::ip {

auto icmp_type_name(uint8_t type) noexcept -> std::string_view
{
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACHABLE:
            return "Destination Unreachable";
        case ICMP_TYPE_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_TYPE_REDIRECT:
            return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case ICMP_TYPE_ROUTER_ADVERTISEMENT:
            return "Router Advertisement";
        case ICMP_TYPE_ROUTER_SOLICITATION:
            return "Router Solicitation";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_TYPE_PARAMETER_PROBLEM:
            return "Parameter Problem";
        case ICMP_TYPE_TIMESTAMP_REQUEST:
            return "Timestamp Request";
        case ICMP_TYPE_TIMESTAMP_REPLY:
            return "Timestamp Reply";
        case ICMP_TYPE_INFO_REQUEST:
            return "Info Request";
        case ICMP_TYPE_INFO_REPLY:
            return "Info Reply";
        case ICMP_TYPE_ADDRESS_MASK_REQUEST:
            return "Address Mask Request";
        case ICMP_TYPE_ADDRESS_MASK_REPLY:
            return "Address Mask Reply";
        default:
            return "Unknown";
    }
}

}  // namespace statusbar::ip
