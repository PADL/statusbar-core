// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ip/ip_icmpv6.hpp"

#include <string_view>

namespace statusbar::ip {

auto icmpv6_type_name(uint8_t type) noexcept -> std::string_view
{
    switch (type) {
        case ICMPV6_TYPE_DEST_UNREACHABLE:
            return "Destination Unreachable";
        case ICMPV6_TYPE_PACKET_TOO_BIG:
            return "Packet Too Big";
        case ICMPV6_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMPV6_TYPE_PARAMETER_PROBLEM:
            return "Parameter Problem";
        case ICMPV6_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMPV6_TYPE_MLD_QUERY:
            return "MLD Query";
        case ICMPV6_TYPE_MLD_REPORT:
            return "MLD Report";
        case ICMPV6_TYPE_MLD_DONE:
            return "MLD Done";
        case ICMPV6_TYPE_MLDV2_REPORT:
            return "MLDv2 Report";
        case ICMPV6_TYPE_ROUTER_SOLICITATION:
            return "Router Solicitation";
        case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
            return "Router Advertisement";
        case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
            return "Neighbor Solicitation";
        case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
            return "Neighbor Advertisement";
        case ICMPV6_TYPE_REDIRECT:
            return "Redirect";
        default:
            return "Unknown";
    }
}

}  // namespace statusbar::ip
