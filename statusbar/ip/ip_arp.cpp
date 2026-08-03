// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ip/ip_arp.hpp"

#include <string_view>

namespace statusbar::ip {

auto arp_op_name(uint16_t op) noexcept -> std::string_view
{
    switch (op) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
        case ARP_OP_RARP_REQUEST:
            return "RARP Request";
        case ARP_OP_RARP_REPLY:
            return "RARP Reply";
        default:
            return "Unknown";
    }
}

}  // namespace statusbar::ip
