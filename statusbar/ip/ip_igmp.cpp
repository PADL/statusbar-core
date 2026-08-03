// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ip/ip_igmp.hpp"

#include <string_view>

namespace statusbar::ip {

auto igmp_type_name(uint8_t type) noexcept -> std::string_view
{
    switch (type) {
        case IGMP_TYPE_MEMBERSHIP_QUERY:
            return "Membership Query";
        case IGMP_TYPE_MEMBERSHIP_REPORT_V1:
            return "Membership Report (v1)";
        case IGMP_TYPE_MEMBERSHIP_REPORT_V2:
            return "Membership Report (v2)";
        case IGMP_TYPE_LEAVE_GROUP:
            return "Leave Group";
        case IGMP_TYPE_MEMBERSHIP_REPORT_V3:
            return "Membership Report (v3)";
        default:
            return "Unknown";
    }
}

}  // namespace statusbar::ip
