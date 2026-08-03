// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/tsn/tsn_error.hpp"

#include <string_view>

namespace statusbar::tsn {

auto tsn_error_name(TsnError e) noexcept -> std::string_view
{
    switch (e) {
        case TsnError::attribute_table_full:
            return "attribute table full";
        case TsnError::observer_table_full:
            return "observer table full";
        case TsnError::interesting_table_full:
            return "interesting stream id table full";
        case TsnError::invalid_vlan_id:
            return "invalid VLAN id";
        case TsnError::invalid_stream_id:
            return "invalid stream id";
        case TsnError::invalid_configuration:
            return "invalid TSN configuration";
    }
    return "unknown TSN error";
}

}  // namespace statusbar::tsn
