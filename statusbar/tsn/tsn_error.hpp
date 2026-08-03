#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

//
// TSN / MRP error codes
//
// Covers failure modes specific to the local-endpoint MRP/MSRP/MVRP
// implementation — primarily capacity-related errors stemming from the
// fixed-size attribute and observer tables configured at construction
// time via MsrpConfig / MvrpConfig.
//

#include "statusbar/status/status.hpp"

#include <string>
#include <string_view>
#include <system_error>

namespace statusbar::tsn {

enum class TsnError
{
    attribute_table_full = 1,  ///< local declare_*/create failed: the
                               ///< attribute-type table is at its configured
                               ///< max capacity
    observer_table_full,       ///< subscribe() failed: observer slot table full
    interesting_table_full,    ///< add_interesting_stream_id() failed: set at max
    invalid_vlan_id,           ///< VID outside the [1, 4094] range
    invalid_stream_id,         ///< zero / reserved StreamId used as key
    invalid_configuration,     ///< config struct violates an invariant
};

/// Get human-readable name for TsnError
[[nodiscard]] auto tsn_error_name(TsnError e) noexcept -> std::string_view;

/// Error category for TSN errors
class TsnErrorCategory : public std::error_category
{
  public:
    [[nodiscard]] auto name() const noexcept -> char const* override { return "statusbar.tsn"; }

    [[nodiscard]] auto message(int ev) const -> std::string override
    {
        return std::string{tsn_error_name(static_cast<TsnError>(ev))};
    }
};

/// Get the TSN error category singleton
[[nodiscard]] inline auto tsn_error_category() noexcept -> std::error_category const&
{
    static TsnErrorCategory const category;
    return category;
}

/// Create an error_code from a TsnError
[[nodiscard]] inline auto make_error_code(TsnError e) noexcept -> std::error_code
{
    return std::error_code{static_cast<int>(e), tsn_error_category()};
}

}  // namespace statusbar::tsn

template <>
struct std::is_error_code_enum<statusbar::tsn::TsnError> : std::true_type
{};
