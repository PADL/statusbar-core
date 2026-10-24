// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rss.hpp"

#include <algorithm>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <system_error>

#    include <linux/ethtool.h>
#    include <linux/sockios.h>
#    include <net/if.h>
#endif

namespace statusbar::net {

auto rss_indirection_all(size_t const size, uint32_t const queue_id) -> RssIndirection
{
    return RssIndirection(size, queue_id);
}

auto rss_steered_to(std::span<uint32_t const> const table, uint32_t const queue_id) noexcept -> bool
{
    return !table.empty() && std::ranges::all_of(table, [queue_id](uint32_t const q) { return q == queue_id; });
}

#if defined(__linux__)

namespace {

// ethtool_rxfh_indir is { cmd, size, ring_index[] }: built as words, header first.
static_assert(sizeof(ethtool_rxfh_indir) == 2 * sizeof(uint32_t));
constexpr size_t RXFH_HEADER_WORDS = 2;

[[nodiscard]] auto rxfh_ioctl(std::string_view const interface_name, std::vector<uint32_t>& request) -> Status
{
    ifreq ifr{};
    set_ifr_data(ifr, request.data());
    return ifreq_ioctl(interface_name, SIOCETHTOOL, ifr);
}

}  // namespace

auto rss_indirection(std::string_view const interface_name) -> StatusValue<RssIndirection>
{
    // A zero size asks for the table's size; then the table itself.
    std::vector<uint32_t> request{ETHTOOL_GRXFHINDIR, 0};
    if (auto status = rxfh_ioctl(interface_name, request); !status) {
        return failure(status.error());
    }
    uint32_t const size = request[1];
    if (size == 0) {
        return failure(std::make_error_code(std::errc::operation_not_supported));
    }
    request.assign(RXFH_HEADER_WORDS + size, 0);
    request[0] = ETHTOOL_GRXFHINDIR;
    request[1] = size;
    if (auto status = rxfh_ioctl(interface_name, request); !status) {
        return failure(status.error());
    }
    return RssIndirection(request.begin() + RXFH_HEADER_WORDS, request.end());
}

auto set_rss_indirection(std::string_view const interface_name, std::span<uint32_t const> const table) -> Status
{
    std::vector<uint32_t> request{ETHTOOL_SRXFHINDIR, static_cast<uint32_t>(table.size())};
    request.insert(request.end(), table.begin(), table.end());
    return rxfh_ioctl(interface_name, request);
}

auto set_rss_indirection_all(std::string_view const interface_name, uint32_t const queue_id) -> StatusValue<RssIndirection>
{
    auto previous = rss_indirection(interface_name);
    if (!previous) {
        return failure(previous.error());
    }
    if (!rss_steered_to(*previous, queue_id)) {
        auto const table = rss_indirection_all(previous->size(), queue_id);
        if (auto status = set_rss_indirection(interface_name, table); !status) {
            return failure(status.error());
        }
    }
    return previous;
}

#endif  // __linux__

}  // namespace statusbar::net
