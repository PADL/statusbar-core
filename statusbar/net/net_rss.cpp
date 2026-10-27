// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rss.hpp"

#include <algorithm>
#include <system_error>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <linux/ethtool.h>
#    include <linux/sockios.h>
#    include <net/if.h>
#endif

namespace statusbar::net {

namespace detail {

auto make_steered_table(size_t const entries, uint32_t const queue_id) -> RssIndirection
{
    return RssIndirection(entries, queue_id);
}

auto is_steered_to(std::span<uint32_t const> const table, uint32_t const queue_id) noexcept -> bool
{
    return !table.empty() && std::ranges::all_of(table, [queue_id](uint32_t const queue) { return queue == queue_id; });
}

auto plan_rss_steer(std::span<uint32_t const> const current, uint32_t const rx_queues, uint32_t const queue_id)
    -> StatusValue<RssSteerPlan>
{
    if (current.empty()) {
        return failure(std::make_error_code(std::errc::operation_not_supported));
    }
    // rx_queues == 0 means the NIC would not say how many it has; the driver's
    // own check is then all there is.
    if (rx_queues != 0 && queue_id >= rx_queues) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    RssSteerPlan plan{.previous = RssIndirection(current.begin(), current.end()), .wanted = std::nullopt};
    if (!is_steered_to(current, queue_id)) {
        plan.wanted = make_steered_table(current.size(), queue_id);
    }
    return plan;
}

}  // namespace detail

#if defined(__linux__)

namespace {

// ethtool_rxfh_indir is { __u32 cmd; __u32 size; __u32 ring_index[]; }. It is
// built as a vector of words rather than a byte buffer and a cast: the words
// are the layout, and a word vector is correctly aligned by construction.
static_assert(sizeof(ethtool_rxfh_indir) == 2 * sizeof(uint32_t));
constexpr size_t IndirHeaderWords = 2;

/// Hand `words` to SIOCETHTOOL as the ifr_data payload.
[[nodiscard]] auto ethtool_words(std::string_view const interface_name, std::vector<uint32_t>& words) -> Status
{
    ifreq request{};
    set_ifr_data(request, words.data());
    return ifreq_ioctl(interface_name, SIOCETHTOOL, request);
}

/// The interface's RSS indirection table, or operation_not_supported when it
/// has none.
[[nodiscard]] auto read_rss_indirection(std::string_view const interface_name) -> StatusValue<RssIndirection>
{
    // A size of 0 asks only how large the table is; then it is asked for again
    // with room to hold it.
    std::vector<uint32_t> words{ETHTOOL_GRXFHINDIR, 0};
    if (auto const status = ethtool_words(interface_name, words); !status) {
        return failure(status.error());
    }
    auto const entries = words[1];
    if (entries == 0) {
        return failure(std::make_error_code(std::errc::operation_not_supported));
    }

    words.assign(IndirHeaderWords + entries, 0);
    words[0] = ETHTOOL_GRXFHINDIR;
    words[1] = entries;
    if (auto const status = ethtool_words(interface_name, words); !status) {
        return failure(status.error());
    }
    return RssIndirection(words.begin() + IndirHeaderWords, words.end());
}

/// How many RX queues the interface has, or 0 if it would not say. Not an
/// error: the count is only used to refuse a queue that cannot exist, and a
/// driver that will not report it still checks the write itself.
[[nodiscard]] auto read_rx_queue_count(std::string_view const interface_name) -> uint32_t
{
    ethtool_rxnfc rings{};
    rings.cmd = ETHTOOL_GRXRINGS;
    ifreq request{};
    set_ifr_data(request, &rings);
    if (auto const status = ifreq_ioctl(interface_name, SIOCETHTOOL, request); !status) {
        return 0;
    }
    // data is a __u64; a queue count that does not fit in 32 bits is not a
    // thing, and clamping keeps the comparison honest if one ever appears.
    return rings.data > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(rings.data);
}

}  // namespace

auto set_rss_indirection(std::string_view const interface_name, std::span<uint32_t const> const table) -> Status
{
    std::vector<uint32_t> words(IndirHeaderWords + table.size(), 0);
    words[0] = ETHTOOL_SRXFHINDIR;
    words[1] = static_cast<uint32_t>(table.size());
    std::ranges::copy(table, words.begin() + IndirHeaderWords);
    return ethtool_words(interface_name, words);
}

auto set_rss_indirection_all(std::string_view const interface_name, uint32_t const queue_id) -> StatusValue<RssIndirection>
{
    auto current = read_rss_indirection(interface_name);
    if (!current) {
        return failure(current.error());
    }
    auto plan = detail::plan_rss_steer(*current, read_rx_queue_count(interface_name), queue_id);
    if (!plan) {
        return failure(plan.error());
    }
    if (plan->wanted.has_value()) {
        if (auto const status = set_rss_indirection(interface_name, *plan->wanted); !status) {
            return failure(status.error());
        }
    }
    return plan->previous;
}

#else  // !__linux__

auto set_rss_indirection(std::string_view const, std::span<uint32_t const>) -> Status
{
    // ethtool's indirection table is a Linux interface; no BSD equivalent is
    // exposed to userspace.
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto set_rss_indirection_all(std::string_view const, uint32_t const) -> StatusValue<RssIndirection>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

#endif  // __linux__

}  // namespace statusbar::net
