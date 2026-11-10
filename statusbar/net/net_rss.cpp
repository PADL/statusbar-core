// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rss.hpp"

#include <algorithm>
#include <system_error>
#include <utility>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <linux/ethtool.h>
#    include <linux/sockios.h>
#    include <net/if.h>
#endif

namespace statusbar::net {

auto rss_indirection_all(size_t const entries, uint32_t const queue_id) -> RssIndirection
{
    return RssIndirection(entries, queue_id);
}

auto rss_steered_to(std::span<uint32_t const> const table, uint32_t const queue_id) noexcept -> bool
{
    return !table.empty() && std::ranges::all_of(table, [queue_id](uint32_t const queue) { return queue == queue_id; });
}

namespace detail {

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
    if (!rss_steered_to(current, queue_id)) {
        plan.wanted = rss_indirection_all(current.size(), queue_id);
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

/// An indirection-table request: the command, the bucket count, and room for
/// that many ring indices. The layout lives here once rather than in each of
/// the three places that builds one.
[[nodiscard]] auto indir_request(uint32_t const cmd, uint32_t const entries) -> std::vector<uint32_t>
{
    std::vector<uint32_t> words(IndirHeaderWords + entries, 0);
    words[0] = cmd;
    words[1] = entries;
    return words;
}

/// How many buckets the table has. A size of 0 in the request asks only for
/// the size; 0 back means the NIC has no RSS at all.
[[nodiscard]] auto read_indirection_size(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    auto words = indir_request(ETHTOOL_GRXFHINDIR, 0);
    if (auto const status = ethtool_words(interface_name, words); !status) {
        return failure(status.error());
    }
    if (words[1] == 0) {
        return failure(std::make_error_code(std::errc::operation_not_supported));
    }
    return words[1];
}

}  // namespace

auto rss_indirection(std::string_view const interface_name) -> StatusValue<RssIndirection>
{
    auto const entries = read_indirection_size(interface_name);
    if (!entries) {
        return failure(entries.error());
    }
    auto words = indir_request(ETHTOOL_GRXFHINDIR, *entries);
    if (auto const status = ethtool_words(interface_name, words); !status) {
        return failure(status.error());
    }
    return RssIndirection(words.begin() + IndirHeaderWords, words.end());
}

auto rx_queue_count(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    ethtool_rxnfc rings{};
    rings.cmd = ETHTOOL_GRXRINGS;
    ifreq request{};
    set_ifr_data(request, &rings);
    if (auto const status = ifreq_ioctl(interface_name, SIOCETHTOOL, request); !status) {
        return failure(status.error());
    }
    // data is a __u64; a queue count that does not fit in 32 bits is not a thing
    return rings.data > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(rings.data);
}

auto set_rss_indirection(std::string_view const interface_name, std::span<uint32_t const> const table) -> Status
{
    auto words = indir_request(ETHTOOL_SRXFHINDIR, static_cast<uint32_t>(table.size()));
    std::ranges::copy(table, words.begin() + IndirHeaderWords);
    return ethtool_words(interface_name, words);
}

auto set_rss_indirection_all(std::string_view const interface_name, uint32_t const queue_id) -> StatusValue<RssIndirection>
{
    auto current = rss_indirection(interface_name);
    if (!current) {
        return failure(current.error());
    }
    auto plan = detail::plan_rss_steer(*current, rx_queue_count(interface_name).value_or(0), queue_id);
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

auto rx_queue_count(std::string_view const) -> StatusValue<uint32_t>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto rss_indirection(std::string_view const) -> StatusValue<RssIndirection>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

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

// ---------------------------------------------------------------------------
// RssSteering
// ---------------------------------------------------------------------------

RssSteering::RssSteering(RssControl& control, std::string_view const interface_name, RssIndirection previous)
    : control_{&control}
    , interface_{interface_name}
    , previous_{std::move(previous)}
{}

RssSteering::RssSteering(RssSteering&& other) noexcept
    : control_{other.control_}
    , interface_{std::move(other.interface_)}
    , previous_{std::move(other.previous_)}
{
    other.release();
}

auto RssSteering::operator=(RssSteering&& other) noexcept -> RssSteering&
{
    if (this != &other) {
        // Whatever this guard still owed is owed on the way out, before it
        // takes on another interface's debt.
        (void)restore();
        control_ = other.control_;
        interface_ = std::move(other.interface_);
        previous_ = std::move(other.previous_);
        other.release();
    }
    return *this;
}

RssSteering::~RssSteering()
{
#if __cpp_exceptions
    try {
#endif
        (void)restore();
#if __cpp_exceptions
    } catch (...) {  // NOLINT(bugprone-empty-catch) a destructor has nobody to report to
    }
#endif
}

auto RssSteering::release() noexcept -> void
{
    control_ = nullptr;
    previous_.clear();
}

auto RssSteering::restorable() const -> Status
{
    auto const current = control_->indirection(interface_);
    if (!current) {
        return failure(current.error());
    }
    if (current->size() != previous_.size()) {
        // The NIC's channel count changed under us. The table we hold no
        // longer describes this NIC, and padding or truncating it to fit
        // would be inventing a layout.
        return failure(std::make_error_code(std::errc::state_not_recoverable));
    }
    return success();
}

auto RssSteering::restore() -> Status
{
    if (control_ == nullptr) {
        return success();
    }
    if (auto const check = restorable(); !check) {
        return failure(check.error());
    }
    if (auto const status = control_->set_indirection(interface_, previous_); !status) {
        // Still owed: a caller who can fix whatever refused the write may try
        // again, and the destructor will.
        return failure(status.error());
    }
    release();
    return success();
}

auto RssSteering::steer(RssControl& control, std::string_view const interface_name, uint32_t const queue_id)
    -> StatusValue<RssSteering>
{
    auto previous = control.steer_all(interface_name, queue_id);
    if (!previous) {
        return failure(previous.error());
    }
    if (rss_steered_to(*previous, queue_id)) {
        // Nothing was written, so nothing is owed. Holding this table would
        // only buy a pointless write - and on some drivers a link reset - at
        // the end of the socket's life.
        return RssSteering{};
    }
    return RssSteering{control, interface_name, std::move(*previous)};
}

}  // namespace statusbar::net
