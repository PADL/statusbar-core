// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_ethtool_stats.hpp"

#include "statusbar/buffer/span_utils.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <linux/ethtool.h>
#endif

namespace statusbar::net {

auto parse_stat_names(std::span<uint8_t const> const blob, size_t const count) -> StatusValue<std::vector<std::string>>
{
    if (blob.size() / ETHTOOL_STAT_NAME_SIZE < count) {
        return failure(std::make_error_code(std::errc::bad_message));
    }
    std::vector<std::string> names;
    names.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        auto const field = as_string_view(blob.subspan(i * ETHTOOL_STAT_NAME_SIZE, ETHTOOL_STAT_NAME_SIZE));
        names.emplace_back(field.substr(0, field.find('\0')));
    }
    return names;
}

namespace {

/// `text`, all of it, as a decimal queue number.
auto queue_number(std::string_view const text) noexcept -> std::optional<uint32_t>
{
    uint32_t value = 0;
    auto const [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

/// The queue number between `prefix` and `suffix` of `name`.
auto between(std::string_view const name, std::string_view const prefix, std::string_view const suffix) noexcept
    -> std::optional<uint32_t>
{
    if (name.size() <= prefix.size() + suffix.size() || !name.starts_with(prefix) || !name.ends_with(suffix)) {
        return std::nullopt;
    }
    return queue_number(name.substr(prefix.size(), name.size() - prefix.size() - suffix.size()));
}

/// Each driver family's name for a queue's packets: the prefix after "rx"/"tx", and the suffix.
struct QueueStatPattern
{
    std::string_view prefix;
    std::string_view suffix;
};
constexpr std::array<QueueStatPattern, 3> QUEUE_STAT_PATTERNS{{
    {.prefix = "_queue_", .suffix = "_packets"},
    {.prefix = "-", .suffix = ".packets"},
    {.prefix = "", .suffix = "_packets"},
}};

/// `name`'s queue in one direction, under any of the patterns.
auto queue_in(std::string_view const name, std::string_view const direction) noexcept -> std::optional<uint32_t>
{
    if (!name.starts_with(direction)) {
        return std::nullopt;
    }
    for (auto const& pattern : QUEUE_STAT_PATTERNS) {
        if (auto const queue = between(name.substr(direction.size()), pattern.prefix, pattern.suffix)) {
            return queue;
        }
    }
    return std::nullopt;
}

}  // namespace

auto queue_stat_name(std::string_view const name) noexcept -> std::optional<QueueStatName>
{
    if (auto const rx = queue_in(name, "rx")) {
        return QueueStatName{.tx = false, .queue = *rx};
    }
    if (auto const tx = queue_in(name, "tx")) {
        return QueueStatName{.tx = true, .queue = *tx};
    }
    return std::nullopt;
}

auto queue_packets(std::span<EthtoolStat const> const stats) -> std::vector<QueuePackets>
{
    std::vector<QueuePackets> out;
    for (auto const& stat : stats) {
        auto const named = queue_stat_name(stat.name);
        if (!named) {
            continue;
        }
        auto at = std::ranges::find(out, named->queue, &QueuePackets::queue);
        if (at == out.end()) {
            at = out.insert(std::ranges::upper_bound(out, named->queue, {}, &QueuePackets::queue), {.queue = named->queue});
        }
        (named->tx ? at->tx : at->rx) = stat.value;
    }
    return out;
}

#if defined(__linux__)

namespace {

/// struct ethtool_gstrings and struct ethtool_stats before their data.
struct StringsHeader
{
    uint32_t cmd{0};
    uint32_t string_set{0};
    uint32_t len{0};
};
struct StatsHeader
{
    uint32_t cmd{0};
    uint32_t n_stats{0};
};
static_assert(sizeof(StringsHeader) == sizeof(struct ::ethtool_gstrings));
static_assert(sizeof(StatsHeader) == sizeof(struct ::ethtool_stats));

/// Room for a GSTRINGS or GSTATS reply after GDRVINFO reported `count`, which is sent exactly: a kernel with the
/// CVE-2025-68795 fix copies nothing on a mismatch, one without it copies the driver's own count. The extra room
/// covers that growth only up to 2n+64.
[[nodiscard]] constexpr auto stat_capacity(uint32_t const count) noexcept -> size_t
{
    return (size_t{count} * 2) + 64;
}

/// `header` and `payload` zeroed bytes after it through `request`: the buffer as the driver left it, `header`
/// read back from it.
template <typename Header>
[[nodiscard]] auto ethtool_request(EthtoolRequest const& request, Header& header, size_t const payload)
    -> StatusValue<std::vector<uint8_t>>
{
    std::vector<uint8_t> buffer(sizeof(Header) + payload, 0);  // operator new's alignment suits the u64 data
    span_copy(make_span(buffer).first(sizeof(Header)), make_const_span(header));
    if (auto const status = request(make_span(buffer)); !status) {
        return failure(status.error());
    }
    span_copy(make_span(header), make_const_span(buffer).first(sizeof(Header)));
    return buffer;
}

/// How many statistics the driver keeps (ETHTOOL_GDRVINFO's n_stats); never 0.
[[nodiscard]] auto stat_count(EthtoolRequest const& request) -> StatusValue<uint32_t>
{
    ethtool_drvinfo info{};
    info.cmd = ETHTOOL_GDRVINFO;
    if (auto const sent = ethtool_request(request, info, 0); !sent) {
        return failure(sent.error());
    }
    if (info.n_stats == 0) {
        return failure(std::make_error_code(std::errc::operation_not_supported));
    }
    return info.n_stats;
}

/// `resource_unavailable_try_again` unless the reply's count is the one sent (0: a fixed kernel refused it).
[[nodiscard]] auto as_sent(uint32_t const reported, uint32_t const sent) -> Status
{
    return reported == sent ? success() : Status{failure(std::make_error_code(std::errc::resource_unavailable_try_again))};
}

/// The driver's `count` statistic names (ETHTOOL_GSTRINGS of ETH_SS_STATS).
[[nodiscard]] auto stat_names(EthtoolRequest const& request, uint32_t const count) -> StatusValue<std::vector<std::string>>
{
    StringsHeader header{.cmd = ETHTOOL_GSTRINGS, .string_set = ETH_SS_STATS, .len = count};
    auto const buffer = ethtool_request(request, header, stat_capacity(count) * ETHTOOL_STAT_NAME_SIZE);
    auto const same = buffer.and_then([&](auto const&) { return as_sent(header.len, count); });
    if (!same) {
        return failure(same.error());
    }
    return parse_stat_names(make_const_span(*buffer).subspan(sizeof(header)), count);
}

/// The `count` u64 values in an ETHTOOL_GSTATS payload.
auto stat_values_in(std::span<uint8_t const> const payload, uint32_t const count) -> std::vector<uint64_t>
{
    std::vector<uint64_t> values(count);
    for (size_t i = 0; i < count; ++i) {
        span_copy(make_span(values[i]), payload.subspan(i * sizeof(uint64_t), sizeof(uint64_t)));
    }
    return values;
}

/// The driver's `count` statistic values (ETHTOOL_GSTATS).
[[nodiscard]] auto stat_values(EthtoolRequest const& request, uint32_t const count) -> StatusValue<std::vector<uint64_t>>
{
    StatsHeader header{.cmd = ETHTOOL_GSTATS, .n_stats = count};
    auto const buffer = ethtool_request(request, header, stat_capacity(count) * sizeof(uint64_t));
    auto const same = buffer.and_then([&](auto const&) { return as_sent(header.n_stats, count); });
    if (!same) {
        return failure(same.error());
    }
    return stat_values_in(make_const_span(*buffer).subspan(sizeof(header)), count);
}

/// Each name with its value, in the driver's order (both as many).
[[nodiscard]] auto paired(std::vector<std::string> names, std::vector<uint64_t> const& values) -> std::vector<EthtoolStat>
{
    std::vector<EthtoolStat> stats;
    stats.reserve(names.size());
    for (size_t i = 0; i < names.size() && i < values.size(); ++i) {
        stats.push_back({.name = std::move(names[i]), .value = values[i]});
    }
    return stats;
}

/// One reading: the count, then as many names and values, each reply with room past the count.
[[nodiscard]] auto read_stats(EthtoolRequest const& request) -> StatusValue<std::vector<EthtoolStat>>
{
    auto const count = stat_count(request);
    auto names = count.and_then([&](uint32_t const n) { return stat_names(request, n); });
    auto const values = names.and_then([&](auto const&) { return stat_values(request, *count); });
    if (!values) {
        return failure(values.error());
    }
    return paired(std::move(*names), *values);
}

}  // namespace

auto ethtool_stats(EthtoolRequest const& request) -> StatusValue<std::vector<EthtoolStat>>
{
    auto stats = read_stats(request);
    if (stats || stats.error() != std::errc::resource_unavailable_try_again) {
        return stats;
    }
    return read_stats(request);  // the count changed while it was read: once more
}

auto ethtool_stats(std::string_view const interface_name) -> StatusValue<std::vector<EthtoolStat>>
{
    return ethtool_stats(
        [interface_name](std::span<uint8_t> const payload) { return ethtool_ioctl(interface_name, payload.data()); });
}

#else

auto ethtool_stats(std::string_view const /*interface_name*/) -> StatusValue<std::vector<EthtoolStat>>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto ethtool_stats(EthtoolRequest const& /*request*/) -> StatusValue<std::vector<EthtoolStat>>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

#endif

}  // namespace statusbar::net
