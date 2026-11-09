// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The statistic names' parser and the per-queue counter names, on crafted payloads; the ioctl
// itself only by its refusals, as no host here has a NIC with per-queue counters.

#include "statusbar/net/net_ethtool_stats.hpp"

#include "statusbar/test/test.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// An ETHTOOL_GSTRINGS payload holding `names`, each NUL-padded to its field.
auto blob_of(std::vector<std::string_view> const& names) -> std::vector<uint8_t>
{
    std::vector<uint8_t> blob(names.size() * ETHTOOL_STAT_NAME_SIZE, 0);
    for (size_t i = 0; i < names.size(); ++i) {
        std::copy(names[i].begin(), names[i].end(), blob.begin() + static_cast<std::ptrdiff_t>(i * ETHTOOL_STAT_NAME_SIZE));
    }
    return blob;
}

}  // namespace

TEST(net_ethtool_stats, names_end_at_their_first_nul)
{
    auto const names = parse_stat_names(blob_of({"rx_packets", "tx_queue_0_packets"}), 2);
    EXPECT_TRUE(names.has_value());
    EXPECT_TRUE(names && *names == (std::vector<std::string>{"rx_packets", "tx_queue_0_packets"}));
}

TEST(net_ethtool_stats, a_full_width_name_is_kept_whole)
{
    std::string const wide(ETHTOOL_STAT_NAME_SIZE, 'x');
    auto const names = parse_stat_names(blob_of({wide}), 1);
    EXPECT_TRUE(names && names->front() == wide);
}

TEST(net_ethtool_stats, a_short_payload_is_a_bad_message)
{
    auto const names = parse_stat_names(blob_of({"rx_packets"}), 2);
    EXPECT_FALSE(names.has_value());
    EXPECT_TRUE(names.error_or(std::error_code{}) == std::errc::bad_message);
}

TEST(net_ethtool_stats, each_drivers_queue_counter_names_are_recognised)
{
    EXPECT_TRUE((queue_stat_name("rx_queue_3_packets") == QueueStatName{.tx = false, .queue = 3}));
    EXPECT_TRUE((queue_stat_name("tx_queue_12_packets") == QueueStatName{.tx = true, .queue = 12}));
    EXPECT_TRUE((queue_stat_name("rx-1.packets") == QueueStatName{.tx = false, .queue = 1}));
    EXPECT_TRUE((queue_stat_name("tx-0.packets") == QueueStatName{.tx = true, .queue = 0}));
    EXPECT_TRUE((queue_stat_name("rx7_packets") == QueueStatName{.tx = false, .queue = 7}));
}

TEST(net_ethtool_stats, other_counters_are_not_queue_counters)
{
    EXPECT_FALSE(queue_stat_name("rx_packets").has_value());
    EXPECT_FALSE(queue_stat_name("rx_queue_0_bytes").has_value());
    EXPECT_FALSE(queue_stat_name("rx_queue__packets").has_value());
    EXPECT_FALSE(queue_stat_name("tx_queue_x_packets").has_value());
    EXPECT_FALSE(queue_stat_name("rx_queue_0_restart_packets").has_value());
    EXPECT_FALSE(queue_stat_name("").has_value());
}

TEST(net_ethtool_stats, queue_packets_are_gathered_by_queue)
{
    std::vector<EthtoolStat> const stats{
        {.name = "rx_packets", .value = 99},
        {.name = "tx_queue_1_packets", .value = 20},
        {.name = "rx_queue_1_packets", .value = 10},
        {.name = "rx_queue_0_packets", .value = 5},
    };
    auto const queues = queue_packets(stats);
    EXPECT_EQ(queues.size(), size_t{2});
    EXPECT_TRUE((queues.at(0) == QueuePackets{.queue = 0, .rx = 5, .tx = std::nullopt}));
    EXPECT_TRUE((queues.at(1) == QueuePackets{.queue = 1, .rx = 10, .tx = 20}));
}

TEST(net_ethtool_stats, a_driver_without_queue_counters_gives_none)
{
    std::vector<EthtoolStat> const stats{{.name = "rx_packets", .value = 1}, {.name = "tx_packets", .value = 2}};
    EXPECT_TRUE(queue_packets(stats).empty());
}

TEST(net_ethtool_stats, an_unknown_interface_fails)
{
    auto const stats = ethtool_stats("nosuchif0");
    EXPECT_FALSE(stats.has_value());
}

TEST_MAIN(statusbar_net, net_ethtool_stats_test)
