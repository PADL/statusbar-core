// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The statistic names' parser and the per-queue counter names, on crafted payloads; the reading against
// a pretend driver whose count changes; the ioctl itself only by its refusals.

#include "statusbar/net/net_ethtool_stats.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/test/test.hpp"

#include <cstdint>
#include <format>
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

#if defined(__linux__)

#    include <linux/ethtool.h>

namespace {

/// What a pretend driver reports in one reading: the GDRVINFO count, then the GSTRINGS and GSTATS counts.
struct Reading
{
    uint32_t drvinfo{0};
    uint32_t strings{0};
    uint32_t stats{0};
};

/// The two kernels: with the CVE-2025-68795 fix a count other than the driver's copies nothing and reads
/// back 0; without it the driver's own count is written back, with as many entries as fit (and, in a real
/// kernel, more).
enum class Kernel : uint8_t
{
    fixed,
    unfixed,
};

/// A driver answering GDRVINFO, GSTRINGS and GSTATS with its counts at the time, as `kernel` passes them on.
class StatsRecorder
{
  public:
    StatsRecorder(Kernel const kernel, std::vector<Reading> readings)
        : kernel_{kernel}
        , readings_{std::move(readings)}
    {}

    auto answer(std::span<uint8_t> const payload) -> Status
    {
        uint32_t cmd = 0;
        span_load(cmd, payload);
        if (cmd == ETHTOOL_GDRVINFO) {
            reading_ = readings_.at(drvinfo_calls_++);
            return put_u32(payload, offsetof(ethtool_drvinfo, n_stats), reading_.drvinfo);
        }
        return cmd == ETHTOOL_GSTRINGS ? strings(payload) : stats(payload);
    }

    [[nodiscard]] auto drvinfo_calls() const noexcept -> size_t { return drvinfo_calls_; }
    /// Every count a GSTRINGS or GSTATS request carried.
    [[nodiscard]] auto counts_sent() const noexcept -> std::vector<uint32_t> const& { return sent_; }

  private:
    static auto put_u32(std::span<uint8_t> const payload, size_t const offset, uint32_t const value) -> Status
    {
        span_store(payload.subspan(offset, sizeof(value)), value);
        return success();
    }

    /// The count the kernel copies out for a request of `sent` when the driver has `count`.
    auto copied(std::span<uint8_t> const payload, size_t const offset, uint32_t const count) -> uint32_t
    {
        uint32_t sent = 0;
        span_load(sent, payload.subspan(offset, sizeof(sent)));
        sent_.push_back(sent);
        return kernel_ == Kernel::fixed && sent != count ? 0 : count;
    }

    auto strings(std::span<uint8_t> const payload) -> Status
    {
        auto const data = payload.subspan(sizeof(ethtool_gstrings));
        auto const count = copied(payload, offsetof(ethtool_gstrings, len), reading_.strings);
        for (size_t i = 0; i < count && (i + 1) * ETHTOOL_STAT_NAME_SIZE <= data.size(); ++i) {
            auto const name = std::format("rx_queue_{}_packets", i);
            span_copy(data.subspan(i * ETHTOOL_STAT_NAME_SIZE, name.size()), make_const_span(std::string_view{name}));
        }
        return put_u32(payload, offsetof(ethtool_gstrings, len), count);
    }

    auto stats(std::span<uint8_t> const payload) -> Status
    {
        auto const data = payload.subspan(sizeof(struct ::ethtool_stats));
        auto const count = copied(payload, offsetof(struct ::ethtool_stats, n_stats), reading_.stats);
        for (size_t i = 0; i < count && (i + 1) * sizeof(uint64_t) <= data.size(); ++i) {
            span_store(data.subspan(i * sizeof(uint64_t), sizeof(uint64_t)), uint64_t{100 + i});
        }
        return put_u32(payload, offsetof(struct ::ethtool_stats, n_stats), count);
    }

    Kernel kernel_;
    std::vector<Reading> readings_;
    Reading reading_{};
    std::vector<uint32_t> sent_;
    size_t drvinfo_calls_{0};
};

auto read_from(StatsRecorder& driver) -> StatusValue<std::vector<EthtoolStat>>
{
    return net::ethtool_stats([&driver](std::span<uint8_t> const payload) { return driver.answer(payload); });
}

}  // namespace

TEST(net_ethtool_stats, the_drvinfo_count_is_sent_and_read_whole)
{
    for (auto const kernel : {Kernel::fixed, Kernel::unfixed}) {
        StatsRecorder driver{kernel, {{.drvinfo = 5, .strings = 5, .stats = 5}}};
        auto const stats = read_from(driver);
        EXPECT_TRUE(stats && stats->size() == 5);
        EXPECT_TRUE(stats && stats->back().name == "rx_queue_4_packets" && stats->back().value == 104);
        EXPECT_TRUE(driver.counts_sent() == (std::vector<uint32_t>{5, 5}));
    }
}

TEST(net_ethtool_stats, a_fixed_kernels_empty_reply_to_a_changed_count_is_read_again)
{
    StatsRecorder driver{Kernel::fixed, {{.drvinfo = 2, .strings = 5, .stats = 5}, {.drvinfo = 5, .strings = 5, .stats = 5}}};
    auto const stats = read_from(driver);
    EXPECT_TRUE(stats && stats->size() == 5);
    EXPECT_TRUE(driver.counts_sent() == (std::vector<uint32_t>{2, 5, 5}));
}

TEST(net_ethtool_stats, an_unfixed_kernels_own_count_is_read_again)
{
    StatsRecorder driver{Kernel::unfixed, {{.drvinfo = 2, .strings = 5, .stats = 5}, {.drvinfo = 5, .strings = 5, .stats = 5}}};
    auto const stats = read_from(driver);
    EXPECT_TRUE(stats && stats->size() == 5);
    EXPECT_EQ(driver.drvinfo_calls(), size_t{2});
}

TEST(net_ethtool_stats, names_and_values_of_different_counts_are_read_again)
{
    StatsRecorder driver{Kernel::fixed, {{.drvinfo = 4, .strings = 4, .stats = 5}, {.drvinfo = 5, .strings = 5, .stats = 5}}};
    auto const stats = read_from(driver);
    EXPECT_TRUE(stats && stats->size() == 5);
    EXPECT_EQ(driver.drvinfo_calls(), size_t{2});
}

TEST(net_ethtool_stats, a_count_changing_twice_running_is_resource_unavailable)
{
    for (auto const kernel : {Kernel::fixed, Kernel::unfixed}) {
        StatsRecorder driver{kernel, {{.drvinfo = 2, .strings = 3, .stats = 3}, {.drvinfo = 3, .strings = 4, .stats = 4}}};
        auto const stats = read_from(driver);
        EXPECT_TRUE(!stats && stats.error() == std::errc::resource_unavailable_try_again);
        EXPECT_EQ(driver.drvinfo_calls(), size_t{2});
    }
}

#endif

TEST_MAIN(statusbar_net, net_ethtool_stats_test)
