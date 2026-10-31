// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The launch-time mode from the driver's answer, and the launch-time queue's mqprio layout and its
// requests (and remove_own_mqprio_root's) against a recording TcControl. Nothing is sent to the kernel.

#include "statusbar/net/net_tc_launch_time.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using namespace statusbar;
using namespace statusbar::net::tc;

// The driver's one answer decides: on only where it honours launch time; a failed query removes a
// leftover etf when none is wanted and asks for nothing when one is.
TEST(tc_launch_time, the_mode_follows_the_driver_s_answer)
{
    EXPECT_TRUE(launch_time_mode(true, true) == LaunchTimeMode::on);
    EXPECT_TRUE(launch_time_mode(false, true) == LaunchTimeMode::off);
    EXPECT_TRUE(launch_time_mode(true, false) == LaunchTimeMode::unsupported);
    EXPECT_TRUE(launch_time_mode(false, false) == LaunchTimeMode::unsupported);
    auto const no_query = failure(std::errc::no_such_file_or_directory);
    EXPECT_TRUE(launch_time_mode(true, no_query) == LaunchTimeMode::unsupported);
    EXPECT_TRUE(launch_time_mode(false, no_query) == LaunchTimeMode::off);
}

#if defined(__linux__)

namespace {

constexpr uint16_t MAJOR = 0x9100;
constexpr int IFINDEX = 3;

/// A TcControl that records each request as `tc` would spell it and keeps the qdiscs as the kernel would.
class RecordingTc final : public TcControl
{
  public:
    std::vector<std::string> requests{};
    std::optional<QdiscInfo> root{};    ///< get(ROOT)'s answer (none: ENOENT)
    std::vector<QdiscInfo> children{};  ///< the qdiscs below the root
    std::error_code etf_error{};        ///< every replace_etf's answer

    auto replace_mqprio(int /*ifindex*/, MqprioQdisc const& q) -> Status override
    {
        requests.push_back(std::format("replace root mqprio {:x}: num_tc {}", q.major, q.num_tc));
        root = QdiscInfo{.handle = make_handle(q.major, 0), .parent = ROOT, .kind = "mqprio", .mqprio = q};
        children.clear();
        return success();
    }
    auto replace_cbs(int /*ifindex*/, CbsQdisc const& /*q*/) -> Status override { return failure(std::errc::not_supported); }
    auto replace_etf(int /*ifindex*/, EtfQdisc const& q) -> Status override
    {
        requests.push_back(std::format("replace {:x}:{:x} etf delta {}", q.parent >> 16U, q.parent & 0xFFFFU, q.delta_ns));
        if (etf_error) {
            return failure(etf_error);
        }
        std::erase_if(children, [&](QdiscInfo const& c) { return c.parent == q.parent; });
        children.push_back(QdiscInfo{.handle = make_handle(0x8001, 0), .parent = q.parent, .kind = "etf", .etf = q});
        return success();
    }
    auto replace_kind(int /*ifindex*/, uint32_t /*parent*/, std::string_view /*kind*/) -> Status override
    {
        return failure(std::errc::not_supported);
    }
    auto remove(int /*ifindex*/, uint32_t const handle, uint32_t const parent) -> Status override
    {
        requests.push_back(
            parent == ROOT ? std::format("del root {:x}:", handle >> 16U)
                           : std::format("del {:x}:{:x} handle {:x}:", parent >> 16U, parent & 0xFFFFU, handle >> 16U));
        if (parent == ROOT) {
            root.reset();
            children.clear();
        }
        std::erase_if(children, [&](QdiscInfo const& c) { return c.parent == parent; });
        return success();
    }
    auto get(int /*ifindex*/, uint32_t const parent) -> StatusValue<QdiscInfo> override
    {
        requests.push_back(
            parent == ROOT ? std::string{"show root"} : std::format("show {:x}:{:x}", parent >> 16U, parent & 0xFFFFU));
        auto const it = std::ranges::find(children, parent, &QdiscInfo::parent);
        if (parent == ROOT && root) {
            return *root;
        }
        if (parent != ROOT && it != children.end()) {
            return *it;
        }
        return failure(std::errc::no_such_file_or_directory);
    }
    [[nodiscard]] auto last_message() const noexcept -> std::string const& override { return message_; }

    /// The requests since the last take, cleared.
    auto take() -> std::vector<std::string> { return std::exchange(requests, {}); }

  private:
    std::string message_{};
};

/// The kernel's default root: mq, numbered 0.
auto default_root() -> QdiscInfo
{
    return QdiscInfo{.handle = 0, .parent = ROOT, .kind = "mq"};
}

auto queue_zero_of_four() -> LaunchTimeQueue
{
    return LaunchTimeQueue{.major = MAJOR, .queue = 0, .tx_queues = 4};
}

}  // namespace

// Queue 0 of 4 (an I226): class 0 is the socket's queue alone, class 1 the other three, and every
// priority maps to class 1, so the kernel's frames never reach the etf's queue.
TEST(tc_launch_time, the_socket_s_queue_is_a_class_no_priority_maps_to)
{
    auto const mqprio = launch_time_mqprio(queue_zero_of_four());
    EXPECT_TRUE(mqprio.has_value());
    if (!mqprio) {
        return;
    }
    EXPECT_EQ(mqprio->num_tc, uint8_t{2});
    EXPECT_TRUE(mqprio->count[0] == 1 && mqprio->offset[0] == 0);
    EXPECT_TRUE(mqprio->count[1] == 3 && mqprio->offset[1] == 1);
    EXPECT_TRUE(std::ranges::all_of(mqprio->prio_tc_map, [](uint8_t const tc) { return tc == 1; }));
    EXPECT_FALSE(mqprio->hw);
    EXPECT_EQ(launch_time_class(queue_zero_of_four()), make_handle(MAJOR, 1));
    auto const middle = launch_time_mqprio(LaunchTimeQueue{.major = MAJOR, .queue = 1, .tx_queues = 4});
    EXPECT_TRUE(middle && middle->num_tc == 3 && middle->count[0] == 1 && middle->offset[1] == 1 && middle->offset[2] == 2);
    EXPECT_TRUE(middle && middle->prio_tc_map[0] == 0 && middle->prio_tc_map[7] == 0);
    EXPECT_FALSE(launch_time_mqprio(LaunchTimeQueue{.major = MAJOR, .queue = 0, .tx_queues = 1}).has_value());
    EXPECT_FALSE(launch_time_mqprio(LaunchTimeQueue{.major = MAJOR, .queue = 4, .tx_queues = 4}).has_value());
    EXPECT_FALSE(launch_time_mqprio(LaunchTimeQueue{.major = 0, .queue = 0, .tx_queues = 4}).has_value());
}

// PTP on queue 2 of 4: the socket's queue 0 and the idle queue 1 take no priority, PTP_PRIORITY
// alone maps to queue 2 and every other priority to queue 3.
TEST(tc_launch_time, ptp_event_traffic_has_a_queue_of_its_own)
{
    auto queue = queue_zero_of_four();
    queue.ptp_queue = 2;
    auto const mqprio = launch_time_mqprio(queue);
    EXPECT_TRUE(mqprio.has_value());
    if (!mqprio) {
        return;
    }
    EXPECT_EQ(mqprio->num_tc, uint8_t{4});
    for (uint8_t tc = 0; tc < 4; ++tc) {
        EXPECT_TRUE(mqprio->count[tc] == 1 && mqprio->offset[tc] == tc);
    }
    EXPECT_EQ(mqprio->prio_tc_map[PTP_PRIORITY], uint8_t{2});
    EXPECT_EQ(std::ranges::count(mqprio->prio_tc_map, uint8_t{3}), 15);
    queue.ptp_queue = 1;  // right after the socket's: nothing idle, the rest on queues 2-3
    auto const adjacent = launch_time_mqprio(queue);
    EXPECT_TRUE(adjacent && adjacent->num_tc == 3 && adjacent->count[2] == 2 && adjacent->prio_tc_map[0] == 2);
}

// The request, byte for byte (little-endian hosts): `tc qdisc replace dev <if3> root handle 9100: mqprio
// num_tc 4 map 3 3 3 3 3 3 3 2 3 3 3 3 3 3 3 3 queues 1@0 1@1 1@2 1@3 hw 0`.
TEST(tc_launch_time, the_ptp_layout_request_bytes)
{
    if constexpr (std::endian::native != std::endian::little) {
        return;
    }
    auto queue = queue_zero_of_four();
    queue.ptp_queue = 2;
    // clang-format off
    std::array<uint8_t, 136> const want{
        0x88, 0x00, 0x00, 0x00,  0x24, 0x00,  0x05, 0x05,  0x07, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x91,  0xff, 0xff, 0xff, 0xff,  0x00, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x01, 0x00,  'm', 'q', 'p', 'r', 'i', 'o', 0x00,  0x00,
        0x56, 0x00, 0x02, 0x00,
        0x04,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x02,  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x00,
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    };
    // clang-format on
    RequestBuffer out{};
    auto const length =
        launch_time_mqprio(queue).and_then([&](MqprioQdisc const& q) { return build_replace_mqprio(out, IFINDEX, q, 7); });
    EXPECT_TRUE(length && *length == want.size());
    EXPECT_TRUE(std::ranges::equal(std::span{out}.first(want.size()), want));
}

TEST(tc_launch_time, a_ptp_queue_needs_a_queue_past_it_for_the_rest)
{
    auto queue = queue_zero_of_four();
    for (uint16_t const bad : {uint16_t{0}, uint16_t{3}, uint16_t{4}}) {
        queue.ptp_queue = bad;
        EXPECT_FALSE(launch_time_mqprio(queue).has_value());
    }
    queue.ptp_queue = 2;
    queue.ptp_priority = 16;
    EXPECT_FALSE(launch_time_mqprio(queue).has_value());
}

// A persistent root: off lays it alone, on adds the etf, off takes away only the etf, and a restart keeps
// the root; unsupported still asks nothing.
TEST(tc_launch_time, a_persistent_root_outlives_launch_time)
{
    RecordingTc tc;
    tc.root = default_root();
    auto queue = queue_zero_of_four();
    queue.ptp_queue = 2;
    queue.persistent_root = true;
    auto const none = settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::unsupported);
    EXPECT_TRUE(none && *none == LaunchTimeQueueAction::none && tc.take().empty());
    auto const alone = settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::off);
    EXPECT_TRUE(alone && *alone == LaunchTimeQueueAction::installed);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "replace root mqprio 9100: num_tc 4", "show 9100:1"}));
    (void)settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::on);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "show 9100:1", "replace 9100:1 etf delta 150000"}));
    auto const off = settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::off);
    EXPECT_TRUE(off && *off == LaunchTimeQueueAction::removed);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "show 9100:1", "del 9100:1 handle 8001:"}));
    EXPECT_TRUE(tc.root && tc.root->kind == "mqprio" && tc.children.empty());
    auto const again = settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::off);
    EXPECT_TRUE(again && *again == LaunchTimeQueueAction::kept);
}

// Supported: our mqprio replaces the default root and an offloaded etf goes on the socket's class;
// a restart finds both and asks for nothing more (on igc the first etf resets the adapter, once).
TEST(tc_launch_time, on_lays_the_root_and_the_etf_and_a_restart_keeps_them)
{
    RecordingTc tc;
    tc.root = default_root();
    auto const first = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::on);
    EXPECT_TRUE(first && *first == LaunchTimeQueueAction::installed);
    EXPECT_TRUE(
        (tc.take() ==
         std::vector<std::string>{
             "show root", "replace root mqprio 9100: num_tc 2", "show 9100:1", "replace 9100:1 etf delta 150000"}));
    EXPECT_TRUE(tc.children.size() == 1 && tc.children.front().etf->offload && tc.children.front().etf->skip_sock_check);
    auto const again = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::on);
    EXPECT_TRUE(again && *again == LaunchTimeQueueAction::kept);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "show 9100:1"}));
}

// An etf of another delta on our class is deleted first: etf has no change operation.
TEST(tc_launch_time, another_etf_on_the_class_is_deleted_before_ours_goes_on)
{
    RecordingTc tc;
    tc.root = default_root();
    (void)settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::on);
    tc.take();
    auto queue = queue_zero_of_four();
    queue.etf_delta_ns = 200'000;
    auto const settled = settle_launch_time_queue(tc, IFINDEX, queue, LaunchTimeMode::on);
    EXPECT_TRUE(settled && *settled == LaunchTimeQueueAction::installed);
    EXPECT_TRUE(
        (tc.take() ==
         std::vector<std::string>{"show root", "show 9100:1", "del 9100:1 handle 8001:", "replace 9100:1 etf delta 200000"}));
}

// Unsupported (igb): no request at all. Off: our root, left by an earlier run, is deleted with its etf;
// a root that is not ours stays.
TEST(tc_launch_time, unsupported_asks_nothing_and_off_removes_only_ours)
{
    RecordingTc tc;
    tc.root = default_root();
    auto const none = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::unsupported);
    EXPECT_TRUE(none && *none == LaunchTimeQueueAction::none);
    EXPECT_TRUE(tc.take().empty());
    auto const foreign = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::off);
    EXPECT_TRUE(foreign && *foreign == LaunchTimeQueueAction::none);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root"}));
    (void)settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::on);
    tc.take();
    auto const removed = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::off);
    EXPECT_TRUE(removed && *removed == LaunchTimeQueueAction::removed);
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "del root 9100:"}));
    EXPECT_TRUE(tc.children.empty());
}

// remove_own_mqprio_root: an mqprio under another handle, or another kind under ours, is left alone
TEST(tc_own_root, only_an_mqprio_with_our_handle_is_removed)
{
    RecordingTc tc;
    tc.root = default_root();
    EXPECT_TRUE(remove_own_mqprio_root(tc, IFINDEX, 0x9000) == StatusValue<bool>{false});
    tc.root = QdiscInfo{.handle = make_handle(0x8000, 0), .parent = ROOT, .kind = "mqprio"};
    EXPECT_TRUE(remove_own_mqprio_root(tc, IFINDEX, 0x9000) == StatusValue<bool>{false});
    tc.root = QdiscInfo{.handle = make_handle(0x9000, 0), .parent = ROOT, .kind = "taprio"};
    EXPECT_TRUE(remove_own_mqprio_root(tc, IFINDEX, 0x9000) == StatusValue<bool>{false});
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "show root", "show root"}));
    tc.root = QdiscInfo{.handle = make_handle(0x9000, 0), .parent = ROOT, .kind = "mqprio"};
    EXPECT_TRUE(remove_own_mqprio_root(tc, IFINDEX, 0x9000) == StatusValue<bool>{true});
    EXPECT_TRUE((tc.take() == std::vector<std::string>{"show root", "del root 9000:"}));
    EXPECT_FALSE(tc.root.has_value());
}

// A refused etf (EOPNOTSUPP: no etf offload) is the result, our root left in place.
TEST(tc_launch_time, a_refused_etf_is_the_result)
{
    RecordingTc tc;
    tc.root = default_root();
    tc.etf_error = std::make_error_code(std::errc::operation_not_supported);
    auto const settled = settle_launch_time_queue(tc, IFINDEX, queue_zero_of_four(), LaunchTimeMode::on);
    EXPECT_TRUE(!settled && settled.error() == std::errc::operation_not_supported);
    EXPECT_TRUE(tc.root && tc.root->kind == "mqprio");
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_launch_time_test)
