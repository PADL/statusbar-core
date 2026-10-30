// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The launch-time mode from the driver's answer, and the launch-time queue's mqprio layout and its
// requests against a recording TcControl. Nothing is sent to the kernel.

#include "statusbar/net/net_tc_launch_time.hpp"

#include "statusbar/test/test.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <optional>
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
