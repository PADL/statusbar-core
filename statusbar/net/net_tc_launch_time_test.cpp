// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_launch_time.hpp"

#include "statusbar/net/net_tc_qdisc_recorder.hpp"
#include "statusbar/test/test.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

TEST(tc_launch_time, the_mode_is_on_only_when_the_driver_says_so)
{
    using tc::LaunchTimeMode;
    EXPECT_TRUE(tc::launch_time_mode(true, StatusValue<bool>{true}) == LaunchTimeMode::on);
    // The driver answered, and the answer was no: asking the kernel for an etf
    // would succeed and shape nothing.
    EXPECT_TRUE(tc::launch_time_mode(true, StatusValue<bool>{false}) == LaunchTimeMode::unsupported);
    EXPECT_TRUE(tc::launch_time_mode(false, StatusValue<bool>{true}) == LaunchTimeMode::off);
}

// A query that failed is not an answer. Not wanting launch time still has to
// clear an etf an earlier run left, so that case is `off`, not `unsupported`.
TEST(tc_launch_time, a_failed_driver_query_is_unsupported_only_when_launch_time_was_wanted)
{
    auto const unknown = StatusValue<bool>{failure(std::make_error_code(std::errc::operation_not_supported))};
    EXPECT_TRUE(tc::launch_time_mode(true, unknown) == tc::LaunchTimeMode::unsupported);
    EXPECT_TRUE(tc::launch_time_mode(false, unknown) == tc::LaunchTimeMode::off);
}

#if defined(__linux__)

namespace {

constexpr int IFINDEX = 11;
constexpr std::uint16_t MAJOR = 0x9100;

/// Four TX queues: the socket on 0, PTP on 2, one queue past it for the rest.
[[nodiscard]] auto four_queues() -> tc::LaunchTimeQueue
{
    return tc::LaunchTimeQueue{.major = MAJOR, .queue = 0, .tx_queues = 4, .ptp_queue = 2, .persistent_root = true};
}

/// Three TX queues: no room for a PTP queue with one past it.
[[nodiscard]] auto three_queues() -> tc::LaunchTimeQueue
{
    return tc::LaunchTimeQueue{.major = MAJOR, .queue = 0, .tx_queues = 3};
}

/// A QdiscInfo of `kind` at `parent`, as the kernel would report one.
[[nodiscard]] auto installed(std::string_view kind, std::uint32_t handle, std::uint32_t parent) -> tc::QdiscInfo
{
    tc::QdiscInfo info{.ifindex = IFINDEX, .handle = handle, .parent = parent};
    std::ranges::copy(kind, info.kind.begin());
    return info;
}

/// Our own root as the kernel reports it back: our handle, and the very
/// layout launch_time_mqprio() lays for `queue`.
[[nodiscard]] auto our_root(tc::LaunchTimeQueue const& queue) -> tc::QdiscInfo
{
    auto info = installed("mqprio", tc::make_handle(queue.major, 0), tc::ROOT);
    info.has_mqprio_params = true;
    info.mqprio = *tc::launch_time_mqprio(queue);
    return info;
}

using Op = tc::TcRecorder::Operation;

/// The operations the recorder saw, in order, for a one-line comparison.
[[nodiscard]] auto operations_of(tc::TcRecorder const& recorder) -> std::vector<Op>
{
    std::vector<Op> ops;
    for (auto const& request : recorder.requests()) {
        ops.push_back(request.operation);
    }
    return ops;
}

/// Whether the recorder saw our root deleted - `major:0` at the root - at
/// `index`.
[[nodiscard]] auto removes_our_root_at(tc::TcRecorder const& recorder, std::size_t const index) -> bool
{
    auto const requests = recorder.requests();
    return index < requests.size() && requests[index].operation == Op::remove &&
        requests[index].handle == tc::make_handle(MAJOR, 0) && requests[index].parent == tc::ROOT;
}

}  // namespace

TEST(tc_launch_time, the_etf_hangs_on_the_class_of_the_sockets_own_queue)
{
    EXPECT_EQ(tc::launch_time_class(four_queues()), tc::make_handle(MAJOR, 1));
    auto second = four_queues();
    second.queue = 2;
    EXPECT_EQ(tc::launch_time_class(second), tc::make_handle(MAJOR, 3));
}

TEST(tc_launch_time, the_default_etf_delta_is_one_hundred_and_fifty_microseconds)
{
    EXPECT_EQ(tc::DEFAULT_ETF_DELTA_NS, 150'000);
    EXPECT_EQ(tc::LaunchTimeQueue{}.etf_delta_ns, tc::DEFAULT_ETF_DELTA_NS);
}

// The root lays out queues; it must not ask the driver to offload the map.
// On igb and igc the adapter resets when hardware TC offload appears, which
// takes the link down for seconds and loses gPTP lock.
TEST(tc_launch_time, the_root_does_not_ask_the_driver_to_offload_the_map)
{
    auto const root = tc::launch_time_mqprio(four_queues());
    EXPECT_TRUE(root.has_value());
    if (root) {
        EXPECT_FALSE(root->offload);
        EXPECT_EQ(root->major, MAJOR);
    }
}

// Nothing may be steered to the socket's queue: an skb landing there would
// queue behind - or ahead of - the timed frames the socket writes itself.
TEST(tc_launch_time, no_priority_maps_to_the_sockets_queue)
{
    auto const root = tc::launch_time_mqprio(four_queues());
    EXPECT_TRUE(root.has_value());
    if (!root) {
        return;
    }
    // Traffic class 0 is the socket's queue, by construction.
    EXPECT_EQ(root->offset[0], std::uint16_t{0});
    EXPECT_EQ(root->count[0], std::uint16_t{1});
    for (std::size_t priority = 0; priority < tc::PRIO_MAP_SIZE; ++priority) {
        EXPECT_TRUE(root->prio_tc_map[priority] != 0);
    }
}

TEST(tc_launch_time, ptp_gets_its_own_queue_and_everything_else_the_queues_past_it)
{
    auto const root = tc::launch_time_mqprio(four_queues());
    EXPECT_TRUE(root.has_value());
    if (!root) {
        return;
    }
    EXPECT_EQ(root->num_tc, std::uint8_t{3});
    EXPECT_EQ(root->offset[1], std::uint16_t{2});  // PTP's queue
    EXPECT_EQ(root->count[1], std::uint16_t{1});
    EXPECT_EQ(root->offset[2], std::uint16_t{3});  // the rest
    EXPECT_EQ(root->count[2], std::uint16_t{1});
    EXPECT_EQ(root->prio_tc_map[tc::PTP_PRIORITY], std::uint8_t{1});
    EXPECT_EQ(root->prio_tc_map[0], std::uint8_t{2});
    // Queue 1 is in no traffic class: idle, as a class B queue would be.
}

// With no queue to spare, PTP shares the rest rather than the layout being
// refused: gPTP at priority 7 behind other traffic is worse than nothing, but
// a talker that will not open at all is worse still.
TEST(tc_launch_time, without_a_queue_to_spare_ptp_shares_the_rest)
{
    auto const root = tc::launch_time_mqprio(three_queues());
    EXPECT_TRUE(root.has_value());
    if (!root) {
        return;
    }
    EXPECT_EQ(root->num_tc, std::uint8_t{2});
    EXPECT_EQ(root->offset[1], std::uint16_t{1});
    EXPECT_EQ(root->count[1], std::uint16_t{2});  // queues 1 and 2
    EXPECT_EQ(root->prio_tc_map[tc::PTP_PRIORITY], std::uint8_t{1});
    EXPECT_EQ(root->prio_tc_map[0], std::uint8_t{1});
}

TEST(tc_launch_time, a_queue_layout_that_cannot_work_is_refused)
{
    auto no_major = four_queues();
    no_major.major = 0;
    EXPECT_FALSE(tc::launch_time_mqprio(no_major).has_value());

    auto one_queue = four_queues();
    one_queue.tx_queues = 1;  // nothing left for anything but the socket
    one_queue.ptp_queue.reset();
    EXPECT_FALSE(tc::launch_time_mqprio(one_queue).has_value());

    auto past_the_end = four_queues();
    past_the_end.queue = 4;
    EXPECT_FALSE(tc::launch_time_mqprio(past_the_end).has_value());
}

// A PTP queue must be past the socket's, and must leave a queue past itself
// for everything else; otherwise the layout it describes does not exist.
TEST(tc_launch_time, a_ptp_queue_that_leaves_no_room_is_refused)
{
    auto on_the_socket = four_queues();
    on_the_socket.ptp_queue = 0;
    EXPECT_FALSE(tc::launch_time_mqprio(on_the_socket).has_value());

    auto last = four_queues();
    last.ptp_queue = 3;  // no queue past it for the rest
    EXPECT_FALSE(tc::launch_time_mqprio(last).has_value());
}

TEST(tc_launch_time, the_etf_is_offloaded_on_tai_and_takes_frames_with_no_so_txtime)
{
    auto queue = four_queues();
    queue.etf_delta_ns = 200'000;
    auto const etf = tc::launch_time_etf(queue);
    EXPECT_EQ(etf.parent, tc::make_handle(MAJOR, 1));
    EXPECT_EQ(etf.clockid, tc::ETF_CLOCK_TAI);
    EXPECT_EQ(etf.delta_ns, 200'000);
    EXPECT_TRUE(etf.offload);
    EXPECT_TRUE(etf.skip_sock_check);  // AF_XDP times frames in TX metadata
    EXPECT_FALSE(etf.deadline_mode);   // frames are spread out, not raced
}

// Unsupported must not look anything up: a host without launch time has no
// reason to need CAP_NET_ADMIN, or even an interface that exists.
TEST(tc_launch_time, unsupported_asks_the_kernel_nothing)
{
    tc::TcRecorder recorder;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::unsupported);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::none);
    }
    EXPECT_TRUE(recorder.requests().empty());
}

TEST(tc_launch_time, on_lays_the_root_and_the_etf_when_neither_is_there)
{
    tc::TcRecorder recorder;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    auto const requests = recorder.requests();
    EXPECT_EQ(requests.size(), std::size_t{4});
    if (requests.size() != 4) {
        return;
    }
    EXPECT_TRUE(requests[0].operation == tc::TcRecorder::Operation::get);
    EXPECT_TRUE(requests[1].operation == tc::TcRecorder::Operation::replace_mqprio);
    EXPECT_TRUE(requests[2].operation == tc::TcRecorder::Operation::get);
    EXPECT_TRUE(requests[3].operation == tc::TcRecorder::Operation::replace_etf);
    EXPECT_EQ(requests[3].parent, tc::make_handle(MAJOR, 1));
}

// An earlier run of the same talker left both in place. Rewriting the root
// would take the link down on igb, so what is already ours is left alone.
TEST(tc_launch_time, on_keeps_a_root_and_etf_an_earlier_run_left)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(four_queues()));
    recorder.set_get_result_for(tc::make_handle(MAJOR, 1), installed("etf", 0, tc::make_handle(MAJOR, 1)));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::kept);
    }
    for (auto const& request : recorder.requests()) {
        EXPECT_TRUE(request.operation == tc::TcRecorder::Operation::get);
    }
}

// Our handle on a root laid for another queue layout - the config moved the
// PTP queue between runs - is not ours to keep either: class 2, where the etf
// would hang, was "everything else" in the old layout. It is replaced - and
// deleted first, because the kernel takes a replace under a handle the
// interface already holds as a change to the qdisc there, which mqprio does
// not support: the request comes back EINVAL and the old root stays.
TEST(tc_launch_time, on_deletes_our_root_before_laying_it_again_when_its_layout_is_not_the_one_wanted)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(three_queues()));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::remove, Op::replace_mqprio, Op::get, Op::replace_etf}));
    EXPECT_TRUE(removes_our_root_at(recorder, 1));
    auto const requests = recorder.requests();
    if (requests.size() > 2) {
        EXPECT_EQ(requests[2].mqprio.num_tc, 3);
    }
}

// And a root that merely carries our handle, reporting no layout at all, is
// not ours: there is nothing to say what its classes mean. Same handle, same
// refusal from the kernel, so it too goes before the new one is laid.
TEST(tc_launch_time, a_root_with_our_handle_but_no_layout_is_deleted_and_laid_again)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, installed("mqprio", tc::make_handle(MAJOR, 0), tc::ROOT));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::remove, Op::replace_mqprio, Op::get, Op::replace_etf}));
    EXPECT_TRUE(removes_our_root_at(recorder, 1));
}

// Our handle on a qdisc of another kind is the same case: the kernel refuses
// a replace whose kind differs from what holds the handle, so it is deleted
// first. The delete names the handle alone, and a kind is not needed for it.
TEST(tc_launch_time, a_qdisc_of_another_kind_under_our_handle_is_deleted_and_laid_again)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, installed("prio", tc::make_handle(MAJOR, 0), tc::ROOT));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::remove, Op::replace_mqprio, Op::get, Op::replace_etf}));
    EXPECT_TRUE(removes_our_root_at(recorder, 1));
}

// Somebody else's root is not ours to keep: the queue layout behind it is
// unknown, so the class the etf would hang on may not be the socket's queue.
// It is under a different handle, so a replace under ours grafts over it in
// one request: nothing is deleted, and nothing of theirs is named.
TEST(tc_launch_time, on_replaces_a_root_that_is_not_ours_in_one_request)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, installed("mqprio", tc::make_handle(0x1234, 0), tc::ROOT));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::replace_mqprio, Op::get, Op::replace_etf}));
}

// The delete is a request like any other, and a refusal of it stops the
// sequence: laying the root over a stale one the kernel would not give up is
// exactly the request it refuses.
TEST(tc_launch_time, a_refused_delete_of_a_stale_root_stops_before_the_root_is_laid)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(three_queues()));
    recorder.fail_next_write(std::make_error_code(std::errc::operation_not_permitted), "Operation not permitted");
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_FALSE(action.has_value());
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::remove}));
}

TEST(tc_launch_time, on_lays_only_the_etf_when_the_root_is_already_ours)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(four_queues()));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    std::size_t writes = 0;
    for (auto const& request : recorder.requests()) {
        writes += request.operation == tc::TcRecorder::Operation::replace_etf ? 1 : 0;
        EXPECT_TRUE(request.operation != tc::TcRecorder::Operation::replace_mqprio);
    }
    EXPECT_EQ(writes, std::size_t{1});
}

// Deleting our root takes its etf with it, so off is one request.
TEST(tc_launch_time, off_deletes_our_root_and_the_etf_goes_with_it)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(four_queues()));
    auto queue = four_queues();
    queue.persistent_root = false;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, queue, tc::LaunchTimeMode::off);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::removed);
    }
    auto const requests = recorder.requests();
    EXPECT_EQ(requests.size(), std::size_t{2});
    if (requests.size() == 2) {
        EXPECT_TRUE(requests[1].operation == tc::TcRecorder::Operation::remove);
        EXPECT_EQ(requests[1].handle, tc::make_handle(MAJOR, 0));
        EXPECT_EQ(requests[1].parent, tc::ROOT);
    }
}

// Off must not delete a root somebody else laid.
TEST(tc_launch_time, off_leaves_a_root_that_is_not_ours_alone)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, installed("mqprio", tc::make_handle(0x1234, 0), tc::ROOT));
    auto queue = four_queues();
    queue.persistent_root = false;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, queue, tc::LaunchTimeMode::off);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::none);
    }
    for (auto const& request : recorder.requests()) {
        EXPECT_TRUE(request.operation == tc::TcRecorder::Operation::get);
    }
}

// A persistent root stays: the queue layout is what keeps PTP off the
// socket's queue, and that is wanted whether frames are timed or not. Only
// the etf goes.
TEST(tc_launch_time, off_with_a_persistent_root_removes_only_the_etf)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(four_queues()));
    recorder.set_get_result_for(tc::make_handle(MAJOR, 1), installed("etf", tc::make_handle(0x8003, 0), tc::make_handle(MAJOR, 1)));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::off);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::removed);
    }
    auto const requests = recorder.requests();
    EXPECT_TRUE(!requests.empty());
    if (requests.empty()) {
        return;
    }
    auto const& last = requests.back();
    EXPECT_TRUE(last.operation == tc::TcRecorder::Operation::remove);
    EXPECT_EQ(last.parent, tc::make_handle(MAJOR, 1));
}

// A persistent root under our handle but with an older layout is laid again
// for the same reason `on` lays it again - and deleted first for the same
// reason too.
TEST(tc_launch_time, off_with_a_persistent_root_deletes_a_stale_root_of_ours_before_laying_it_again)
{
    tc::TcRecorder recorder;
    recorder.set_get_result_for(tc::ROOT, our_root(three_queues()));
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::off);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    EXPECT_TRUE((operations_of(recorder) == std::vector{Op::get, Op::remove, Op::replace_mqprio, Op::get}));
    EXPECT_TRUE(removes_our_root_at(recorder, 1));
}

// Nothing of ours anywhere, and a root to keep: the root is laid, and there is
// no etf to take away.
TEST(tc_launch_time, off_with_a_persistent_root_lays_the_root_when_it_is_missing)
{
    tc::TcRecorder recorder;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::off);
    EXPECT_TRUE(action.has_value());
    if (action) {
        EXPECT_TRUE(*action == tc::LaunchTimeQueueAction::installed);
    }
    std::size_t removals = 0;
    for (auto const& request : recorder.requests()) {
        removals += request.operation == tc::TcRecorder::Operation::remove ? 1 : 0;
    }
    EXPECT_EQ(removals, std::size_t{0});
}

// The kernel's reason for refusing is the whole point of speaking netlink, so
// it must survive the helper rather than be flattened to a generic failure.
TEST(tc_launch_time, a_refused_request_stops_the_sequence_and_keeps_its_reason)
{
    tc::TcRecorder recorder;
    recorder.fail_next_write(std::make_error_code(std::errc::operation_not_permitted), "no CAP_NET_ADMIN");
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, four_queues(), tc::LaunchTimeMode::on);
    EXPECT_FALSE(action.has_value());
    if (!action) {
        EXPECT_EQ(action.error(), std::make_error_code(std::errc::operation_not_permitted));
    }
    EXPECT_EQ(recorder.last_message(), std::string{"no CAP_NET_ADMIN"});
    // It stopped: no etf was attempted on a root that was refused.
    for (auto const& request : recorder.requests()) {
        EXPECT_TRUE(request.operation != tc::TcRecorder::Operation::replace_etf);
    }
}

// A layout that cannot work is refused before any request, not after the root
// has been laid and the etf then fails.
TEST(tc_launch_time, a_bad_layout_is_refused_before_anything_is_written)
{
    tc::TcRecorder recorder;
    auto broken = four_queues();
    broken.major = 0;
    auto const action = tc::settle_launch_time_queue(recorder, IFINDEX, broken, tc::LaunchTimeMode::on);
    EXPECT_FALSE(action.has_value());
    EXPECT_TRUE(recorder.requests().empty());
}

#endif  // __linux__

TEST_MAIN(statusbar_net, net_tc_launch_time_test)
