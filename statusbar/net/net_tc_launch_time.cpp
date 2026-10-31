// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_launch_time.hpp"

#include <system_error>

namespace statusbar::net::tc {

auto launch_time_mode(bool const wanted, StatusValue<bool> const& driver) noexcept -> LaunchTimeMode
{
    if (!driver) {
        return wanted ? LaunchTimeMode::unsupported : LaunchTimeMode::off;
    }
    if (!*driver) {
        return LaunchTimeMode::unsupported;
    }
    return wanted ? LaunchTimeMode::on : LaunchTimeMode::off;
}

#if defined(__linux__)

namespace {

/// Append a traffic class of @p count queues from @p offset to @p mqprio: its index.
auto add_class(MqprioQdisc& mqprio, uint16_t const count, uint16_t const offset) noexcept -> uint8_t
{
    uint8_t const tc = mqprio.num_tc++;
    mqprio.count[tc] = count;
    mqprio.offset[tc] = offset;
    return tc;
}

/// Append a class for queues [@p first, @p end) to @p mqprio when the range is not empty.
void add_range(MqprioQdisc& mqprio, uint16_t const first, uint16_t const end) noexcept
{
    if (first < end) {
        (void)add_class(mqprio, static_cast<uint16_t>(end - first), first);
    }
}

/// Whether @p queue can be laid: a handle, the socket's queue among 2 or more, and a PTP queue (if any)
/// past it with a queue past that and a priority mqprio maps.
auto valid(LaunchTimeQueue const& queue) noexcept -> bool
{
    if (queue.major == 0 || queue.tx_queues < 2 || queue.queue >= queue.tx_queues) {
        return false;
    }
    auto const ptp = queue.ptp_queue;
    return !ptp || (*ptp > queue.queue && *ptp + 1 < queue.tx_queues && queue.ptp_priority < PRIORITY_COUNT);
}

/// The classes up to queue @p end in queue order: the queues below the socket's, the socket's alone
/// (class @p own), the queues after it.
auto socket_classes(LaunchTimeQueue const& queue, uint16_t const end, uint8_t& own) noexcept -> MqprioQdisc
{
    MqprioQdisc mqprio{.major = queue.major};
    add_range(mqprio, 0, queue.queue);
    own = add_class(mqprio, 1, queue.queue);
    add_range(mqprio, static_cast<uint16_t>(queue.queue + 1), end);
    return mqprio;
}

/// The root without a PTP queue: every priority to the first class that is not the socket's.
auto shared_mqprio(LaunchTimeQueue const& queue) noexcept -> MqprioQdisc
{
    uint8_t own = 0;
    MqprioQdisc mqprio = socket_classes(queue, queue.tx_queues, own);
    mqprio.prio_tc_map.fill(own == 0 ? 1 : 0);
    return mqprio;
}

/// The root with PTP on @p ptp: the socket's classes up to it (idle but the socket's), PTP's, and the
/// queues past it, which take every other priority.
auto ptp_mqprio(LaunchTimeQueue const& queue, uint16_t const ptp) noexcept -> MqprioQdisc
{
    uint8_t own = 0;
    MqprioQdisc mqprio = socket_classes(queue, ptp, own);
    uint8_t const ptp_tc = add_class(mqprio, 1, ptp);
    mqprio.prio_tc_map.fill(add_class(mqprio, static_cast<uint16_t>(queue.tx_queues - ptp - 1), static_cast<uint16_t>(ptp + 1)));
    mqprio.prio_tc_map[queue.ptp_priority] = ptp_tc;
    return mqprio;
}

/// Whether @p root is our mqprio, laid as @p mqprio.
auto is_ours(StatusValue<QdiscInfo> const& root, MqprioQdisc const& mqprio) noexcept -> bool
{
    return root && root->handle == make_handle(mqprio.major, 0) && root->mqprio == mqprio;
}

/// @p mqprio as @p ifindex's root, kept when it already is: whether it was kept.
auto put_root(TcControl& tc, int const ifindex, MqprioQdisc const& mqprio) -> StatusValue<bool>
{
    if (is_ours(tc.get(ifindex, ROOT), mqprio)) {
        return true;
    }
    auto replaced = tc.replace_mqprio(ifindex, mqprio);
    if (!replaced && replaced.error() == std::errc::invalid_argument) {
        // Our handle with another layout, which mqprio refuses to change: deleted, and laid once more.
        (void)tc.remove(ifindex, make_handle(mqprio.major, 0), ROOT);
        replaced = tc.replace_mqprio(ifindex, mqprio);
    }
    return replaced.transform([] { return false; });
}

/// @p etf on its parent, kept when it is already there: whether it was kept.
auto put_etf(TcControl& tc, int const ifindex, EtfQdisc const& etf) -> StatusValue<bool>
{
    auto const child = tc.get(ifindex, etf.parent);
    if (child && child->etf == etf) {
        return true;
    }
    // etf has no change operation: another etf goes first.
    if (auto removed = child && child->kind == "etf" ? tc.remove(ifindex, child->handle, etf.parent) : Status{}; !removed) {
        return forward_failure(removed);
    }
    return tc.replace_etf(ifindex, etf).transform([] { return false; });
}

/// Our root and etf for @p queue on @p ifindex.
auto install(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue) -> StatusValue<LaunchTimeQueueAction>
{
    return launch_time_mqprio(queue)
        .and_then([&](MqprioQdisc const& mqprio) { return put_root(tc, ifindex, mqprio); })
        .and_then([&](bool const root_kept) {
            return put_etf(tc, ifindex, launch_time_etf(queue)).transform([root_kept](bool const etf_kept) {
                return root_kept && etf_kept ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
            });
        });
}

/// An etf on @p parent deleted: whether there was one.
auto clear_etf(TcControl& tc, int const ifindex, uint32_t const parent) -> StatusValue<bool>
{
    auto const child = tc.get(ifindex, parent);
    if (!child || child->kind != "etf") {
        return false;
    }
    return tc.remove(ifindex, child->handle, parent).transform([] { return true; });
}

/// Our root for @p queue laid or kept, and an etf on the queue's class deleted.
auto root_alone(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue) -> StatusValue<LaunchTimeQueueAction>
{
    auto const kept = launch_time_mqprio(queue).and_then([&](MqprioQdisc const& mqprio) { return put_root(tc, ifindex, mqprio); });
    if (!kept) {
        return forward_failure(kept);
    }
    auto const root = *kept ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
    return clear_etf(tc, ifindex, launch_time_class(queue)).transform([root](bool const removed) {
        return removed ? LaunchTimeQueueAction::removed : root;
    });
}

/// Our root for @p queue, if @p ifindex has it, deleted with its etf.
auto remove_ours(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue) -> StatusValue<LaunchTimeQueueAction>
{
    return remove_own_mqprio_root(tc, ifindex, queue.major).transform([](bool const removed) {
        return removed ? LaunchTimeQueueAction::removed : LaunchTimeQueueAction::none;
    });
}

}  // namespace

auto launch_time_mqprio(LaunchTimeQueue const& queue) noexcept -> StatusValue<MqprioQdisc>
{
    if (!valid(queue)) {
        return failure(std::errc::invalid_argument);
    }
    return queue.ptp_queue ? ptp_mqprio(queue, *queue.ptp_queue) : shared_mqprio(queue);
}

auto launch_time_etf(LaunchTimeQueue const& queue) noexcept -> EtfQdisc
{
    return EtfQdisc{.parent = launch_time_class(queue), .delta_ns = queue.etf_delta_ns, .offload = true, .skip_sock_check = true};
}

auto settle_launch_time_queue(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, LaunchTimeMode const mode)
    -> StatusValue<LaunchTimeQueueAction>
{
    switch (mode) {
        case LaunchTimeMode::on:
            return install(tc, ifindex, queue);
        case LaunchTimeMode::off:
            return queue.persistent_root ? root_alone(tc, ifindex, queue) : remove_ours(tc, ifindex, queue);
        case LaunchTimeMode::unsupported:
            break;
    }
    return LaunchTimeQueueAction::none;
}

#endif  // __linux__

}  // namespace statusbar::net::tc
