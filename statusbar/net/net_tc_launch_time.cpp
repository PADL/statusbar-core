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

/// Our root for @p queue, if @p ifindex has it, deleted with its etf.
auto remove_ours(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue) -> StatusValue<LaunchTimeQueueAction>
{
    return remove_own_mqprio_root(tc, ifindex, queue.major).transform([](bool const removed) {
        return removed ? LaunchTimeQueueAction::removed : LaunchTimeQueueAction::none;
    });
}

}  // namespace

auto launch_time_mqprio(LaunchTimeQueue const& queue) noexcept -> StatusValue<MqprioQdisc>
{  // NOLINT(statusbar-block-statements): the classes in queue order, then the map
    if (queue.major == 0 || queue.tx_queues < 2 || queue.queue >= queue.tx_queues) {
        return failure(std::errc::invalid_argument);
    }
    MqprioQdisc mqprio{.major = queue.major};
    // Classes in queue order: the queues below the socket's, the socket's alone, the queues above it.
    if (queue.queue > 0) {
        (void)add_class(mqprio, queue.queue, 0);
    }
    uint8_t const own = add_class(mqprio, 1, queue.queue);
    if (queue.queue + 1 < queue.tx_queues) {
        (void)add_class(mqprio, static_cast<uint16_t>(queue.tx_queues - queue.queue - 1), static_cast<uint16_t>(queue.queue + 1));
    }
    mqprio.prio_tc_map.fill(own == 0 ? 1 : 0);  // every priority to the first other class
    return mqprio;
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
            return remove_ours(tc, ifindex, queue);
        case LaunchTimeMode::unsupported:
            break;
    }
    return LaunchTimeQueueAction::none;
}

#endif  // __linux__

}  // namespace statusbar::net::tc
