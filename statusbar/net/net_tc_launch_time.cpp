// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_tc_launch_time.hpp"

#include <algorithm>
#include <optional>

namespace statusbar::net::tc {

auto launch_time_mode(bool const wanted, StatusValue<bool> const& driver) noexcept -> LaunchTimeMode
{
    if (!driver) {
        // No answer. Clearing a leftover etf still has to happen, so only a
        // host that *wanted* launch time is told it cannot have it.
        return wanted ? LaunchTimeMode::unsupported : LaunchTimeMode::off;
    }
    if (!wanted) {
        return LaunchTimeMode::off;
    }
    return *driver ? LaunchTimeMode::on : LaunchTimeMode::unsupported;
}

#if defined(__linux__)

namespace {

/// Traffic class 0 is the socket's queue, 1 is PTP's where it has one, and the
/// last is everything else. Named so the layout below reads as the thing it
/// describes. Without a PTP queue there are two classes, and 1 is the rest.
constexpr std::uint8_t SOCKET_CLASS = 0;
constexpr std::uint8_t PTP_CLASS = 1;
constexpr std::uint8_t SHARED_REST_CLASS = 1;

/// Whether @p queue describes a layout that exists on the interface.
[[nodiscard]] auto layout_is_possible(LaunchTimeQueue const& queue) noexcept -> bool
{
    if (queue.major == 0 || queue.tx_queues < 2 || queue.queue >= queue.tx_queues) {
        return false;
    }
    // Everything that is not the socket's timed traffic goes on the queues
    // past it, so there has to be one.
    return queue.queue + 1 < queue.tx_queues;
}

/// Whether @p queue's PTP queue, if it has one, is somewhere it can be: past
/// the socket's, with at least one queue past itself for everything else.
[[nodiscard]] auto ptp_queue_is_possible(LaunchTimeQueue const& queue) noexcept -> bool
{
    if (!queue.ptp_queue.has_value()) {
        return true;
    }
    if (queue.ptp_priority >= PRIO_MAP_SIZE) {
        return false;
    }
    return *queue.ptp_queue > queue.queue && *queue.ptp_queue + 1 < queue.tx_queues;
}

/// Put traffic class @p tc_index over the queues [@p first, @p first + @p
/// count).
auto place(MqprioQdisc& root, std::uint8_t const tc_index, std::uint16_t const first, std::uint16_t const count) noexcept -> void
{
    root.offset[tc_index] = first;
    root.count[tc_index] = count;
}

/// The layout with a queue for PTP: the socket's, PTP's, and the rest past it.
/// Any queue between the socket's and PTP's is in no class at all, and so is
/// idle - which is what an SR class B queue would be on this NIC.
/// PTP at its own priority, everything else on the class holding the rest.
auto map_priorities_with_ptp(MqprioQdisc& root, std::uint8_t const rest_class, std::uint8_t const ptp_priority) noexcept -> void
{
    root.prio_tc_map.fill(rest_class);
    root.prio_tc_map[ptp_priority] = PTP_CLASS;
}

/// The three classes over the queues: the socket's, PTP's, and the rest past
/// PTP's. Any queue between the socket's and PTP's is in no class, and idle.
auto place_classes_with_ptp(MqprioQdisc& root, LaunchTimeQueue const& queue, std::uint8_t const rest_class) noexcept -> void
{
    auto const ptp = *queue.ptp_queue;
    auto const rest = static_cast<std::uint16_t>(ptp + 1);
    place(root, SOCKET_CLASS, queue.queue, 1);
    place(root, PTP_CLASS, ptp, 1);
    place(root, rest_class, rest, static_cast<std::uint16_t>(queue.tx_queues - rest));
}

auto lay_out_with_ptp(MqprioQdisc& root, LaunchTimeQueue const& queue) noexcept -> void
{
    std::uint8_t const rest_class = PTP_CLASS + 1;
    root.num_tc = static_cast<std::uint8_t>(rest_class + 1);
    place_classes_with_ptp(root, queue, rest_class);
    map_priorities_with_ptp(root, rest_class, queue.ptp_priority);
}

/// The layout without one: the socket's queue, and everything else - PTP
/// included - on the queues past it.
auto lay_out_shared(MqprioQdisc& root, LaunchTimeQueue const& queue) noexcept -> void
{
    auto const rest = static_cast<std::uint16_t>(queue.queue + 1);
    root.num_tc = SHARED_REST_CLASS + 1;
    place(root, SOCKET_CLASS, queue.queue, 1);
    place(root, SHARED_REST_CLASS, rest, static_cast<std::uint16_t>(queue.tx_queues - rest));
    root.prio_tc_map.fill(SHARED_REST_CLASS);
}

}  // namespace

auto launch_time_mqprio(LaunchTimeQueue const& queue) noexcept -> StatusValue<MqprioQdisc>
{
    if (!layout_is_possible(queue) || !ptp_queue_is_possible(queue)) {
        return failure(NetError::invalid_argument);
    }
    MqprioQdisc root{};
    root.major = queue.major;
    // Not offloaded, and this is the point of the whole module: see the fourth
    // trap in the header comment. igb and igc reset the adapter when hardware
    // TC offload appears or goes.
    root.offload = false;
    if (queue.ptp_queue.has_value()) {
        lay_out_with_ptp(root, queue);
    } else {
        lay_out_shared(root, queue);
    }
    return root;
}

auto launch_time_etf(LaunchTimeQueue const& queue) noexcept -> EtfQdisc
{
    return EtfQdisc{
        .parent = launch_time_class(queue),
        .clockid = ETF_CLOCK_TAI,
        .delta_ns = queue.etf_delta_ns,
        .offload = true,
        .deadline_mode = false,
        // An AF_XDP socket puts its launch time in the UMEM's TX metadata and
        // never calls SO_TXTIME, so without this the qdisc drops its frames.
        .skip_sock_check = true,
    };
}

namespace {

/// Whether a root the kernel reported lays the queues out as @p wanted
/// does: the same classes, the same queues in each, the same priority map.
[[nodiscard]] auto same_layout(MqprioQdisc const& reported, MqprioQdisc const& wanted) noexcept -> bool
{
    if (reported.num_tc != wanted.num_tc || reported.prio_tc_map != wanted.prio_tc_map) {
        return false;
    }
    auto const classes = static_cast<std::ptrdiff_t>(wanted.num_tc);
    return std::equal(reported.count.begin(), reported.count.begin() + classes, wanted.count.begin()) &&
        std::equal(reported.offset.begin(), reported.offset.begin() + classes, wanted.offset.begin());
}

/// What the interface's root is to this run.
enum class RootState : std::uint8_t
{
    missing,  ///< nothing installed
    ours,     ///< our handle, and the layout this run wants
    stale,    ///< our handle on something else: an older layout of ours, or no layout at all
    foreign,  ///< somebody else's handle: another talker's root, or a shaper configured by hand
};

/// The root as this run sees it: its state, and the root itself where one
/// is installed.
struct Root
{
    RootState state{RootState::missing};
    std::optional<QdiscInfo> installed{};
};

/// Which of those the root is. Ours is an mqprio under our handle major
/// whose layout is the one this run wants. The handle alone is not enough -
/// a config that moved the socket's queue or its PTP queue between runs
/// leaves our handle on a root whose class numbers no longer mean what the
/// etf below assumes - so the layout the kernel reports is compared, and a
/// root that reports none is not ours either. Those are `stale`, and told
/// apart from `foreign` because the two are replaced differently: see
/// ensure_root(). Neither is ours to keep or to delete on `off`.
[[nodiscard]] auto root_state(TcControl& tc, int const ifindex, MqprioQdisc const& wanted) -> StatusValue<Root>
{
    auto const root = find_qdisc(tc, ifindex, ROOT);
    if (!root) {
        return forward_failure(root);
    }
    if (!root->has_value()) {
        return Root{};
    }
    if (handle_major((*root)->handle) != wanted.major) {
        return Root{.state = RootState::foreign, .installed = *root};
    }
    bool const ours = (*root)->kind_name() == "mqprio" && (*root)->has_mqprio_params && same_layout((*root)->mqprio, wanted);
    return Root{.state = ours ? RootState::ours : RootState::stale, .installed = *root};
}

/// The handle of the etf on @p parent, or nullopt if what is there is not an
/// etf (or nothing is).
[[nodiscard]] auto etf_handle_at(TcControl& tc, int const ifindex, std::uint32_t const parent)
    -> StatusValue<std::optional<std::uint32_t>>
{
    auto const found = find_qdisc(tc, ifindex, parent);
    if (!found) {
        return forward_failure(found);
    }
    if (!found->has_value() || (*found)->kind_name() != "etf") {
        return std::optional<std::uint32_t>{};
    }
    return std::optional<std::uint32_t>{(*found)->handle};
}

/// Lay @p root unless it is already ours: a stale root of ours, or a foreign mqprio or taprio, is
/// deleted first (NET_MODULE.md, "Notes & caveats": mqprio takes no change or in-place replace).
[[nodiscard]] auto ensure_root(TcControl& tc, int const ifindex, MqprioQdisc const& root, Root const& seen) -> Status
{
    if (seen.state == RootState::ours) {
        return success();
    }
    if (seen.state == RootState::stale) {
        if (auto const gone = tc.remove(ifindex, make_handle(root.major, 0), ROOT); !gone) {
            return forward_failure(gone);
        }
    }
    if (seen.state == RootState::foreign) {
        if (auto const gone = remove_other_tc_root(tc, ifindex, *seen.installed, root.major); !gone) {
            return forward_failure(gone);
        }
    }
    return tc.replace_mqprio(ifindex, root);
}

/// Lay @p queue's etf unless one is already on its class. Reports whether one
/// was found, so the caller can tell `kept` from `installed`.
[[nodiscard]] auto ensure_etf(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue) -> StatusValue<bool>
{
    auto const etf = etf_handle_at(tc, ifindex, launch_time_class(queue));
    if (!etf) {
        return forward_failure(etf);
    }
    if (etf->has_value()) {
        return true;
    }
    if (auto const laid = tc.replace_etf(ifindex, launch_time_etf(queue)); !laid) {
        return forward_failure(laid);
    }
    return false;
}

/// `on`: the root and the etf, each laid only where it is missing.
[[nodiscard]] auto settle_on(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, MqprioQdisc const& root)
    -> StatusValue<LaunchTimeQueueAction>
{
    auto const state = root_state(tc, ifindex, root);
    if (!state) {
        return forward_failure(state);
    }
    if (auto const laid = ensure_root(tc, ifindex, root, *state); !laid) {
        return forward_failure(laid);
    }
    auto const etf_was_there = ensure_etf(tc, ifindex, queue);
    if (!etf_was_there) {
        return forward_failure(etf_was_there);
    }
    return state->state == RootState::ours && *etf_was_there ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
}

/// `off` where the root goes too: deleting it takes its etf with it.
[[nodiscard]] auto settle_off_removing_root(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, bool const ours)
    -> StatusValue<LaunchTimeQueueAction>
{
    if (!ours) {
        return LaunchTimeQueueAction::none;
    }
    if (auto const gone = tc.remove(ifindex, make_handle(queue.major, 0), ROOT); !gone) {
        return forward_failure(gone);
    }
    return LaunchTimeQueueAction::removed;
}

/// Take the etf off @p parent where there is one. Nothing there is not a
/// failure: `off` asked for it to be gone, and it is.
[[nodiscard]] auto remove_etf_if_there(TcControl& tc, int const ifindex, std::uint32_t const parent) -> StatusValue<bool>
{
    auto const etf = etf_handle_at(tc, ifindex, parent);
    if (!etf) {
        return forward_failure(etf);
    }
    if (!etf->has_value()) {
        return false;
    }
    if (auto const gone = tc.remove(ifindex, **etf, parent); !gone) {
        return forward_failure(gone);
    }
    return true;
}

/// `off` where the root stays: the layout is wanted for its own sake, so it is
/// laid or kept and only the etf is taken away.
[[nodiscard]] auto settle_off_keeping_root(
    TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, MqprioQdisc const& root, Root const& state)
    -> StatusValue<LaunchTimeQueueAction>
{
    if (auto const laid = ensure_root(tc, ifindex, root, state); !laid) {
        return forward_failure(laid);
    }
    auto const removed = remove_etf_if_there(tc, ifindex, launch_time_class(queue));
    if (!removed) {
        return forward_failure(removed);
    }
    if (*removed) {
        return LaunchTimeQueueAction::removed;
    }
    return state.state == RootState::ours ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
}

/// `off`, either way round.
[[nodiscard]] auto settle_off(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, MqprioQdisc const& root)
    -> StatusValue<LaunchTimeQueueAction>
{
    auto const state = root_state(tc, ifindex, root);
    if (!state) {
        return forward_failure(state);
    }
    if (queue.persistent_root) {
        return settle_off_keeping_root(tc, ifindex, queue, root, *state);
    }
    return settle_off_removing_root(tc, ifindex, queue, state->state == RootState::ours);
}

}  // namespace

auto settle_launch_time_queue(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, LaunchTimeMode const mode)
    -> StatusValue<LaunchTimeQueueAction>
{
    if (mode == LaunchTimeMode::unsupported) {
        // Nothing is asked of the kernel, so nothing is looked up: no
        // interface, no privilege.
        return LaunchTimeQueueAction::none;
    }
    // The layout is checked before any request, so a bad one cannot leave half
    // a configuration behind.
    auto const root = launch_time_mqprio(queue);
    if (!root) {
        return forward_failure(root);
    }
    if (mode == LaunchTimeMode::on) {
        return settle_on(tc, ifindex, queue, *root);
    }
    return settle_off(tc, ifindex, queue, *root);
}

#endif  // __linux__

}  // namespace statusbar::net::tc
