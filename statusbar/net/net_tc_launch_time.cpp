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
/// describes.
constexpr std::uint8_t SOCKET_CLASS = 0;
constexpr std::uint8_t PTP_CLASS = 1;

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
    root.num_tc = PTP_CLASS + 1;
    place(root, SOCKET_CLASS, queue.queue, 1);
    place(root, PTP_CLASS, rest, static_cast<std::uint16_t>(queue.tx_queues - rest));
    root.prio_tc_map.fill(PTP_CLASS);
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

/// Nothing installed at a parent is an answer, not a failure: the kernel
/// reports it as a bad handle.
[[nodiscard]] auto is_nothing_there(std::error_code const& error) noexcept -> bool
{
    return error == make_error_code(NetError::invalid_handle);
}

/// What is installed at @p parent, or nullopt for nothing.
[[nodiscard]] auto qdisc_at(TcControl& tc, int const ifindex, std::uint32_t const parent) -> StatusValue<std::optional<QdiscInfo>>
{
    auto const info = tc.get(ifindex, parent);
    if (info) {
        return std::optional<QdiscInfo>{*info};
    }
    if (is_nothing_there(info.error())) {
        return std::optional<QdiscInfo>{};
    }
    return forward_failure(info);
}

/// Whether the interface's root is the mqprio *we* lay, identified by its
/// handle major. Another talker's root, or a shaper somebody configured by
/// hand, is not ours to keep or to delete.
[[nodiscard]] auto root_is_ours(TcControl& tc, int const ifindex, std::uint16_t const major) -> StatusValue<bool>
{
    auto const root = qdisc_at(tc, ifindex, ROOT);
    if (!root) {
        return forward_failure(root);
    }
    if (!root->has_value()) {
        return false;
    }
    return (*root)->kind_name() == "mqprio" && handle_major((*root)->handle) == major;
}

/// The handle of the etf on @p parent, or nullopt if what is there is not an
/// etf (or nothing is).
[[nodiscard]] auto etf_handle_at(TcControl& tc, int const ifindex, std::uint32_t const parent)
    -> StatusValue<std::optional<std::uint32_t>>
{
    auto const found = qdisc_at(tc, ifindex, parent);
    if (!found) {
        return forward_failure(found);
    }
    if (!found->has_value() || (*found)->kind_name() != "etf") {
        return std::optional<std::uint32_t>{};
    }
    return std::optional<std::uint32_t>{(*found)->handle};
}

/// Lay @p root unless it is already ours.
[[nodiscard]] auto ensure_root(TcControl& tc, int const ifindex, MqprioQdisc const& root, bool const ours) -> Status
{
    if (ours) {
        return success();
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
    auto const ours = root_is_ours(tc, ifindex, queue.major);
    if (!ours) {
        return forward_failure(ours);
    }
    if (auto const laid = ensure_root(tc, ifindex, root, *ours); !laid) {
        return forward_failure(laid);
    }
    auto const etf_was_there = ensure_etf(tc, ifindex, queue);
    if (!etf_was_there) {
        return forward_failure(etf_was_there);
    }
    return *ours && *etf_was_there ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
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

/// `off` where the root stays: the layout is wanted for its own sake, so it is
/// laid or kept and only the etf is taken away.
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

[[nodiscard]] auto settle_off_keeping_root(
    TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, MqprioQdisc const& root, bool const ours)
    -> StatusValue<LaunchTimeQueueAction>
{
    if (auto const laid = ensure_root(tc, ifindex, root, ours); !laid) {
        return forward_failure(laid);
    }
    auto const removed = remove_etf_if_there(tc, ifindex, launch_time_class(queue));
    if (!removed) {
        return forward_failure(removed);
    }
    if (*removed) {
        return LaunchTimeQueueAction::removed;
    }
    return ours ? LaunchTimeQueueAction::kept : LaunchTimeQueueAction::installed;
}

/// `off`, either way round.
[[nodiscard]] auto settle_off(TcControl& tc, int const ifindex, LaunchTimeQueue const& queue, MqprioQdisc const& root)
    -> StatusValue<LaunchTimeQueueAction>
{
    auto const ours = root_is_ours(tc, ifindex, queue.major);
    if (!ours) {
        return forward_failure(ours);
    }
    if (queue.persistent_root) {
        return settle_off_keeping_root(tc, ifindex, queue, root, *ours);
    }
    return settle_off_removing_root(tc, ifindex, queue, *ours);
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
