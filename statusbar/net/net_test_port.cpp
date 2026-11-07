// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_test_port.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/net/net_error.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

namespace statusbar::net {

void TestPortContext::close() noexcept
{  // NOLINT(statusbar-block-statements): a many-field reset
    valid_ = false;
    pool_.clear();
    free_list_.clear();
    launch_times_.clear();
    tx_started_.clear();
    rx_queue_.clear();
    tx_captures_.clear();
    joined_multicast_.clear();
    refuse_commits_ = false;
    tx_flushes_ = 0;
    tx_gathers_ = 0;
    last_gather_.clear();
    cycles_begun_ = 0;
    cycles_ended_ = 0;
}

auto TestPortContext::open(TestPortConfig const& config, std::pmr::memory_resource* memory_resource) -> Status
{  // NOLINT(statusbar-block-statements): each of the port's vectors reset and sized in turn
    close();

    hardware_address_ = config.hardware_address;
    interface_index_ = config.interface_index;
    mem_resource_ = memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource();

    pool_ = std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>>(mem_resource_);
    launch_times_ = std::pmr::vector<int64_t>(mem_resource_);
    tx_started_ = std::pmr::vector<uint8_t>(mem_resource_);
    free_list_ = std::pmr::vector<uint64_t>(mem_resource_);
    rx_queue_ = std::pmr::vector<RxEntry>(mem_resource_);
    tx_captures_ = std::pmr::vector<TxCapture>(mem_resource_);
    joined_multicast_ = std::pmr::vector<ieee::Eui48>(mem_resource_);
    last_gather_ = std::pmr::vector<std::span<uint8_t const>>(mem_resource_);
    tx_segments_ = std::max<size_t>(config.tx_segments, 1);

    size_t const pool_size = config.frame_pool_size > 0 ? config.frame_pool_size : 256;
    pool_.resize(pool_size);
    launch_times_.resize(pool_size, 0);
    tx_started_.resize(pool_size, 0);

    free_list_.reserve(pool_size);
    for (size_t i = pool_size; i > 0; --i) {
        free_list_.push_back(static_cast<uint64_t>(i - 1));
    }

    valid_ = true;
    return success();
}

auto TestPortContext::tx_commit(uint64_t handle, size_t len) -> Status
{  // NOLINT(statusbar-block-statements): one frame captured whole, or refused
    if (handle >= pool_.size()) {
        return failure(NetError::invalid_handle);
    }
    tx_started_[static_cast<size_t>(handle)] = 0;
    if (refuse_commits_) {
        free_list_.push_back(handle);
        return failure(NetError::send_failed);
    }

    size_t const actual_len = (len > ETHERNET_PORT_MIN_FRAME_BUFFER) ? ETHERNET_PORT_MIN_FRAME_BUFFER : len;

    auto const& buf = pool_[static_cast<size_t>(handle)];
    TxCapture capture;
    capture.frame.assign(buf.data(), actual_len);
    capture.launch_time_ns = launch_times_[static_cast<size_t>(handle)];
    tx_captures_.push_back(capture);

    free_list_.push_back(handle);
    return success();
}

auto TestPortContext::tx_commit_gather(
    std::optional<uint64_t> const handle,
    size_t const len,
    std::span<std::span<uint8_t const> const> const rest,
    int64_t const launch_time_ns) -> Status
{
    if (handle && *handle >= pool_.size()) {
        return failure(NetError::invalid_handle);
    }
    TxCapture capture;
    capture.launch_time_ns = launch_time_ns != 0 ? launch_time_ns : (handle ? launch_times_[static_cast<size_t>(*handle)] : 0);
    auto const status = gather_into(capture, handle, len, rest);
    if (handle) {
        (void)tx_cancel(*handle);  // the slot back to the free list, sent or not
    }
    return status.transform([&] { record_gather(capture, rest); });
}

void TestPortContext::record_gather(TxCapture const& capture, std::span<std::span<uint8_t const> const> const rest)
{
    tx_captures_.push_back(capture);
    last_gather_.assign(rest.begin(), rest.end());
    ++tx_gathers_;
}

auto TestPortContext::gather_into(
    TxCapture& capture,
    std::optional<uint64_t> const handle,
    size_t const len,
    std::span<std::span<uint8_t const> const> const rest) const -> Status
{
    size_t const pieces = rest.size() + (handle ? 1 : 0);
    if (pieces == 0 || pieces > tx_segments_ || refuse_commits_) {
        return failure(refuse_commits_ ? NetError::send_failed : NetError::invalid_argument);
    }
    size_t const total =
        std::ranges::fold_left(rest, handle ? len : 0, [](size_t sum, auto const piece) { return sum + piece.size(); });
    if (total > ETHERNET_PORT_MIN_FRAME_BUFFER) {
        return failure(NetError::buffer_full);
    }
    concatenate(
        capture, handle ? make_const_span(pool_[static_cast<size_t>(*handle)]).first(len) : std::span<uint8_t const>{}, rest);
    return success();
}

void TestPortContext::concatenate(
    TxCapture& capture, std::span<uint8_t const> const head, std::span<std::span<uint8_t const> const> const rest)
{
    std::span<uint8_t> out{capture.frame.storage};
    span_copy(out.first(head.size()), head);
    out = out.subspan(head.size());
    for (auto const piece : rest) {
        span_copy(out.first(piece.size()), piece);
        out = out.subspan(piece.size());
    }
    capture.frame.length = capture.frame.storage.size() - out.size();
}

auto TestPortContext::tx_start(int64_t launch_time_ns) -> StatusValue<EthernetTxSlot>
{
    if (free_list_.empty()) {
        return failure(NetError::buffer_full);
    }

    uint64_t const handle = free_list_.back();
    free_list_.pop_back();

    launch_times_[static_cast<size_t>(handle)] = launch_time_ns;
    tx_started_[static_cast<size_t>(handle)] = 1;
    return success(EthernetTxSlot{
        .handle = handle,
        .buffer = make_span(pool_[static_cast<size_t>(handle)]),
    });
}

auto TestPortContext::tx_set_launch_time(uint64_t const handle, int64_t const launch_time_ns) -> Status
{
    if (handle >= tx_started_.size() || tx_started_[static_cast<size_t>(handle)] == 0) {
        return failure(NetError::invalid_handle);  // only a frame started and not yet committed
    }
    launch_times_[static_cast<size_t>(handle)] = launch_time_ns;
    return success();
}

auto TestPortContext::tx_cancel(uint64_t handle) -> Status
{
    if (handle >= pool_.size()) {
        return failure(NetError::invalid_handle);
    }
    tx_started_[static_cast<size_t>(handle)] = 0;
    free_list_.push_back(handle);
    return success();
}

auto TestPortContext::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    return rx_start(rx_clock_now());
}

auto TestPortContext::rx_start(RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (rx_queue_.empty()) {
        return success(std::optional<EthernetRxSlot>{});
    }

    RxEntry const entry = rx_queue_.front();
    rx_queue_.erase(rx_queue_.begin());

    return success(std::optional<EthernetRxSlot>{EthernetRxSlot{
        .handle = entry.pool_index,
        .buffer = make_const_span(pool_[static_cast<size_t>(entry.pool_index)]).first(entry.frame_length),
        .timestamp_ns = entry.timestamp_ns != 0 ? entry.timestamp_ns : rx_timestamp_ns(now),
    }});
}

auto TestPortContext::rx_release(uint64_t handle) -> Status
{
    if (handle >= pool_.size()) {
        return failure(NetError::invalid_handle);
    }
    free_list_.push_back(handle);
    return success();
}

auto TestPortContext::join_multicast(ieee::Eui48 const& mac) -> Status
{
    joined_multicast_.push_back(mac);
    return success();
}

auto TestPortContext::leave_multicast(ieee::Eui48 const& mac) -> Status
{
    if (auto const it = std::ranges::find(joined_multicast_, mac); it != joined_multicast_.end()) {
        joined_multicast_.erase(it);
    }
    return success();
}

auto TestPortContext::holds(std::span<uint8_t const> const bytes) const noexcept -> bool
{
    // The pool is one array of equal frames: the span's address within it, then within its frame.
    if (bytes.empty() || pool_.empty()) {
        return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): an address compared, never dereferenced
    auto const first = reinterpret_cast<std::uintptr_t>(pool_.front().data());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): as above
    auto const at = reinterpret_cast<std::uintptr_t>(bytes.data());
    if (at < first || at - first >= pool_.size() * ETHERNET_PORT_MIN_FRAME_BUFFER) {
        return false;
    }
    return ((at - first) % ETHERNET_PORT_MIN_FRAME_BUFFER) + bytes.size() <= ETHERNET_PORT_MIN_FRAME_BUFFER;
}

auto TestPortContext::pop_tx() -> std::optional<TxCapture>
{
    if (tx_captures_.empty()) {
        return std::nullopt;
    }
    TxCapture result = tx_captures_.front();
    tx_captures_.erase(tx_captures_.begin());
    return result;
}

auto TestPortContext::inject_rx(std::span<uint8_t const> frame, int64_t timestamp_ns) -> Status
{
    if (free_list_.empty()) {
        return failure(NetError::buffer_full);
    }

    uint64_t const handle = free_list_.back();
    free_list_.pop_back();

    size_t const copy_len = (frame.size() > ETHERNET_PORT_MIN_FRAME_BUFFER) ? ETHERNET_PORT_MIN_FRAME_BUFFER : frame.size();
    auto& buf = pool_[static_cast<size_t>(handle)];
    std::copy_n(frame.data(), copy_len, buf.data());

    rx_queue_.push_back(RxEntry{
        .pool_index = handle,
        .frame_length = copy_len,
        .timestamp_ns = timestamp_ns,
    });

    return success();
}

}  // namespace statusbar::net
