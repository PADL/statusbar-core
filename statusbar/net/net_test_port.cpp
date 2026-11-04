// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_test_port.hpp"

#include "statusbar/net/net_error.hpp"

namespace statusbar::net {

void TestPortContext::close() noexcept
{  // NOLINT(statusbar-block-statements): a many-field reset
    valid_ = false;
    pool_.clear();
    free_list_.clear();
    launch_times_.clear();
    rx_queue_.clear();
    tx_captures_.clear();
    joined_multicast_.clear();
    refuse_commits_ = false;
    tx_flushes_ = 0;
    cycles_begun_ = 0;
    cycles_ended_ = 0;
}

auto TestPortContext::open(TestPortConfig const& config, std::pmr::memory_resource* memory_resource) -> Status
{
    close();

    hardware_address_ = config.hardware_address;
    interface_index_ = config.interface_index;
    mem_resource_ = memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource();

    pool_ = std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>>(mem_resource_);
    launch_times_ = std::pmr::vector<int64_t>(mem_resource_);
    free_list_ = std::pmr::vector<uint64_t>(mem_resource_);
    rx_queue_ = std::pmr::vector<RxEntry>(mem_resource_);
    tx_captures_ = std::pmr::vector<TxCapture>(mem_resource_);
    joined_multicast_ = std::pmr::vector<ieee::Eui48>(mem_resource_);

    size_t const pool_size = config.frame_pool_size > 0 ? config.frame_pool_size : 256;
    pool_.resize(pool_size);
    launch_times_.resize(pool_size, 0);

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

auto TestPortContext::tx_start(int64_t launch_time_ns) -> StatusValue<EthernetTxSlot>
{
    if (free_list_.empty()) {
        return failure(NetError::buffer_full);
    }

    uint64_t const handle = free_list_.back();
    free_list_.pop_back();

    launch_times_[static_cast<size_t>(handle)] = launch_time_ns;

    return success(EthernetTxSlot{
        .handle = handle,
        .buffer = make_span(pool_[static_cast<size_t>(handle)]),
    });
}

auto TestPortContext::tx_cancel(uint64_t handle) -> Status
{
    if (handle >= pool_.size()) {
        return failure(NetError::invalid_handle);
    }
    free_list_.push_back(handle);
    return success();
}

auto TestPortContext::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (rx_queue_.empty()) {
        return success(std::optional<EthernetRxSlot>{});
    }

    RxEntry const entry = rx_queue_.front();
    rx_queue_.erase(rx_queue_.begin());

    return success(std::optional<EthernetRxSlot>{EthernetRxSlot{
        .handle = entry.pool_index,
        .buffer = make_const_span(pool_[static_cast<size_t>(entry.pool_index)]).first(entry.frame_length),
        .timestamp_ns = entry.timestamp_ns,
    }});
}

auto TestPortContext::rx_start(int64_t const now_ns) -> StatusValue<std::optional<EthernetRxSlot>>
{
    auto slot = rx_start();
    if (slot && *slot) {
        (*slot)->timestamp_ns = now_ns;
    }
    return slot;
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
