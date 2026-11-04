#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// LoopbackPort — paired synthetic EthernetPorts connected back-to-back.
/// TX on one port becomes RX on the other, and vice versa. Entirely userspace.

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_ethernet_port.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace statusbar::net {

/// Configuration for a loopback port pair.
struct LoopbackPortConfig
{
    ieee::Eui48 mac_a{};
    ieee::Eui48 mac_b{};
    size_t frame_pool_size{256};
};

/// Shared queues between a loopback pair. Not for direct use — created by create_loopback_pair().
struct LoopbackSharedQueues
{
    struct QueuedFrame
    {
        EthernetFrameBuffer data;
        int64_t timestamp_ns{0};
    };

    std::deque<QueuedFrame> a_to_b;
    std::deque<QueuedFrame> b_to_a;
};

/// One end of a loopback pair. Satisfies the EthernetPort concept.
class LoopbackPortContext
{
  public:
    struct TxCapture
    {
        EthernetFrameBuffer frame;
        int64_t launch_time_ns{0};
    };

    LoopbackPortContext() = default;

    /// @param memory_resource Memory resource for pool_, launch_times_,
    ///        free_list_, and tx_captures_. nullptr is treated as
    ///        std::pmr::get_default_resource().
    void init(
        ieee::Eui48 mac,
        bool is_side_a,
        std::shared_ptr<LoopbackSharedQueues> shared,
        size_t pool_size,
        std::pmr::memory_resource* memory_resource = nullptr)
    {
        hardware_address_ = mac;
        is_side_a_ = is_side_a;
        shared_ = std::move(shared);
        mem_resource_ = memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource();

        pool_ = std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>>(mem_resource_);
        launch_times_ = std::pmr::vector<int64_t>(mem_resource_);
        free_list_ = std::pmr::vector<size_t>(mem_resource_);
        tx_captures_ = std::pmr::vector<TxCapture>(mem_resource_);

        pool_.resize(pool_size);
        launch_times_.resize(pool_size, 0);
        free_list_.reserve(pool_size);
        for (size_t i = 0; i < pool_size; ++i) {
            free_list_.push_back(i);
        }
        valid_ = true;
    }

    // --- EthernetPort interface ---

    [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }
    [[nodiscard]] auto fd() const noexcept -> int { return -1; }
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return hardware_address_; }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return is_side_a_ ? 1u : 2u; }

    auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
    {
        if (free_list_.empty()) {
            return failure(NetError::buffer_full);
        }
        auto const idx = free_list_.back();
        free_list_.pop_back();
        launch_times_[idx] = launch_time_ns;
        return EthernetTxSlot{.handle = idx, .buffer = std::span<uint8_t>{pool_[idx]}};
    }

    auto tx_commit(uint64_t handle, size_t len) -> Status
    {
        auto const idx = static_cast<size_t>(handle);
        if (idx >= pool_.size()) {
            return failure(NetError::invalid_handle);
        }
        auto const copy_len = std::min(len, pool_[idx].size());

        // Capture the frame into an inline buffer so no heap allocation
        // happens on the TX path. The same inline buffer is then copied into
        // both the tx_captures_ record and the peer's RX queue — those copies
        // are a plain memcpy of ~1536 bytes of POD, not allocator traffic.
        EthernetFrameBuffer captured;
        captured.assign(pool_[idx].data(), copy_len);

        tx_captures_.push_back(TxCapture{.frame = captured, .launch_time_ns = launch_times_[idx]});
        free_list_.push_back(idx);

        // Push to peer's RX queue
        auto& queue = is_side_a_ ? shared_->a_to_b : shared_->b_to_a;
        queue.push_back(LoopbackSharedQueues::QueuedFrame{.data = captured, .timestamp_ns = 0});
        return success();
    }

    auto tx_cancel(uint64_t handle) -> Status
    {
        free_list_.push_back(static_cast<size_t>(handle));
        return success();
    }

    auto tx_flush() -> Status { return success(); }

    /// The next frame the peer committed, stamped @p now: the RX clock as
    /// the caller read it for this pass (a loopback has no kernel to stamp).
    auto rx_start(RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
    {
        auto& queue = is_side_a_ ? shared_->b_to_a : shared_->a_to_b;
        if (queue.empty()) {
            return std::optional<EthernetRxSlot>{std::nullopt};
        }
        if (free_list_.empty()) {
            return failure(NetError::buffer_full);
        }
        auto const frame = queue.front();
        queue.pop_front();
        return std::optional<EthernetRxSlot>{copy_into_slot(frame, now)};
    }

    /// rx_start(now) with the RX clock read here.
    auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>> { return rx_start(rx_clock_now()); }

    auto rx_release(uint64_t handle) -> Status
    {
        free_list_.push_back(static_cast<size_t>(handle));
        return success();
    }

    auto join_multicast(ieee::Eui48 const& /*mac*/) -> Status { return success(); }

    void begin_cycle() noexcept {}
    auto end_cycle() -> Status { return success(); }

    // --- Test harness ---

    [[nodiscard]] auto rx_pending() const noexcept -> size_t
    {
        auto const& queue = is_side_a_ ? shared_->b_to_a : shared_->a_to_b;
        return queue.size();
    }

    [[nodiscard]] auto tx_pending() const noexcept -> size_t { return tx_captures_.size(); }

    auto pop_tx() -> std::optional<TxCapture>
    {
        if (tx_captures_.empty()) {
            return std::nullopt;
        }
        auto cap = tx_captures_.front();
        tx_captures_.erase(tx_captures_.begin());
        return cap;
    }

  private:
    /// @p frame copied into the slot at the top of the free list, taken.
    auto copy_into_slot(LoopbackSharedQueues::QueuedFrame const& frame, RxTimePoint const now) -> EthernetRxSlot
    {
        auto const idx = free_list_.back();
        free_list_.pop_back();
        auto const copy_len = std::min(frame.data.size(), pool_[idx].size());
        span_copy(make_span(pool_[idx]), frame.data);
        return EthernetRxSlot{
            .handle = idx,
            .buffer = std::span<uint8_t const>{pool_[idx].data(), copy_len},
            .timestamp_ns = frame.timestamp_ns != 0 ? frame.timestamp_ns : rx_timestamp_ns(now)};
    }

    ieee::Eui48 hardware_address_{};
    bool is_side_a_{true};
    bool valid_{false};
    std::shared_ptr<LoopbackSharedQueues> shared_;
    std::pmr::memory_resource* mem_resource_{std::pmr::get_default_resource()};

    std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>> pool_{mem_resource_};
    std::pmr::vector<int64_t> launch_times_{mem_resource_};
    std::pmr::vector<size_t> free_list_{mem_resource_};
    std::pmr::vector<TxCapture> tx_captures_{mem_resource_};
};

static_assert(EthernetPort<LoopbackPortContext>, "LoopbackPortContext must satisfy EthernetPort");

/// Create a connected pair of loopback ports.
/// TX on port A becomes RX on port B, and vice versa.
///
/// The shared queue storage is allocated through `alloc` via
/// std::allocate_shared, so callers that need to bound or redirect
/// the single allocation performed here (e.g. using a pool allocator
/// at init time) can pass a stateful allocator. The default
/// std::allocator<LoopbackSharedQueues> preserves the historical
/// behavior.
template <class Alloc = std::allocator<LoopbackSharedQueues>>
inline auto create_loopback_pair(
    LoopbackPortConfig const& config, Alloc const& alloc = Alloc{}, std::pmr::memory_resource* port_memory_resource = nullptr)
    -> std::pair<LoopbackPortContext, LoopbackPortContext>
{
    auto shared = std::allocate_shared<LoopbackSharedQueues>(alloc);
    LoopbackPortContext a;
    LoopbackPortContext b;
    a.init(config.mac_a, true, shared, config.frame_pool_size, port_memory_resource);
    b.init(config.mac_b, false, shared, config.frame_pool_size, port_memory_resource);
    return {std::move(a), std::move(b)};
}

}  // namespace statusbar::net
