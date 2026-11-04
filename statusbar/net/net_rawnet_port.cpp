// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rawnet_port.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee_ethernet.hpp"
#include "statusbar/net/net_error.hpp"

namespace statusbar::net {

auto RawnetPort::open(RawnetPortConfig const& config) noexcept -> Status
{
    close();  // which also resets both pools
    if (config.interface_name.empty() || config.ethertype == 0) {
        return failure(NetError::invalid_argument);
    }
    if (auto status = open_sockets(config); !status) {
        close();
        return status;
    }
    rx_clock_id_ = config.rx_clock_id;
    return success();
}

auto RawnetPort::open_sockets(RawnetPortConfig const& config) noexcept -> Status
{
    // Transmit side first: transmit-only, so the kernel never queues a copy
    // of every frame of this ethertype for a socket that would only drain
    // and discard it.
    if (auto status = tx_.open(config.interface_name, config.ethertype, nullptr, config.qdisc_bypass, /*transmit_only=*/true);
        !status) {
        return status;
    }
    if (config.priority != 0) {
        if (auto status = tx_.set_priority(config.priority); !status) {
            return status;
        }
    }
    return rx_.open(config.interface_name, config.ethertype, nullptr, /*qdisc_bypass=*/false);
}

void RawnetPort::close() noexcept
{
    tx_.close();
    rx_.close();
    tx_pool_.reset();
    rx_pool_.reset();
}

auto RawnetPort::tx_start(int64_t const launch_time_ns) noexcept -> StatusValue<EthernetTxSlot>
{
    (void)launch_time_ns;  // AF_PACKET has no per-frame launch time.
    if (!tx_.valid()) {
        return failure(NetError::not_connected);
    }
    auto const handle = tx_pool_.take();
    if (!handle) {
        return failure(NetError::buffer_full);
    }
    return success(EthernetTxSlot{.handle = *handle, .buffer = std::span<uint8_t>{tx_pool_.buffers[*handle]}});
}

auto RawnetPort::tx_commit(uint64_t const handle, size_t const frame_length) noexcept -> Status
{
    if (!tx_.valid()) {
        return failure(NetError::not_connected);
    }
    if (handle >= TX_SLOTS || frame_length > ETHERNET_PORT_MIN_FRAME_BUFFER) {
        return failure(NetError::invalid_argument);
    }
    // The slot goes back whether or not the send went out: a frame the
    // kernel refused is not going to be retried from this buffer.
    auto const sent = tx_.send(std::span<uint8_t const>{tx_pool_.buffers[handle]}.first(frame_length));
    (void)tx_pool_.give_back(handle);
    if (!sent) {
        return failure(sent.error());
    }
    return success();
}

auto RawnetPort::tx_cancel(uint64_t const handle) noexcept -> Status
{
    return tx_pool_.give_back(handle) ? success() : failure(NetError::invalid_handle);
}

auto RawnetPort::rx_start() noexcept -> StatusValue<std::optional<EthernetRxSlot>>
{
    return rx_next([this] { return now_ns(); });
}

auto RawnetPort::rx_start(int64_t const now) noexcept -> StatusValue<std::optional<EthernetRxSlot>>
{
    return rx_next([now] { return now; });
}

template <typename Stamp>
auto RawnetPort::rx_next(Stamp const& stamp) noexcept -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (!rx_.valid()) {
        return failure(NetError::not_connected);
    }
    auto const handle = rx_pool_.take();
    if (!handle) {
        return failure(NetError::buffer_full);
    }
    auto const frame_length = receive_frame(*handle);
    if (!frame_length || *frame_length == 0) {
        (void)rx_pool_.give_back(*handle);
        return frame_length ? success(std::optional<EthernetRxSlot>{}) : failure(frame_length.error());
    }
    return success(std::optional<EthernetRxSlot>{EthernetRxSlot{
        .handle = *handle,
        .buffer = make_const_span(rx_pool_.buffers[*handle]).first(*frame_length),
        .timestamp_ns = stamp(),  // read only once a frame is there
    }});
}

auto RawnetPort::receive_frame(uint64_t const handle) noexcept -> StatusValue<size_t>
{
    auto& buffer = rx_pool_.buffers[handle];
    // RawnetContext hands back the payload with the L2 header stripped; the
    // header goes back in front so the slot holds a whole frame, as every
    // other port's does.
    ieee::EthernetFrame header{};
    auto const received = rx_.recv(&header.src_mac, &header.dest_mac, std::span<uint8_t>{buffer}.subspan(ETHERNET_HEADER_SIZE));
    if (!received || *received <= 0) {
        // Nothing queued is not an error; anything else is.
        bool const nothing = !received ? received.error() == NetError::would_block : true;
        return nothing ? success(size_t{0}) : failure(received.error());
    }
    header.ethertype = rx_.ethertype();
    return success(ieee::store_unchecked(std::span<uint8_t>{buffer}, header) + static_cast<size_t>(*received));
}

auto RawnetPort::now_ns() const noexcept -> int64_t
{
    return software_rx_timestamp_ns(rx_clock_id_);
}

auto RawnetPort::rx_release(uint64_t const handle) noexcept -> Status
{
    return rx_pool_.give_back(handle) ? success() : failure(NetError::invalid_handle);
}

}  // namespace statusbar::net
