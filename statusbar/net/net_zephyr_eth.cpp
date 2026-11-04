// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_zephyr_eth.hpp"

#include <algorithm>

#if defined(__ZEPHYR__)

#    include <cstddef>
#    include <cstdint>

#    include <zephyr/net/ethernet.h>
#    include <zephyr/net/net_if.h>
#    include <zephyr/net/net_pkt.h>
#    include <zephyr/net/promiscuous.h>
#    include <zephyr/net/ptp_time.h>
#    include <zephyr/net/socket.h>  // AF_PACKET

namespace statusbar::net {

namespace {
constexpr uint64_t kSlotHandle = 1;
}  // namespace

auto ZephyrEthPort::open(net_if* iface) -> StatusValue<ZephyrEthPort>
{
    if (iface == nullptr) {
        iface = net_if_get_default();
    }
    if (iface == nullptr) {
        return failure(std::errc::no_such_device);
    }
    net_if_up(iface);

    ZephyrEthPort port;
    port.iface_ = iface;
    port.if_index_ = static_cast<unsigned int>(net_if_get_by_iface(iface));

    net_linkaddr* const la = net_if_get_link_addr(iface);
    if (la != nullptr && la->len == ieee::Eui48::LENGTH) {
        for (size_t i = 0; i < ieee::Eui48::LENGTH; ++i) {
            port.mac_.value[i] = la->addr[i];
        }
    }

    net_promisc_mode_on(iface);
    return port;  // StatusValue<ZephyrEthPort> constructed from the value
}

auto ZephyrEthPort::tx_start(int64_t /*launch_time_ns*/) -> StatusValue<EthernetTxSlot>
{
    if (tx_in_use_) {
        return failure(std::errc::device_or_resource_busy);
    }
    tx_in_use_ = true;
    return EthernetTxSlot{.handle = kSlotHandle, .buffer = std::span<uint8_t>(tx_buf_.storage)};
}

auto ZephyrEthPort::tx_commit(uint64_t handle, size_t frame_length) -> Status
{
    if (!tx_in_use_ || handle != kSlotHandle) {
        return failure(std::errc::invalid_argument);
    }
    if (frame_length < 14 || frame_length > tx_buf_.storage.size()) {
        tx_in_use_ = false;
        return failure(std::errc::invalid_argument);
    }

    // Raw L2: family AF_PACKET + no socket context => Zephyr's ethernet_send
    // takes the "raw packet, just send it" path and transmits our full frame
    // (dst|src|[VLAN]|ethertype|payload) verbatim — no header is prepended.
    net_pkt* const pkt = net_pkt_alloc_with_buffer(iface_, frame_length, AF_PACKET, static_cast<net_ip_protocol>(0), K_MSEC(100));
    if (pkt == nullptr) {
        tx_in_use_ = false;
        return failure(std::errc::not_enough_memory);
    }
    if (net_pkt_write(pkt, tx_buf_.storage.data(), frame_length) < 0) {
        net_pkt_unref(pkt);
        tx_in_use_ = false;
        return failure(std::errc::io_error);
    }
    // Rewind the read cursor to the start of the frame. Zephyr's ethernet_send
    // calls net_pkt_cursor_init() only on the cooked (header-filling) path; the
    // raw AF_PACKET "goto send" branch skips it, so without this the driver
    // reads from the post-write cursor (end of data) and transmits nothing.
    net_pkt_cursor_init(pkt);
    // net_if_queue_tx consumes the packet's reference (the stack unrefs after TX).
    // In Zephyr 4.x the function returns void; treat enqueue as unconditionally
    // successful (the driver will report TX errors via net events if needed).
    net_if_queue_tx(iface_, pkt);
    tx_in_use_ = false;
    return success();
}

auto ZephyrEthPort::tx_cancel(uint64_t handle) -> Status
{
    if (handle == kSlotHandle) {
        tx_in_use_ = false;
    }
    return success();
}

auto ZephyrEthPort::tx_flush() -> Status
{
    return success();  // net_if_queue_tx is immediate
}

auto ZephyrEthPort::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    return rx_start(rx_clock_now());
}

auto ZephyrEthPort::rx_start(RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (rx_in_use_) {
        return failure(std::errc::device_or_resource_busy);
    }
    net_pkt* const pkt = net_promisc_mode_wait_data(K_NO_WAIT);
    if (pkt == nullptr) {
        return std::optional<EthernetRxSlot>{std::nullopt};
    }
    return take_packet(pkt, now);
}

auto ZephyrEthPort::take_packet(net_pkt* const pkt, RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
{
    int64_t const stack_ns = static_cast<int64_t>(net_pkt_timestamp_ns(pkt));
    size_t const len = std::min(static_cast<size_t>(net_pkt_get_len(pkt)), rx_buf_.storage.size());
    if (!read_packet(pkt, len)) {
        return failure(std::errc::io_error);
    }
    rx_buf_.length = len;
    rx_in_use_ = true;
    return std::optional<EthernetRxSlot>{EthernetRxSlot{
        .handle = kSlotHandle,
        .buffer = std::span<uint8_t const>(rx_buf_.storage.data(), len),
        .timestamp_ns = stack_ns != 0 ? stack_ns : rx_timestamp_ns(now)}};
}

auto ZephyrEthPort::read_packet(net_pkt* const pkt, size_t const len) -> bool
{
    net_pkt_cursor_init(pkt);
    int const r = net_pkt_read(pkt, rx_buf_.storage.data(), len);
    net_pkt_unref(pkt);
    return r == 0;
}

auto ZephyrEthPort::rx_release(uint64_t handle) -> Status
{
    if (handle == kSlotHandle) {
        rx_in_use_ = false;
    }
    return success();
}

auto ZephyrEthPort::join_multicast(ieee::Eui48 const& /*mac*/) -> Status
{
    return success();  // promiscuous mode already receives all frames
}

auto ZephyrEthPort::end_cycle() -> Status
{
    return success();
}

}  // namespace statusbar::net

#endif  // __ZEPHYR__
