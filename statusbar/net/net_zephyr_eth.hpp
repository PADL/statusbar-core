#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// ZephyrEthPort — EthernetPort backend for Zephyr (STM32H7 / NUCLEO-H753ZI).
///
/// Wraps Zephyr's net-stack packet API: raw AF_PACKET net_pkt TX (the full frame
/// incl. VLAN tag is sent verbatim) + promiscuous net_pkt RX carrying the MAC's
/// hardware RX timestamp. Copying, single-slot, heap-free.
///
/// This header is portable (no <zephyr/...>): it forward-declares net_if and the
/// implementation lives in net_zephyr_eth.cpp, compiled only on the board. The
/// static_assert verifies concept conformance wherever this header is included —
/// host CI included.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

struct net_if;
struct net_pkt;

namespace statusbar::net {

class ZephyrEthPort
{
  public:
    /// Resolve the iface (default if null), bring it up, read the MAC, enable
    /// promiscuous mode. Failure: std::errc::no_such_device.
    [[nodiscard]] static auto open(net_if* iface = nullptr) -> StatusValue<ZephyrEthPort>;

    [[nodiscard]] auto valid() const noexcept -> bool { return iface_ != nullptr; }
    [[nodiscard]] auto fd() const noexcept -> int { return -1; }
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return mac_; }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return if_index_; }

    /// NOTE: `launch_time_ns` (TSN/AVB launch-time TX scheduling) is currently
    /// IGNORED — frames are sent immediately. The STM32H7 ETH has no launch-time
    /// TX; a future zero-copy DMA backend could honor it. Consumers that depend
    /// on time-scheduled TX (e.g. an AVTP talker) must not assume it is applied.
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>;
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) -> Status;
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status;
    [[nodiscard]] auto tx_flush() -> Status;

    /// The next received frame, with the stack's stamp or @p now (the RX
    /// clock as the caller read it for this pass) when the stack gave none.
    [[nodiscard]] auto rx_start(RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status;

    [[nodiscard]] auto join_multicast(ieee::Eui48 const& mac) -> Status;
    void begin_cycle() noexcept {}
    [[nodiscard]] auto end_cycle() -> Status;

  private:
    /// @p pkt read into the one RX buffer and unreferenced: the slot, in use
    /// until rx_release().
    [[nodiscard]] auto take_packet(net_pkt* pkt, RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// @p pkt's first @p len bytes read into the RX buffer; the packet is
    /// unreferenced either way.
    [[nodiscard]] auto read_packet(net_pkt* pkt, size_t len) -> bool;

    net_if* iface_ = nullptr;
    ieee::Eui48 mac_{};
    unsigned int if_index_ = 0;
    EthernetFrameBuffer tx_buf_{};
    EthernetFrameBuffer rx_buf_{};
    bool tx_in_use_ = false;
    bool rx_in_use_ = false;
};

static_assert(EthernetPort<ZephyrEthPort>);

}  // namespace statusbar::net
