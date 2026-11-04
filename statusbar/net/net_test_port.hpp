#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TestPortContext — pure userspace, fully cross-platform EthernetPort backend
/// for synthetic offline testing. No kernel interfaces, no stubs needed.
/// Satisfies the EthernetPort concept.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/status/status.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory_resource>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

namespace statusbar::net {

/// Configuration for TestPortContext
struct TestPortConfig
{
    ieee::Eui48 hardware_address{};
    unsigned int interface_index{1};
    size_t frame_pool_size{256};
};

/// Pure userspace Ethernet port for use in unit tests.
///
/// Supports injection of synthetic RX frames via inject_rx() and inspection
/// of transmitted frames via pop_tx(). All operations are synchronous and
/// in-process. No file descriptors, sockets, or kernel interfaces are used.
///
/// Satisfies the EthernetPort concept.
class TestPortContext
{
  public:
    /// Captured TX frame with its TSN launch time.
    ///
    /// `frame` is a fixed-capacity inline buffer (EthernetFrameBuffer) rather
    /// than a std::vector, so capturing a TX does not heap-allocate.
    struct TxCapture
    {
        EthernetFrameBuffer frame;
        int64_t launch_time_ns;
    };

    TestPortContext() = default;

    ~TestPortContext() { close(); }

    // Move-only semantics
    TestPortContext(TestPortContext&&) noexcept = default;
    auto operator=(TestPortContext&&) noexcept -> TestPortContext& = default;
    TestPortContext(TestPortContext const&) = delete;
    auto operator=(TestPortContext const&) -> TestPortContext& = delete;

    //
    // Lifecycle
    //

    /// Open the test port with the given configuration
    /// @param config Configuration specifying MAC address, interface index, and pool size
    /// @param memory_resource Memory resource for internal pool/free-list/capture
    ///        vectors. nullptr → std::pmr::get_default_resource().
    [[nodiscard]] auto open(TestPortConfig const& config, std::pmr::memory_resource* memory_resource = nullptr) -> Status;

    /// Close the test port and release all resources
    void close() noexcept;

    /// Returns true after open(), false after close()
    [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }

    /// Always returns -1 (no real file descriptor)
    [[nodiscard]] auto fd() const noexcept -> int { return -1; }

    /// Get the configured hardware (MAC) address
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return hardware_address_; }

    /// Get the configured interface index
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return interface_index_; }

    //
    // TX API
    //

    /// Start a TX operation. Pops a slot from the free list and records launch_time_ns.
    /// Returns failure with no_buffer_space if pool is exhausted.
    /// @param launch_time_ns TSN/AVB launch time in nanoseconds (stored for inspection)
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>;

    /// Commit a TX slot. Copies len bytes from the pool buffer into a TxCapture
    /// along with the stored launch_time_ns, then returns the slot to the free list.
    /// @param handle Opaque pool index from tx_start()
    /// @param len Number of bytes written to the TX buffer
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t len) -> Status;

    /// Cancel a TX slot, returning it to the free list without transmitting.
    /// @param handle Opaque pool index from tx_start()
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status;

    /// No-op flush (all TX is synchronous in TestPortContext).
    [[nodiscard]] auto tx_flush() -> Status { return success(); }

    //
    // RX API
    //

    /// Start an RX operation. Returns nullopt if no frames are pending.
    /// Pops the front frame from the RX queue and returns an EthernetRxSlot
    /// carrying the stamp it was injected with, or @p now when that was 0.
    [[nodiscard]] auto rx_start(RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;

    /// Release an RX slot back to the free list.
    /// @param handle Opaque pool index from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status;

    //
    // Multicast
    //

    /// Records the multicast address (no actual hardware filtering).
    /// @param mac Multicast MAC address to record
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& mac) -> Status;

    //
    // Per-cycle housekeeping (no-ops)
    //

    void begin_cycle() noexcept {}

    [[nodiscard]] auto end_cycle() -> Status { return success(); }

    //
    // Test harness API (not part of EthernetPort concept)
    //

    /// Inject a synthetic RX frame into the port's receive queue.
    /// Copies frame data into a pool slot and enqueues it.
    /// Returns failure with no_buffer_space if pool is exhausted.
    /// @param frame Ethernet frame data to inject
    /// @param timestamp_ns Simulated capture timestamp in nanoseconds
    [[nodiscard]] auto inject_rx(std::span<uint8_t const> frame, int64_t timestamp_ns = 0) -> Status;

    /// Returns the number of RX frames pending in the receive queue.
    [[nodiscard]] auto rx_pending() const noexcept -> size_t { return rx_queue_.size(); }

    /// Returns the number of TX captures pending (committed but not yet popped).
    [[nodiscard]] auto tx_pending() const noexcept -> size_t { return tx_captures_.size(); }

    /// Pop and return the oldest captured TX frame, or nullopt if none.
    [[nodiscard]] auto pop_tx() -> std::optional<TxCapture>;

    /// Returns the list of multicast groups joined so far.
    [[nodiscard]] auto joined_multicast_groups() const noexcept -> std::span<ieee::Eui48 const>
    {
        return std::span<ieee::Eui48 const>(joined_multicast_.data(), joined_multicast_.size());
    }

  private:
    struct RxEntry
    {
        uint64_t pool_index;
        size_t frame_length;
        int64_t timestamp_ns;
    };

    bool valid_{false};
    ieee::Eui48 hardware_address_{};
    unsigned int interface_index_{1};

    std::pmr::memory_resource* mem_resource_{std::pmr::get_default_resource()};

    /// Frame buffer pool — each slot holds one full-sized Ethernet frame
    std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>> pool_{mem_resource_};

    /// Per-slot launch times (indexed by pool index)
    std::pmr::vector<int64_t> launch_times_{mem_resource_};

    /// Free list — stack of available pool indices
    std::pmr::vector<uint64_t> free_list_{mem_resource_};

    /// Pending RX frames (FIFO)
    std::pmr::vector<RxEntry> rx_queue_{mem_resource_};

    /// Committed TX frames waiting to be inspected by the test
    std::pmr::vector<TxCapture> tx_captures_{mem_resource_};

    /// Multicast groups registered via join_multicast()
    std::pmr::vector<ieee::Eui48> joined_multicast_{mem_resource_};
};

/// Verify TestPortContext satisfies the EthernetPort concept at compile time
static_assert(EthernetPort<TestPortContext>, "TestPortContext must satisfy EthernetPort concept");

}  // namespace statusbar::net
