#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// BpfPortContext — cross-platform copy-based EthernetPort for dev/testing.
/// Uses AF_PACKET/SOCK_RAW on Linux, /dev/bpfN on macOS.
/// NOT suitable for real-time; frames are copied and sent immediately on commit.
/// Satisfies the EthernetPort concept.

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>

#include <net/if.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#    include <arpa/inet.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <sys/socket.h>
#elif defined(__APPLE__)
#    include <ifaddrs.h>

#    include <net/bpf.h>
#    include <net/if_dl.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#    include <sys/types.h>
#endif

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/status/status.hpp"

#include <algorithm>
#include <array>
#include <expected>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace statusbar::net {

/// Configuration for BpfPortContext
struct BpfPortConfig
{
    std::string_view interface_name;
    uint16_t ethertype{0};        ///< Kernel-level ethertype filter (0 = all)
    size_t frame_pool_size{256};  ///< Number of internal frame buffers
};

/// Cross-platform copy-based EthernetPort using BPF (macOS) or AF_PACKET (Linux).
///
/// Implements direct raw socket I/O with internal frame buffer pooling.
/// Frames are copied and sent immediately on tx_commit() (no batching).
/// Satisfies the EthernetPort concept.
///
/// Move-only. Not thread-safe.
class BpfPortContext
{
  public:
    BpfPortContext() = default;

    ~BpfPortContext() { close(); }

    // Move-only
    BpfPortContext(BpfPortContext&& other) noexcept { swap(other); }

    auto operator=(BpfPortContext&& other) noexcept -> BpfPortContext&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    BpfPortContext(BpfPortContext const&) = delete;
    auto operator=(BpfPortContext const&) -> BpfPortContext& = delete;

    //
    // Lifecycle
    //

    /// @param config Configuration specifying interface, ethertype filter, and pool size
    /// @param memory_resource Memory resource for internal pool/free-list/
    ///        launch-times (and the bpf_read_buffer on macOS). nullptr →
    ///        std::pmr::get_default_resource().
    [[nodiscard]] auto open(BpfPortConfig const& config, std::pmr::memory_resource* memory_resource = nullptr) -> Status;

    void close() noexcept;

    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }

    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return hardware_address_; }

    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return if_index_; }

    //
    // TX API
    //

    /// @param launch_time_ns TSN/AVB launch time in nanoseconds (0 for immediate send)
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>
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

    /// @param handle Opaque slot handle from tx_start()
    /// @param len Number of bytes written to the TX buffer
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t len) -> Status;

    /// @param handle Opaque slot handle from tx_start()
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status
    {
        if (handle >= pool_.size()) {
            return failure(NetError::invalid_handle);
        }
        free_list_.push_back(handle);
        return success();
    }

    [[nodiscard]] auto tx_flush() -> Status { return success(); }

    //
    // RX API
    //

    /// The next received frame. Linux (AF_PACKET) stamps it @p now, the RX
    /// clock as the caller read it for this pass; macOS keeps the BPF
    /// header's stamp, the kernel's wall clock in microseconds.
    [[nodiscard]] auto rx_start(RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;

    /// @param handle Opaque slot handle from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status
    {
        if (handle >= pool_.size()) {
            return failure(NetError::invalid_handle);
        }
        free_list_.push_back(handle);
        return success();
    }

    //
    // Multicast
    //

    /// @param addr Multicast MAC address to join
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;

    //
    // Per-cycle housekeeping (no-ops)
    //

    void begin_cycle() noexcept {}

    [[nodiscard]] auto end_cycle() -> Status { return success(); }

  private:
    void swap(BpfPortContext& other) noexcept;

#if defined(__linux__)
    /// One recv into the slot @p handle: the frame length, 0 when nothing
    /// was queued.
    [[nodiscard]] auto receive_frame(uint64_t handle) -> StatusValue<size_t>;
    /// The slot at the top of the free list, taken, holding a frame of
    /// @p length stamped @p now.
    [[nodiscard]] auto take_slot(size_t length, RxTimePoint now) -> EthernetRxSlot;
#elif defined(__APPLE__)
    /// One packet of the BPF read buffer: where its frame starts, how much
    /// of it was captured, and the kernel's stamp.
    struct BpfPacket
    {
        uint8_t const* data;
        size_t caplen;
        int64_t timestamp_ns;
    };
    [[nodiscard]] auto buffered_bpf_header() const -> struct bpf_hdr const*;
    [[nodiscard]] auto next_buffered_packet() -> std::optional<BpfPacket>;
    [[nodiscard]] auto next_buffered_frame() -> std::optional<EthernetRxSlot>;
    [[nodiscard]] auto copy_into_slot(BpfPacket const& packet) -> EthernetRxSlot;
    [[nodiscard]] auto fill_read_buffer() -> StatusValue<bool>;
#endif

    /// Allocate the internal frame pool and free list.
    /// @param pool_size Number of frame buffers to allocate
    void allocate_pool(size_t pool_size)
    {
        pool_.resize(pool_size);
        launch_times_.resize(pool_size, 0);
        free_list_.reserve(pool_size);
        for (size_t i = pool_size; i > 0; --i) {
            free_list_.push_back(static_cast<uint64_t>(i - 1));
        }
    }

    int fd_{-1};
    ieee::Eui48 hardware_address_{};
    unsigned int if_index_{0};
    uint16_t ethertype_{0};

    std::pmr::memory_resource* mem_resource_{std::pmr::get_default_resource()};

    /// Frame buffer pool
    std::pmr::vector<std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>> pool_{mem_resource_};

    /// Free list stack of available pool indices
    std::pmr::vector<uint64_t> free_list_{mem_resource_};

    /// Per-slot launch times (indexed by pool index)
    std::pmr::vector<int64_t> launch_times_{mem_resource_};

#if defined(__APPLE__)
    /// BPF buffer length from BIOCGBLEN
    size_t bpf_buf_len_{0};

    /// Internal BPF read buffer
    std::pmr::vector<uint8_t> bpf_read_buffer_{mem_resource_};
    size_t bpf_read_offset_{0};
    size_t bpf_read_length_{0};
#endif
};

/// Verify BpfPortContext satisfies the EthernetPort concept at compile time
static_assert(EthernetPort<BpfPortContext>, "BpfPortContext must satisfy EthernetPort concept");

}  // namespace statusbar::net
