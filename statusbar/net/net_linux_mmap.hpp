#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Linux PACKET_MMAP module for statusbar.net
/// Provides zero-copy Ethernet frame transmission and reception using AF_PACKET with memory-mapped ring buffers.
/// This module is Linux-specific and uses TPACKET_V2 for wide compatibility.

#if defined(__linux__)

#    include <fcntl.h>
#    include <poll.h>
#    include <unistd.h>

#    include <cerrno>
#    include <cstring>
#    include <ctime>

#    include <arpa/inet.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <net/if.h>
#    include <sys/ioctl.h>
#    include <sys/mman.h>
#    include <sys/socket.h>

#endif  // __linux__

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/status/status.hpp"
#include "statusbar/status/throw_or_abort.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace statusbar::net {

/// Constants for PACKET_MMAP ring buffer configuration
inline constexpr size_t MMAP_FRAME_SIZE = 2048;        ///< Size of each frame slot (tpacket2_hdr + data)
inline constexpr size_t MMAP_MAX_FRAME_LENGTH = 1522;  ///< Maximum Ethernet frame with QinQ VLAN
inline constexpr size_t MMAP_MIN_FRAME_LENGTH = 64;    ///< IEEE 802.3 minimum frame size

/// What a PACKET_MMAP send may exceed the device MTU by: the Ethernet header
/// and one 802.1Q tag. af_packet's limit is mtu + hard_header_len + VLAN_HLEN.
inline constexpr size_t MMAP_TX_MTU_OVERHEAD = 14 + 4;

/// The longest frame tx_commit() takes on a device with @p mtu: the slot's
/// MMAP_MAX_FRAME_LENGTH, or less where the MTU allows less. The kernel
/// refuses a longer send with EMSGSIZE and leaves its slot
/// TP_STATUS_WRONG_FORMAT at the head of the ring, where it stops: nothing
/// committed after it is sent until the socket closes. So the bound is
/// applied here, before the kernel sees the frame.
[[nodiscard]] constexpr auto mmap_max_tx_frame_length(size_t const mtu) noexcept -> size_t
{
    size_t const kernel_limit = mtu + MMAP_TX_MTU_OVERHEAD;
    return kernel_limit < MMAP_MAX_FRAME_LENGTH ? kernel_limit : MMAP_MAX_FRAME_LENGTH;
}

/// Error codes specific to MMAP operations
enum class MmapError
{
    socket_creation_failed = 1,
    interface_not_found,
    bind_failed,
    set_nonblocking_failed,
    set_priority_failed,
    get_hwaddr_failed,
    set_packet_version_failed,
    join_multicast_failed,
    allocate_ring_failed,
    mmap_failed,
    not_open,
    tx_ring_full,
    rx_ring_empty,
    invalid_index,
    not_supported_on_platform,
    frame_too_long,
};

/// Error category for MmapError
class MmapErrorCategory : public std::error_category
{
  public:
    [[nodiscard]] auto name() const noexcept -> char const* override { return "statusbar.net.mmap"; }

    /// @param ev Error code value to convert to a message string
    [[nodiscard]] auto message(int ev) const -> std::string override;
};

/// Get the singleton MmapError category instance
[[nodiscard]] auto mmap_error_category() noexcept -> std::error_category const&;

/// Create an error_code from a MmapError
/// @param e The MmapError value to convert
[[nodiscard]] auto make_error_code(MmapError e) noexcept -> std::error_code;

/// Configuration for MmapContext
struct MmapConfig
{
    std::string_view interface_name;  ///< Network interface name (e.g., "eth0")
    uint16_t ethertype{0};            ///< Ethertype filter (0 = all)
    uint32_t priority{0};             ///< Socket priority for QoS
    size_t rx_queue_size{256};        ///< Number of RX frame slots (sized for burst headroom)
    size_t tx_queue_size{256};        ///< Number of TX frame slots (sized for burst headroom)
};

}  // namespace statusbar::net

/// Register MmapError as an error code enum
template <>
struct std::is_error_code_enum<statusbar::net::MmapError> : std::true_type
{};

namespace statusbar::net {

#if defined(__linux__)

// Linux-specific constants and helpers

/// Get the system page size (cached after first call)
[[nodiscard]] inline auto get_page_size() noexcept -> size_t
{
    static size_t const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    return page_size;
}

/// Get the MMAP block size (must be >= page size and hold at least one frame)
[[nodiscard]] inline auto get_mmap_block_size() noexcept -> size_t
{
    size_t const page_size = get_page_size();
    // Block size must be at least page size and large enough for one frame
    return page_size >= MMAP_FRAME_SIZE ? page_size : MMAP_FRAME_SIZE;
}

/// Get frames per block based on runtime block size
[[nodiscard]] inline auto get_frames_per_block() noexcept -> size_t
{
    return get_mmap_block_size() / MMAP_FRAME_SIZE;
}

///
/// MmapContext provides zero-copy Ethernet frame TX/RX using Linux PACKET_MMAP.
///
/// This class implements a start/end pattern for zero-copy buffer access:
/// - TX: tx_start() returns a buffer slot, caller fills it, tx_commit() sends it
/// - RX: rx_start() returns received data, rx_release() returns buffer to kernel
///
/// The context manages memory-mapped ring buffers shared with the kernel,
/// enabling efficient packet processing without data copies.
///
class MmapContext
{
  public:
    MmapContext() = default;

    ~MmapContext() { close(); }

    // Move-only semantics
    MmapContext(MmapContext&& other) noexcept { swap(other); }

    auto operator=(MmapContext&& other) noexcept -> MmapContext&
    {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    MmapContext(MmapContext const&) = delete;
    auto operator=(MmapContext const&) -> MmapContext& = delete;

    /// Open the PACKET_MMAP context with the given configuration
    /// @param config Configuration specifying interface, ethertype, queue sizes, and priority
    [[nodiscard]] auto open(MmapConfig const& config) -> Status;

    /// Close the context and release all resources
    auto close() noexcept -> void;

    /// Check if the context is open and valid
    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// Get the underlying file descriptor (for poll/epoll integration)
    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }

    /// Get the hardware (MAC) address of the interface
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return hardware_address_; }

    /// Get the interface index
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return if_index_; }

    /// The longest frame tx_commit() takes, and the size of the buffer
    /// tx_start() hands out: mmap_max_tx_frame_length() of the interface's
    /// MTU as read at open(), MMAP_MAX_FRAME_LENGTH before open and on a
    /// device that will not say.
    [[nodiscard]] auto max_tx_frame_length() const noexcept -> size_t { return max_tx_frame_length_; }

    //
    // TX API - Zero-copy transmit using start/commit/cancel pattern
    //

    /// Start a TX operation, returning a buffer slot to fill.
    /// The launch_time_ns parameter is used for hardware TX scheduling (TSN/AVB).
    /// If the TX ring is full, returns failure with MmapError::tx_ring_full.
    /// @param launch_time_ns TSN/AVB launch time in nanoseconds (0 for immediate send)
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>;

    /// Commit a TX slot for transmission.
    /// The frame_length is the total frame size including Ethernet header (min 64 bytes).
    /// A frame longer than max_tx_frame_length() is refused with
    /// MmapError::frame_too_long and its slot given back as tx_cancel()
    /// gives one back, so the refusal costs the caller that frame and
    /// nothing committed after it.
    /// @param handle Opaque slot handle from tx_start()
    /// @param frame_length Total frame size including Ethernet header (minimum 64 bytes)
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) -> Status;

    /// Cancel a TX slot, returning it to available state. It is the next
    /// slot tx_start() hands out: the kernel sends the ring in order and
    /// stops at the first slot that is not a send request, so a cancelled
    /// slot left behind the index would hold every later frame until the
    /// index came round to fill it.
    /// @param handle The handle from the last tx_start(); any other is
    ///        refused with MmapError::invalid_index.
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status;

    /// Flush pending TX frames to the kernel.
    /// This kicks the kernel to actually transmit queued frames.
    [[nodiscard]] auto tx_flush() -> Status;

    //
    // RX API - Zero-copy receive using start/release pattern
    //

    /// Start an RX operation, returning received frame data if available.
    /// Returns std::nullopt wrapped in StatusValue if no frame is ready.
    /// The slot is stamped @p now, the RX clock as the caller read it for
    /// this pass. The kernel's own stamp (tp_sec/tp_nsec) is on
    /// CLOCK_REALTIME, not the RX clock, and is not handed on.
    [[nodiscard]] auto rx_start(RxTimePoint now) -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;

    /// Release an RX slot back to the kernel for reuse.
    /// @param handle Opaque slot handle from rx_start()
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status;

    //
    // Multicast support
    //

    /// Join a multicast group to receive frames sent to the given address.
    /// @param addr Multicast MAC address to join
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;

    /// Drop a multicast group membership taken with join_multicast().
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const& addr) -> Status;

    //
    // Per-cycle housekeeping
    //

    void begin_cycle() noexcept {}

    [[nodiscard]] auto end_cycle() -> Status { return success(); }

  private:
    void swap(MmapContext& other) noexcept;

    /// Get pointer to TX tpacket2_hdr at given index.
    /// Alignment: tx_ring_ is page-aligned (from mmap) and tp_frame_size is
    /// TPACKET_ALIGN'd by the kernel, so the resulting pointer satisfies
    /// tpacket2_hdr alignment requirements.
    [[nodiscard]] auto tx_header_at(size_t index) noexcept -> tpacket2_hdr*
    {
        auto* base = static_cast<uint8_t*>(tx_ring_);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<tpacket2_hdr*>(base + (index * tx_req_.tp_frame_size));
    }

    /// Get pointer to RX tpacket2_hdr at given index.
    /// Alignment: same as tx_header_at — page-aligned base + TPACKET_ALIGN'd stride.
    [[nodiscard]] auto rx_header_at(size_t index) noexcept -> tpacket2_hdr*
    {
        auto* base = static_cast<uint8_t*>(rx_ring_);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<tpacket2_hdr*>(base + (index * rx_req_.tp_frame_size));
    }

    /// Get pointer to TX payload at given header.
    /// For SOCK_RAW with TPACKET_V2, data starts at TPACKET_ALIGN(sizeof(tpacket2_hdr)).
    /// The TPACKET_ALIGN macro ensures the offset satisfies the kernel's alignment contract.
    [[nodiscard]] static auto tx_payload(tpacket2_hdr* hdr) noexcept -> uint8_t*
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<uint8_t*>(hdr) + TPACKET_ALIGN(sizeof(tpacket2_hdr));
    }

    /// Get pointer to RX payload at given header.
    /// tp_mac offset is set by the kernel and points to the Ethernet header within the frame.
    [[nodiscard]] static auto rx_payload(tpacket2_hdr* hdr) noexcept -> uint8_t const*
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<uint8_t const*>(hdr) + hdr->tp_mac;
    }

    // Internal state
    int fd_{-1};
    ieee::Eui48 hardware_address_{};
    unsigned int if_index_{0};
    uint16_t ethertype_{0};

    // Ring buffer memory
    void* ring_memory_{nullptr};
    size_t ring_memory_size_{0};

    // TX ring state
    void* tx_ring_{nullptr};
    tpacket_req tx_req_{};
    size_t tx_index_{0};
    uint64_t tx_slot_in_use_{UINT64_MAX};                // Handle of slot from tx_start(), or UINT64_MAX if none
    size_t max_tx_frame_length_{MMAP_MAX_FRAME_LENGTH};  // see max_tx_frame_length()

    // RX ring state
    void* rx_ring_{nullptr};
    tpacket_req rx_req_{};
    size_t rx_index_{0};
};

#else  // !__linux__

// Stub class for non-Linux platforms
// All operations will fail with not_supported_on_platform

class MmapContext
{
  public:
    [[nodiscard]] auto open(MmapConfig const&) -> Status { return failure(MmapError::not_supported_on_platform); }
    void close() noexcept {}
    [[nodiscard]] auto valid() const noexcept -> bool { return false; }
    [[nodiscard]] auto fd() const noexcept -> int { return -1; }
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const&
    {
        static ieee::Eui48 const empty{};
        return empty;
    }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int { return 0; }
    [[nodiscard]] auto max_tx_frame_length() const noexcept -> size_t { return MMAP_MAX_FRAME_LENGTH; }
    [[nodiscard]] auto tx_start(int64_t = 0) -> StatusValue<EthernetTxSlot>
    {
        return failure(MmapError::not_supported_on_platform);
    }
    [[nodiscard]] auto tx_commit(uint64_t, size_t) -> Status { return failure(MmapError::not_supported_on_platform); }
    [[nodiscard]] auto tx_cancel(uint64_t) -> Status { return failure(MmapError::not_supported_on_platform); }
    [[nodiscard]] auto tx_flush() -> Status { return failure(MmapError::not_supported_on_platform); }
    [[nodiscard]] auto rx_start(RxTimePoint) -> StatusValue<std::optional<EthernetRxSlot>>
    {
        return failure(MmapError::not_supported_on_platform);
    }
    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
    {
        return failure(MmapError::not_supported_on_platform);
    }
    [[nodiscard]] auto rx_release(uint64_t) -> Status { return failure(MmapError::not_supported_on_platform); }
    [[nodiscard]] auto join_multicast(ieee::Eui48 const&) -> Status { return failure(MmapError::not_supported_on_platform); }
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const&) -> Status { return failure(MmapError::not_supported_on_platform); }
    void begin_cycle() noexcept {}
    [[nodiscard]] auto end_cycle() -> Status { return failure(MmapError::not_supported_on_platform); }
};

#endif  // __linux__

/// RAII wrapper that opens MmapContext on construction, throws on failure
struct MmapContextOpen
{
    /// @param ctx MmapContext to open
    /// @param config Configuration for the PACKET_MMAP context
    explicit MmapContextOpen(MmapContext& ctx, MmapConfig const& config)
    {
        if (auto status = ctx.open(config); !status) {
            throw_or_abort(status.error());
        }
    }
};

}  // namespace statusbar::net
