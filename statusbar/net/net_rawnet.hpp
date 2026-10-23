#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Raw Ethernet (Layer 2) socket utilities
/// Provides RawnetContext for sending/receiving raw Ethernet frames
/// Supports Linux (AF_PACKET) and macOS (BPF)

#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <net/if.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#    include <arpa/inet.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <sys/socket.h>
#elif defined(__APPLE__)
#    include <fcntl.h>
#    include <ifaddrs.h>

#    include <net/bpf.h>
#    include <net/if_dl.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#endif

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_socket.hpp"
#include "statusbar/sg14/inplace_function.h"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace statusbar::net {

using ieee::Eui48;

/// Maximum Ethernet frame size (standard MTU + headers, no VLAN)
inline constexpr size_t MAX_ETHERNET_FRAME_SIZE = 1514;

/// Maximum Ethernet frame size with VLAN tag (MTU + headers + VLAN tag)
inline constexpr size_t MAX_ETHERNET_FRAME_SIZE_VLAN = 1518;

/// Maximum Ethernet frame size with double VLAN (QinQ)
inline constexpr size_t MAX_ETHERNET_FRAME_SIZE_QINQ = 1522;

/// Minimum Ethernet frame size (excluding FCS)
inline constexpr size_t MIN_ETHERNET_FRAME_SIZE = 60;

/// Ethernet header size (dest MAC + src MAC + ethertype) — from ieee::protocols
using ieee::protocols::ETHERNET_HEADER_SIZE;

/// VLAN tag size (TPID + TCI)
inline constexpr size_t VLAN_TAG_SIZE = 4;

/// Maximum payload size (standard MTU)
inline constexpr size_t MAX_ETHERNET_PAYLOAD = 1500;

/// Maximum payload size including VLAN tag bytes that appear in payload
/// When receiving VLAN-tagged frames, the kernel may include the VLAN tag
/// in the payload depending on configuration
inline constexpr size_t MAX_ETHERNET_PAYLOAD_WITH_VLAN = 1504;

/// Context for raw Ethernet socket operations
/// Provides platform-independent interface for Layer 2 networking
class RawnetContext
{
  public:
    RawnetContext() noexcept = default;
    ~RawnetContext() noexcept { close(); }

    // No copy
    RawnetContext(RawnetContext const&) = delete;
    auto operator=(RawnetContext const&) -> RawnetContext& = delete;

    // Move allowed
    RawnetContext(RawnetContext&& other) noexcept
        : fd_{other.fd_}
        , ethertype_{other.ethertype_}
        , interface_index_{other.interface_index_}
        , my_mac_{other.my_mac_}
        , default_dest_mac_{other.default_dest_mac_}
        , transmit_only_{other.transmit_only_}
        , tx_tap_{std::move(other.tx_tap_)}
#if defined(__APPLE__)
        , bpf_buffer_size_{other.bpf_buffer_size_}
#endif
    {
        other.fd_ = -1;
        other.interface_index_ = -1;
        other.tx_tap_ = {};
    }

    auto operator=(RawnetContext&& other) noexcept -> RawnetContext&;

    /// Open a raw Ethernet socket
    /// @param interface_name Network interface name (e.g., "en0", "eth0")
    /// @param ethertype EtherType to filter/use (e.g., 0x88f7 for gPTP)
    /// @param multicast_mac Optional multicast MAC address to join (nullptr = none)
    /// @param qdisc_bypass Set PACKET_QDISC_BYPASS for lower TX latency. OFF by
    ///        default. Note: bypass does NOT drop frames — they still reach the
    ///        wire — but it skips the egress tap, so bypass frames are invisible
    ///        to tcpdump/AF_PACKET on the *sending* host. Default-off keeps local
    ///        capture working; enable only for latency-critical TX.
    /// @param transmit_only Open a socket that only sends and never receives
    ///        (Linux: an AF_PACKET socket of protocol 0, never bound). A
    ///        multicast_mac is then only the default destination, not joined.
    ///        Use it for every socket nobody reads (a stream talker): an
    ///        unread receiving socket is handed, and drops, a copy of every
    ///        frame of its ethertype. join_multicast, leave_multicast and
    ///        set_subtype_filter then refuse (invalid_argument): joining binds
    ///        the socket, which would hook it, unfiltered, into delivery.
    /// @return Status indicating success or failure
    [[nodiscard]] auto open(
        std::string_view interface_name,
        uint16_t ethertype,
        Eui48 const* multicast_mac = nullptr,
        bool qdisc_bypass = false,
        bool transmit_only = false) noexcept -> Status;

    /// Narrow reception to frames of this socket's ethertype whose first
    /// payload byte (the AVTP subtype, for 0x22F0) is in @p subtypes,
    /// untagged or under one 802.1Q tag. Replaces the ethertype-only kernel
    /// filter open() attached; an empty set restores it. On a shared
    /// ethertype it keeps, for example, an ATDECC socket from being woken by
    /// every AVB stream frame on the segment. Linux only: elsewhere a no-op
    /// success (receivers still check the subtype themselves).
    /// Frames already queued when it is attached stay queued (the kernel does
    /// not refilter them), so a receiver still checks the subtype.
    /// @return invalid_argument for more than rawnet_filter::MAX_SUBTYPES
    ///         (8) subtypes or on a transmit_only socket; the setsockopt errno
    ///         on failure
    [[nodiscard]] auto set_subtype_filter(std::span<uint8_t const> subtypes) const noexcept -> Status;

    /// Close the socket
    void close() noexcept;

    /// Send a raw Ethernet frame including ethernet header.
    /// @param full_frame Full frame data (with Ethernet header)
    /// @return Number of bytes sent, or error
    [[nodiscard]] auto send(std::span<uint8_t const> full_frame) const noexcept -> StatusValue<ssize_t>;

    /// Send an Ethernet frame
    /// @param dest_mac Destination MAC address (nullptr = use default)
    /// @param payload Payload data (without Ethernet header)
    /// @return Number of bytes sent, or error
    [[nodiscard]] auto send(Eui48 const* dest_mac, std::span<uint8_t const> payload) noexcept -> StatusValue<ssize_t>;

    /// Send an Ethernet frame carrying a single 802.1Q VLAN tag.
    ///
    /// AVB stream (AVTP) frames MUST be VLAN-tagged with the SR class VID and the
    /// SR class priority in the PCP field: bridges classify a frame into an SR
    /// class (and its credit-based shaper / reserved bandwidth) by the PCP of its
    /// VLAN tag, and per IEEE 802.1Q an untagged frame is not part of any SR
    /// class. The frame is built as
    /// [dst][src][TPID=0x8100][TCI=pcp<<13|vid][ethertype][payload].
    ///
    /// @param dest_mac Destination MAC address (nullptr = use default)
    /// @param payload Payload data (without Ethernet header or VLAN tag)
    /// @param vlan_id 12-bit VLAN ID (VID)
    /// @param pcp 3-bit priority code point (SR class priority)
    /// @return Number of payload bytes sent, or error
    [[nodiscard]] auto send_vlan(Eui48 const* dest_mac, std::span<uint8_t const> payload, uint16_t vlan_id, uint8_t pcp) noexcept
        -> StatusValue<ssize_t>;

    /// Receive an Ethernet frame
    /// @param src_mac Output: source MAC address
    /// @param dest_mac Output: destination MAC address
    /// @param payload_buf Buffer to receive payload (without Ethernet header)
    /// @return Number of payload bytes received, or error
    [[nodiscard]] auto recv(Eui48* src_mac, Eui48* dest_mac, std::span<uint8_t> payload_buf) noexcept -> StatusValue<ssize_t>;

    /// Join a multicast group
    /// @param multicast_mac Multicast MAC address to join
    /// @return Status indicating success or failure
    [[nodiscard]] auto join_multicast(Eui48 const& multicast_mac) const noexcept -> Status;

    /// Leave a multicast group previously joined with join_multicast().
    /// Symmetric to join_multicast (PACKET_DROP_MEMBERSHIP on Linux). Used to
    /// release a remote talker's stream group when a listener disconnects, so
    /// per-connection dest-MAC churn (e.g. a Meyer Galaxy) does not accumulate
    /// stale NIC multicast filter entries.
    /// @param multicast_mac Multicast MAC address to leave
    /// @return Status indicating success or failure
    [[nodiscard]] auto leave_multicast(Eui48 const& multicast_mac) const noexcept -> Status;

    /// Set the socket's priority (SO_PRIORITY), the skb->priority of every
    /// frame it sends.
    ///
    /// This is what steers a PACKET_QDISC_BYPASS socket onto a hardware TX
    /// queue: bypass frames skip every software qdisc, and the kernel picks
    /// their queue from skb->priority through the netdev's priority-to-traffic-
    /// class map (which an mqprio root installs, even in software mode) and that
    /// class's queue range. With priority 0 they land on a best-effort queue,
    /// whatever PCP their VLAN tag carries. Priorities 0-6 need no privilege;
    /// 7 and above need CAP_NET_ADMIN. Linux only: elsewhere a no-op success.
    /// @return the setsockopt errno on failure; bad_file_descriptor when not open
    [[nodiscard]] auto set_priority(int priority) noexcept -> Status;

    /// Check if the socket is valid
    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// Get the file descriptor
    [[nodiscard]] auto fd() const noexcept -> int { return fd_; }

    /// Get the EtherType
    [[nodiscard]] auto ethertype() const noexcept -> uint16_t { return ethertype_; }

    /// Get the interface index
    [[nodiscard]] auto interface_index() const noexcept -> int { return interface_index_; }

    /// Get our MAC address
    [[nodiscard]] auto my_mac() const noexcept -> Eui48 const& { return my_mac_; }

    /// Get the default destination MAC address
    [[nodiscard]] auto default_dest_mac() const noexcept -> Eui48 const& { return default_dest_mac_; }

    /// Set the default destination MAC address
    /// @param mac MAC address to use as the default destination
    void set_default_dest_mac(Eui48 const& mac) noexcept { default_dest_mac_ = mac; }

    /// Optional egress tap. When set, it is invoked with the EXACT bytes handed to
    /// sendto (full L2 frame, VLAN tag included) on every successful send_vlan().
    /// This is the only way to observe a PACKET_QDISC_BYPASS stream's own egress
    /// (a co-located capture never sees it). The callback runs inline on the
    /// caller's thread -- which for the stream TX path is the media-timer RT thread
    /// -- so it MUST be non-blocking (e.g. an in-memory recorder). Cleared by
    /// default; passing a default-constructed function disables it.
    using TxTap = statusbar::sg14::inplace_function<void(std::span<uint8_t const>), 32>;
    void set_tx_tap(TxTap tap) noexcept { tx_tap_ = std::move(tap); }

#if defined(__APPLE__)
    /// Get the BPF buffer size (macOS only)
    [[nodiscard]] auto bpf_buffer_size() const noexcept -> size_t { return bpf_buffer_size_; }
#endif

  private:
    int fd_{-1};
    uint16_t ethertype_{0};
    int interface_index_{-1};
    Eui48 my_mac_{};
    Eui48 default_dest_mac_{};
    bool transmit_only_{false};  ///< opened transmit_only: never joins, binds or filters
    TxTap tx_tap_{};

#if defined(__APPLE__)
    size_t bpf_buffer_size_{0};
    std::array<uint8_t, 32768> bpf_read_buffer_{};
    size_t bpf_read_offset_{0};
    size_t bpf_read_length_{0};
#endif
};

//
// Platform-specific system includes are in net_rawnet_impl.cpp
//

}  // namespace statusbar::net
