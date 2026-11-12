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
#include "statusbar/net/net_cbpf_emit.hpp"
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
        , transmit_only_{other.transmit_only_}
        , my_mac_{other.my_mac_}
        , default_dest_mac_{other.default_dest_mac_}
        , tx_tap_{std::move(other.tx_tap_)}
#if defined(__APPLE__)
        , bpf_buffer_size_{other.bpf_buffer_size_}
#endif
    {
        other.fd_ = -1;
        other.interface_index_ = -1;
        other.transmit_only_ = false;
        other.tx_tap_ = {};
    }

    auto operator=(RawnetContext&& other) noexcept -> RawnetContext&;

    /// Open a raw Ethernet socket on one interface. A receiving socket is
    /// bound to that interface here (on Linux with ETH_P_ALL, which keeps
    /// same-host delivery; see the implementation), so it hears its
    /// ethertype from that interface only, whether or not it ever joins a
    /// group.
    /// @param interface_name Network interface name (e.g., "en0", "eth0")
    /// @param ethertype EtherType to filter/use (e.g., 0x88f7 for gPTP)
    /// @param multicast_mac Optional multicast MAC address to join (nullptr = none)
    /// @param qdisc_bypass Set PACKET_QDISC_BYPASS for lower TX latency. OFF by
    ///        default. Note: bypass does NOT drop frames — they still reach the
    ///        wire — but it skips the egress tap, so bypass frames are invisible
    ///        to tcpdump/AF_PACKET on the *sending* host. Default-off keeps local
    ///        capture working; enable only for latency-critical TX.
    /// @param transmit_only Open a socket that never receives. A talker that
    ///        only sends should not be handed a copy of every frame of its
    ///        ethertype: today a send-only socket still pays for a receive
    ///        path it drains and throws away. On Linux this opens protocol 0
    ///        and never binds, so the socket is not registered for receive at
    ///        all; on macOS BPF the equivalent is a drop-all read filter.
    ///        `join_multicast`, `leave_multicast` and `set_subtype_filter`
    ///        all refuse on such a socket — joining a group would bind it and
    ///        put it back on the receive path. `send` and `set_priority` work
    ///        normally.
    /// @return Status indicating success or failure
    [[nodiscard]] auto open(
        std::string_view interface_name,
        uint16_t ethertype,
        Eui48 const* multicast_mac = nullptr,
        bool qdisc_bypass = false,
        bool transmit_only = false) noexcept -> Status;

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

    /// Join a multicast group. The socket is bound to its interface by
    /// open(); this adds the group membership (PACKET_ADD_MEMBERSHIP on
    /// Linux) and nothing else.
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

    /// Narrow the kernel-side filter to this socket's ethertype plus a set
    /// of AVTP subtypes, matching both untagged frames and frames carrying
    /// one 802.1Q tag.
    ///
    /// The socket is opened on ETH_P_ALL (see open()), so without a filter
    /// the kernel wakes us for every frame on the wire — on a busy link tens
    /// of thousands of times a second, nearly all for frames we discard in
    /// user space after a syscall and a copy. open() already attaches an
    /// ethertype-only filter; this narrows it further to the subtypes we
    /// actually consume, which for a listener is the difference between
    /// costing a core and costing a few percent of one.
    ///
    /// Attaching replaces any filter already on the socket. Frames that
    /// arrived under the previous, wider filter are still queued, so this
    /// attaches a drop-all program, drains the queue, and only then
    /// attaches the real one — otherwise the caller's next reads return
    /// frames the new filter would have rejected.
    ///
    /// @param subtypes 1 to `rawnet_filter::MAX_SUBTYPES` AVTP subtype
    ///        values (the first payload byte). Validated before the socket
    ///        is touched.
    /// @return Status; `invalid_argument` for an empty or oversized set or
    ///         on a transmit-only socket, `not_connected` if not open.
    [[nodiscard]] auto set_subtype_filter(std::span<uint8_t const> subtypes) const noexcept -> Status;

    /// Set the socket's egress priority (SO_PRIORITY on Linux).
    ///
    /// This is a prerequisite, not an optimisation: SO_PRIORITY is what
    /// `packet_pick_tx_queue` reads to choose the TX queue for a frame.
    /// Without it every frame we send lands on the default queue, so an
    /// mqprio map and a credit-based shaper configured on the NIC have no
    /// effect on our traffic at all.
    ///
    /// Permitted on a transmit-only socket — that is the socket that most
    /// needs it.
    ///
    /// @param priority Non-negative priority; maps to the skb priority the
    ///        mqprio priority-to-traffic-class map is indexed by.
    /// @return Status; `invalid_argument` if negative, `not_connected` if
    ///         not open, `not_supported` on platforms without SO_PRIORITY.
    [[nodiscard]] auto set_priority(int priority) noexcept -> Status;

    /// Whether this socket was opened transmit-only.
    [[nodiscard]] auto transmit_only() const noexcept -> bool { return transmit_only_; }

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
    /// The part of set_subtype_filter()'s contract that can fail before any
    /// program is built: the subtype set, then the socket, then the mode.
    [[nodiscard]] auto check_filter_preconditions(std::span<uint8_t const> subtypes) const noexcept -> Status;

    /// Install a cBPF program as this socket's receive filter
    /// (SO_ATTACH_FILTER on Linux, BIOCSETF on macOS BPF). Replaces any
    /// program already attached.
    [[nodiscard]] auto attach_cbpf(std::span<cbpf::Instruction const> program) const noexcept -> Status;

    /// Install `program` such that nothing admitted by the previous filter
    /// survives in the receive queue.
    [[nodiscard]] auto replace_filter(std::span<cbpf::Instruction const> program) const noexcept -> Status;

#if defined(__linux__)
    /// Read and discard whatever is already queued, bounded so a socket
    /// under live flood cannot turn a filter change into an endless loop.
    void drain_receive_queue() const noexcept;

    /// Bind the socket to interface_index_ on ETH_P_ALL. open() does this
    /// for every receiving socket; see there for why ETH_P_ALL.
    [[nodiscard]] auto bind_to_interface() const noexcept -> Status;
#endif

    int fd_{-1};
    uint16_t ethertype_{0};
    int interface_index_{-1};
    bool transmit_only_{false};
    Eui48 my_mac_{};
    Eui48 default_dest_mac_{};
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
