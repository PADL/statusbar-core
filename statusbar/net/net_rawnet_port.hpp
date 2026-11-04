#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_rawnet_port.hpp
/// @brief RawnetPort: the EthernetPort shape of a RawnetContext pair.
///
/// The stream entities have always run their audio on two plain AF_PACKET
/// sockets: a transmit-only one with PACKET_QDISC_BYPASS, so the frames it
/// sends do not come straight back in on the other, and a receive one
/// joined to the stream groups. This class is that pair behind the
/// EthernetPort API, so code written against the concept can run on it
/// unchanged - and so the entities can pick a ring backend at runtime
/// without keeping a second code path for this one.
///
/// What it is not: zero-copy. tx_start() hands out a buffer from a small
/// pool and tx_commit() copies it into the kernel with one sendto;
/// rx_start() is one recv into a pool buffer. That is what the sockets
/// cost today, with the one syscall per frame they have always cost.
///
/// Two consequences of the pair that a single-socket port does not have:
///
///   - TX and RX may be driven from two threads at once. Each side is its
///     own socket with its own pool and nothing shared between them, which
///     is exactly how the entities use it (media timer sends, reactor or RX
///     timer receives). AnyEthernetPort::tx_rx_independent() reports it.
///   - The RX frame comes back with a rebuilt 14-byte header. RawnetContext
///     strips the L2 header (and any 802.1Q tag) and returns the payload;
///     the EthernetPort contract is the whole frame, so the destination,
///     source and the socket's ethertype are put back in front. The tag is
///     not: a caller that wants the VLAN a frame arrived on needs a ring
///     backend, which delivers the frame as it was.
///
/// launch_time_ns is accepted and ignored on tx_start(): AF_PACKET has no
/// per-frame launch time. Same as BpfPortContext.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/net/net_rawnet.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <span>
#include <string_view>

namespace statusbar::net {

struct RawnetPortConfig
{
    std::string_view interface_name;
    /// The one ethertype both sockets carry (0 is refused: a port for
    /// everything has no use for the rebuilt RX header).
    uint16_t ethertype{0};
    /// SO_PRIORITY for the transmit socket, 0 to leave the default. The
    /// value is skb->priority, which an mqprio root maps to a traffic class.
    int priority{0};
    /// PACKET_QDISC_BYPASS on the transmit socket. On by default: this port
    /// exists for stream egress, and bypass is what keeps its own frames
    /// off its RX socket. Off makes the egress visible to local capture.
    bool qdisc_bypass{true};
};

class RawnetPort
{
  public:
    /// Frames in flight on each side. TX slots are returned on commit or
    /// cancel, so a sender that commits what it starts needs one; RX slots
    /// are held between rx_start() and rx_release().
    static constexpr size_t TX_SLOTS = 8;
    static constexpr size_t RX_SLOTS = 8;

    RawnetPort() noexcept = default;
    ~RawnetPort() noexcept = default;
    RawnetPort(RawnetPort const&) = delete;
    auto operator=(RawnetPort const&) -> RawnetPort& = delete;
    RawnetPort(RawnetPort&&) noexcept = default;
    auto operator=(RawnetPort&&) noexcept -> RawnetPort& = default;

    [[nodiscard]] auto open(RawnetPortConfig const& config) noexcept -> Status;
    void close() noexcept;

    [[nodiscard]] auto valid() const noexcept -> bool { return tx_.valid() && rx_.valid(); }
    /// The receive socket: the one a reactor polls for readiness.
    [[nodiscard]] auto fd() const noexcept -> int { return rx_.fd(); }
    [[nodiscard]] auto tx_fd() const noexcept -> int { return tx_.fd(); }
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const& { return rx_.my_mac(); }
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int
    {
        return rx_.interface_index() < 0 ? 0U : static_cast<unsigned int>(rx_.interface_index());
    }
    [[nodiscard]] auto ethertype() const noexcept -> uint16_t { return rx_.ethertype(); }

    // TX
    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) noexcept -> StatusValue<EthernetTxSlot>;
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) noexcept -> Status;
    [[nodiscard]] auto tx_cancel(uint64_t handle) noexcept -> Status;
    /// Nothing is batched, so nothing to flush.
    [[nodiscard]] auto tx_flush() noexcept -> Status { return success(); }

    // RX
    /// The next received frame, stamped @p now: the RX clock as the caller
    /// read it for this pass.
    [[nodiscard]] auto rx_start(RxTimePoint now) noexcept -> StatusValue<std::optional<EthernetRxSlot>>;
    /// rx_start(now) with the RX clock read here.
    [[nodiscard]] auto rx_start() noexcept -> StatusValue<std::optional<EthernetRxSlot>>;
    [[nodiscard]] auto rx_release(uint64_t handle) noexcept -> Status;

    // Multicast, on the receive socket.
    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) noexcept -> Status { return rx_.join_multicast(addr); }
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const& addr) noexcept -> Status { return rx_.leave_multicast(addr); }

    void begin_cycle() noexcept {}
    [[nodiscard]] auto end_cycle() noexcept -> Status { return success(); }

    /// The sockets themselves, for what only they offer (a subtype filter,
    /// a tap). Not for sending or receiving around the port.
    [[nodiscard]] auto tx() noexcept -> RawnetContext& { return tx_; }
    [[nodiscard]] auto rx() noexcept -> RawnetContext& { return rx_; }

  private:
    using FrameBuffer = std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER>;

    [[nodiscard]] auto open_sockets(RawnetPortConfig const& config) noexcept -> Status;
    /// One recv into the slot, header rebuilt: the frame length, 0 when
    /// nothing was queued.
    [[nodiscard]] auto receive_frame(uint64_t handle) noexcept -> StatusValue<size_t>;

    /// A pool of frame buffers. A slot is out between take() and
    /// give_back(); a handle that is not out - never issued, or already
    /// returned - is refused, which is what makes a double release visible.
    template <size_t N>
    struct Pool
    {
        std::array<FrameBuffer, N> buffers{};
        std::array<bool, N> out{};
        size_t out_count{0};

        void reset() noexcept
        {
            out.fill(false);
            out_count = 0;
        }
        [[nodiscard]] auto take() noexcept -> std::optional<uint64_t>
        {
            if (out_count >= N) {
                return std::nullopt;
            }
            for (size_t i = 0; i < N; ++i) {
                if (!out[i]) {
                    out[i] = true;
                    ++out_count;
                    return static_cast<uint64_t>(i);
                }
            }
            return std::nullopt;
        }
        [[nodiscard]] auto give_back(uint64_t const handle) noexcept -> bool
        {
            if (handle >= N || !out[handle]) {
                return false;
            }
            out[handle] = false;
            --out_count;
            return true;
        }
    };

    RawnetContext tx_{};
    RawnetContext rx_{};
    Pool<TX_SLOTS> tx_pool_{};
    Pool<RX_SLOTS> rx_pool_{};
};

static_assert(EthernetPort<RawnetPort>);

}  // namespace statusbar::net
