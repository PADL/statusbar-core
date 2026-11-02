#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file net_any_ethernet_port.hpp
/// @brief AnyEthernetPort: one EthernetPort whose backend is chosen at runtime.
///
/// EthernetPort is a concept, and the backends that satisfy it are distinct
/// types: a caller templated on the port picks one when it is compiled. A
/// daemon that reads its backend from a config file cannot do that, and it
/// should not have to be a template from its main loop down to make the
/// choice. This class holds whichever backend was asked for and forwards
/// every operation of the concept to it, so it satisfies EthernetPort
/// itself, and the choice is a string in a config file:
///
///   rawnet  - a transmit socket and a receive socket, plain AF_PACKET,
///             one syscall and one copy per frame. Works everywhere,
///             needs CAP_NET_RAW, and is what the entities ran on before
///             the choice existed. The default for that reason.
///   mmap    - PACKET_MMAP (TPACKET_V2) rings on one AF_PACKET socket.
///             Linux. No copy into the kernel, one kick per batch.
///   xdp     - AF_XDP on one queue of the NIC, with the XDP program from
///             net_linux_xdp steering frames into it. Linux, needs the
///             program loaded (CAP_BPF/CAP_NET_ADMIN), and on a NIC with
///             a native driver it is the only path that is zero-copy and
///             the only one that can carry a launch time. On a NIC
///             without one (the Pi's macb, say) it runs in generic mode
///             and gains little over rawnet.
///
/// The one thing the backends do not agree on is threads. The concept
/// says a port is single-threaded. rawnet's two sockets share nothing,
/// so its TX and its RX can be driven from two threads at once; the ring
/// backends share state between the two sides (the UMEM free list, the
/// fill and completion rings) and cannot. tx_rx_independent() says which
/// a caller got, so a caller with a sending thread and a receiving thread
/// can serialise them only when it must.
///
/// Forwarding is one std::visit per call. On the data path that is a
/// switch on the backend index, which costs less than the syscall or the
/// ring write it leads to.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/net/net_linux_mmap.hpp"
#include "statusbar/net/net_linux_xdp.hpp"
#include "statusbar/net/net_rawnet_port.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace statusbar::net {

enum class EthernetBackend : uint8_t
{
    rawnet = 0,
    mmap,
    xdp,
};

/// The names as a config file or a command line spells them, in enum order.
inline constexpr std::array<std::string_view, 3> ETHERNET_BACKEND_NAMES{"rawnet", "mmap", "xdp"};

/// The names joined for a usage line: "rawnet|mmap|xdp".
inline constexpr std::string_view ETHERNET_BACKEND_CHOICES = "rawnet|mmap|xdp";

/// A backend by name, or nullopt for a name that is not one. Exact and
/// lower-case: a config file that says "XDP" is asked to say "xdp".
[[nodiscard]] constexpr auto parse_ethernet_backend(std::string_view const name) noexcept -> std::optional<EthernetBackend>
{
    for (size_t i = 0; i < ETHERNET_BACKEND_NAMES.size(); ++i) {
        if (ETHERNET_BACKEND_NAMES[i] == name) {
            return static_cast<EthernetBackend>(i);
        }
    }
    return std::nullopt;
}

[[nodiscard]] constexpr auto ethernet_backend_name(EthernetBackend const backend) noexcept -> std::string_view
{
    auto const index = static_cast<size_t>(backend);
    return index < ETHERNET_BACKEND_NAMES.size() ? ETHERNET_BACKEND_NAMES[index] : std::string_view{"?"};
}

/// What every backend needs, plus what only some of them take. A field a
/// backend has no use for is ignored by it, not refused: the same config
/// serves whichever backend the string names.
struct AnyEthernetPortConfig
{
    std::string_view interface_name;
    /// The ethertype the port carries. rawnet and mmap filter on it in the
    /// kernel; xdp steers by `xdp_filter_rules` instead and ignores it.
    uint16_t ethertype{0};
    /// skb->priority for transmitted frames (rawnet, mmap). 0 leaves the
    /// socket default.
    int priority{0};
    /// Slots per ring (mmap TX and RX, xdp RX and TX; xdp's fill and
    /// completion rings get twice this).
    size_t ring_size{256};
    /// Clock for RX timestamps where the backend stamps in software.
    int rx_clock_id{CLOCK_MONOTONIC_RAW};

    // xdp only.
    uint32_t xdp_queue_id{0};
    /// Which frames the XDP program steers into the socket; everything else
    /// goes on to the kernel. Required for xdp: with no rules the socket
    /// receives nothing. The span must outlive open().
    std::span<CompiledRule<tcam_default_window_bytes> const> xdp_filter_rules{};
    XdpAttachMode xdp_attach_mode{XdpAttachMode::native};
    XdpBindMode xdp_bind_mode{XdpBindMode::auto_};
    /// See XdpConfig::tx_launch_time.
    bool xdp_tx_launch_time{false};
};

class AnyEthernetPort
{
  public:
    AnyEthernetPort() noexcept = default;
    ~AnyEthernetPort() noexcept = default;
    AnyEthernetPort(AnyEthernetPort const&) = delete;
    auto operator=(AnyEthernetPort const&) -> AnyEthernetPort& = delete;
    AnyEthernetPort(AnyEthernetPort&&) noexcept = default;
    auto operator=(AnyEthernetPort&&) noexcept -> AnyEthernetPort& = default;

    /// Open `backend` on the interface. A backend this build or platform
    /// does not have fails with its own not_supported_on_platform; a port
    /// that was open is closed first either way.
    [[nodiscard]] auto open(EthernetBackend backend, AnyEthernetPortConfig const& config) -> Status;
    void close() noexcept;

    /// The backend in force, or nullopt while closed.
    [[nodiscard]] auto backend() const noexcept -> std::optional<EthernetBackend>;

    /// Whether TX and RX may be driven from two threads at once: true for
    /// rawnet, whose two sides are two sockets; false for the ring
    /// backends. False while closed, which is the safe answer.
    [[nodiscard]] auto tx_rx_independent() const noexcept -> bool;

    /// One line for a startup log: the backend and what it actually got,
    /// e.g. "xdp (native, zero-copy)" or "rawnet (AF_PACKET, two sockets)".
    [[nodiscard]] auto describe() const -> std::string;

    // --- EthernetPort ---
    [[nodiscard]] auto valid() const noexcept -> bool;
    [[nodiscard]] auto fd() const noexcept -> int;
    [[nodiscard]] auto hardware_address() const noexcept -> ieee::Eui48 const&;
    [[nodiscard]] auto interface_index() const noexcept -> unsigned int;

    [[nodiscard]] auto tx_start(int64_t launch_time_ns = 0) -> StatusValue<EthernetTxSlot>;
    [[nodiscard]] auto tx_commit(uint64_t handle, size_t frame_length) -> Status;
    [[nodiscard]] auto tx_cancel(uint64_t handle) -> Status;
    [[nodiscard]] auto tx_flush() -> Status;

    [[nodiscard]] auto rx_start() -> StatusValue<std::optional<EthernetRxSlot>>;
    [[nodiscard]] auto rx_release(uint64_t handle) -> Status;

    [[nodiscard]] auto join_multicast(ieee::Eui48 const& addr) -> Status;
    [[nodiscard]] auto leave_multicast(ieee::Eui48 const& addr) -> Status;

    void begin_cycle() noexcept;
    [[nodiscard]] auto end_cycle() -> Status;

    /// The backend object, when it is that one. For what only it offers:
    /// RawnetPort::rx() for a subtype filter, XdpContext stats, and so on.
    template <typename T>
    [[nodiscard]] auto as() noexcept -> T*
    {
        return std::get_if<T>(&port_);
    }
    template <typename T>
    [[nodiscard]] auto as() const noexcept -> T const*
    {
        return std::get_if<T>(&port_);
    }

  private:
    using Port = std::variant<std::monostate, RawnetPort, MmapContext, XdpContext>;

    [[nodiscard]] auto open_backend(EthernetBackend backend, AnyEthernetPortConfig const& config) -> Status;

    Port port_{};
};

static_assert(EthernetPort<AnyEthernetPort>);

}  // namespace statusbar::net
