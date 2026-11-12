#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// EthernetPort concept and common types for zero-copy Ethernet TX/RX
/// Defines the unified API that MmapContext, XdpContext, BpfPortContext,
/// and TestPortContext all satisfy.

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/realtime/realtime_clock.hpp"
#include "statusbar/status/status.hpp"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iterator>
#include <optional>
#include <span>

namespace statusbar::net {

/// VLAN tag matching mode (shared between TrafficClassifier and XDP filter rules)
/// Relocated from net_linux_xdp.cppm to be available cross-platform.
enum class VlanMatch : uint8_t
{
    untagged_only,
    tagged_any,
    tagged_exact,
};

/// Minimum guaranteed frame buffer size (standard Ethernet with QinQ VLAN)
inline constexpr size_t ETHERNET_PORT_MIN_FRAME_BUFFER = 1522;

/// Fixed-capacity byte buffer sized for one full Ethernet frame
/// (ETHERNET_PORT_MIN_FRAME_BUFFER == 1522 bytes of inline storage plus a
/// runtime length).
///
/// Used by the synthetic EthernetPort backends (TestPortContext,
/// LoopbackPortContext, PipePortContext, PcapReplayPortContext) to hold
/// captured TX frames and queued RX frames without the per-record heap
/// allocation that `std::vector<uint8_t>` would incur. Every TxCapture /
/// QueuedFrame instance now stores its payload inline; copying or moving
/// is a plain struct copy of ~1536 bytes, with no allocator traffic.
///
/// Exposes a vector-like read API (`data`, `size`, `empty`, `operator[]`,
/// `begin`/`end`) and an implicit conversion to `std::span<uint8_t const>`
/// so existing call sites that read a capture's bytes as a span or pass it
/// to code expecting a span continue to compile unchanged.
struct EthernetFrameBuffer
{
    std::array<uint8_t, ETHERNET_PORT_MIN_FRAME_BUFFER> storage{};
    size_t length{0};

    //
    // vector-like accessors (read)
    //

    [[nodiscard]] auto data() noexcept -> uint8_t* { return storage.data(); }
    [[nodiscard]] auto data() const noexcept -> uint8_t const* { return storage.data(); }
    [[nodiscard]] auto size() const noexcept -> size_t { return length; }
    [[nodiscard]] auto empty() const noexcept -> bool { return length == 0; }

    [[nodiscard]] auto operator[](size_t i) noexcept -> uint8_t& { return storage[i]; }
    [[nodiscard]] auto operator[](size_t i) const noexcept -> uint8_t const& { return storage[i]; }

    [[nodiscard]] auto begin() noexcept -> uint8_t* { return storage.data(); }
    [[nodiscard]] auto end() noexcept -> uint8_t* { return storage.data() + length; }
    [[nodiscard]] auto begin() const noexcept -> uint8_t const* { return storage.data(); }
    [[nodiscard]] auto end() const noexcept -> uint8_t const* { return storage.data() + length; }

    //
    // Implicit conversion to std::span<uint8_t const> so existing code that
    // constructs a span from the capture (e.g. `std::span{cap.frame}`) or
    // passes it directly into an API taking `std::span<uint8_t const>` keeps
    // working without an explicit `.data()/.size()` dance.
    //

    // NOLINTNEXTLINE(google-explicit-constructor)
    operator std::span<uint8_t const>() const noexcept { return {storage.data(), length}; }

    //
    // Mutation — matches the shape of the few std::vector operations used by
    // the existing synthetic-port tx_commit implementations.
    //

    /// Copy `n` bytes from a raw pointer, clamped to capacity.
    void assign(uint8_t const* src, size_t n) noexcept
    {
        length = std::min(n, storage.size());
        if (length > 0) {
            std::memcpy(storage.data(), src, length);
        }
    }

    /// Copy from an iterator range `[first, last)`, clamped to capacity.
    /// Matches `std::vector::assign(first, last)` so drop-in call sites
    /// keep compiling.
    template <typename It>
    void assign(It first, It last) noexcept
    {
        auto const requested = static_cast<size_t>(std::distance(first, last));
        length = std::min(requested, storage.size());
        for (size_t i = 0; i < length; ++i, ++first) {
            storage[i] = static_cast<uint8_t>(*first);
        }
    }
};

/// TX slot returned by EthernetPort::tx_start()
struct EthernetTxSlot
{
    uint64_t handle;            ///< Opaque: ring index (MMAP), UMEM addr (XDP), pool index (BpfPort/TestPort)
    std::span<uint8_t> buffer;  ///< Writable frame buffer (>= ETHERNET_PORT_MIN_FRAME_BUFFER bytes)
};

/// RX slot returned by EthernetPort::rx_start()
struct EthernetRxSlot
{
    uint64_t handle;                  ///< Opaque slot handle for rx_release()
    std::span<uint8_t const> buffer;  ///< Full Ethernet frame including 14-byte header
    int64_t timestamp_ns;             ///< Capture timestamp in nanoseconds: the kernel's where it gave one, else the RX clock
};

/// The clock a port stamps a received frame on when it stamps in software:
/// CLOCK_MONOTONIC_RAW, the timing reference clock. It is not configurable:
/// a stamp is compared with other stamps and with timer deadlines, all of
/// which are on this clock. The mmap ring's kernel stamp (tp_sec/tp_nsec,
/// CLOCK_REALTIME) is on another clock and is not handed on in its place.
using RxClock = realtime::MonotonicRawClock;
using RxTimePoint = RxClock::time_point;

/// The RX clock now. rx_start() reads it once; a caller draining a port
/// reads it once per pass and tells every rx_start(now) of the pass, so a
/// pass costs one clock read however many frames it takes.
[[nodiscard]] inline auto rx_clock_now() noexcept -> RxTimePoint
{
    return RxTimePoint{RxClock::duration{realtime::read_monotonic_raw_ns()}};
}

/// @p now as an EthernetRxSlot::timestamp_ns.
[[nodiscard]] constexpr auto rx_timestamp_ns(RxTimePoint const now) noexcept -> int64_t
{
    return now.time_since_epoch().count();
}

/// Concept for zero-copy Ethernet frame TX/RX backends.
///
/// All implementations are single-threaded. The caller must not access a port
/// concurrently from multiple threads.
///
/// rx_start() / rx_release() must be paired 1:1. Calling rx_start() again
/// before releasing the previous slot is undefined behavior.
///
/// rx_start(now) is told the RX clock (an RxTimePoint the caller read once
/// for its pass) and stamps the frame from it where the kernel gave no
/// stamp; rx_start() reads the clock once and forwards. A drain loop calls
/// the told form.
///
/// launch_time_ns is in TAI nanoseconds for TSN/AVB hardware TX scheduling.
template <typename T>
concept EthernetPort = requires(
    T& port, T const& cport, uint64_t handle, size_t len, int64_t launch_time_ns, ieee::Eui48 const& mac, RxTimePoint now) {
    // Lifecycle
    { port.valid() } -> std::same_as<bool>;
    { port.fd() } -> std::same_as<int>;
    { cport.hardware_address() } -> std::same_as<ieee::Eui48 const&>;
    { cport.interface_index() } -> std::same_as<unsigned int>;

    // TX: start/commit/cancel/flush
    { port.tx_start(launch_time_ns) } -> std::same_as<StatusValue<EthernetTxSlot>>;
    { port.tx_commit(handle, len) } -> std::same_as<Status>;
    { port.tx_cancel(handle) } -> std::same_as<Status>;
    { port.tx_flush() } -> std::same_as<Status>;

    // RX: start (told the RX clock, and asking) / release
    { port.rx_start(now) } -> std::same_as<StatusValue<std::optional<EthernetRxSlot>>>;
    { port.rx_start() } -> std::same_as<StatusValue<std::optional<EthernetRxSlot>>>;
    { port.rx_release(handle) } -> std::same_as<Status>;

    // Multicast
    { port.join_multicast(mac) } -> std::same_as<Status>;

    // Per-cycle housekeeping
    { port.begin_cycle() } -> std::same_as<void>;
    { port.end_cycle() } -> std::same_as<Status>;
};

// Guard-based RAII wrappers layered on top of the handle-based EthernetPort API.
// These are zero-allocation stack values that auto-cancel/release on destruction.
// Multiple guards can coexist (they hold Port& not Port&&).

/// RAII guard for a TX slot. Auto-cancels on destruction if not committed.
/// Move-only: cannot be copied.
template <EthernetPort Port>
class EthernetTxGuard
{
  public:
    EthernetTxGuard(Port& port, EthernetTxSlot slot) noexcept
        : port_{port}
        , handle_{slot.handle}
        , buffer_{slot.buffer}
    {}

    ~EthernetTxGuard()
    {
        if (!committed_) {
            (void)port_.tx_cancel(handle_);
        }
    }

    // Move-only
    EthernetTxGuard(EthernetTxGuard&& other) noexcept
        : port_{other.port_}
        , handle_{other.handle_}
        , buffer_{other.buffer_}
        , committed_{other.committed_}
    {
        other.committed_ = true;  // prevent double-cancel
    }

    EthernetTxGuard(EthernetTxGuard const&) = delete;
    auto operator=(EthernetTxGuard const&) -> EthernetTxGuard& = delete;
    auto operator=(EthernetTxGuard&&) -> EthernetTxGuard& = delete;

    /// Writable frame buffer.
    [[nodiscard]] auto buffer() noexcept -> std::span<uint8_t> { return buffer_; }

    /// Commit the frame for transmission. Consumes the guard logically
    /// (destructor becomes a no-op). Returns the commit status.
    [[nodiscard]] auto commit(size_t frame_length) -> Status
    {
        committed_ = true;
        return port_.tx_commit(handle_, frame_length);
    }

    /// Explicitly cancel without sending. Destructor becomes a no-op.
    auto cancel() -> Status
    {
        committed_ = true;
        return port_.tx_cancel(handle_);
    }

    /// The opaque handle (for advanced use).
    [[nodiscard]] auto handle() const noexcept -> uint64_t { return handle_; }

  private:
    Port& port_;
    uint64_t handle_;
    std::span<uint8_t> buffer_;
    bool committed_ = false;
};

/// RAII guard for an RX slot. Auto-releases on destruction.
/// Move-only: cannot be copied.
template <EthernetPort Port>
class EthernetRxGuard
{
  public:
    EthernetRxGuard(Port& port, EthernetRxSlot slot) noexcept
        : port_{port}
        , handle_{slot.handle}
        , buffer_{slot.buffer}
        , timestamp_ns_{slot.timestamp_ns}
    {}

    ~EthernetRxGuard()
    {
        if (!released_) {
            (void)port_.rx_release(handle_);
        }
    }

    // Move-only
    EthernetRxGuard(EthernetRxGuard&& other) noexcept
        : port_{other.port_}
        , handle_{other.handle_}
        , buffer_{other.buffer_}
        , timestamp_ns_{other.timestamp_ns_}
        , released_{other.released_}
    {
        other.released_ = true;
    }

    EthernetRxGuard(EthernetRxGuard const&) = delete;
    auto operator=(EthernetRxGuard const&) -> EthernetRxGuard& = delete;
    auto operator=(EthernetRxGuard&&) -> EthernetRxGuard& = delete;

    /// Read-only frame buffer (full Ethernet frame including header).
    [[nodiscard]] auto buffer() const noexcept -> std::span<uint8_t const> { return buffer_; }

    /// Capture timestamp in nanoseconds.
    [[nodiscard]] auto timestamp_ns() const noexcept -> int64_t { return timestamp_ns_; }

    /// Explicitly release the slot early. Destructor becomes a no-op.
    auto release() -> Status
    {
        released_ = true;
        return port_.rx_release(handle_);
    }

    /// The opaque handle (for advanced use).
    [[nodiscard]] auto handle() const noexcept -> uint64_t { return handle_; }

  private:
    Port& port_;
    uint64_t handle_;
    std::span<uint8_t const> buffer_;
    int64_t timestamp_ns_;
    bool released_ = false;
};

/// Acquire a TX guard from a port. Returns failure if the port's TX pool is exhausted.
/// @param port The EthernetPort to acquire a TX slot from
/// @param launch_time_ns TAI nanoseconds for TSN/AVB hardware TX scheduling (0 = immediate)
template <EthernetPort Port>
[[nodiscard]] auto tx_guard(Port& port, int64_t launch_time_ns = 0) -> StatusValue<EthernetTxGuard<Port>>
{
    auto slot = port.tx_start(launch_time_ns);
    if (!slot) {
        return failure(slot.error());
    }
    return EthernetTxGuard<Port>{port, *slot};
}

/// Acquire an RX guard from a port. Returns nullopt if no frame is available.
/// @param port The EthernetPort to receive from
/// @param now The RX clock, read once by the caller for its whole pass
template <EthernetPort Port>
[[nodiscard]] auto rx_guard(Port& port, RxTimePoint const now) -> StatusValue<std::optional<EthernetRxGuard<Port>>>
{
    auto result = port.rx_start(now);
    if (!result) {
        return failure(result.error());
    }
    // Bind the inner optional to a local so bugprone-unchecked-optional-access
    // can link the has_value() check and the subsequent dereference.
    auto& slot_opt = *result;
    if (!slot_opt.has_value()) {
        return success(std::optional<EthernetRxGuard<Port>>{std::nullopt});
    }
    return success(std::optional<EthernetRxGuard<Port>>{EthernetRxGuard<Port>{port, *slot_opt}});
}

/// rx_guard(port, now) with the RX clock read once here.
template <EthernetPort Port>
[[nodiscard]] auto rx_guard(Port& port) -> StatusValue<std::optional<EthernetRxGuard<Port>>>
{
    return rx_guard(port, rx_clock_now());
}

/// Send a single frame using a callback to fill the buffer.
/// Acquires a TX slot, calls the fill function, and commits if the returned
/// frame length is > 0. Auto-cancels if the fill function returns 0 or throws.
///
/// @param port The EthernetPort to send on
/// @param launch_time_ns TAI nanoseconds for TSN/AVB hardware TX scheduling (0 = immediate)
/// @param fill Callback: receives writable buffer span, returns frame length (0 = cancel)
template <EthernetPort Port, typename F>
[[nodiscard]] auto send_frame(Port& port, int64_t launch_time_ns, F fill) -> Status
{
    auto guard_result = tx_guard(port, launch_time_ns);
    if (!guard_result) {
        return failure(guard_result.error());
    }
    auto& guard = *guard_result;

    auto const frame_length = fill(guard.buffer());
    if (frame_length == 0) {
        return success();  // guard auto-cancels
    }
    return guard.commit(frame_length);
}

}  // namespace statusbar::net
