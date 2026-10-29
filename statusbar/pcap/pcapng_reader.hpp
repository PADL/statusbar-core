#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/pcap/pcapng_base.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory_resource>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace statusbar::pcap {

/// Interface information parsed from IDB.
struct InterfaceInfo
{
    LinkType link_type{LinkType::Ethernet};
    uint32_t snap_length{65535};
    uint64_t ts_resol{1000000};  ///< Timestamp resolution (units per second), default microseconds
};

/// PcapNG file reader for Wireshark-compatible capture files.
///
/// Reads Ethernet frames from a PcapNG file. Handles both native and
/// byte-swapped file formats automatically. Supports Section Header,
/// Interface Description, and Enhanced Packet blocks.
///
/// Construct via the static `open()` factory; the ctor is private so callers
/// always see the `StatusValue<PcapngReader>` failure surface.
class PcapngReader
{
  public:
    /// Open a PcapNG file for reading.
    /// @param filename Path to the PcapNG file.
    /// @param memory_resource Memory resource for the interface-description
    ///        table. nullptr → std::pmr::get_default_resource().
    /// @return A configured PcapngReader on success, or a PcapError.
    [[nodiscard]] static auto open(std::string const& filename, std::pmr::memory_resource* memory_resource = nullptr)
        -> StatusValue<PcapngReader>;

    ~PcapngReader() = default;

    // Non-copyable
    PcapngReader(PcapngReader const&) = delete;
    auto operator=(PcapngReader const&) -> PcapngReader& = delete;

    // Movable
    PcapngReader(PcapngReader&&) noexcept = default;
    auto operator=(PcapngReader&&) noexcept -> PcapngReader& = default;

    /// Read the next packet from the file.
    /// @return success(true) if a packet was read, success(false) on clean EOF,
    /// or failure(PcapError::...) on a read error.
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, Packet& packet) -> StatusValue<bool>;

    /// Read the next packet block and report the length the frame had on the
    /// wire — the EPB's original_length, or the SPB's, which is the only
    /// length an SPB carries.
    /// @param timestamp_us Receives the timestamp (0 for a Simple Packet Block)
    /// @param packet Receives the captured bytes
    /// @param original_len Receives the wire length; may be nullptr
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> StatusValue<bool>;

    /// Read the next packet and parse the Ethernet header.
    /// @return success(true) if a packet was read, success(false) on clean EOF,
    /// or failure(PcapError::...) on a read error.
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, ieee::Eui48& da, ieee::Eui48& sa, uint16_t* ethertype, Packet& payload)
        -> StatusValue<bool>;

  private:
    explicit PcapngReader(std::pmr::memory_resource* memory_resource)
        : interfaces_{memory_resource != nullptr ? memory_resource : std::pmr::get_default_resource()}
    {}

    [[nodiscard]] auto read_interface_description(size_t body_length) -> bool;
    [[nodiscard]] auto read_enhanced_packet(size_t body_length, uint64_t* timestamp_us, Packet& packet, uint32_t* original_len)
        -> bool;
    [[nodiscard]] auto read_simple_packet(size_t body_length, uint64_t* timestamp_us, Packet& packet, uint32_t* original_len)
        -> bool;

    FilePtr file_{nullptr, [](FILE*) -> void {}};
    std::string filename_;
    bool swap_{false};
    bool seen_first_timestamp_{false};
    uint64_t first_timestamp_us_{0};
    std::pmr::vector<InterfaceInfo> interfaces_;
};

/// Read all packets from a PcapngReader, calling a callback for each one.
///
/// The callback receives: (timestamp_us, dst_mac, src_mac, ethertype, payload).
/// Returns success() when EOF is reached, or a PcapError if a read fails.
template <typename Func>
[[nodiscard]] auto for_each_packet(PcapngReader& reader, Func const& on_packet) -> Status
{
    uint64_t timestamp_us = 0;
    ieee::Eui48 da{};
    ieee::Eui48 sa{};
    uint16_t ethertype = 0;
    Packet payload;
    for (;;) {
        auto step = reader.read_packet(&timestamp_us, da, sa, &ethertype, payload);
        if (!step) {
            return failure(step.error());
        }
        if (!*step) {
            return success();  // EOF
        }
        on_packet(timestamp_us, da, sa, ethertype, payload);
    }
}

}  // namespace statusbar::pcap
