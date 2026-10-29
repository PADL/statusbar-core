#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace statusbar::pcap {

/// PCAP file writer for Wireshark-compatible capture files.
///
/// Writes Ethernet frames to a PCAP file. If the file already exists,
/// new packets are appended. If not, a new file with proper header is created.
///
/// Construct via the static `open()` factory; the ctor is private so callers
/// always see the `StatusValue<FileWriter>` failure surface.
class FileWriter
{
  public:
    /// Open or create a PCAP file for writing.
    /// @param filename Path to the PCAP file.
    /// @return A configured FileWriter on success, or a PcapError on
    /// open / create / header-write failure.
    [[nodiscard]] static auto open(std::string const& filename) -> StatusValue<FileWriter>;

    ~FileWriter() = default;

    // Non-copyable
    FileWriter(FileWriter const&) = delete;
    auto operator=(FileWriter const&) -> FileWriter& = delete;

    // Movable
    FileWriter(FileWriter&&) noexcept = default;
    auto operator=(FileWriter&&) noexcept -> FileWriter& = default;

    //
    // Zero-allocation span-based API (preferred for runtime use)
    //

    /// Write a complete Ethernet frame with current timestamp (zero-allocation).
    /// @param packet The frame as a span. Any length is written as-is,
    ///        including one too short for an Ethernet header: a capture
    ///        records what happened, and a runt is part of that.
    [[nodiscard]] auto write_packet(std::span<uint8_t const> packet) -> Status
    {
        return write_packet(get_current_time_in_microseconds(), packet);
    }

    /// Write a complete Ethernet frame with specified timestamp (zero-allocation).
    /// @param timestamp_us Timestamp in microseconds since epoch.
    /// @param packet The frame as a span. Any length is written as-is; see
    ///        the overload above. Read such a record back with the raw
    ///        read_packet(), since the Ethernet-parsing one reports zeroed
    ///        addresses for a frame shorter than 14 bytes.
    [[nodiscard]] auto write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet) -> Status;

    /// Write an Ethernet frame from components with current timestamp (zero-allocation).
    [[nodiscard]] auto write_packet(
        ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload) -> Status
    {
        return write_packet(get_current_time_in_microseconds(), da, sa, ethertype, payload);
    }

    /// Write an Ethernet frame from components with specified timestamp (zero-allocation).
    [[nodiscard]] auto write_packet(
        uint64_t timestamp_us, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload)
        -> Status;

    //
    // Legacy vector-based API (convenience, delegates to span API)
    //

    [[nodiscard]] auto write_packet(Packet const& packet) -> Status { return write_packet(std::span<uint8_t const>{packet}); }

    [[nodiscard]] auto write_packet(uint64_t timestamp_us, Packet const& packet) -> Status
    {
        return write_packet(timestamp_us, std::span<uint8_t const>{packet});
    }

    [[nodiscard]] auto write_packet(ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, Packet const& payload)
        -> Status
    {
        return write_packet(da, sa, ethertype, std::span<uint8_t const>{payload});
    }

    [[nodiscard]] auto write_packet(
        uint64_t timestamp_us, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, Packet const& payload) -> Status
    {
        return write_packet(timestamp_us, da, sa, ethertype, std::span<uint8_t const>{payload});
    }

    /// Flush pending writes to disk.
    void flush();

  private:
    FileWriter() = default;

    FilePtr file_{nullptr, [](FILE*) -> void {}};
    std::string filename_;
};

}  // namespace statusbar::pcap
