#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/pcap/pcapng_base.hpp"
#include "statusbar/status/status.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <utility>

namespace statusbar::pcap {

/// PcapNG file writer for Wireshark-compatible capture files.
///
/// Creates a new pcapng file with a Section Header Block and a single
/// Ethernet Interface Description Block, then emits one Enhanced Packet
/// Block per packet. Timestamps are microsecond-resolution (EPB ts_high/ts_low
/// as a 64-bit count of microseconds since the Unix epoch).
///
/// Blocks are written in native byte order; the byte-order magic in the SHB
/// lets readers detect endianness.
///
/// Construct via the static `open()` factory; the ctor is private so callers
/// always see the `StatusValue<PcapngFileWriter>` failure surface.
class PcapngFileWriter
{
  public:
    /// Create a new pcapng file. Truncates any existing file at the path.
    /// @return Configured writer on success, or a PcapError on
    /// open / header-write failure.
    [[nodiscard]] static auto open(std::string const& filename) -> StatusValue<PcapngFileWriter>;

    ~PcapngFileWriter() = default;

    PcapngFileWriter(PcapngFileWriter const&) = delete;
    auto operator=(PcapngFileWriter const&) -> PcapngFileWriter& = delete;

    PcapngFileWriter(PcapngFileWriter&&) noexcept = default;
    auto operator=(PcapngFileWriter&&) noexcept -> PcapngFileWriter& = default;

    /// Write a complete Ethernet frame with the current timestamp.
    [[nodiscard]] auto write_packet(std::span<uint8_t const> packet) -> Status
    {
        return write_packet(get_current_time_in_microseconds(), packet);
    }

    /// Write a complete Ethernet frame with an explicit microsecond timestamp.
    [[nodiscard]] auto write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet) -> Status;

    /// Write a snapped (truncated) capture: the bytes kept, plus the length
    /// the frame had on the wire, as the EPB's original_length. See
    /// FileWriter::write_packet for why a reader needs the second number.
    /// @param timestamp_us Timestamp in microseconds since epoch.
    /// @param packet The captured bytes.
    /// @param original_len The frame's length on the wire; equal to
    ///        packet.size() for a complete frame.
    /// @return PcapError::invalid_original_length if @p original_len is
    ///         smaller than @p packet.
    [[nodiscard]] auto write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet, uint32_t original_len) -> Status;

    /// Write an Ethernet frame from its header components and payload, current timestamp.
    [[nodiscard]] auto write_packet(
        ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload) -> Status
    {
        return write_packet(get_current_time_in_microseconds(), da, sa, ethertype, payload);
    }

    /// Write an Ethernet frame from its header components and payload, explicit timestamp.
    [[nodiscard]] auto write_packet(
        uint64_t timestamp_us, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload)
        -> Status;

    /// Flush pending writes to disk.
    void flush();

  private:
    PcapngFileWriter() = default;

    [[nodiscard]] auto write_section_header_block() -> Status;
    [[nodiscard]] auto write_interface_description_block() -> Status;
    [[nodiscard]] auto write_raw(void const* data, size_t size) -> Status;
    [[nodiscard]] auto write_u32(uint32_t value) -> Status;
    [[nodiscard]] auto write_pad_to_4(size_t unaligned_size) -> Status;

    FilePtr file_{nullptr, [](FILE*) -> void {}};
    std::string filename_;
};

}  // namespace statusbar::pcap
