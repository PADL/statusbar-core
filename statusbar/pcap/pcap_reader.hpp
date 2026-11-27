#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace statusbar::pcap {

/// PCAP file reader for Wireshark-compatible capture files.
///
/// Reads Ethernet frames from a PCAP file. Handles both native and
/// byte-swapped file formats automatically, and both resolutions of the
/// record timestamps: a nanosecond pcap is read like a microsecond one, its
/// timestamps cut to microseconds.
///
/// Construct via the static `open()` factory; the ctor is private so callers
/// always see the `StatusValue<FileReader>` failure surface.
class FileReader
{
  public:
    /// Open a PCAP file for reading.
    /// @param filename Path to the PCAP file.
    /// @return A configured FileReader on success, or a PcapError on
    /// open / read / format-validation failure.
    [[nodiscard]] static auto open(std::string const& filename) -> StatusValue<FileReader>;

    ~FileReader() = default;

    // Non-copyable
    FileReader(FileReader const&) = delete;
    auto operator=(FileReader const&) -> FileReader& = delete;

    // Movable
    FileReader(FileReader&&) noexcept = default;
    auto operator=(FileReader&&) noexcept -> FileReader& = default;

    /// Read the next packet from the file.
    /// @param timestamp_us Output: timestamp in microseconds (relative to first packet).
    /// @param packet Output: the complete Ethernet frame data.
    /// @return success(true) if a packet was read, success(false) on clean EOF,
    /// or failure(PcapError::...) on a read error.
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, Packet& packet) -> StatusValue<bool>;

    /// Read the next record and report the length the frame had on the wire.
    /// @param timestamp_us Receives the timestamp, relative to the first record
    /// @param packet Receives the captured bytes
    /// @param original_len Receives the record's orig_len — larger than
    ///        packet.size() for a snapped capture, equal for a complete
    ///        frame. May be nullptr. A file claiming an orig_len below its
    ///        own incl_len is malformed and reported verbatim; a negative
    ///        one is refused as an invalid record header.
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> StatusValue<bool>;

    /// Read the next packet and parse the Ethernet header.
    /// @param timestamp_us Output: timestamp in microseconds (relative to first packet).
    /// @param da Output: destination MAC address (6 bytes).
    /// @param sa Output: source MAC address (6 bytes).
    /// @param ethertype Output: Ethernet type/length field.
    /// @param payload Output: Ethernet payload (after the 14-byte header).
    /// @return success(true) if a packet was read, success(false) on clean EOF,
    /// or failure(PcapError::...) on a read error.
    [[nodiscard]] auto read_packet(uint64_t* timestamp_us, ieee::Eui48& da, ieee::Eui48& sa, uint16_t* ethertype, Packet& payload)
        -> StatusValue<bool>;

  private:
    FileReader() = default;

    /// Read the file header and take the layout its magic number names.
    [[nodiscard]] auto read_file_header() -> Status;
    /// Read the next record header into @p rec, in this host's byte order, and
    /// refuse lengths no record can have. success(false) on a clean EOF.
    [[nodiscard]] auto read_record_header(RecordHeader& rec) -> StatusValue<bool>;
    /// Read the next record: its header into @p rec and its captured bytes
    /// into @p packet. success(false) on a clean EOF.
    [[nodiscard]] auto read_record(RecordHeader& rec, Packet& packet) -> StatusValue<bool>;
    /// @p timestamp_us relative to the first record's, which this call makes
    /// it when there has been none.
    [[nodiscard]] auto relative_timestamp_us(uint64_t timestamp_us) noexcept -> uint64_t;

    FilePtr file_{nullptr, [](FILE*) -> void {}};
    std::string filename_;
    FileLayout layout_{};
    bool seen_first_timestamp_{false};
    uint64_t first_timestamp_us_{0};
};

/// Read all packets from a FileReader, calling a callback for each one.
/// Stops on EOF; on a read error, returns the error to the caller.
///
/// @param reader The pcap reader to read from.
/// @param on_packet Callback: `void(uint64_t timestamp_us, Eui48 const& da, Eui48 const& sa, uint16_t ethertype, Packet const& payload)`.
template <typename Func>
[[nodiscard]] auto for_each_packet(FileReader& reader, Func const& on_packet) -> Status
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
