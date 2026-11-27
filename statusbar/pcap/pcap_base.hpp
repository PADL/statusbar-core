#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ieee/ieee.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace statusbar::pcap {

/// Packet data type - a vector of bytes representing an Ethernet frame
using Packet = std::vector<uint8_t>;

/// PCAP file magic numbers
constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

/// The magic numbers of a "nanosecond pcap": the same file, with the fraction
/// of each record's timestamp counted in nanoseconds (libpcap 1.5 and later
/// write it when asked for nanosecond precision).
constexpr uint32_t PCAP_NSEC_MAGIC_NATIVE = 0xa1b23c4d;
constexpr uint32_t PCAP_NSEC_MAGIC_SWAPPED = 0x4d3cb2a1;

/// What a classic pcap file's magic number says of the file.
struct FileLayout
{
    bool swapped{false};      ///< its headers are in the other byte order than this host's
    bool nanoseconds{false};  ///< the fraction of a record's timestamp counts nanoseconds, else microseconds

    auto operator==(FileLayout const&) const -> bool = default;
};

/// The layout a magic number stands for; nullopt when it is no pcap magic.
[[nodiscard]] constexpr auto file_layout_of(uint32_t const magic_number) noexcept -> std::optional<FileLayout>
{
    switch (magic_number) {
        case PCAP_MAGIC_NATIVE:
            return FileLayout{.swapped = false, .nanoseconds = false};
        case PCAP_MAGIC_SWAPPED:
            return FileLayout{.swapped = true, .nanoseconds = false};
        case PCAP_NSEC_MAGIC_NATIVE:
            return FileLayout{.swapped = false, .nanoseconds = true};
        case PCAP_NSEC_MAGIC_SWAPPED:
            return FileLayout{.swapped = true, .nanoseconds = true};
        default:
            return std::nullopt;
    }
}

/// PCAP file header (from Wireshark libpcap format)
/// See: http://wiki.wireshark.org/Development/LibpcapFileFormat
struct FileHeader
{
    uint32_t magic_number;   ///< Magic number (0xa1b2c3d4 or byte-swapped)
    uint16_t version_major;  ///< Major version number
    uint16_t version_minor;  ///< Minor version number
    int32_t thiszone;        ///< GMT to local correction
    uint32_t sigfigs;        ///< Accuracy of timestamps
    uint32_t snaplen;        ///< Max length of captured packets, in octets
    uint32_t network;        ///< Data link type (1 = Ethernet)
};

/// PCAP packet record header
struct RecordHeader
{
    uint32_t ts_sec;   ///< Timestamp seconds
    uint32_t ts_usec;  ///< Timestamp microseconds (nanoseconds in a nanosecond pcap, see FileLayout)
    int32_t incl_len;  ///< Number of octets of packet saved in file
    int32_t orig_len;  ///< Actual length of packet
};

/// A record's timestamp in microseconds: ts_sec, and the fraction in ts_usec,
/// which counts nanoseconds when @p nanoseconds (FileLayout::nanoseconds) and
/// is then cut to whole microseconds. @p rec is in this host's byte order.
[[nodiscard]] constexpr auto record_timestamp_us(RecordHeader const& rec, bool const nanoseconds) noexcept -> uint64_t
{
    uint64_t const fraction_us = nanoseconds ? rec.ts_usec / 1000U : rec.ts_usec;
    return (static_cast<uint64_t>(rec.ts_sec) * 1'000'000U) + fraction_us;
}

/// Swap bytes of a 32-bit value (for endian conversion)
[[nodiscard]] constexpr auto swap_bytes(uint32_t v) noexcept -> uint32_t
{
    uint32_t r = 0;
    r |= ((v >> 24) & 0x000000ff);
    r |= ((v >> 8) & 0x0000ff00);
    r |= ((v << 8) & 0x00ff0000);
    r |= ((v << 24) & 0xff000000);
    return r;
}

/// Get current time in microseconds since epoch
[[nodiscard]] inline auto get_current_time_in_microseconds() noexcept -> uint64_t
{
    auto const now = std::chrono::system_clock::now();
    auto const duration = now.time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(duration).count());
}

/// RAII wrapper for FILE* with custom deleter
using FilePtr = std::unique_ptr<FILE, void (*)(FILE*)>;

/// Create a FilePtr from a filename and mode
/// @param filename The file path to open
/// @param mode The fopen mode string (e.g., "rb", "wb")
/// @return A FilePtr managing the opened file, or nullptr on failure
[[nodiscard]] inline auto make_file(std::string const& filename, char const* mode) noexcept -> FilePtr
{
    FILE* f = std::fopen(filename.c_str(), mode);
    return {f, [](FILE* fp) -> void {
                if (fp) {
                    std::fclose(fp);
                }
            }};
}

}  // namespace statusbar::pcap
