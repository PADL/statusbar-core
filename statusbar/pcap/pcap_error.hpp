#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// PCAP / PcapNG module error types.
///
/// The pcap module historically reported errors via `std::runtime_error`;
/// the API was migrated to `StatusValue<T>` / `Status` returning factories
/// and methods, with this enum carrying the failure reason.

#include <string>
#include <system_error>

namespace statusbar::pcap {

enum class PcapError
{
    /// Could not open an existing file for reading.
    file_open_failed = 1,
    /// Could not create or open a file for writing.
    file_create_failed,
    /// Could not append to an existing file for writing.
    file_append_failed,
    /// fread / std::fread returned short or failed before EOF.
    file_read_failed,
    /// fwrite / std::fwrite returned short.
    file_write_failed,
    /// PCAP file header was short, truncated, or otherwise unreadable.
    invalid_pcap_header,
    /// PCAP magic number was neither native nor byte-swapped.
    incompatible_magic,
    /// PCAP record header was short or had an out-of-range incl_len.
    invalid_record_header,
    /// PCAP record's incl_len exceeded the 32 KiB / 64 KiB sanity bound,
    /// or was negative.
    record_too_large,
    /// PcapNG block header was short or had an invalid block_length.
    invalid_block_header,
    /// PcapNG file did not start with a Section Header Block.
    invalid_section_header,
    /// PcapNG SHB byte_order_magic was neither native nor byte-swapped.
    invalid_byte_order_magic,
    /// PcapNG Interface Description Block was short or malformed.
    invalid_interface_description,
    /// PcapNG Enhanced Packet Block was short or had a captured_length
    /// that exceeded the 64 KiB cap (or the remaining body).
    invalid_enhanced_packet,
    /// PcapNG Simple Packet Block was short or malformed.
    invalid_simple_packet,
    /// A write asked for an original (wire) length smaller than the bytes
    /// being written, which would describe a frame shorter than its own
    /// capture.
    invalid_original_length,
};

class PcapErrorCategory : public std::error_category
{
  public:
    [[nodiscard]] auto name() const noexcept -> char const* override { return "statusbar.pcap"; }
    [[nodiscard]] auto message(int ev) const -> std::string override;
};

[[nodiscard]] auto pcap_error_category() noexcept -> std::error_category const&;

[[nodiscard]] auto make_error_code(PcapError e) noexcept -> std::error_code;

}  // namespace statusbar::pcap

template <>
struct std::is_error_code_enum<statusbar::pcap::PcapError> : std::true_type
{};
