// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/pcap/pcap_error.hpp"

namespace statusbar::pcap {

auto PcapErrorCategory::message(int ev) const -> std::string
{
    switch (static_cast<PcapError>(ev)) {
        case PcapError::file_open_failed:
            return "Failed to open pcap file for reading";
        case PcapError::file_create_failed:
            return "Failed to create pcap file";
        case PcapError::file_append_failed:
            return "Failed to append to pcap file";
        case PcapError::file_read_failed:
            return "I/O error reading pcap file";
        case PcapError::file_write_failed:
            return "I/O error writing pcap file";
        case PcapError::invalid_pcap_header:
            return "Truncated or unreadable pcap file header";
        case PcapError::incompatible_magic:
            return "Unrecognised pcap magic number";
        case PcapError::invalid_record_header:
            return "Truncated or invalid pcap record header";
        case PcapError::record_too_large:
            return "pcap record's incl_len exceeds the supported maximum";
        case PcapError::invalid_block_header:
            return "Truncated or invalid pcapng block header";
        case PcapError::invalid_section_header:
            return "pcapng file did not start with a Section Header Block";
        case PcapError::invalid_byte_order_magic:
            return "pcapng Section Header Block has invalid byte_order_magic";
        case PcapError::invalid_interface_description:
            return "Truncated or invalid pcapng Interface Description Block";
        case PcapError::invalid_enhanced_packet:
            return "Truncated or invalid pcapng Enhanced Packet Block";
        case PcapError::invalid_simple_packet:
            return "Truncated or invalid pcapng Simple Packet Block";
        case PcapError::invalid_original_length:
            return "Original (wire) length is smaller than the captured bytes";
    }
    return "Unknown pcap error";
}

auto pcap_error_category() noexcept -> std::error_category const&
{
    static PcapErrorCategory const instance;
    return instance;
}

auto make_error_code(PcapError e) noexcept -> std::error_code
{
    return {static_cast<int>(e), pcap_error_category()};
}

}  // namespace statusbar::pcap
