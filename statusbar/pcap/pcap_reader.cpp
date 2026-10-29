// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
#include "statusbar/pcap/pcap_reader.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee_ethernet.hpp"
#include "statusbar/pcap/pcap.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <utility>

namespace statusbar::pcap {

auto FileReader::open(std::string const& filename) -> StatusValue<FileReader>
{
    FileReader reader;
    reader.filename_ = filename;
    reader.file_ = make_file(filename, "rb");
    if (!reader.file_) {
        return failure(PcapError::file_open_failed);
    }
    FileHeader header{};
    if (std::fread(&header, sizeof(header), 1, reader.file_.get()) != 1) {
        return failure(PcapError::invalid_pcap_header);
    }
    if (header.magic_number == PCAP_MAGIC_NATIVE) {
        reader.swap_ = false;
    } else if (header.magic_number == PCAP_MAGIC_SWAPPED) {
        reader.swap_ = true;
    } else {
        return failure(PcapError::incompatible_magic);
    }
    return success(std::move(reader));
}

auto FileReader::read_packet(uint64_t* timestamp_us, Packet& packet) -> StatusValue<bool>
{
    if (std::feof(file_.get()) != 0) {
        return success(false);
    }
    RecordHeader rec_header{};
    if (std::fread(&rec_header, sizeof(rec_header), 1, file_.get()) != 1) {
        if (std::feof(file_.get()) != 0) {
            return success(false);
        }
        return failure(PcapError::invalid_record_header);
    }
    if (swap_) {
        rec_header.incl_len = static_cast<int32_t>(swap_bytes(static_cast<uint32_t>(rec_header.incl_len)));
        rec_header.orig_len = static_cast<int32_t>(swap_bytes(static_cast<uint32_t>(rec_header.orig_len)));
        rec_header.ts_sec = swap_bytes(rec_header.ts_sec);
        rec_header.ts_usec = swap_bytes(rec_header.ts_usec);
    }
    if (rec_header.incl_len > 32768 || rec_header.incl_len < 0) {
        return failure(PcapError::record_too_large);
    }
    uint64_t const timestamp = (static_cast<uint64_t>(rec_header.ts_sec) * 1000000) + rec_header.ts_usec;
    packet.resize(static_cast<size_t>(rec_header.incl_len));
    // fread(ptr, 0, 1) returns 0 and would read as a failure, so a
    // zero-length record -- ours or another tool's -- is a record with no
    // bytes, not a broken file. PcapngReader already guards this way.
    if (!packet.empty() && std::fread(packet.data(), packet.size(), 1, file_.get()) != 1) {
        return failure(PcapError::file_read_failed);
    }
    if (!seen_first_timestamp_) {
        seen_first_timestamp_ = true;
        first_timestamp_us_ = timestamp;
    }
    *timestamp_us = timestamp - first_timestamp_us_;
    return success(true);
}

auto FileReader::read_packet(uint64_t* timestamp_us, ieee::Eui48& da, ieee::Eui48& sa, uint16_t* ethertype, Packet& payload)
    -> StatusValue<bool>
{
    Packet frame;
    auto step = read_packet(timestamp_us, frame);
    if (!step) {
        return forward_failure(step);
    }
    if (!*step) {
        return success(false);
    }
    if (frame.size() >= 14) {
        std::span<uint8_t const> const frame_span{frame};
        statusbar::span_copy(da.value, frame_span.subspan(0, 6));
        statusbar::span_copy(sa.value, frame_span.subspan(6, 6));
        *ethertype = (static_cast<uint16_t>(frame[12]) << 8) | frame[13];
        size_t const payload_len = frame.size() - 14;
        if (payload_len <= 1524) {
            payload.resize(payload_len);
            statusbar::span_copy(payload, frame_span.subspan(14, payload_len));
        } else {
            payload.clear();
        }
    } else {
        da = {};
        sa = {};
        *ethertype = 0;
        payload.clear();
    }
    return success(true);
}

}  // namespace statusbar::pcap
