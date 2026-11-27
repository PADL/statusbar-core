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
    if (auto const header = reader.read_file_header(); !header) {
        return failure(header.error());
    }
    return success(std::move(reader));
}

auto FileReader::read_file_header() -> Status
{
    FileHeader header{};
    if (std::fread(&header, sizeof(header), 1, file_.get()) != 1) {
        return failure(PcapError::invalid_pcap_header);
    }
    auto const layout = file_layout_of(header.magic_number);
    if (!layout) {
        return failure(PcapError::incompatible_magic);
    }
    layout_ = *layout;
    return success();
}

auto FileReader::read_packet(uint64_t* timestamp_us, Packet& packet) -> StatusValue<bool>
{
    return read_packet(timestamp_us, packet, nullptr);
}

auto FileReader::read_packet(uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> StatusValue<bool>
{
    RecordHeader rec_header{};
    auto const got = read_record(rec_header, packet);
    if (!got || !*got) {
        return got;  // a read error, or a clean EOF
    }
    if (original_len != nullptr) {
        *original_len = static_cast<uint32_t>(rec_header.orig_len);
    }
    *timestamp_us = relative_timestamp_us(record_timestamp_us(rec_header, layout_.nanoseconds));
    return success(true);
}

auto FileReader::read_record_header(RecordHeader& rec) -> StatusValue<bool>
{
    if (std::feof(file_.get()) != 0) {
        return success(false);
    }
    if (std::fread(&rec, sizeof(rec), 1, file_.get()) != 1) {
        if (std::feof(file_.get()) != 0) {
            return success(false);
        }
        return failure(PcapError::invalid_record_header);
    }
    if (layout_.swapped) {
        rec.incl_len = static_cast<int32_t>(swap_bytes(static_cast<uint32_t>(rec.incl_len)));
        rec.orig_len = static_cast<int32_t>(swap_bytes(static_cast<uint32_t>(rec.orig_len)));
        rec.ts_sec = swap_bytes(rec.ts_sec);
        rec.ts_usec = swap_bytes(rec.ts_usec);
    }
    if (rec.incl_len > 32768 || rec.incl_len < 0) {
        return failure(PcapError::record_too_large);
    }
    // A negative orig_len is the same class of nonsense as a negative
    // incl_len: a 32-bit field read as signed, from a file we did not write.
    if (rec.orig_len < 0) {
        return failure(PcapError::invalid_record_header);
    }
    return success(true);
}

auto FileReader::read_record(RecordHeader& rec, Packet& packet) -> StatusValue<bool>
{
    auto const header = read_record_header(rec);
    if (!header || !*header) {
        return header;
    }
    packet.resize(static_cast<size_t>(rec.incl_len));
    // fread(ptr, 0, 1) returns 0 and would read as a failure, so a
    // zero-length record -- ours or another tool's -- is a record with no
    // bytes, not a broken file. PcapngReader already guards this way.
    if (!packet.empty() && std::fread(packet.data(), packet.size(), 1, file_.get()) != 1) {
        return failure(PcapError::file_read_failed);
    }
    return success(true);
}

auto FileReader::relative_timestamp_us(uint64_t const timestamp_us) noexcept -> uint64_t
{
    if (!seen_first_timestamp_) {
        seen_first_timestamp_ = true;
        first_timestamp_us_ = timestamp_us;
    }
    return timestamp_us - first_timestamp_us_;
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
