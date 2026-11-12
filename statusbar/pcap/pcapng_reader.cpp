// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
#include "statusbar/pcap/pcapng_reader.hpp"

#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/ieee/ieee_ethernet.hpp"
#include "statusbar/pcap/pcap.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/pcap/pcapng_base.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace statusbar::pcap {

auto PcapngReader::open(std::string const& filename, std::pmr::memory_resource* memory_resource) -> StatusValue<PcapngReader>
{
    PcapngReader reader{memory_resource};
    reader.filename_ = filename;
    reader.file_ = make_file(filename, "rb");
    if (!reader.file_) {
        return failure(PcapError::file_open_failed);
    }
    PcapngBlockHeader header{};
    if (std::fread(&header, sizeof(header), 1, reader.file_.get()) != 1) {
        return failure(PcapError::invalid_block_header);
    }
    if (header.block_type != static_cast<uint32_t>(PcapngBlockType::SectionHeader)) {
        return failure(PcapError::invalid_section_header);
    }
    PcapngSectionHeaderBody shb{};
    if (std::fread(&shb, sizeof(shb), 1, reader.file_.get()) != 1) {
        return failure(PcapError::invalid_section_header);
    }
    if (shb.byte_order_magic == PCAPNG_BYTE_ORDER_MAGIC) {
        reader.swap_ = false;
    } else if (shb.byte_order_magic == PCAPNG_BYTE_ORDER_MAGIC_SWAPPED) {
        reader.swap_ = true;
    } else {
        return failure(PcapError::invalid_byte_order_magic);
    }
    uint32_t const block_length = reader.swap_ ? swap_bytes32(header.block_length) : header.block_length;
    size_t const remaining = block_length - sizeof(header) - sizeof(shb) - 4;
    if (remaining < 1000000) {
        std::fseek(reader.file_.get(), static_cast<long>(remaining + 4), SEEK_CUR);
    }
    return success(std::move(reader));
}

auto PcapngReader::read_packet(uint64_t* timestamp_us, Packet& packet) -> StatusValue<bool>
{
    return read_packet(timestamp_us, packet, nullptr);
}

auto PcapngReader::read_packet(uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> StatusValue<bool>
{
    while (true) {
        if (std::feof(file_.get()) != 0) {
            return success(false);
        }
        PcapngBlockHeader header{};
        if (std::fread(&header, sizeof(header), 1, file_.get()) != 1) {
            if (std::feof(file_.get()) != 0) {
                return success(false);
            }
            return failure(PcapError::invalid_block_header);
        }
        uint32_t const block_type = swap_ ? swap_bytes32(header.block_type) : header.block_type;
        uint32_t const block_length = swap_ ? swap_bytes32(header.block_length) : header.block_length;
        if (block_length < sizeof(header) + 4) {
            return failure(PcapError::invalid_block_header);
        }
        size_t const body_length = block_length - sizeof(header) - 4;
        if (block_type == static_cast<uint32_t>(PcapngBlockType::InterfaceDescription)) {
            if (!read_interface_description(body_length)) {
                return failure(PcapError::invalid_interface_description);
            }
            continue;
        }
        if (block_type == static_cast<uint32_t>(PcapngBlockType::EnhancedPacket)) {
            if (!read_enhanced_packet(body_length, timestamp_us, packet, original_len)) {
                return failure(PcapError::invalid_enhanced_packet);
            }
            return success(true);
        }
        if (block_type == static_cast<uint32_t>(PcapngBlockType::SimplePacket)) {
            if (!read_simple_packet(body_length, timestamp_us, packet, original_len)) {
                return failure(PcapError::invalid_simple_packet);
            }
            return success(true);
        }
        if (block_type == static_cast<uint32_t>(PcapngBlockType::SectionHeader)) {
            interfaces_.clear();
            if (body_length > 0 && body_length < 1000000) {
                std::fseek(file_.get(), static_cast<long>(body_length + 4), SEEK_CUR);
            }
            continue;
        }
        if (body_length > 0 && body_length < 100000000) {
            std::fseek(file_.get(), static_cast<long>(body_length + 4), SEEK_CUR);
        }
    }
}

auto PcapngReader::read_packet(uint64_t* timestamp_us, ieee::Eui48& da, ieee::Eui48& sa, uint16_t* ethertype, Packet& payload)
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
            statusbar::span_copy(std::span{payload}, frame_span.subspan(14, payload_len));
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

auto PcapngReader::read_interface_description(size_t body_length) -> bool
{
    InterfaceInfo info;
    if (body_length < sizeof(PcapngInterfaceDescBody) || !read_interface_body(info)) {
        return false;
    }
    if (!read_interface_options(body_length - sizeof(PcapngInterfaceDescBody), info)) {
        return false;
    }
    interfaces_.push_back(info);
    return true;
}

auto PcapngReader::read_interface_body(InterfaceInfo& info) -> bool
{
    PcapngInterfaceDescBody idb{};
    if (std::fread(&idb, sizeof(idb), 1, file_.get()) != 1) {
        return false;
    }
    info.link_type = static_cast<LinkType>(swap_ ? swap_bytes16(idb.link_type) : idb.link_type);
    info.snap_length = swap_ ? swap_bytes32(idb.snap_length) : idb.snap_length;
    return true;
}

auto PcapngReader::read_interface_options(size_t remaining, InterfaceInfo& info) -> bool
{
    if (remaining >= 1000000) {
        return false;
    }
    while (remaining >= sizeof(PcapngOptionHeader)) {
        OptionStep const step = read_interface_option(remaining, info);
        if (step == OptionStep::bad) {
            return false;
        }
        if (step == OptionStep::done) {
            break;
        }
    }
    std::fseek(file_.get(), static_cast<long>(remaining + 4), SEEK_CUR);
    return true;
}

auto PcapngReader::read_interface_option(size_t& remaining, InterfaceInfo& info) -> OptionStep
{
    auto const option = read_option_header(remaining);
    if (!option) {
        return OptionStep::bad;
    }
    if (option->code == static_cast<uint16_t>(PcapngIdbOption::end_of_options)) {
        return OptionStep::done;
    }
    if (option->padded_length > remaining || !read_option_value(*option, info)) {
        return OptionStep::bad;
    }
    remaining -= option->padded_length;
    return OptionStep::more;
}

auto PcapngReader::read_option_header(size_t& remaining) -> std::optional<DecodedOption>
{
    PcapngOptionHeader header{};
    if (std::fread(&header, sizeof(header), 1, file_.get()) != 1) {
        return std::nullopt;
    }
    remaining -= sizeof(header);
    uint16_t const length = swap_ ? swap_bytes16(header.length) : header.length;
    return DecodedOption{.code = swap_ ? swap_bytes16(header.code) : header.code, .padded_length = align_to_4(length)};
}

auto PcapngReader::read_option_value(DecodedOption const& option, InterfaceInfo& info) -> bool
{
    if (option.code != static_cast<uint16_t>(PcapngIdbOption::if_tsresol) || option.padded_length != 4) {
        return std::fseek(file_.get(), static_cast<long>(option.padded_length), SEEK_CUR) == 0;
    }
    uint8_t value[4] = {};
    if (std::fread(value, sizeof(value), 1, file_.get()) != 1) {
        return false;
    }
    uint64_t const units = pcapng_units_per_second(value[0]);
    if (units != 0) {
        info.ts_resol = units;
    }
    return true;
}

auto PcapngReader::read_enhanced_packet(size_t body_length, uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> bool
{
    PcapngEnhancedPacketBody epb{};
    if (body_length < sizeof(epb) || std::fread(&epb, sizeof(epb), 1, file_.get()) != 1) {
        return false;
    }
    if (original_len != nullptr) {
        *original_len = swap_ ? swap_bytes32(epb.original_length) : epb.original_length;
    }
    if (!read_captured_bytes(body_length - sizeof(epb), swap_ ? swap_bytes32(epb.captured_length) : epb.captured_length, packet)) {
        return false;
    }
    *timestamp_us = relative_timestamp_us(epb_timestamp_us(epb));
    return true;
}

auto PcapngReader::epb_timestamp_us(PcapngEnhancedPacketBody const& epb) const -> uint64_t
{
    uint32_t const ts_high = swap_ ? swap_bytes32(epb.timestamp_high) : epb.timestamp_high;
    uint32_t const ts_low = swap_ ? swap_bytes32(epb.timestamp_low) : epb.timestamp_low;
    uint32_t const iface_id = swap_ ? swap_bytes32(epb.interface_id) : epb.interface_id;
    uint64_t const ts_resol = (iface_id < interfaces_.size()) ? interfaces_[iface_id].ts_resol : InterfaceInfo{}.ts_resol;
    return pcapng_ticks_to_us((static_cast<uint64_t>(ts_high) << 32) | ts_low, ts_resol);
}

auto PcapngReader::read_captured_bytes(size_t after_header, uint32_t captured_len, Packet& packet) -> bool
{
    if (captured_len > 65535) {
        return false;
    }
    uint32_t const padded_len = align_to_4(captured_len);
    packet.resize(captured_len);
    if (captured_len > 0 && std::fread(packet.data(), captured_len, 1, file_.get()) != 1) {
        return false;
    }
    skip_to_next_block(after_header - padded_len, padded_len - captured_len);
    return true;
}

void PcapngReader::skip_to_next_block(size_t remaining, uint32_t padding)
{
    if (padding > 0) {
        std::fseek(file_.get(), static_cast<long>(padding), SEEK_CUR);
    }
    if (remaining > 0 && remaining < 1000000) {
        std::fseek(file_.get(), static_cast<long>(remaining + 4), SEEK_CUR);
    } else {
        std::fseek(file_.get(), 4, SEEK_CUR);
    }
}

auto PcapngReader::relative_timestamp_us(uint64_t timestamp) -> uint64_t
{
    if (!seen_first_timestamp_) {
        seen_first_timestamp_ = true;
        first_timestamp_us_ = timestamp;
    }
    return timestamp - first_timestamp_us_;
}

auto PcapngReader::read_simple_packet(size_t body_length, uint64_t* timestamp_us, Packet& packet, uint32_t* original_len) -> bool
{
    if (body_length < sizeof(PcapngSimplePacketBody)) {
        return false;
    }
    PcapngSimplePacketBody spb{};
    if (std::fread(&spb, sizeof(spb), 1, file_.get()) != 1) {
        return false;
    }
    uint32_t const wire_len = swap_ ? swap_bytes32(spb.original_length) : spb.original_length;
    if (original_len != nullptr) {
        *original_len = wire_len;
    }
    uint32_t captured_len = static_cast<uint32_t>(body_length - sizeof(spb));
    if (!interfaces_.empty() && captured_len > interfaces_[0].snap_length) {
        captured_len = interfaces_[0].snap_length;
    }
    if (captured_len > wire_len) {
        captured_len = wire_len;
    }
    if (captured_len > 65535) {
        return false;
    }
    packet.resize(captured_len);
    if (captured_len > 0) {
        if (std::fread(packet.data(), captured_len, 1, file_.get()) != 1) {
            return false;
        }
    }
    uint32_t const padded_len = align_to_4(captured_len);
    uint32_t const padding = padded_len - captured_len;
    if (padding > 0) {
        std::fseek(file_.get(), static_cast<long>(padding), SEEK_CUR);
    }
    std::fseek(file_.get(), 4, SEEK_CUR);
    *timestamp_us = 0;
    return true;
}

}  // namespace statusbar::pcap
