// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
#include "statusbar/pcap/pcapng_writer.hpp"

#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"
#include "statusbar/pcap/pcapng_base.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <utility>

namespace statusbar::pcap {

namespace {

constexpr uint32_t SHB_BODY_SIZE = sizeof(PcapngSectionHeaderBody);     // 16
constexpr uint32_t IDB_BODY_SIZE = sizeof(PcapngInterfaceDescBody);     // 8
constexpr uint32_t EPB_BODY_SIZE = sizeof(PcapngEnhancedPacketBody);    // 20
constexpr uint32_t BLOCK_FRAMING_SIZE = sizeof(PcapngBlockHeader) + 4;  // type+length + trailing length

}  // namespace

auto PcapngFileWriter::open(std::string const& filename) -> StatusValue<PcapngFileWriter>
{
    PcapngFileWriter writer;
    writer.filename_ = filename;
    writer.file_ = make_file(filename, "wb");
    if (!writer.file_) {
        return failure(PcapError::file_create_failed);
    }
    if (auto s = writer.write_section_header_block(); !s) {
        return forward_failure(s);
    }
    if (auto s = writer.write_interface_description_block(); !s) {
        return forward_failure(s);
    }
    return success(std::move(writer));
}

auto PcapngFileWriter::write_raw(void const* data, size_t size) -> Status
{
    if (size == 0) {
        return success();
    }
    if (std::fwrite(data, size, 1, file_.get()) != 1) {
        return failure(PcapError::file_write_failed);
    }
    return success();
}

auto PcapngFileWriter::write_u32(uint32_t value) -> Status
{
    return write_raw(&value, sizeof(value));
}

auto PcapngFileWriter::write_pad_to_4(size_t unaligned_size) -> Status
{
    size_t const padding = align_to_4(static_cast<uint32_t>(unaligned_size)) - unaligned_size;
    if (padding > 0) {
        std::array<uint8_t, 3> const zeros{};
        return write_raw(zeros.data(), padding);
    }
    return success();
}

auto PcapngFileWriter::write_section_header_block() -> Status
{
    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::SectionHeader);
    header.block_length = BLOCK_FRAMING_SIZE + SHB_BODY_SIZE;

    PcapngSectionHeaderBody body{};
    body.byte_order_magic = PCAPNG_BYTE_ORDER_MAGIC;
    body.version_major = 1;
    body.version_minor = 0;
    body.section_length = -1;  // section length unknown

    if (auto s = write_raw(&header, sizeof(header)); !s) {
        return s;
    }
    if (auto s = write_raw(&body, sizeof(body)); !s) {
        return s;
    }
    return write_u32(header.block_length);
}

auto PcapngFileWriter::write_interface_description_block() -> Status
{
    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::InterfaceDescription);
    header.block_length = BLOCK_FRAMING_SIZE + IDB_BODY_SIZE;

    PcapngInterfaceDescBody body{};
    body.link_type = static_cast<uint16_t>(LinkType::Ethernet);
    body.reserved = 0;
    body.snap_length = 65535;

    if (auto s = write_raw(&header, sizeof(header)); !s) {
        return s;
    }
    if (auto s = write_raw(&body, sizeof(body)); !s) {
        return s;
    }
    return write_u32(header.block_length);
}

auto PcapngFileWriter::write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet) -> Status
{
    return write_packet(timestamp_us, packet, static_cast<uint32_t>(packet.size()));
}

auto PcapngFileWriter::write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet, uint32_t original_len) -> Status
{
    if (original_len < packet.size()) {
        return failure(PcapError::invalid_original_length);
    }
    // Any length, as in FileWriter::write_packet. write_raw() already
    // answers success for a zero-size body, and align_to_4() pads a short
    // frame to the block alignment, so the block after it still parses.
    uint32_t const captured_len = static_cast<uint32_t>(packet.size());
    uint32_t const padded_len = align_to_4(captured_len);
    uint32_t const block_length = BLOCK_FRAMING_SIZE + EPB_BODY_SIZE + padded_len;

    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::EnhancedPacket);
    header.block_length = block_length;

    PcapngEnhancedPacketBody body{};
    body.interface_id = 0;
    body.timestamp_high = static_cast<uint32_t>(timestamp_us >> 32);
    body.timestamp_low = static_cast<uint32_t>(timestamp_us & 0xFFFFFFFFU);
    body.captured_length = captured_len;
    body.original_length = original_len;

    if (auto s = write_raw(&header, sizeof(header)); !s) {
        return s;
    }
    if (auto s = write_raw(&body, sizeof(body)); !s) {
        return s;
    }
    if (auto s = write_raw(packet.data(), packet.size()); !s) {
        return s;
    }
    if (auto s = write_pad_to_4(packet.size()); !s) {
        return s;
    }
    return write_u32(block_length);
}

auto PcapngFileWriter::write_packet(
    uint64_t timestamp_us, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload)
    -> Status
{
    constexpr size_t ETH_HEADER_SIZE = 14;
    size_t const frame_size = ETH_HEADER_SIZE + payload.size();
    uint32_t const captured_len = static_cast<uint32_t>(frame_size);
    uint32_t const padded_len = align_to_4(captured_len);
    uint32_t const block_length = BLOCK_FRAMING_SIZE + EPB_BODY_SIZE + padded_len;

    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::EnhancedPacket);
    header.block_length = block_length;

    PcapngEnhancedPacketBody body{};
    body.interface_id = 0;
    body.timestamp_high = static_cast<uint32_t>(timestamp_us >> 32);
    body.timestamp_low = static_cast<uint32_t>(timestamp_us & 0xFFFFFFFFU);
    body.captured_length = captured_len;
    body.original_length = captured_len;

    if (auto s = write_raw(&header, sizeof(header)); !s) {
        return s;
    }
    if (auto s = write_raw(&body, sizeof(body)); !s) {
        return s;
    }

    if (auto s = write_raw(da.value.data(), 6); !s) {
        return s;
    }
    if (auto s = write_raw(sa.value.data(), 6); !s) {
        return s;
    }
    std::array<uint8_t, 2> const ethertype_bytes{
        static_cast<uint8_t>(ethertype >> 8),
        static_cast<uint8_t>(ethertype & 0xff),
    };
    if (auto s = write_raw(ethertype_bytes.data(), ethertype_bytes.size()); !s) {
        return s;
    }
    if (!payload.empty()) {
        if (auto s = write_raw(payload.data(), payload.size()); !s) {
            return s;
        }
    }
    if (auto s = write_pad_to_4(frame_size); !s) {
        return s;
    }
    return write_u32(block_length);
}

void PcapngFileWriter::flush()
{
    if (file_) {
        std::fflush(file_.get());
    }
}

}  // namespace statusbar::pcap
