// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT
#include "statusbar/pcap/pcap_writer.hpp"

#include "statusbar/ieee/ieee_ethernet.hpp"
#include "statusbar/pcap/pcap.hpp"
#include "statusbar/pcap/pcap_base.hpp"
#include "statusbar/pcap/pcap_error.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <utility>

namespace statusbar::pcap {

namespace {

[[nodiscard]] auto write_file_header(FILE* file) -> Status
{
    FileHeader header{};
    header.magic_number = PCAP_MAGIC_NATIVE;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 0xffff;
    header.network = 1;
    if (std::fwrite(&header, sizeof(header), 1, file) != 1) {
        return failure(PcapError::file_write_failed);
    }
    return success();
}

[[nodiscard]] auto write_ethernet_frame(
    FILE* file, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload) -> Status
{
    auto const fwrite_one = [&](void const* ptr, size_t size) -> Status {
        if (std::fwrite(ptr, size, 1, file) != 1) {
            return failure(PcapError::file_write_failed);
        }
        return success();
    };
    if (auto s = fwrite_one(da.value.data(), 6); !s) {
        return s;
    }
    if (auto s = fwrite_one(sa.value.data(), 6); !s) {
        return s;
    }
    uint8_t const ethertype_bytes[2] = {static_cast<uint8_t>(ethertype >> 8), static_cast<uint8_t>(ethertype & 0xff)};
    if (auto s = fwrite_one(ethertype_bytes, 2); !s) {
        return s;
    }
    if (!payload.empty()) {
        if (auto s = fwrite_one(payload.data(), payload.size()); !s) {
            return s;
        }
    }
    return success();
}

}  // namespace

auto FileWriter::open(std::string const& filename) -> StatusValue<FileWriter>
{
    FileWriter writer;
    writer.filename_ = filename;

    // Detect existing file by trying to open for read; if it exists, open for
    // append (no header rewrite), otherwise create + write header.
    writer.file_ = make_file(filename, "rb");
    if (writer.file_) {
        writer.file_ = make_file(filename, "a+b");
        if (!writer.file_) {
            return failure(PcapError::file_append_failed);
        }
    } else {
        writer.file_ = make_file(filename, "wb");
        if (!writer.file_) {
            return failure(PcapError::file_create_failed);
        }
        if (auto s = write_file_header(writer.file_.get()); !s) {
            return forward_failure(s);
        }
    }
    return success(std::move(writer));
}

auto FileWriter::write_packet(uint64_t timestamp_us, std::span<uint8_t const> packet) -> Status
{
    // Any length is written, including one too short to hold an Ethernet
    // header. A runt or a truncated frame is a wire event, and usually the
    // reason someone opened a capture; pcap has no minimum record length.
    RecordHeader rec_header{};
    rec_header.ts_sec = static_cast<uint32_t>(timestamp_us / 1000000);
    rec_header.ts_usec = static_cast<uint32_t>(timestamp_us % 1000000);
    rec_header.incl_len = static_cast<int32_t>(packet.size());
    rec_header.orig_len = rec_header.incl_len;
    if (std::fwrite(&rec_header, sizeof(rec_header), 1, file_.get()) != 1) {
        return failure(PcapError::file_write_failed);
    }
    // fwrite(ptr, 0, 1) returns 0, which is indistinguishable from a write
    // error, so an empty packet writes its header and nothing else.
    if (!packet.empty() && std::fwrite(packet.data(), packet.size(), 1, file_.get()) != 1) {
        return failure(PcapError::file_write_failed);
    }
    return success();
}

auto FileWriter::write_packet(
    uint64_t timestamp_us, ieee::Eui48 const& da, ieee::Eui48 const& sa, uint16_t ethertype, std::span<uint8_t const> payload)
    -> Status
{
    RecordHeader rec_header{};
    rec_header.ts_sec = static_cast<uint32_t>(timestamp_us / 1000000);
    rec_header.ts_usec = static_cast<uint32_t>(timestamp_us % 1000000);
    rec_header.incl_len = static_cast<int32_t>(payload.size() + 14);
    rec_header.orig_len = rec_header.incl_len;
    if (std::fwrite(&rec_header, sizeof(rec_header), 1, file_.get()) != 1) {
        return failure(PcapError::file_write_failed);
    }
    return write_ethernet_frame(file_.get(), da, sa, ethertype, payload);
}

void FileWriter::flush()
{
    if (file_) {
        std::fflush(file_.get());
    }
}

}  // namespace statusbar::pcap
