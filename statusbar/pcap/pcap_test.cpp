// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for PCAP module
// Tests PCAP base functionality and constants

#include "statusbar/pcap/pcap.hpp"

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace statusbar::pcap;

//
// Static asserts: Compile-time verification of constants and constexpr functions
//

// PCAP magic numbers
static_assert(PCAP_MAGIC_NATIVE == 0xa1b2c3d4, "PCAP native magic number per libpcap spec");
static_assert(PCAP_MAGIC_SWAPPED == 0xd4c3b2a1, "PCAP swapped magic number per libpcap spec");
static_assert(swap_bytes(PCAP_MAGIC_NATIVE) == PCAP_MAGIC_SWAPPED, "swap_bytes should reverse magic");

// PCAPNG magic numbers
static_assert(PCAPNG_BYTE_ORDER_MAGIC == 0x1a2b3c4d, "PCAPNG byte order magic per spec");
static_assert(PCAPNG_BYTE_ORDER_MAGIC_SWAPPED == 0x4d3c2b1a, "PCAPNG swapped magic per spec");
static_assert(swap_bytes32(PCAPNG_BYTE_ORDER_MAGIC) == PCAPNG_BYTE_ORDER_MAGIC_SWAPPED, "swap_bytes32 reverses magic");

// swap_bytes constexpr verification
static_assert(swap_bytes(0x12345678U) == 0x78563412U, "swap_bytes correctness");
static_assert(swap_bytes(swap_bytes(0xDEADBEEFU)) == 0xDEADBEEFU, "swap_bytes double swap is identity");
static_assert(swap_bytes(0U) == 0U, "swap_bytes(0) == 0");
static_assert(swap_bytes(0xFFFFFFFFU) == 0xFFFFFFFFU, "swap_bytes(0xFFFFFFFF) == 0xFFFFFFFF");

// swap_bytes16 constexpr verification
static_assert(swap_bytes16(0x1234U) == 0x3412U, "swap_bytes16 correctness");
static_assert(swap_bytes16(swap_bytes16(0xABCDU)) == 0xABCDU, "swap_bytes16 double swap is identity");
static_assert(swap_bytes16(0U) == 0U, "swap_bytes16(0) == 0");
static_assert(swap_bytes16(0xFFFFU) == 0xFFFFU, "swap_bytes16(0xFFFF) == 0xFFFF");

// swap_bytes32 constexpr verification
static_assert(swap_bytes32(0x12345678U) == 0x78563412U, "swap_bytes32 correctness");
static_assert(swap_bytes32(swap_bytes32(0xDEADBEEFU)) == 0xDEADBEEFU, "swap_bytes32 double swap is identity");

// swap_bytes64 constexpr verification
static_assert(swap_bytes64(0x0102030405060708ULL) == 0x0807060504030201ULL, "swap_bytes64 correctness");
static_assert(swap_bytes64(swap_bytes64(0xDEADBEEFCAFEBABEULL)) == 0xDEADBEEFCAFEBABEULL, "swap_bytes64 double swap is identity");
static_assert(swap_bytes64(0ULL) == 0ULL, "swap_bytes64(0) == 0");

// align_to_4 constexpr verification
static_assert(align_to_4(0U) == 0U, "align_to_4(0) == 0");
static_assert(align_to_4(1U) == 4U, "align_to_4(1) == 4");
static_assert(align_to_4(2U) == 4U, "align_to_4(2) == 4");
static_assert(align_to_4(3U) == 4U, "align_to_4(3) == 4");
static_assert(align_to_4(4U) == 4U, "align_to_4(4) == 4");
static_assert(align_to_4(5U) == 8U, "align_to_4(5) == 8");
static_assert(align_to_4(100U) == 100U, "align_to_4(100) == 100 (already aligned)");
static_assert(align_to_4(101U) == 104U, "align_to_4(101) == 104");

// PcapngBlockType enum values per pcapng spec
static_assert(static_cast<uint32_t>(PcapngBlockType::SectionHeader) == 0x0a0d0d0a, "SHB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::InterfaceDescription) == 1, "IDB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::Packet) == 2, "Packet block type (obsolete)");
static_assert(static_cast<uint32_t>(PcapngBlockType::SimplePacket) == 3, "SPB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::NameResolution) == 4, "NRB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::InterfaceStatistics) == 5, "ISB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::EnhancedPacket) == 6, "EPB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::DecryptionSecrets) == 0x0a, "DSB block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::CustomCopyable) == 0x00000bad, "Custom copyable block type");
static_assert(static_cast<uint32_t>(PcapngBlockType::CustomNotCopyable) == 0x40000bad, "Custom not copyable block type");

// LinkType enum values per tcpdump.org
static_assert(static_cast<uint16_t>(LinkType::Null) == 0, "Null link type");
static_assert(static_cast<uint16_t>(LinkType::Ethernet) == 1, "Ethernet link type");
static_assert(static_cast<uint16_t>(LinkType::Ppp) == 9, "PPP link type");
static_assert(static_cast<uint16_t>(LinkType::PppEther) == 51, "PPP over Ethernet link type");
static_assert(static_cast<uint16_t>(LinkType::Raw) == 101, "Raw IP link type");
static_assert(static_cast<uint16_t>(LinkType::Ieee80211) == 105, "IEEE 802.11 link type");
static_assert(static_cast<uint16_t>(LinkType::Linux_sll) == 113, "Linux SLL link type");
static_assert(static_cast<uint16_t>(LinkType::Linux_sll2) == 276, "Linux SLL2 link type");

// Structure sizes per PCAP/PCAPNG specifications
static_assert(sizeof(FileHeader) == 24, "PCAP FileHeader is 24 bytes per spec");
static_assert(sizeof(RecordHeader) == 16, "PCAP RecordHeader is 16 bytes per spec");
static_assert(sizeof(PcapngBlockHeader) == 8, "PCAPNG block header is 8 bytes");
static_assert(sizeof(PcapngSectionHeaderBody) == 16, "PCAPNG SHB body is 16 bytes");
static_assert(sizeof(PcapngInterfaceDescBody) == 8, "PCAPNG IDB body is 8 bytes");
static_assert(sizeof(PcapngEnhancedPacketBody) == 20, "PCAPNG EPB body is 20 bytes");
static_assert(sizeof(PcapngSimplePacketBody) == 4, "PCAPNG SPB body is 4 bytes");

// InterfaceInfo default values
static_assert(InterfaceInfo{}.link_type == LinkType::Ethernet, "Default link type is Ethernet");
static_assert(InterfaceInfo{}.snap_length == 65535, "Default snap length is 65535");
static_assert(InterfaceInfo{}.ts_resol == 1000000, "Default timestamp resolution is microseconds");

//
// Tests: PCAP Magic Numbers
//

TEST(pcap_magic, native)
{
    EXPECT_EQ(PCAP_MAGIC_NATIVE, 0xa1b2c3d4U);
}

TEST(pcap_magic, swapped)
{
    EXPECT_EQ(PCAP_MAGIC_SWAPPED, 0xd4c3b2a1U);
}

TEST(pcap_magic, swapped_is_byte_reversed)
{
    // Verify that SWAPPED is actually byte-reversed NATIVE
    EXPECT_EQ(PCAP_MAGIC_SWAPPED, swap_bytes(PCAP_MAGIC_NATIVE));
}

//
// Tests: swap_bytes function
//

TEST(pcap_swap_bytes, identity)
{
    // Swapping twice should give back the original
    uint32_t original = 0x12345678;
    EXPECT_EQ(swap_bytes(swap_bytes(original)), original);
}

TEST(pcap_swap_bytes, values)
{
    EXPECT_EQ(swap_bytes(0x12345678U), 0x78563412U);
    EXPECT_EQ(swap_bytes(0x00000001U), 0x01000000U);
    EXPECT_EQ(swap_bytes(0xFF000000U), 0x000000FFU);
    EXPECT_EQ(swap_bytes(0x00FF0000U), 0x0000FF00U);
}

TEST(pcap_swap_bytes, zero)
{
    EXPECT_EQ(swap_bytes(0U), 0U);
}

TEST(pcap_swap_bytes, all_ones)
{
    EXPECT_EQ(swap_bytes(0xFFFFFFFFU), 0xFFFFFFFFU);
}

//
// Tests: FileHeader structure
//

TEST(pcap_file_header, size)
{
    // FileHeader should be 24 bytes per PCAP spec
    EXPECT_EQ(sizeof(FileHeader), 24U);
}

TEST(pcap_file_header, field_offsets)
{
    EXPECT_EQ(offsetof(FileHeader, magic_number), 0U);
    EXPECT_EQ(offsetof(FileHeader, version_major), 4U);
    EXPECT_EQ(offsetof(FileHeader, version_minor), 6U);
    EXPECT_EQ(offsetof(FileHeader, thiszone), 8U);
    EXPECT_EQ(offsetof(FileHeader, sigfigs), 12U);
    EXPECT_EQ(offsetof(FileHeader, snaplen), 16U);
    EXPECT_EQ(offsetof(FileHeader, network), 20U);
}

//
// Tests: RecordHeader structure
//

TEST(pcap_record_header, size)
{
    // RecordHeader should be 16 bytes per PCAP spec
    EXPECT_EQ(sizeof(RecordHeader), 16U);
}

TEST(pcap_record_header, field_offsets)
{
    EXPECT_EQ(offsetof(RecordHeader, ts_sec), 0U);
    EXPECT_EQ(offsetof(RecordHeader, ts_usec), 4U);
    EXPECT_EQ(offsetof(RecordHeader, incl_len), 8U);
    EXPECT_EQ(offsetof(RecordHeader, orig_len), 12U);
}

//
// Tests: PcapNG block types
//

TEST(pcapng_block_types, values)
{
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::SectionHeader), 0x0a0d0d0aU);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::InterfaceDescription), 0x00000001U);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::Packet), 0x00000002U);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::SimplePacket), 0x00000003U);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::NameResolution), 0x00000004U);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::InterfaceStatistics), 0x00000005U);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::EnhancedPacket), 0x00000006U);
}

TEST(pcapng_block_types, custom)
{
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::CustomCopyable), 0x00000badU);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::CustomNotCopyable), 0x40000badU);
}

//
// Tests: PcapNG byte order magic
//

TEST(pcapng_magic, native)
{
    EXPECT_EQ(PCAPNG_BYTE_ORDER_MAGIC, 0x1a2b3c4dU);
}

TEST(pcapng_magic, swapped)
{
    EXPECT_EQ(PCAPNG_BYTE_ORDER_MAGIC_SWAPPED, 0x4d3c2b1aU);
}

TEST(pcapng_magic, swapped_is_byte_reversed)
{
    EXPECT_EQ(PCAPNG_BYTE_ORDER_MAGIC_SWAPPED, swap_bytes32(PCAPNG_BYTE_ORDER_MAGIC));
}

//
// Tests: PcapNG link types
//

TEST(pcapng_link_types, values)
{
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Null), 0);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Ethernet), 1);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Ppp), 9);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::PppEther), 51);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Raw), 101);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Ieee80211), 105);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Linux_sll), 113);
    EXPECT_EQ(static_cast<uint16_t>(LinkType::Linux_sll2), 276);
}

//
// Tests: PcapNG swap functions
//

TEST(pcapng_swap16, values)
{
    EXPECT_EQ(swap_bytes16(0x1234U), 0x3412U);
    EXPECT_EQ(swap_bytes16(0xFF00U), 0x00FFU);
    EXPECT_EQ(swap_bytes16(0x0001U), 0x0100U);
}

TEST(pcapng_swap16, identity)
{
    uint16_t original = 0xABCD;
    EXPECT_EQ(swap_bytes16(swap_bytes16(original)), original);
}

TEST(pcapng_swap32, values)
{
    EXPECT_EQ(swap_bytes32(0x12345678U), 0x78563412U);
    EXPECT_EQ(swap_bytes32(0xFF000000U), 0x000000FFU);
}

TEST(pcapng_swap32, identity)
{
    uint32_t original = 0xDEADBEEF;
    EXPECT_EQ(swap_bytes32(swap_bytes32(original)), original);
}

TEST(pcapng_swap64, values)
{
    EXPECT_EQ(swap_bytes64(0x0102030405060708ULL), 0x0807060504030201ULL);
    EXPECT_EQ(swap_bytes64(0xFF00000000000000ULL), 0x00000000000000FFULL);
}

TEST(pcapng_swap64, identity)
{
    uint64_t original = 0xDEADBEEFCAFEBABEULL;
    EXPECT_EQ(swap_bytes64(swap_bytes64(original)), original);
}

//
// Tests: PcapNG alignment
//

TEST(pcapng_align, already_aligned)
{
    EXPECT_EQ(align_to_4(0U), 0U);
    EXPECT_EQ(align_to_4(4U), 4U);
    EXPECT_EQ(align_to_4(8U), 8U);
    EXPECT_EQ(align_to_4(16U), 16U);
}

TEST(pcapng_align, needs_padding)
{
    EXPECT_EQ(align_to_4(1U), 4U);
    EXPECT_EQ(align_to_4(2U), 4U);
    EXPECT_EQ(align_to_4(3U), 4U);
    EXPECT_EQ(align_to_4(5U), 8U);
    EXPECT_EQ(align_to_4(6U), 8U);
    EXPECT_EQ(align_to_4(7U), 8U);
    EXPECT_EQ(align_to_4(9U), 12U);
}

//
// Tests: PcapNG structure sizes
//

TEST(pcapng_structs, block_header_size)
{
    EXPECT_EQ(sizeof(PcapngBlockHeader), 8U);
}

TEST(pcapng_structs, section_header_body_size)
{
    EXPECT_EQ(sizeof(PcapngSectionHeaderBody), 16U);
}

TEST(pcapng_structs, interface_desc_body_size)
{
    EXPECT_EQ(sizeof(PcapngInterfaceDescBody), 8U);
}

TEST(pcapng_structs, enhanced_packet_body_size)
{
    EXPECT_EQ(sizeof(PcapngEnhancedPacketBody), 20U);
}

TEST(pcapng_structs, simple_packet_body_size)
{
    EXPECT_EQ(sizeof(PcapngSimplePacketBody), 4U);
}

//
// Tests: Packet type
//

TEST(pcap_packet, is_vector)
{
    Packet packet;
    packet.push_back(0x01);
    packet.push_back(0x02);
    packet.push_back(0x03);
    EXPECT_EQ(packet.size(), 3U);
    EXPECT_EQ(packet[0], 0x01);
    EXPECT_EQ(packet[1], 0x02);
    EXPECT_EQ(packet[2], 0x03);
}

TEST(pcap_packet, resize)
{
    Packet packet;
    packet.resize(100);
    EXPECT_EQ(packet.size(), 100U);
}

//
// Tests: FileWriter and FileReader roundtrip
//

TEST(pcap_file_rw, write_and_read_basic)
{
    // Create a temporary file path
    std::string const filename = "/tmp/statusbar_pcap_test_basic.pcap";

    // Remove any existing file
    std::remove(filename.c_str());

    // Create a test Ethernet frame (minimum 15 bytes to pass FileWriter's check)
    Packet test_frame;
    // Destination MAC: 00:11:22:33:44:55
    test_frame.push_back(0x00);
    test_frame.push_back(0x11);
    test_frame.push_back(0x22);
    test_frame.push_back(0x33);
    test_frame.push_back(0x44);
    test_frame.push_back(0x55);
    // Source MAC: AA:BB:CC:DD:EE:FF
    test_frame.push_back(0xAA);
    test_frame.push_back(0xBB);
    test_frame.push_back(0xCC);
    test_frame.push_back(0xDD);
    test_frame.push_back(0xEE);
    test_frame.push_back(0xFF);
    // EtherType: 0x0800 (IPv4)
    test_frame.push_back(0x08);
    test_frame.push_back(0x00);
    // Payload: "Hello"
    test_frame.push_back('H');
    test_frame.push_back('e');
    test_frame.push_back('l');
    test_frame.push_back('l');
    test_frame.push_back('o');

    uint64_t const write_timestamp = 1000000ULL;  // 1 second

    // Write the packet
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(write_timestamp, test_frame);
        writer.flush();
    }

    // Read it back
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t read_timestamp = 0;
        Packet read_frame;
        auto step = reader.read_packet(&read_timestamp, read_frame);
        EXPECT_TRUE(step.has_value());
        bool got_packet = *step;

        EXPECT_TRUE(got_packet);
        EXPECT_EQ(read_timestamp, 0U);  // First packet is relative timestamp 0
        EXPECT_EQ(read_frame.size(), test_frame.size());
        for (size_t i = 0; i < test_frame.size(); ++i) {
            EXPECT_EQ(read_frame[i], test_frame[i]);
        }
    }

    // Clean up
    std::remove(filename.c_str());
}

TEST(pcap_file_rw, write_and_read_multiple)
{
    std::string const filename = "/tmp/statusbar_pcap_test_multi.pcap";
    std::remove(filename.c_str());

    // Create test frames
    std::vector<Packet> test_frames;
    for (int i = 0; i < 3; ++i) {
        Packet frame;
        // Minimal Ethernet header (14 bytes) + 1 byte payload
        for (int j = 0; j < 14; ++j) {
            frame.push_back(static_cast<uint8_t>(j));
        }
        frame.push_back(static_cast<uint8_t>(i));  // Unique payload per frame
        test_frames.push_back(frame);
    }

    // Write packets with increasing timestamps
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        for (size_t i = 0; i < test_frames.size(); ++i) {
            (void)writer.write_packet(i * 1000000ULL, test_frames[i]);  // 0, 1s, 2s
        }
        writer.flush();
    }

    // Read packets back
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        for (size_t i = 0; i < test_frames.size(); ++i) {
            uint64_t timestamp = 0;
            Packet read_frame;
            auto step = reader.read_packet(&timestamp, read_frame);
            EXPECT_TRUE(step.has_value());
            bool got_packet = *step;
            EXPECT_TRUE(got_packet);
            EXPECT_EQ(timestamp, i * 1000000ULL);  // Relative to first packet
            EXPECT_EQ(read_frame.size(), test_frames[i].size());
            EXPECT_EQ(read_frame.back(), test_frames[i].back());  // Check unique payload
        }

        // Verify no more packets
        uint64_t timestamp = 0;
        Packet empty_frame;
        auto step = reader.read_packet(&timestamp, empty_frame);
        EXPECT_TRUE(step.has_value());
        EXPECT_FALSE(*step);
    }

    std::remove(filename.c_str());
}

TEST(pcap_file_rw, write_and_read_with_ethernet_components)
{
    std::string const filename = "/tmp/statusbar_pcap_test_eth.pcap";
    std::remove(filename.c_str());

    statusbar::ieee::Eui48 da{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint16_t ethertype = 0x88F7;  // PTP
    Packet payload;
    payload.push_back(0x12);
    payload.push_back(0x34);
    payload.push_back(0x56);

    // Write using component form
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(2000000ULL, da, sa, ethertype, payload);
        writer.flush();
    }

    // Read using component form
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        statusbar::ieee::Eui48 read_da;
        statusbar::ieee::Eui48 read_sa;
        uint16_t read_ethertype = 0;
        Packet read_payload;

        auto step = reader.read_packet(&timestamp, read_da, read_sa, &read_ethertype, read_payload);
        EXPECT_TRUE(step.has_value());
        bool got_packet = *step;
        EXPECT_TRUE(got_packet);
        EXPECT_EQ(timestamp, 0U);  // First packet relative
        EXPECT_EQ(read_da.value, da.value);
        EXPECT_EQ(read_sa.value, sa.value);
        EXPECT_EQ(read_ethertype, ethertype);
        EXPECT_EQ(read_payload.size(), payload.size());
        for (size_t i = 0; i < payload.size(); ++i) {
            EXPECT_EQ(read_payload[i], payload[i]);
        }
    }

    std::remove(filename.c_str());
}

// `write_too_small_ignored` lived here. It wrote a 10-byte frame and a
// 15-byte frame and asserted the file held only the 15-byte one, which
// pinned the discarding of runts as intended behaviour. Its replacement is
// `pcap_short_frame a_runt_between_two_frames_displaces_neither`, which
// writes the same shape and asserts every frame survives.

TEST(pcap_file_rw, open_nonexistent_throws)
{
    auto rdr = FileReader::open("/tmp/definitely_does_not_exist_12345.pcap");
    EXPECT_FALSE(rdr.has_value());
    EXPECT_EQ(rdr.error(), make_error_code(PcapError::file_open_failed));
}

TEST(pcap_file_rw, timestamp_relative_to_first)
{
    std::string const filename = "/tmp/statusbar_pcap_test_ts.pcap";
    std::remove(filename.c_str());

    // Write packets with absolute timestamps
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        Packet frame;
        for (int i = 0; i < 15; ++i) {
            frame.push_back(static_cast<uint8_t>(i));
        }
        (void)writer.write_packet(5000000ULL, frame);   // 5 seconds absolute
        (void)writer.write_packet(7500000ULL, frame);   // 7.5 seconds absolute
        (void)writer.write_packet(10000000ULL, frame);  // 10 seconds absolute
        writer.flush();
    }

    // Read - timestamps should be relative to first packet
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        Packet frame;

        auto s1 = reader.read_packet(&timestamp, frame);
        EXPECT_TRUE(s1.has_value());
        EXPECT_TRUE(*s1);
        EXPECT_EQ(timestamp, 0U);  // First packet = 0

        auto s2 = reader.read_packet(&timestamp, frame);
        EXPECT_TRUE(s2.has_value());
        EXPECT_TRUE(*s2);
        EXPECT_EQ(timestamp, 2500000U);  // 7.5 - 5 = 2.5 seconds

        auto s3 = reader.read_packet(&timestamp, frame);
        EXPECT_TRUE(s3.has_value());
        EXPECT_TRUE(*s3);
        EXPECT_EQ(timestamp, 5000000U);  // 10 - 5 = 5 seconds
    }

    std::remove(filename.c_str());
}

TEST(pcap_file_rw, append_to_existing)
{
    std::string const filename = "/tmp/statusbar_pcap_test_append.pcap";
    std::remove(filename.c_str());

    Packet frame1, frame2;
    for (int i = 0; i < 15; ++i) {
        frame1.push_back(static_cast<uint8_t>(i));
        frame2.push_back(static_cast<uint8_t>(i + 100));
    }

    // Create file with first packet
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(1000000ULL, frame1);
        writer.flush();
    }

    // Append second packet (FileWriter opens in append mode for existing files)
    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(2000000ULL, frame2);
        writer.flush();
    }

    // Read both packets
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        Packet read_frame;

        auto s1 = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(s1.has_value());
        EXPECT_TRUE(*s1);
        EXPECT_EQ(read_frame[0], 0);  // First frame starts with 0

        auto s2 = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(s2.has_value());
        EXPECT_TRUE(*s2);
        EXPECT_EQ(read_frame[0], 100);  // Second frame starts with 100
    }

    std::remove(filename.c_str());
}

TEST(pcap_file_rw, read_short_frame_handled)
{
    std::string const filename = "/tmp/statusbar_pcap_test_short.pcap";
    std::remove(filename.c_str());

    // 15 bytes: an Ethernet header plus a single payload byte, which is
    // what the payload-size assertion below reads. Exactly 14, and shorter,
    // are covered by the pcap_short_frame group.
    Packet min_frame;
    for (int i = 0; i < 15; ++i) {
        min_frame.push_back(static_cast<uint8_t>(i));
    }

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(1000000ULL, min_frame);
        writer.flush();
    }

    // Read with Ethernet parsing - payload should be 1 byte
    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        statusbar::ieee::Eui48 da, sa;
        uint16_t ethertype = 0;
        Packet payload;

        auto step = reader.read_packet(&timestamp, da, sa, &ethertype, payload);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(payload.size(), 1U);  // 15 - 14 = 1 byte payload
    }

    std::remove(filename.c_str());
}

//
// Tests: Zero-allocation span-based API
//

TEST(pcap_span_api, write_with_array)
{
    std::string const filename = "/tmp/statusbar_pcap_test_span_array.pcap";
    std::remove(filename.c_str());

    // Use std::array instead of vector - zero runtime allocation
    std::array<uint8_t, 20> frame{};
    // DA
    frame[0] = 0x00;
    frame[1] = 0x11;
    frame[2] = 0x22;
    frame[3] = 0x33;
    frame[4] = 0x44;
    frame[5] = 0x55;
    // SA
    frame[6] = 0xAA;
    frame[7] = 0xBB;
    frame[8] = 0xCC;
    frame[9] = 0xDD;
    frame[10] = 0xEE;
    frame[11] = 0xFF;
    // EtherType
    frame[12] = 0x08;
    frame[13] = 0x00;
    // Payload
    frame[14] = 'T';
    frame[15] = 'E';
    frame[16] = 'S';
    frame[17] = 'T';
    frame[18] = '!';
    frame[19] = '!';

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        // Pass std::array directly - converts to span implicitly
        (void)writer.write_packet(1000000ULL, frame);
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        Packet read_frame;
        auto step = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_frame.size(), 20U);
        EXPECT_EQ(read_frame[14], 'T');
        EXPECT_EQ(read_frame[19], '!');
    }

    std::remove(filename.c_str());
}

TEST(pcap_span_api, write_components_with_array_payload)
{
    std::string const filename = "/tmp/statusbar_pcap_test_span_payload.pcap";
    std::remove(filename.c_str());

    statusbar::ieee::Eui48 da{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint16_t ethertype = 0x88F7;

    // Fixed-size payload - no heap allocation
    std::array<uint8_t, 4> payload = {0xDE, 0xAD, 0xBE, 0xEF};

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        // Pass std::array as payload - zero allocation
        (void)writer.write_packet(2000000ULL, da, sa, ethertype, payload);
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        statusbar::ieee::Eui48 read_da, read_sa;
        uint16_t read_ethertype = 0;
        Packet read_payload;

        auto step = reader.read_packet(&timestamp, read_da, read_sa, &read_ethertype, read_payload);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_payload.size(), 4U);
        EXPECT_EQ(read_payload[0], 0xDE);
        EXPECT_EQ(read_payload[1], 0xAD);
        EXPECT_EQ(read_payload[2], 0xBE);
        EXPECT_EQ(read_payload[3], 0xEF);
    }

    std::remove(filename.c_str());
}

TEST(pcap_span_api, reuse_buffer_no_allocation)
{
    std::string const filename = "/tmp/statusbar_pcap_test_span_reuse.pcap";
    std::remove(filename.c_str());

    // Pre-allocate buffer once at init time
    std::array<uint8_t, 64> reusable_buffer{};

    // Fill Ethernet header (same for all packets)
    for (int i = 0; i < 6; ++i) {
        reusable_buffer[i] = static_cast<uint8_t>(i);             // DA
        reusable_buffer[6 + i] = static_cast<uint8_t>(i + 0xA0);  // SA
    }
    reusable_buffer[12] = 0x08;
    reusable_buffer[13] = 0x00;

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;

        // Write multiple packets reusing same buffer - zero allocations per packet
        for (int pkt = 0; pkt < 5; ++pkt) {
            // Only modify payload portion
            reusable_buffer[14] = static_cast<uint8_t>(pkt);
            reusable_buffer[15] = static_cast<uint8_t>(pkt * 10);

            // Use subspan to write only the used portion
            (void)writer.write_packet(
                static_cast<uint64_t>(pkt) * 1000000ULL, std::span<uint8_t const>{reusable_buffer.data(), 16});
        }
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        for (int pkt = 0; pkt < 5; ++pkt) {
            uint64_t timestamp = 0;
            Packet read_frame;
            auto step = reader.read_packet(&timestamp, read_frame);
            EXPECT_TRUE(step.has_value());
            EXPECT_TRUE(*step);
            EXPECT_EQ(read_frame.size(), 16U);
            EXPECT_EQ(read_frame[14], static_cast<uint8_t>(pkt));
            EXPECT_EQ(read_frame[15], static_cast<uint8_t>(pkt * 10));
        }
    }

    std::remove(filename.c_str());
}

//
// Tests: Edge cases for swap functions
//

TEST(pcap_swap_edge, single_byte_patterns)
{
    // Test single byte in each position for 32-bit
    EXPECT_EQ(swap_bytes(0x01000000U), 0x00000001U);
    EXPECT_EQ(swap_bytes(0x00010000U), 0x00000100U);
    EXPECT_EQ(swap_bytes(0x00000100U), 0x00010000U);
    EXPECT_EQ(swap_bytes(0x00000001U), 0x01000000U);
}

TEST(pcap_swap_edge, alternating_bits)
{
    // Alternating bit patterns
    EXPECT_EQ(swap_bytes(0xAAAAAAAAU), 0xAAAAAAAAU);
    EXPECT_EQ(swap_bytes(0x55555555U), 0x55555555U);
    EXPECT_EQ(swap_bytes16(0xAAAAU), 0xAAAAU);
    EXPECT_EQ(swap_bytes16(0x5555U), 0x5555U);
}

TEST(pcap_swap64_edge, single_byte_positions)
{
    // Test single byte in each position for 64-bit
    EXPECT_EQ(swap_bytes64(0x0100000000000000ULL), 0x0000000000000001ULL);
    EXPECT_EQ(swap_bytes64(0x0001000000000000ULL), 0x0000000000000100ULL);
    EXPECT_EQ(swap_bytes64(0x0000010000000000ULL), 0x0000000000010000ULL);
    EXPECT_EQ(swap_bytes64(0x0000000100000000ULL), 0x0000000001000000ULL);
}

//
// Tests: Edge cases for alignment
//

TEST(pcap_align_edge, large_values)
{
    // Large values that are already aligned
    EXPECT_EQ(align_to_4(1000000U), 1000000U);
    EXPECT_EQ(align_to_4(0xFFFFFFFCU), 0xFFFFFFFCU);
}

TEST(pcap_align_edge, near_max)
{
    // Values near the alignment boundary
    EXPECT_EQ(align_to_4(1020U), 1020U);  // 1020 = 255*4
    EXPECT_EQ(align_to_4(1021U), 1024U);
    EXPECT_EQ(align_to_4(1022U), 1024U);
    EXPECT_EQ(align_to_4(1023U), 1024U);
    EXPECT_EQ(align_to_4(1024U), 1024U);
}

//
// Tests: Edge cases for FileHeader field offsets and values
//

TEST(pcap_header_edge, default_values)
{
    FileHeader header{};
    header.magic_number = PCAP_MAGIC_NATIVE;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 0xFFFF;
    header.network = 1;  // Ethernet

    EXPECT_EQ(header.magic_number, PCAP_MAGIC_NATIVE);
    EXPECT_EQ(header.version_major, 2U);
    EXPECT_EQ(header.version_minor, 4U);
    EXPECT_EQ(header.thiszone, 0);
    EXPECT_EQ(header.sigfigs, 0U);
    EXPECT_EQ(header.snaplen, 0xFFFFU);
    EXPECT_EQ(header.network, 1U);
}

TEST(pcap_header_edge, negative_timezone)
{
    FileHeader header{};
    header.thiszone = -28800;  // UTC-8 (PST)
    EXPECT_EQ(header.thiszone, -28800);
}

//
// Tests: Edge cases for RecordHeader
//

TEST(pcap_record_edge, max_timestamp)
{
    RecordHeader rec{};
    rec.ts_sec = 0xFFFFFFFF;  // Max uint32
    rec.ts_usec = 999999;     // Max valid microseconds
    rec.incl_len = 1514;      // Max Ethernet frame
    rec.orig_len = 1514;

    EXPECT_EQ(rec.ts_sec, 0xFFFFFFFFU);
    EXPECT_EQ(rec.ts_usec, 999999U);
    EXPECT_EQ(rec.incl_len, 1514);
    EXPECT_EQ(rec.orig_len, 1514);
}

TEST(pcap_record_edge, truncated_packet)
{
    RecordHeader rec{};
    rec.ts_sec = 1000;
    rec.ts_usec = 500000;
    rec.incl_len = 100;   // Captured only 100 bytes
    rec.orig_len = 1514;  // Original was full frame

    EXPECT_TRUE(rec.incl_len < rec.orig_len);
}

//
// Tests: Edge cases for InterfaceInfo
//

TEST(pcap_interface_edge, custom_values)
{
    InterfaceInfo info;
    info.link_type = LinkType::Raw;
    info.snap_length = 262144;   // Large snap length
    info.ts_resol = 1000000000;  // Nanoseconds

    EXPECT_EQ(info.link_type, LinkType::Raw);
    EXPECT_EQ(info.snap_length, 262144U);
    EXPECT_EQ(info.ts_resol, 1000000000ULL);
}

TEST(pcap_interface_edge, all_link_types)
{
    // Verify all link types can be assigned
    InterfaceInfo info;

    info.link_type = LinkType::Null;
    EXPECT_EQ(static_cast<uint16_t>(info.link_type), 0);

    info.link_type = LinkType::Ethernet;
    EXPECT_EQ(static_cast<uint16_t>(info.link_type), 1);

    info.link_type = LinkType::Ieee80211;
    EXPECT_EQ(static_cast<uint16_t>(info.link_type), 105);

    info.link_type = LinkType::Linux_sll2;
    EXPECT_EQ(static_cast<uint16_t>(info.link_type), 276);
}

//
// Tests: Edge cases for PcapngBlockHeader
//

TEST(pcapng_block_edge, minimum_block_size)
{
    // Minimum valid block: header (8) + trailing length (4) = 12 bytes
    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::EnhancedPacket);
    header.block_length = 12;

    EXPECT_EQ(header.block_type, 6U);
    EXPECT_EQ(header.block_length, 12U);
}

TEST(pcapng_block_edge, large_block)
{
    PcapngBlockHeader header{};
    header.block_type = static_cast<uint32_t>(PcapngBlockType::EnhancedPacket);
    header.block_length = 65536;  // 64KB block

    EXPECT_EQ(header.block_length, 65536U);
}

//
// Tests: Edge cases for PcapngEnhancedPacketBody
//

TEST(pcapng_epb_edge, max_timestamp)
{
    PcapngEnhancedPacketBody epb{};
    epb.interface_id = 0;
    epb.timestamp_high = 0xFFFFFFFF;
    epb.timestamp_low = 0xFFFFFFFF;
    epb.captured_length = 1514;
    epb.original_length = 1514;

    uint64_t timestamp = (static_cast<uint64_t>(epb.timestamp_high) << 32) | epb.timestamp_low;
    EXPECT_EQ(timestamp, 0xFFFFFFFFFFFFFFFFULL);
}

TEST(pcapng_epb_edge, multiple_interfaces)
{
    PcapngEnhancedPacketBody epb{};
    epb.interface_id = 255;  // High interface ID

    EXPECT_EQ(epb.interface_id, 255U);
}

//
// Tests: Edge cases for file I/O error handling
//

TEST(pcap_io_edge, invalid_file_paths)
{
    // Test various invalid file paths
    auto rdr = FileReader::open("/nonexistent/path/to/file.pcap");
    EXPECT_FALSE(rdr.has_value());
    EXPECT_EQ(rdr.error(), make_error_code(PcapError::file_open_failed));
}

TEST(pcap_io_edge, empty_filename)
{
    auto rdr = FileReader::open("");
    EXPECT_FALSE(rdr.has_value());
    EXPECT_EQ(rdr.error(), make_error_code(PcapError::file_open_failed));
}

TEST(pcap_io_edge, directory_as_file)
{
    auto rdr = FileReader::open("/tmp");  // A directory, not a file
    EXPECT_FALSE(rdr.has_value());
}

//
// Tests: Edge cases for empty payload handling
//

TEST(pcap_payload_edge, zero_payload_components)
{
    std::string const filename = "/tmp/statusbar_pcap_test_empty_payload.pcap";
    std::remove(filename.c_str());

    statusbar::ieee::Eui48 da{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint16_t ethertype = 0x0800;
    std::span<uint8_t const> empty_payload;

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(1000000ULL, da, sa, ethertype, empty_payload);
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        statusbar::ieee::Eui48 read_da, read_sa;
        uint16_t read_ethertype = 0;
        Packet read_payload;

        auto step = reader.read_packet(&timestamp, read_da, read_sa, &read_ethertype, read_payload);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_payload.size(), 0U);  // Empty payload
        EXPECT_EQ(read_ethertype, ethertype);
    }

    std::remove(filename.c_str());
}

//
// Tests: Edge cases for timestamp calculations
//

TEST(pcap_timestamp_edge, zero_timestamp)
{
    std::string const filename = "/tmp/statusbar_pcap_test_zero_ts.pcap";
    std::remove(filename.c_str());

    Packet frame;
    for (int i = 0; i < 15; ++i) {
        frame.push_back(static_cast<uint8_t>(i));
    }

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(0ULL, frame);  // Zero timestamp
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 999;
        Packet read_frame;
        auto step = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(timestamp, 0U);  // First packet always has relative timestamp 0
    }

    std::remove(filename.c_str());
}

TEST(pcap_timestamp_edge, large_timestamp_delta)
{
    std::string const filename = "/tmp/statusbar_pcap_test_large_ts.pcap";
    std::remove(filename.c_str());

    Packet frame;
    for (int i = 0; i < 15; ++i) {
        frame.push_back(static_cast<uint8_t>(i));
    }

    uint64_t const base_ts = 1000000000000ULL;  // Very large base (in us, ~31 years)
    uint64_t const delta = 86400000000ULL;      // 1 day in microseconds

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(base_ts, frame);
        (void)writer.write_packet(base_ts + delta, frame);
        writer.flush();
    }

    {
        auto rdr = FileReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        Packet read_frame;

        auto s1 = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(s1.has_value());
        EXPECT_TRUE(*s1);
        EXPECT_EQ(timestamp, 0U);  // First packet

        auto s2 = reader.read_packet(&timestamp, read_frame);
        EXPECT_TRUE(s2.has_value());
        EXPECT_TRUE(*s2);
        EXPECT_EQ(timestamp, delta);  // Delta from first packet
    }

    std::remove(filename.c_str());
}

//
// Tests: PcapNG writer/reader roundtrip
//

TEST(pcapng_roundtrip, write_pcap_read_pcapng)
{
    // Write a PCAP file with FileWriter, then read it back with PcapngReader
    // This tests PcapngReader since FileWriter produces standard PCAP format
    // and PcapngReader should be able to read it... but PcapngReader expects pcapng format.
    // Instead, we test by writing a pcapng file manually.

    // For testing PcapngReader, we need a pcapng file. Create one by writing raw bytes.
    std::string const filename = "/tmp/statusbar_pcapng_test_roundtrip.pcapng";
    std::remove(filename.c_str());

    // Build a minimal valid PcapNG file in memory:
    // SHB + IDB + EPB (with a 20-byte Ethernet frame)
    std::vector<uint8_t> pcapng_data;

    auto write_u32 = [&](uint32_t v) {
        pcapng_data.push_back(static_cast<uint8_t>(v & 0xFF));
        pcapng_data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        pcapng_data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        pcapng_data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto write_u16 = [&](uint16_t v) {
        pcapng_data.push_back(static_cast<uint8_t>(v & 0xFF));
        pcapng_data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };

    // Section Header Block (SHB)
    // body: byte_order_magic(4) + version_major(2) + version_minor(2) + section_length(8) = 16
    // Need options padding so remaining > 0 (reader skips trailing length only when remaining > 0)
    // total = 8(header) + 16(body) + 4(options pad) + 4(trailer) = 32
    write_u32(0x0a0d0d0a);  // block type
    write_u32(32);          // block length
    write_u32(0x1a2b3c4d);  // byte order magic (native)
    write_u16(1);           // version major
    write_u16(0);           // version minor
    write_u32(0xFFFFFFFF);  // section length (unspecified)
    write_u32(0xFFFFFFFF);  // section length high (unspecified)
    write_u32(0);           // 4 bytes options padding
    write_u32(32);          // trailing block length

    // Interface Description Block (IDB)
    // body: link_type(2) + reserved(2) + snap_length(4) = 8
    // Need options padding so remaining > 0
    // total = 8(header) + 8(body) + 4(options pad) + 4(trailer) = 24
    write_u32(1);      // block type (IDB)
    write_u32(24);     // block length
    write_u16(1);      // link type (Ethernet)
    write_u16(0);      // reserved
    write_u32(65535);  // snap length
    write_u32(0);      // 4 bytes options padding
    write_u32(24);     // trailing block length

    // Enhanced Packet Block (EPB) - first packet
    // body: interface_id(4) + ts_high(4) + ts_low(4) + captured_len(4) + original_len(4) = 20
    // packet data: 20 bytes, padded to 20 (already aligned)
    // total = 8(header) + 20(body) + 20(data) + 4(trailer) = 52
    uint8_t frame1[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // DA
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // SA
        0x08, 0x00,                          // EtherType
        'H',  'e',  'l',  'l',  'o',  '!'    // Payload (6 bytes)
    };
    write_u32(6);        // block type (EPB)
    write_u32(52);       // block length
    write_u32(0);        // interface_id
    write_u32(0);        // timestamp high (0 seconds)
    write_u32(1000000);  // timestamp low (1 second in microseconds)
    write_u32(20);       // captured length
    write_u32(20);       // original length
    for (auto b : frame1) {
        pcapng_data.push_back(b);
    }
    write_u32(52);  // trailing block length

    // Enhanced Packet Block (EPB) - second packet
    uint8_t frame2[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // DA
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,  // SA
        0x88, 0xF7,                          // EtherType (PTP)
        'W',  'o',  'r',  'l',  'd',  '!'    // Payload (6 bytes)
    };
    write_u32(6);        // block type (EPB)
    write_u32(52);       // block length
    write_u32(0);        // interface_id
    write_u32(0);        // timestamp high
    write_u32(3000000);  // timestamp low (3 seconds in microseconds)
    write_u32(20);       // captured length
    write_u32(20);       // original length
    for (auto b : frame2) {
        pcapng_data.push_back(b);
    }
    write_u32(52);  // trailing block length

    // Write the pcapng to file
    {
        auto* f = std::fopen(filename.c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        std::fwrite(pcapng_data.data(), 1, pcapng_data.size(), f);
        std::fclose(f);
    }

    // Read with PcapngReader
    {
        auto rdr = PcapngReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;

        uint64_t timestamp = 0;
        Packet packet;

        // First packet
        auto s1 = reader.read_packet(&timestamp, packet);
        EXPECT_TRUE(s1.has_value());
        EXPECT_TRUE(*s1);
        EXPECT_EQ(timestamp, 0U);  // First packet is relative 0
        EXPECT_EQ(packet.size(), 20U);
        EXPECT_EQ(packet[0], 0x00);  // DA[0]
        EXPECT_EQ(packet[14], 'H');  // Payload start

        // Second packet
        auto s2 = reader.read_packet(&timestamp, packet);
        EXPECT_TRUE(s2.has_value());
        EXPECT_TRUE(*s2);
        EXPECT_EQ(timestamp, 2000000U);  // 3s - 1s = 2s relative
        EXPECT_EQ(packet.size(), 20U);
        EXPECT_EQ(packet[14], 'W');  // Payload start

        // No more packets
        auto eof = reader.read_packet(&timestamp, packet);
        EXPECT_TRUE(eof.has_value());
        EXPECT_FALSE(*eof);
    }

    std::remove(filename.c_str());
}

TEST(pcapng_roundtrip, read_with_ethernet_components)
{
    std::string const filename = "/tmp/statusbar_pcapng_test_eth.pcapng";
    std::remove(filename.c_str());

    std::vector<uint8_t> data;
    auto write_u32 = [&](uint32_t v) {
        data.push_back(static_cast<uint8_t>(v & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto write_u16 = [&](uint16_t v) {
        data.push_back(static_cast<uint8_t>(v & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };

    // SHB (with options padding so reader skips trailing length)
    write_u32(0x0a0d0d0a);
    write_u32(32);
    write_u32(0x1a2b3c4d);
    write_u16(1);
    write_u16(0);
    write_u32(0xFFFFFFFF);
    write_u32(0xFFFFFFFF);
    write_u32(0);  // options padding
    write_u32(32);

    // IDB (with options padding)
    write_u32(1);
    write_u32(24);
    write_u16(1);
    write_u16(0);
    write_u32(65535);
    write_u32(0);  // options padding
    write_u32(24);

    // EPB with 18-byte frame (14-byte header + 4-byte payload), padded to 20
    uint8_t frame[] = {
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,  // DA
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,  // SA
        0x88,
        0xF7,  // EtherType
        0xDE,
        0xAD,
        0xBE,
        0xEF  // Payload
    };
    write_u32(6);
    write_u32(52);  // 8 + 20 + 20(padded) + 4 = 52
    write_u32(0);
    write_u32(0);
    write_u32(0);
    write_u32(18);  // captured
    write_u32(18);  // original
    for (auto b : frame) {
        data.push_back(b);
    }
    // 2 bytes padding to align to 4
    data.push_back(0);
    data.push_back(0);
    write_u32(52);

    {
        auto* f = std::fopen(filename.c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        std::fwrite(data.data(), 1, data.size(), f);
        std::fclose(f);
    }

    {
        auto rdr = PcapngReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        auto& reader = *rdr;
        uint64_t timestamp = 0;
        statusbar::ieee::Eui48 da, sa;
        uint16_t ethertype = 0;
        Packet payload;

        auto step = reader.read_packet(&timestamp, da, sa, &ethertype, payload);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(da.value[0], 0xAA);
        EXPECT_EQ(da.value[5], 0xFF);
        EXPECT_EQ(sa.value[0], 0x11);
        EXPECT_EQ(sa.value[5], 0x66);
        EXPECT_EQ(ethertype, 0x88F7U);
        EXPECT_EQ(payload.size(), 4U);
        EXPECT_EQ(payload[0], 0xDE);
        EXPECT_EQ(payload[3], 0xEF);
    }

    std::remove(filename.c_str());
}

TEST(pcapng_roundtrip, open_nonexistent_throws)
{
    auto rdr = PcapngReader::open("/tmp/definitely_does_not_exist_pcapng.pcapng");
    EXPECT_FALSE(rdr.has_value());
    EXPECT_EQ(rdr.error(), make_error_code(PcapError::file_open_failed));
}

TEST(pcapng_roundtrip, invalid_magic_throws)
{
    std::string const filename = "/tmp/statusbar_pcapng_test_invalid.pcapng";
    std::remove(filename.c_str());

    // Write a file with valid SHB block type but invalid byte order magic
    uint8_t bad_data[] = {
        0x0a, 0x0d, 0x0d, 0x0a,  // SHB block type
        0x1c, 0x00, 0x00, 0x00,  // block length = 28
        0x00, 0x00, 0x00, 0x00,  // BAD byte order magic
        0x01, 0x00,              // version major
        0x00, 0x00,              // version minor
        0xFF, 0xFF, 0xFF, 0xFF,  // section length
        0xFF, 0xFF, 0xFF, 0xFF,  // section length high
        0x1c, 0x00, 0x00, 0x00,  // trailing block length
    };

    auto* f = std::fopen(filename.c_str(), "wb");
    std::fwrite(bad_data, 1, sizeof(bad_data), f);
    std::fclose(f);

    auto rdr = PcapngReader::open(filename);
    EXPECT_FALSE(rdr.has_value());
    EXPECT_EQ(rdr.error(), make_error_code(PcapError::invalid_byte_order_magic));

    std::remove(filename.c_str());
}

//
// Tests: align_to_4 runtime coverage
//

TEST(pcapng_align_rt, runtime_coverage)
{
    uint32_t volatile v0 = 0, v1 = 1, v4 = 4, v5 = 5, v100 = 100, v101 = 101;
    EXPECT_EQ(align_to_4(v0), 0U);
    EXPECT_EQ(align_to_4(v1), 4U);
    EXPECT_EQ(align_to_4(v4), 4U);
    EXPECT_EQ(align_to_4(v5), 8U);
    EXPECT_EQ(align_to_4(v100), 100U);
    EXPECT_EQ(align_to_4(v101), 104U);
}

//
// FileWriter: no-timestamp and vector overload coverage
//

TEST(pcap_writer_notimestamp, write_packet_span_no_ts)
{
    std::string const path = "/tmp/statusbar_pcap_notimestamp_span.pcap";
    std::remove(path.c_str());

    // Build a minimal Ethernet frame (14-byte header + 4 bytes payload = 18 bytes)
    std::array<uint8_t, 18> frame{};
    // DA
    frame[0] = 0x01;
    frame[1] = 0x02;
    frame[2] = 0x03;
    frame[3] = 0x04;
    frame[4] = 0x05;
    frame[5] = 0x06;
    // SA
    frame[6] = 0x0A;
    frame[7] = 0x0B;
    frame[8] = 0x0C;
    frame[9] = 0x0D;
    frame[10] = 0x0E;
    frame[11] = 0x0F;
    // Ethertype
    frame[12] = 0x08;
    frame[13] = 0x00;
    // Payload
    frame[14] = 0xDE;
    frame[15] = 0xAD;
    frame[16] = 0xBE;
    frame[17] = 0xEF;

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(std::span<uint8_t const>{frame});
    }

    // Read back and verify
    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet packet;
    auto step = reader.read_packet(&ts, packet);
    EXPECT_TRUE(step.has_value());
    bool ok = *step;
    EXPECT_TRUE(ok);
    // ts is relative to first packet, so single-packet file yields ts=0
    EXPECT_EQ(packet.size(), size_t{18});
    EXPECT_EQ(packet[14], uint8_t{0xDE});

    std::remove(path.c_str());
}

TEST(pcap_writer_notimestamp, write_packet_components_no_ts)
{
    std::string const path = "/tmp/statusbar_pcap_notimestamp_comp.pcap";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    std::array<uint8_t, 4> payload = {0xCA, 0xFE, 0xBA, 0xBE};

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(da, sa, uint16_t{0x0800}, std::span<uint8_t const>{payload});
    }

    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet packet;
    auto step = reader.read_packet(&ts, packet);
    EXPECT_TRUE(step.has_value());
    bool ok = *step;
    EXPECT_TRUE(ok);
    // ts is relative to first packet, so single-packet file yields ts=0
    EXPECT_EQ(packet.size(), size_t{18});  // 14 header + 4 payload
    // Check ethertype
    EXPECT_EQ(packet[12], uint8_t{0x08});
    EXPECT_EQ(packet[13], uint8_t{0x00});
    // Check payload
    EXPECT_EQ(packet[14], uint8_t{0xCA});

    std::remove(path.c_str());
}

TEST(pcap_writer_vector, write_packet_vector_no_ts)
{
    std::string const path = "/tmp/statusbar_pcap_vector_nots.pcap";
    std::remove(path.c_str());

    Packet frame(18, 0);
    frame[0] = 0x01;
    frame[6] = 0x0A;
    frame[12] = 0x08;
    frame[14] = 0xAB;

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(frame);
    }

    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet out;
    auto step = reader.read_packet(&ts, out);
    EXPECT_TRUE(step.has_value());
    EXPECT_TRUE(*step);
    EXPECT_EQ(out.size(), size_t{18});
    EXPECT_EQ(out[14], uint8_t{0xAB});

    std::remove(path.c_str());
}

TEST(pcap_writer_vector, write_packet_vector_with_ts)
{
    std::string const path = "/tmp/statusbar_pcap_vector_ts.pcap";
    std::remove(path.c_str());

    Packet frame(18, 0);
    frame[0] = 0x01;
    frame[6] = 0x0A;
    frame[12] = 0x08;
    frame[14] = 0xCD;

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{5000000}, frame);
    }

    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet out;
    auto step = reader.read_packet(&ts, out);
    EXPECT_TRUE(step.has_value());
    EXPECT_TRUE(*step);
    EXPECT_EQ(out[14], uint8_t{0xCD});

    std::remove(path.c_str());
}

TEST(pcap_writer_vector, write_packet_components_vector_no_ts)
{
    std::string const path = "/tmp/statusbar_pcap_comp_vector_nots.pcap";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    Packet payload = {0x11, 0x22, 0x33, 0x44};

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(da, sa, uint16_t{0x88F7}, payload);
    }

    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet out;
    auto step = reader.read_packet(&ts, out);
    EXPECT_TRUE(step.has_value());
    EXPECT_TRUE(*step);
    EXPECT_EQ(out.size(), size_t{18});
    EXPECT_EQ(out[12], uint8_t{0x88});
    EXPECT_EQ(out[13], uint8_t{0xF7});

    std::remove(path.c_str());
}

TEST(pcap_writer_vector, write_packet_components_vector_with_ts)
{
    std::string const path = "/tmp/statusbar_pcap_comp_vector_ts.pcap";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    Packet payload = {0x55, 0x66, 0x77, 0x88};

    {
        auto wtr = FileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{10000000}, da, sa, uint16_t{0x22F0}, payload);
    }

    auto rdr = FileReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet out;
    auto step = reader.read_packet(&ts, out);
    EXPECT_TRUE(step.has_value());
    EXPECT_TRUE(*step);
    EXPECT_EQ(out[12], uint8_t{0x22});
    EXPECT_EQ(out[13], uint8_t{0xF0});
    EXPECT_EQ(out[14], uint8_t{0x55});

    std::remove(path.c_str());
}

//
// Original (wire) length tests
//
// A snapped capture keeps part of a frame. incl_len is what is in the file;
// orig_len is what was on the wire, and it is the only way a reader knows it
// is looking at a fragment. Both writers used to set them equal with no way
// to say otherwise, so every snapped capture claimed the frames were as
// short as the bytes kept.
//

namespace {

/// Fills a frame with a recognisable ramp so a byte assertion says which
/// byte, not just that something differed.
auto ramp_frame(size_t size) -> Packet
{
    Packet frame;
    for (size_t i = 0; i < size; ++i) {
        frame.push_back(static_cast<uint8_t>(i));
    }
    return frame;
}

/// Read a whole file, for comparing two writers' output byte for byte.
auto slurp(std::string const& path) -> std::vector<uint8_t>
{
    std::vector<uint8_t> bytes;
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        return bytes;
    }
    std::array<uint8_t, 512> chunk{};
    size_t got = 0;
    while ((got = std::fread(chunk.data(), 1, chunk.size(), f)) > 0) {
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(got));
    }
    (void)std::fclose(f);
    return bytes;
}

}  // namespace

TEST(pcap_original_length, a_snapped_record_reports_the_wire_length)
{
    std::string const filename = "/tmp/statusbar_pcap_test_snapped.pcap";
    std::remove(filename.c_str());
    Packet const kept = ramp_frame(16);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            // 16 bytes kept out of a 200-byte frame, as `tcpdump -s 16` would.
            EXPECT_TRUE(wtr->write_packet(1000000ULL, kept, 200U).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        uint32_t original = 0;
        auto step = rdr->read_packet(&ts, read_back, &original);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{16});
        EXPECT_EQ(original, uint32_t{200});
    }

    std::remove(filename.c_str());
}

TEST(pcap_original_length, a_complete_frame_reports_its_own_length)
{
    std::string const filename = "/tmp/statusbar_pcap_test_complete.pcap";
    std::remove(filename.c_str());
    Packet const frame = ramp_frame(20);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, frame).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        uint32_t original = 0;
        auto step = rdr->read_packet(&ts, read_back, &original);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(original, uint32_t{20});
    }

    std::remove(filename.c_str());
}

TEST(pcap_original_length, matching_lengths_write_exactly_what_the_plain_overload_writes)
{
    // The plain overload routes through this one, so this asserts the
    // routing rather than hoping the two stay in step.
    std::string const plain_path = "/tmp/statusbar_pcap_test_eq_plain.pcap";
    std::string const explicit_path = "/tmp/statusbar_pcap_test_eq_explicit.pcap";
    std::remove(plain_path.c_str());
    std::remove(explicit_path.c_str());
    Packet const frame = ramp_frame(20);

    {
        auto plain = FileWriter::open(plain_path);
        auto with_len = FileWriter::open(explicit_path);
        EXPECT_TRUE(plain.has_value());
        EXPECT_TRUE(with_len.has_value());
        if (plain && with_len) {
            EXPECT_TRUE(plain->write_packet(1000000ULL, frame).has_value());
            EXPECT_TRUE(with_len->write_packet(1000000ULL, frame, 20U).has_value());
            plain->flush();
            with_len->flush();
        }
    }

    auto const plain_bytes = slurp(plain_path);
    EXPECT_FALSE(plain_bytes.empty());
    EXPECT_TRUE(plain_bytes == slurp(explicit_path));

    std::remove(plain_path.c_str());
    std::remove(explicit_path.c_str());
}

TEST(pcap_original_length, a_wire_length_below_the_capture_is_refused)
{
    std::string const filename = "/tmp/statusbar_pcap_test_bad_origlen.pcap";
    std::remove(filename.c_str());
    Packet const kept = ramp_frame(16);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            // A frame shorter than its own capture describes nothing.
            auto status = wtr->write_packet(1000000ULL, kept, 10U);
            EXPECT_FALSE(status.has_value());
            EXPECT_EQ(status.error(), make_error_code(PcapError::invalid_original_length));
            wtr->flush();
        }
    }

    // Refused means nothing was written, not a half-written record: the file
    // holds its header and no records.
    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto eof = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(eof.has_value());
        EXPECT_FALSE(*eof);
    }

    std::remove(filename.c_str());
}

TEST(pcap_original_length, a_negative_wire_length_in_a_file_is_refused)
{
    // orig_len is a signed 32-bit field in the record header. We never write
    // a negative one; a file from elsewhere can carry one, and it must not
    // reach a caller as a four-billion-byte frame.
    std::string const filename = "/tmp/statusbar_pcap_test_neg_origlen.pcap";
    std::remove(filename.c_str());

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, ramp_frame(20)).has_value());
            wtr->flush();
        }
    }

    // Patch orig_len in place: 24-byte file header, then ts_sec, ts_usec and
    // incl_len ahead of it.
    {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        std::FILE* f = std::fopen(filename.c_str(), "r+b");
        EXPECT_TRUE(f != nullptr);
        if (f != nullptr) {
            EXPECT_EQ(std::fseek(f, 24 + 12, SEEK_SET), 0);
            std::array<uint8_t, 4> const negative{0xFF, 0xFF, 0xFF, 0xFF};
            EXPECT_EQ(std::fwrite(negative.data(), negative.size(), 1, f), size_t{1});
            (void)std::fclose(f);
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        uint32_t original = 0;
        auto step = rdr->read_packet(&ts, read_back, &original);
        EXPECT_FALSE(step.has_value());
        EXPECT_EQ(step.error(), make_error_code(PcapError::invalid_record_header));
    }

    std::remove(filename.c_str());
}

TEST(pcapng_original_length, a_snapped_block_reports_the_wire_length)
{
    std::string const path = "/tmp/statusbar_pcapng_test_snapped.pcapng";
    std::remove(path.c_str());
    Packet const kept = ramp_frame(16);

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(uint64_t{1000000}, std::span<uint8_t const>{kept}, 200U).has_value());
            wtr->flush();
        }
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        uint32_t original = 0;
        auto step = rdr->read_packet(&ts, read_back, &original);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{16});
        EXPECT_EQ(original, uint32_t{200});
    }

    std::remove(path.c_str());
}

TEST(pcapng_original_length, matching_lengths_write_exactly_what_the_plain_overload_writes)
{
    std::string const plain_path = "/tmp/statusbar_pcapng_test_eq_plain.pcapng";
    std::string const explicit_path = "/tmp/statusbar_pcapng_test_eq_explicit.pcapng";
    std::remove(plain_path.c_str());
    std::remove(explicit_path.c_str());
    Packet const frame = ramp_frame(20);

    {
        auto plain = PcapngFileWriter::open(plain_path);
        auto with_len = PcapngFileWriter::open(explicit_path);
        EXPECT_TRUE(plain.has_value());
        EXPECT_TRUE(with_len.has_value());
        if (plain && with_len) {
            EXPECT_TRUE(plain->write_packet(uint64_t{1000000}, std::span<uint8_t const>{frame}).has_value());
            EXPECT_TRUE(with_len->write_packet(uint64_t{1000000}, std::span<uint8_t const>{frame}, 20U).has_value());
            plain->flush();
            with_len->flush();
        }
    }

    auto const plain_bytes = slurp(plain_path);
    EXPECT_FALSE(plain_bytes.empty());
    EXPECT_TRUE(plain_bytes == slurp(explicit_path));

    std::remove(plain_path.c_str());
    std::remove(explicit_path.c_str());
}

TEST(pcapng_original_length, a_wire_length_below_the_capture_is_refused)
{
    std::string const path = "/tmp/statusbar_pcapng_test_bad_origlen.pcapng";
    std::remove(path.c_str());

    auto wtr = PcapngFileWriter::open(path);
    EXPECT_TRUE(wtr.has_value());
    if (wtr) {
        auto status = wtr->write_packet(uint64_t{1000000}, std::span<uint8_t const>{ramp_frame(16)}, 10U);
        EXPECT_FALSE(status.has_value());
        EXPECT_EQ(status.error(), make_error_code(PcapError::invalid_original_length));
    }

    std::remove(path.c_str());
}

TEST(pcapng_original_length, a_simple_packet_block_reports_its_wire_length)
{
    // An SPB carries only the wire length -- the captured length is whatever
    // the block has room for. The reader already computed this number and
    // threw it away.
    std::string const path = "/tmp/statusbar_pcapng_test_spb_origlen.pcapng";
    std::remove(path.c_str());

    std::vector<uint8_t> data;
    auto write_u32 = [&](uint32_t v) {
        data.push_back(static_cast<uint8_t>(v & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto write_u16 = [&](uint16_t v) {
        data.push_back(static_cast<uint8_t>(v & 0xFF));
        data.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };

    // SHB: 8 header + 16 body + 4 options pad + 4 trailer
    write_u32(0x0a0d0d0a);
    write_u32(32);
    write_u32(0x1a2b3c4d);
    write_u16(1);
    write_u16(0);
    write_u32(0xFFFFFFFF);
    write_u32(0xFFFFFFFF);
    write_u32(0);
    write_u32(32);

    // IDB: snap length 16, so the reader keeps the captured bytes as they are
    write_u32(1);
    write_u32(24);
    write_u16(1);
    write_u16(0);
    write_u32(16);
    write_u32(0);
    write_u32(24);

    // SPB: 8 header + 4 body (original_length) + 16 data + 4 trailer = 32
    write_u32(3);
    write_u32(32);
    write_u32(200);  // the frame was 200 bytes on the wire
    for (uint8_t i = 0; i < 16; ++i) {
        data.push_back(i);
    }
    write_u32(32);

    {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        std::FILE* f = std::fopen(path.c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        if (f != nullptr) {
            EXPECT_EQ(std::fwrite(data.data(), data.size(), 1, f), size_t{1});
            (void)std::fclose(f);
        }
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        uint32_t original = 0;
        auto step = rdr->read_packet(&ts, read_back, &original);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{16});
        EXPECT_EQ(original, uint32_t{200});
    }

    std::remove(path.c_str());
}

TEST(pcapng_original_length, the_two_argument_read_still_works_on_a_snapped_block)
{
    // The nullptr path: a caller that does not care must not have to care.
    std::string const path = "/tmp/statusbar_pcapng_test_snapped_nullptr.pcapng";
    std::remove(path.c_str());

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(uint64_t{1000000}, std::span<uint8_t const>{ramp_frame(16)}, 200U).has_value());
            wtr->flush();
        }
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto step = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{16});
    }

    std::remove(path.c_str());
}

//
// Short-frame tests
//
// A capture is a record of what happened. A frame shorter than an Ethernet
// header is a runt or a truncation -- a wire event, and usually the very
// thing someone opened a capture to look at -- so the writers carry it
// instead of discarding it. The raw-span overloads write what they are
// given; only the (da, sa, ethertype, payload) overloads impose a header,
// and they cannot produce anything shorter than one.
//

TEST(pcap_short_frame, a_fourteen_byte_frame_round_trips)
{
    // Exactly 14 bytes is a complete Ethernet header with an empty payload:
    // a frame, not a runt. The old `<= 14` guard destroyed it, and no test
    // covered the boundary.
    std::string const filename = "/tmp/statusbar_pcap_test_exactly_14.pcap";
    std::remove(filename.c_str());
    Packet const frame = ramp_frame(14);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, frame).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto step = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{14});
        EXPECT_EQ(read_back[0], uint8_t{0});
        EXPECT_EQ(read_back[13], uint8_t{13});
    }

    std::remove(filename.c_str());
}

TEST(pcap_short_frame, a_runt_frame_round_trips)
{
    std::string const filename = "/tmp/statusbar_pcap_test_runt.pcap";
    std::remove(filename.c_str());
    Packet const runt = ramp_frame(10);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, runt).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto step = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{10});
        EXPECT_EQ(read_back[9], uint8_t{9});
    }

    std::remove(filename.c_str());
}

TEST(pcap_short_frame, a_runt_between_two_frames_displaces_neither)
{
    // The failure this replaces: the capture came back with two frames and
    // read as complete, so nothing said the middle one had been dropped.
    // This is what `write_too_small_ignored` used to assert as correct.
    std::string const filename = "/tmp/statusbar_pcap_test_runt_middle.pcap";
    std::remove(filename.c_str());
    Packet const first = ramp_frame(15);
    Packet const runt = ramp_frame(10);
    Packet const last = ramp_frame(20);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, first).has_value());
            EXPECT_TRUE(wtr->write_packet(2000000ULL, runt).has_value());
            EXPECT_TRUE(wtr->write_packet(3000000ULL, last).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        std::array<size_t, 3> const want{15, 10, 20};
        for (size_t const expected : want) {
            uint64_t ts = 0;
            Packet read_back;
            auto step = rdr->read_packet(&ts, read_back);
            EXPECT_TRUE(step.has_value());
            EXPECT_TRUE(*step);
            EXPECT_EQ(read_back.size(), expected);
        }
        uint64_t ts = 0;
        Packet read_back;
        auto eof = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(eof.has_value());
        EXPECT_FALSE(*eof);
    }

    std::remove(filename.c_str());
}

TEST(pcap_short_frame, a_runt_read_through_the_ethernet_overload_reports_no_addresses)
{
    // The record is kept, but it cannot be split into header and payload.
    // The reader answers with zeroed addresses and an empty payload rather
    // than refusing the record, so iteration continues; a caller that needs
    // to tell this apart from a frame of zeroes must use the raw overload.
    std::string const filename = "/tmp/statusbar_pcap_test_runt_eth.pcap";
    std::remove(filename.c_str());
    Packet const runt = ramp_frame(10);

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, runt).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        statusbar::ieee::Eui48 da{};
        statusbar::ieee::Eui48 sa{};
        da.value = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        sa.value = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        uint16_t ethertype = 0xFFFF;
        Packet payload;

        auto step = rdr->read_packet(&ts, da, sa, &ethertype, payload);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(da.value[0], uint8_t{0});
        EXPECT_EQ(sa.value[0], uint8_t{0});
        EXPECT_EQ(ethertype, uint16_t{0});
        EXPECT_TRUE(payload.empty());
    }

    std::remove(filename.c_str());
}

TEST(pcap_short_frame, an_empty_record_round_trips)
{
    // Not a frame anyone wants, but the writer no longer has a length it
    // refuses, so an empty span has to go somewhere defined. It writes a
    // zero-length record, and the reader reads one back instead of
    // reporting file_read_failed on a zero-byte fread.
    std::string const filename = "/tmp/statusbar_pcap_test_empty_record.pcap";
    std::remove(filename.c_str());

    {
        auto wtr = FileWriter::open(filename);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(1000000ULL, std::span<uint8_t const>{}).has_value());
            EXPECT_TRUE(wtr->write_packet(2000000ULL, ramp_frame(20)).has_value());
            wtr->flush();
        }
    }

    auto rdr = FileReader::open(filename);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto first = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(first.has_value());
        EXPECT_TRUE(*first);
        EXPECT_TRUE(read_back.empty());
        // The record that follows is still found, which is the part that
        // matters: a zero-length record must not desynchronise the file.
        auto second = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(second.has_value());
        EXPECT_TRUE(*second);
        EXPECT_EQ(read_back.size(), size_t{20});
    }

    std::remove(filename.c_str());
}

TEST(pcapng_short_frame, a_fourteen_byte_frame_round_trips)
{
    std::string const path = "/tmp/statusbar_pcapng_test_exactly_14.pcapng";
    std::remove(path.c_str());
    Packet const frame = ramp_frame(14);

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(uint64_t{1000000}, std::span<uint8_t const>{frame}).has_value());
            wtr->flush();
        }
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto step = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{14});
        EXPECT_EQ(read_back[13], uint8_t{13});
    }

    std::remove(path.c_str());
}

TEST(pcapng_short_frame, a_runt_frame_round_trips_and_keeps_the_block_aligned)
{
    // 10 bytes pads to 12 in the block body. Getting that wrong does not
    // corrupt the runt itself -- it desynchronises everything after it, so
    // the frame that follows is the real assertion.
    std::string const path = "/tmp/statusbar_pcapng_test_runt.pcapng";
    std::remove(path.c_str());
    Packet const runt = ramp_frame(10);
    Packet const after = ramp_frame(21);

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        if (wtr) {
            EXPECT_TRUE(wtr->write_packet(uint64_t{1000000}, std::span<uint8_t const>{runt}).has_value());
            EXPECT_TRUE(wtr->write_packet(uint64_t{2000000}, std::span<uint8_t const>{after}).has_value());
            wtr->flush();
        }
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    if (rdr) {
        uint64_t ts = 0;
        Packet read_back;
        auto step = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(step.has_value());
        EXPECT_TRUE(*step);
        EXPECT_EQ(read_back.size(), size_t{10});
        EXPECT_EQ(read_back[9], uint8_t{9});

        auto next = rdr->read_packet(&ts, read_back);
        EXPECT_TRUE(next.has_value());
        EXPECT_TRUE(*next);
        EXPECT_EQ(read_back.size(), size_t{21});
        EXPECT_EQ(read_back[20], uint8_t{20});
    }

    std::remove(path.c_str());
}

//
// PcapngFileWriter tests
//

TEST(pcapng_writer, roundtrip_span)
{
    std::string const path = "/tmp/statusbar_pcapng_writer_span.pcapng";
    std::remove(path.c_str());

    std::array<uint8_t, 18> frame{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x08,
        0x00,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
    };

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{1234567890}, std::span<uint8_t const>{frame});
        writer.flush();
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet packet;
    auto s1 = reader.read_packet(&ts, packet);
    EXPECT_TRUE(s1.has_value());
    EXPECT_TRUE(*s1);
    EXPECT_EQ(packet.size(), size_t{18});
    EXPECT_EQ(packet[0], uint8_t{0x01});
    EXPECT_EQ(packet[14], uint8_t{0xDE});
    auto eof = reader.read_packet(&ts, packet);
    EXPECT_TRUE(eof.has_value());
    EXPECT_FALSE(*eof);

    std::remove(path.c_str());
}

TEST(pcapng_writer, roundtrip_components)
{
    std::string const path = "/tmp/statusbar_pcapng_writer_comp.pcapng";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::array<uint8_t, 5> payload = {0xCA, 0xFE, 0xBA, 0xBE, 0x42};

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{2000000}, da, sa, uint16_t{0x22EA}, std::span<uint8_t const>{payload});
        (void)writer.write_packet(uint64_t{3000000}, da, sa, uint16_t{0x22EA}, std::span<uint8_t const>{payload});
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    statusbar::ieee::Eui48 out_da{};
    statusbar::ieee::Eui48 out_sa{};
    uint16_t out_ethertype = 0;
    Packet out_payload;
    auto s1 = reader.read_packet(&ts, out_da, out_sa, &out_ethertype, out_payload);
    EXPECT_TRUE(s1.has_value());
    EXPECT_TRUE(*s1);
    EXPECT_EQ(out_da.value[0], uint8_t{0x11});
    EXPECT_EQ(out_sa.value[0], uint8_t{0xAA});
    EXPECT_EQ(out_ethertype, uint16_t{0x22EA});
    EXPECT_EQ(out_payload.size(), size_t{5});
    EXPECT_EQ(out_payload[0], uint8_t{0xCA});
    EXPECT_EQ(out_payload[4], uint8_t{0x42});
    auto s2 = reader.read_packet(&ts, out_da, out_sa, &out_ethertype, out_payload);
    EXPECT_TRUE(s2.has_value());
    EXPECT_TRUE(*s2);
    // Second packet timestamp is relative to first
    EXPECT_EQ(ts, uint64_t{1000000});
    auto eof = reader.read_packet(&ts, out_payload);
    EXPECT_TRUE(eof.has_value());
    EXPECT_FALSE(*eof);

    std::remove(path.c_str());
}

TEST(pcapng_writer, padding_for_non_aligned_frame)
{
    std::string const path = "/tmp/statusbar_pcapng_writer_pad.pcapng";
    std::remove(path.c_str());

    // 15-byte frame: captured_length not 4-aligned, must be padded
    std::array<uint8_t, 15> frame{};
    frame[0] = 0xFF;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x77;

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{42}, std::span<uint8_t const>{frame});
    }

    auto rdr = PcapngReader::open(path);
    EXPECT_TRUE(rdr.has_value());
    auto& reader = *rdr;
    uint64_t ts = 0;
    Packet packet;
    auto step = reader.read_packet(&ts, packet);
    EXPECT_TRUE(step.has_value());
    EXPECT_TRUE(*step);
    EXPECT_EQ(packet.size(), size_t{15});
    EXPECT_EQ(packet[14], uint8_t{0x77});
    auto eof = reader.read_packet(&ts, packet);
    EXPECT_TRUE(eof.has_value());
    EXPECT_FALSE(*eof);

    std::remove(path.c_str());
}

TEST(pcapng_writer, create_fails_for_unwritable_path)
{
    auto wtr = PcapngFileWriter::open("/no/such/directory/file.pcapng");
    EXPECT_FALSE(wtr.has_value());
}

//
// PcapReplayDriver tests
//

TEST(pcap_replay, yields_packets_with_synthetic_time)
{
    std::string const path = "/tmp/statusbar_pcap_replay_input.pcapng";
    std::remove(path.c_str());

    // Build two frames 2.5 seconds apart in absolute time; the replay driver
    // should place them at t=0 and t=2.5s in synthetic time.
    statusbar::ieee::Eui48 da{};
    da.value = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    statusbar::ieee::Eui48 sa_peer{};
    sa_peer.value = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    statusbar::ieee::Eui48 sa_other{};
    sa_other.value = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    std::array<uint8_t, 4> payload_peer = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 4> payload_other = {0x0A, 0x0B, 0x0C, 0x0D};

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{1'000'000'000}, da, sa_peer, uint16_t{0x22EA}, std::span<uint8_t const>{payload_peer});
        (void)writer.write_packet(uint64_t{1'000'500'000}, da, sa_other, uint16_t{0x22EB}, std::span<uint8_t const>{payload_other});
        (void)writer.write_packet(uint64_t{1'002'500'000}, da, sa_peer, uint16_t{0x22EA}, std::span<uint8_t const>{payload_peer});
    }

    auto drv = PcapReplayDriver::open(path);
    EXPECT_TRUE(drv.has_value());
    auto& driver = *drv;
    ReplayEvent e{};

    auto s1 = driver.next(e);
    EXPECT_TRUE(s1.has_value());
    EXPECT_TRUE(*s1);
    EXPECT_EQ(e.timestamp.time_since_epoch().count(), int64_t{0});
    EXPECT_EQ(e.frame.src_mac.value[0], uint8_t{0xAA});
    EXPECT_EQ(e.frame.ethertype, uint16_t{0x22EA});
    EXPECT_FALSE(e.frame.vlan_tag.is_set());
    EXPECT_EQ(e.payload.size(), size_t{4});
    EXPECT_EQ(e.payload[0], uint8_t{0x01});

    auto s2 = driver.next(e);
    EXPECT_TRUE(s2.has_value());
    EXPECT_TRUE(*s2);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::microseconds>(e.timestamp.time_since_epoch()).count(), int64_t{500'000});
    EXPECT_EQ(e.frame.src_mac.value[0], uint8_t{0x11});
    EXPECT_EQ(e.frame.ethertype, uint16_t{0x22EB});

    auto s3 = driver.next(e);
    EXPECT_TRUE(s3.has_value());
    EXPECT_TRUE(*s3);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::microseconds>(e.timestamp.time_since_epoch()).count(), int64_t{2'500'000});

    auto eof = driver.next(e);
    EXPECT_TRUE(eof.has_value());
    EXPECT_FALSE(*eof);
    EXPECT_EQ(driver.stats().packets_total, size_t{3});
    EXPECT_EQ(
        std::chrono::duration_cast<std::chrono::microseconds>(driver.current_time().time_since_epoch()).count(),
        int64_t{2'500'000});

    std::remove(path.c_str());
}

TEST(pcap_replay, empty_capture_returns_false)
{
    std::string const path = "/tmp/statusbar_pcap_replay_empty.pcapng";
    std::remove(path.c_str());
    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
    }  // SHB + IDB only, no packets

    auto drv = PcapReplayDriver::open(path);
    EXPECT_TRUE(drv.has_value());
    auto& driver = *drv;
    ReplayEvent e{};
    auto step = driver.next(e);
    EXPECT_TRUE(step.has_value());
    EXPECT_FALSE(*step);
    EXPECT_EQ(driver.stats().packets_total, size_t{0});

    std::remove(path.c_str());
}

TEST(pcap_replay, missing_file_throws)
{
    auto drv = PcapReplayDriver::open("/tmp/definitely_does_not_exist_replay.pcapng");
    EXPECT_FALSE(drv.has_value());
    EXPECT_EQ(drv.error(), make_error_code(PcapError::file_open_failed));
}

TEST(pcap_replay, vlan_tagged_frames_expose_inner_ethertype_and_tag)
{
    std::string const path = "/tmp/statusbar_pcap_replay_vlan.pcapng";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x91, 0xE0, 0xF0, 0x00, 0x14, 0x81};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0x00, 0x1C, 0xAB, 0x00, 0x55, 0xD8};

    // Manually build a VLAN-tagged Ethernet frame: dst(6) + src(6) +
    // 0x8100 TPID + TCI(pri=5, vid=2) + inner ethertype 0x22F0 + 4-byte
    // AVTP placeholder payload.
    std::array<uint8_t, 22> raw{};
    std::ranges::copy(da.value, raw.begin());
    std::ranges::copy(sa.value, raw.begin() + 6);
    raw[12] = 0x81;
    raw[13] = 0x00;
    // TCI: PCP=5 (top 3 bits of TCI high byte), VID=2
    raw[14] = static_cast<uint8_t>((5U << 5) | 0x00);
    raw[15] = 0x02;
    raw[16] = 0x22;  // inner ethertype = 0x22F0
    raw[17] = 0xF0;
    raw[18] = 0xDE;
    raw[19] = 0xAD;
    raw[20] = 0xBE;
    raw[21] = 0xEF;

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        (void)writer.write_packet(uint64_t{1'000'000'000}, std::span<uint8_t const>{raw});
    }

    auto drv = PcapReplayDriver::open(path);
    EXPECT_TRUE(drv.has_value());
    auto& driver = *drv;
    size_t seen = 0;
    (void)driver.for_each([&](ReplayEvent const& e) {
        ++seen;
        EXPECT_EQ(e.frame.ethertype, uint16_t{0x22F0});
        EXPECT_TRUE(e.frame.vlan_tag.is_set());
        EXPECT_EQ(e.frame.vlan_tag.get_vid(), uint16_t{2});
        EXPECT_EQ(e.frame.vlan_tag.get_pcp(), uint8_t{5});
        EXPECT_EQ(e.payload.size(), size_t{4});
        EXPECT_EQ(e.payload[0], uint8_t{0xDE});
    });
    EXPECT_EQ(seen, size_t{1});

    std::remove(path.c_str());
}

TEST(pcap_replay, for_each_stops_when_callback_returns_false)
{
    std::string const path = "/tmp/statusbar_pcap_replay_stop.pcapng";
    std::remove(path.c_str());

    statusbar::ieee::Eui48 da{};
    da.value = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    statusbar::ieee::Eui48 sa{};
    sa.value = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::array<uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};

    {
        auto wtr = PcapngFileWriter::open(path);
        EXPECT_TRUE(wtr.has_value());
        auto& writer = *wtr;
        for (uint64_t i = 0; i < 5; ++i) {
            uint64_t const ts = 1'000'000'000ULL + (i * 1'000'000ULL);
            (void)writer.write_packet(ts, da, sa, uint16_t{0x22EA}, std::span<uint8_t const>{payload});
        }
    }

    auto drv = PcapReplayDriver::open(path);
    EXPECT_TRUE(drv.has_value());
    auto& driver = *drv;
    size_t seen = 0;
    (void)driver.for_each([&](ReplayEvent const&) -> bool {
        ++seen;
        return seen < 2;  // stop after the second packet
    });
    EXPECT_EQ(seen, size_t{2});

    std::remove(path.c_str());
}

//
// Test Runner
//

//
// Tests: PcapngReader honours if_tsresol
//

namespace {

/// Hand-built pcapng blocks in the host's byte order (the reader reads the
/// section header's magic to pick native or swapped; these are native).
template <typename T>
void put(std::vector<uint8_t>& out, T value)
{
    std::array<uint8_t, sizeof(T)> bytes{};
    std::memcpy(bytes.data(), &value, sizeof(T));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

[[nodiscard]] auto pcapng_block(PcapngBlockType type, std::vector<uint8_t> const& body) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    auto const total = static_cast<uint32_t>(sizeof(PcapngBlockHeader) + body.size() + 4);
    put(out, static_cast<uint32_t>(type));
    put(out, total);
    out.insert(out.end(), body.begin(), body.end());
    put(out, total);
    return out;
}

[[nodiscard]] auto section_header_block() -> std::vector<uint8_t>
{
    std::vector<uint8_t> body;
    put(body, PCAPNG_BYTE_ORDER_MAGIC);
    put(body, uint16_t{1});
    put(body, uint16_t{0});
    put(body, int64_t{-1});
    return pcapng_block(PcapngBlockType::SectionHeader, body);
}

/// An Ethernet IDB; with @p tsresol, an if_name option first (so the walk
/// has to step over a value it does not read) and then if_tsresol.
[[nodiscard]] auto interface_block(std::optional<uint8_t> tsresol) -> std::vector<uint8_t>
{
    std::vector<uint8_t> body;
    put(body, static_cast<uint16_t>(LinkType::Ethernet));
    put(body, uint16_t{0});
    put(body, uint32_t{65535});
    if (tsresol) {
        put(body, uint16_t{2});  // if_name
        put(body, uint16_t{4});
        body.insert(body.end(), {'e', 't', 'h', '0'});
        put(body, static_cast<uint16_t>(PcapngIdbOption::if_tsresol));
        put(body, uint16_t{1});
        body.insert(body.end(), {*tsresol, 0, 0, 0});
    }
    put(body, uint16_t{0});  // opt_endofopt
    put(body, uint16_t{0});
    return pcapng_block(PcapngBlockType::InterfaceDescription, body);
}

[[nodiscard]] auto packet_block(uint64_t timestamp_ticks, std::vector<uint8_t> const& frame) -> std::vector<uint8_t>
{
    std::vector<uint8_t> body;
    put(body, uint32_t{0});
    put(body, static_cast<uint32_t>(timestamp_ticks >> 32));
    put(body, static_cast<uint32_t>(timestamp_ticks & 0xffffffffU));
    put(body, static_cast<uint32_t>(frame.size()));
    put(body, static_cast<uint32_t>(frame.size()));
    body.insert(body.end(), frame.begin(), frame.end());
    body.resize(body.size() + (align_to_4(static_cast<uint32_t>(frame.size())) - frame.size()), 0);
    return pcapng_block(PcapngBlockType::EnhancedPacket, body);
}

/// Writes SHB, IDB and two EPBs, reads them back, and returns the second
/// packet's timestamp as the reader reports it (relative to the first).
[[nodiscard]] auto second_packet_offset_us(std::string const& filename, std::optional<uint8_t> tsresol, uint64_t t1, uint64_t t2)
    -> uint64_t
{
    std::vector<uint8_t> const frame(64, 0xab);
    std::vector<uint8_t> file;
    for (auto const& block : {section_header_block(), interface_block(tsresol), packet_block(t1, frame), packet_block(t2, frame)}) {
        file.insert(file.end(), block.begin(), block.end());
    }
    std::remove(filename.c_str());
    {
        std::FILE* f = std::fopen(filename.c_str(), "wb");
        EXPECT_TRUE(f != nullptr);
        EXPECT_EQ(std::fwrite(file.data(), 1, file.size(), f), file.size());
        (void)std::fclose(f);
    }
    uint64_t second = 0;
    {
        auto rdr = PcapngReader::open(filename);
        EXPECT_TRUE(rdr.has_value());
        Packet packet;
        uint64_t first = 0;
        auto s1 = rdr->read_packet(&first, packet);
        EXPECT_TRUE(s1.has_value() && *s1);
        EXPECT_EQ(first, 0U);
        EXPECT_EQ(packet.size(), frame.size());
        auto s2 = rdr->read_packet(&second, packet);
        EXPECT_TRUE(s2.has_value() && *s2);
    }
    std::remove(filename.c_str());
    return second;
}

}  // namespace

TEST(pcapng_tsresol, decodes_powers_of_ten_and_two)
{
    EXPECT_EQ(pcapng_units_per_second(6), 1'000'000U);
    EXPECT_EQ(pcapng_units_per_second(9), 1'000'000'000U);
    EXPECT_EQ(pcapng_units_per_second(0), 1U);
    EXPECT_EQ(pcapng_units_per_second(0x80U | 10U), 1024U);
    EXPECT_EQ(pcapng_units_per_second(14), 0U);           // beyond 10^13: out of range
    EXPECT_EQ(pcapng_units_per_second(0x80U | 44U), 0U);  // beyond 2^43: out of range
}

TEST(pcapng_tsresol, a_nanosecond_count_since_the_epoch_converts_without_overflow)
{
    uint64_t const ns = 1'780'000'000'000'000'000ULL + 123'456ULL;
    EXPECT_EQ(pcapng_ticks_to_us(ns, 1'000'000'000U), 1'780'000'000'000'123ULL);
    EXPECT_EQ(pcapng_ticks_to_us(2048, 1024), 2'000'000U);
    EXPECT_EQ(pcapng_ticks_to_us(1500, 1'000'000), 1500U);
    EXPECT_EQ(pcapng_ticks_to_us(1500, 0), 1500U);
}

TEST(pcapng_tsresol, a_nanosecond_capture_reads_as_microseconds)
{
    uint64_t const t1 = 1'780'000'000'000'000'000ULL;  // ns, 2026-ish
    uint64_t const offset =
        second_packet_offset_us("/tmp/statusbar_pcapng_test_tsresol_ns.pcapng", uint8_t{9}, t1, t1 + 1'500'000'000ULL);
    EXPECT_EQ(offset, 1'500'000U);  // 1.5 s, not 1500 s
}

TEST(pcapng_tsresol, a_power_of_two_resolution_is_honoured)
{
    uint64_t const offset =
        second_packet_offset_us("/tmp/statusbar_pcapng_test_tsresol_pow2.pcapng", uint8_t{0x80U | 10U}, 0, 2048);
    EXPECT_EQ(offset, 2'000'000U);
}

TEST(pcapng_tsresol, no_option_means_microseconds)
{
    uint64_t const offset = second_packet_offset_us("/tmp/statusbar_pcapng_test_tsresol_none.pcapng", std::nullopt, 0, 1500);
    EXPECT_EQ(offset, 1500U);
}

TEST_MAIN(statusbar_pcap, pcap_test)
