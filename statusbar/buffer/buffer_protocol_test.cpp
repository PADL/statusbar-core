// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/status/status.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <system_error>
#include <vector>

using namespace statusbar;

using namespace statusbar::protocol;

//
// Test Protocol Type
//

struct TestFixedProtocol
{
    static constexpr size_t LENGTH = 8;
    uint32_t field1;
    uint32_t field2;
};

template <>
struct statusbar::traits::is_serializable_fixed_struct<TestFixedProtocol> : std::true_type
{};

[[nodiscard]] auto load_unchecked(std::span<uint8_t const> const buf, TestFixedProtocol* const item) noexcept
{
    BufferDeserializerBuilder{buf}.parse_unchecked(&item->field1).parse_unchecked(&item->field2);
    return TestFixedProtocol::LENGTH;
}

[[nodiscard]] auto store_unchecked(std::span<uint8_t> const buf, TestFixedProtocol const& item) noexcept
{
    BufferSerializerBuilderWithBuffer{buf}.append_unchecked(item.field1).append_unchecked(item.field2);
    return TestFixedProtocol::LENGTH;
}

//
// Tests: wire_size()
//

TEST(fixed_size_protocol, wire_size_returns_length)
{
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const size = wire_size(proto);

    EXPECT_EQ(size, 8);
}

//
// Tests: can_load()
//

TEST(fixed_size_protocol, can_load_sufficient_buffer)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const status = can_load(buf, &proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
}

TEST(fixed_size_protocol, can_load_exact_buffer)
{
    std::array<uint8_t, 8> data{};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const status = can_load(buf, &proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
}

TEST(fixed_size_protocol, can_load_insufficient_buffer)
{
    std::array<uint8_t, 5> data{};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const status = can_load(buf, &proto);

    EXPECT_FALSE(status);
    EXPECT_EQ(status.error(), BufferError::insufficient_data);
}

TEST(fixed_size_protocol, can_load_accepts_null_type_tag)
{
    // The pointer is a pure type tag: a size query must not dereference
    // it (the PlainType overloads never dereference theirs either).
    std::array<uint8_t, 10> data{};
    auto const status = can_load(std::span<uint8_t const>{data}, static_cast<TestFixedProtocol const*>(nullptr));
    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
}

//
// PlainSizedContiguous loads (std::vector / inplace_vector): pre-sized
// container, bulk byte copy — previously only trait-asserted, untested.
//

TEST(sized_contiguous, vector_load_round_trip_and_short_buffer)
{
    std::array<uint8_t, 8> const wire{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::span<uint8_t const> const buf{wire};

    std::vector<uint16_t> values(4);  // pre-sized: 4 x 2 bytes
    auto const can = can_load(buf, &values);
    EXPECT_TRUE(can);
    EXPECT_EQ(can.value(), 8);

    auto const status = load(buf, &values);
    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
    if constexpr (std::endian::native == std::endian::little) {
        EXPECT_EQ(values[0], 0x0201);
        EXPECT_EQ(values[3], 0x0807);
    } else {
        EXPECT_EQ(values[0], 0x0102);
        EXPECT_EQ(values[3], 0x0708);
    }

    std::vector<uint16_t> too_many(5);  // needs 10 bytes, buffer has 8
    auto const short_status = load(buf, &too_many);
    EXPECT_FALSE(short_status);
    EXPECT_EQ(short_status.error(), BufferError::insufficient_data);
}

TEST(sized_contiguous, inplace_vector_load_and_empty)
{
    std::array<uint8_t, 4> const wire{0xAA, 0xBB, 0xCC, 0xDD};
    std::span<uint8_t const> const buf{wire};

    statusbar::sg14::inplace_vector<uint8_t, 8> values;
    values.resize(3);  // pre-sized to 3 of the 4 available bytes
    auto const status = load(buf, &values);
    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 3);
    EXPECT_EQ(values[0], 0xAA);
    EXPECT_EQ(values[2], 0xCC);

    // An empty pre-sized container loads zero bytes successfully.
    statusbar::sg14::inplace_vector<uint8_t, 8> empty;
    auto const empty_status = load(buf, &empty);
    EXPECT_TRUE(empty_status);
    EXPECT_EQ(empty_status.value(), 0);
}

//
// Tests: can_store()
//

TEST(fixed_size_protocol, can_store_sufficient_buffer)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const status = can_store(buf, proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
}

TEST(fixed_size_protocol, can_store_exact_buffer)
{
    std::array<uint8_t, 8> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const status = can_store(buf, proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
}

TEST(fixed_size_protocol, can_store_insufficient_buffer)
{
    std::array<uint8_t, 5> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const status = can_store(buf, proto);

    EXPECT_FALSE(status);
    EXPECT_EQ(status.error(), BufferError::insufficient_space);
}

//
// Tests: load()
//

TEST(fixed_size_protocol, load_deserializes_correctly)
{
    std::array<uint8_t, 10> data{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xFF, 0xFF};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const status = load(buf, &proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
    // Raw load, no byte-order conversion — expectations follow the host.
    if constexpr (std::endian::native == std::endian::little) {
        EXPECT_EQ(proto.field1, 0x78563412);
        EXPECT_EQ(proto.field2, 0xF0DEBC9A);
    } else {
        EXPECT_EQ(proto.field1, 0x12345678);
        EXPECT_EQ(proto.field2, 0x9ABCDEF0);
    }
}

TEST(fixed_size_protocol, load_insufficient_buffer)
{
    std::array<uint8_t, 5> data{};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const status = load(buf, &proto);

    EXPECT_FALSE(status);
    EXPECT_EQ(status.error(), BufferError::insufficient_data);
}

//
// Tests: store()
//

TEST(fixed_size_protocol, store_serializes_correctly)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const status = store(buf, proto);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 8);
    // Raw store, no byte-order conversion — expectations follow the host.
    if constexpr (std::endian::native == std::endian::little) {
        EXPECT_EQ(data[0], 0x78);
        EXPECT_EQ(data[1], 0x56);
        EXPECT_EQ(data[2], 0x34);
        EXPECT_EQ(data[3], 0x12);
        EXPECT_EQ(data[4], 0xF0);
        EXPECT_EQ(data[5], 0xDE);
        EXPECT_EQ(data[6], 0xBC);
        EXPECT_EQ(data[7], 0x9A);
    } else {
        EXPECT_EQ(data[0], 0x12);
        EXPECT_EQ(data[3], 0x78);
        EXPECT_EQ(data[4], 0x9A);
        EXPECT_EQ(data[7], 0xF0);
    }
}

TEST(fixed_size_protocol, store_insufficient_buffer)
{
    std::array<uint8_t, 5> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0x12345678, .field2 = 0x9ABCDEF0};

    auto const status = store(buf, proto);

    EXPECT_FALSE(status);
    EXPECT_EQ(status.error(), BufferError::insufficient_space);
}

//
// Tests: load_unchecked()
//

TEST(fixed_size_protocol, load_unchecked_deserializes_without_validation)
{
    std::array<uint8_t, 10> data{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xFF, 0xFF};
    std::span<uint8_t const> const buf{data};
    TestFixedProtocol proto{};

    auto const bytes_consumed = load_unchecked(buf, &proto);

    EXPECT_EQ(bytes_consumed, 8);
    EXPECT_EQ(proto.field1, 0x44332211);
    EXPECT_EQ(proto.field2, 0x88776655);
}

//
// Tests: store_unchecked()
//

TEST(fixed_size_protocol, store_unchecked_serializes_without_validation)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t> const buf{data};
    TestFixedProtocol proto{.field1 = 0xAABBCCDD, .field2 = 0x11223344};

    auto const bytes_written = store_unchecked(buf, proto);

    EXPECT_EQ(bytes_written, 8);
    EXPECT_EQ(data[0], 0xDD);
    EXPECT_EQ(data[1], 0xCC);
    EXPECT_EQ(data[2], 0xBB);
    EXPECT_EQ(data[3], 0xAA);
    EXPECT_EQ(data[4], 0x44);
    EXPECT_EQ(data[5], 0x33);
    EXPECT_EQ(data[6], 0x22);
    EXPECT_EQ(data[7], 0x11);
}

//
// Tests: Round-trip serialization/deserialization
//

TEST(fixed_size_protocol, round_trip_preserves_values)
{
    TestFixedProtocol original{.field1 = 0x12345678, .field2 = 0xABCDEF01};
    std::array<uint8_t, 8> buffer{};

    // Serialize
    auto const store_status = store(std::span<uint8_t>{buffer}, original);
    EXPECT_TRUE(store_status);

    // Deserialize
    TestFixedProtocol deserialized{};
    auto const load_status = load(std::span<uint8_t const>{buffer}, &deserialized);
    EXPECT_TRUE(load_status);

    // Verify
    EXPECT_EQ(deserialized.field1, original.field1);
    EXPECT_EQ(deserialized.field2, original.field2);
}

TEST(fixed_size_protocol, round_trip_unchecked_preserves_values)
{
    TestFixedProtocol original{.field1 = 0xFEDCBA98, .field2 = 0x76543210};
    std::array<uint8_t, 8> buffer{};

    // Serialize unchecked
    auto const bytes_written = store_unchecked(std::span<uint8_t>{buffer}, original);
    EXPECT_EQ(bytes_written, 8);

    // Deserialize unchecked
    TestFixedProtocol deserialized{};
    auto const bytes_read = load_unchecked(std::span<uint8_t const>{buffer}, &deserialized);
    EXPECT_EQ(bytes_read, 8);

    // Verify
    EXPECT_EQ(deserialized.field1, original.field1);
    EXPECT_EQ(deserialized.field2, original.field2);
}

TEST(fixed_size_protocol, round_trip_preserves_values_with_builder)
{
    TestFixedProtocol original{.field1 = 0x12345678, .field2 = 0xABCDEF01};
    std::array<uint8_t, 16> storage;
    MutableBuffer buffer(storage);
    BufferSerializerBuilder serializer(buffer);
    serializer.append(original);
    EXPECT_TRUE(serializer);

    // Deserialize
    TestFixedProtocol deserialized{};
    BufferDeserializerBuilder deserializer(buffer.get_span());
    deserializer.parse(&deserialized);
    EXPECT_TRUE(deserializer);

    // Verify
    EXPECT_EQ(deserialized.field1, original.field1);
    EXPECT_EQ(deserialized.field2, original.field2);

    if constexpr (std::endian::native == std::endian::big) {
        EXPECT_EQ(storage[0], 0x12U);
        EXPECT_EQ(storage[1], 0x34U);
    } else {
        EXPECT_EQ(storage[0], 0x78U);
        EXPECT_EQ(storage[1], 0x56U);
    }
}

//
// Main test runner
//

TEST_MAIN(statusbar_buffer, buffer_protocol_test)