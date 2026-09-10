// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <span>
#include <utility>
#include <vector>

using namespace statusbar;

TEST(compiled_deserializer, basic_field_extraction)
{
    std::array<uint8_t, 10> data{0x01, 0x02, 0x03, 0x04, 0x05};
    std::span<uint8_t const> const buf{data};

    uint8_t field1 = 0;
    uint16_t field2 = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&field1](uint8_t v) { field1 = v; }), field<uint16_t>([&field2](uint16_t v) { field2 = v; }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(field1, 0x01);
}

TEST(compiled_deserializer, reuse_across_multiple_buffers)
{
    // Define deserializer once
    uint8_t type = 0;
    uint16_t length = 0;
    uint32_t payload = 0;

    auto const packet_deserializer = make_deserializer(
        field<uint8_t>([&type](uint8_t v) { type = v; }),
        field<uint16_t>([&length](uint16_t v) { length = v; }),
        field<uint32_t>([&payload](uint32_t v) { payload = v; }));

    // Parse first buffer
    std::array<uint8_t, 10> data1{0xAA, 0x00, 0x10, 0x12, 0x34, 0x56, 0x78};
    std::span<uint8_t const> const buf1{data1};
    auto const status1 = packet_deserializer.parse(buf1);

    EXPECT_TRUE(status1);
    EXPECT_EQ(type, 0xAA);

    // Reuse for second buffer
    std::array<uint8_t, 10> data2{0xBB, 0x00, 0x20, 0x87, 0x65, 0x43, 0x21};
    std::span<uint8_t const> const buf2{data2};
    auto const status2 = packet_deserializer.parse(buf2);

    EXPECT_TRUE(status2);
    EXPECT_EQ(type, 0xBB);
}

TEST(compiled_deserializer, error_on_insufficient_data)
{
    std::array<uint8_t, 2> data{0x01, 0x02};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint32_t v2 = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&v1](uint8_t v) { v1 = v; }), field<uint32_t>([&v2](uint32_t v) { v2 = v; }));  // Not enough data

    auto const status = deserializer.parse(buf);

    EXPECT_FALSE(status);
    EXPECT_EQ(v1, 0x01);  // First field should succeed
    EXPECT_EQ(v2, 0);     // Second field should not be modified
}

TEST(compiled_deserializer, sequential_parsing)
{
    std::array<uint8_t, 10> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::span<uint8_t const> const buf{data};

    std::array<uint8_t, 4> parsed{};
    size_t index = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&parsed, &index](uint8_t v) { parsed[index++] = v; }),
        field<uint8_t>([&parsed, &index](uint8_t v) { parsed[index++] = v; }),
        field<uint8_t>([&parsed, &index](uint8_t v) { parsed[index++] = v; }),
        field<uint8_t>([&parsed, &index](uint8_t v) { parsed[index++] = v; }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(index, 4);
    EXPECT_EQ(parsed[0], 0x01);
    EXPECT_EQ(parsed[1], 0x02);
    EXPECT_EQ(parsed[2], 0x03);
    EXPECT_EQ(parsed[3], 0x04);
}

TEST(compiled_deserializer, lambda_with_side_effects)
{
    std::array<uint8_t, 10> data{0x05, 0x00, 0x03};
    std::span<uint8_t const> const buf{data};

    uint32_t sum = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&sum](uint8_t v) { sum += v; }),
        field<uint8_t>([&sum](uint8_t v) { sum += v; }),
        field<uint8_t>([&sum](uint8_t v) { sum += v; }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(sum, 8);  // 5 + 0 + 3
}

TEST(compiled_deserializer, empty_deserializer)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t const> const buf{data};

    auto const deserializer = make_deserializer();  // No fields

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);  // Should succeed with no operations
}

TEST(compiled_deserializer, single_field)
{
    std::array<uint8_t, 10> data{0x42};
    std::span<uint8_t const> const buf{data};

    uint8_t value = 0;

    auto const deserializer = make_deserializer(field<uint8_t>([&value](uint8_t v) { value = v; }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(value, 0x42);
}

TEST(compiled_deserializer, mixed_types)
{
    std::array<uint8_t, 16> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    std::span<uint8_t const> const buf{data};

    uint8_t b = 0;
    uint16_t w = 0;
    uint32_t d = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&b](uint8_t v) { b = v; }), field<uint16_t>([&w](uint16_t v) { w = v; }), field<uint32_t>([&d](uint32_t v) {
            d = v;
        }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(b, 0x01);
}

TEST(compiled_deserializer, skip_bytes)
{
    std::array<uint8_t, 10> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::span<uint8_t const> const buf{data};

    uint8_t first = 0;
    uint8_t after_skip = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&first](uint8_t v) { first = v; }),
        skip<3>(),  // Skip 3 bytes
        field<uint8_t>([&after_skip](uint8_t v) { after_skip = v; }));

    auto const status = deserializer.parse(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(first, 0x01);
    EXPECT_EQ(after_skip, 0x05);  // Skipped 0x02, 0x03, 0x04
}

TEST(compiled_deserializer, skip_multiple_segments)
{
    std::array<uint8_t, 20> data{
        0xAA,  // byte 0
        0x00,
        0x00,
        0x00,  // padding (skip 3)
        0xBB,
        0xCC,  // bytes 4-5
        0x00,
        0x00,  // padding (skip 2)
        0xDD   // byte 8
    };
    std::span<uint8_t const> const buf{data};

    uint8_t b1 = 0, b2 = 0, b3 = 0, b4 = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&b1](uint8_t v) { b1 = v; }),
        skip<3>(),
        field<uint8_t>([&b2](uint8_t v) { b2 = v; }),
        field<uint8_t>([&b3](uint8_t v) { b3 = v; }),
        skip<2>(),
        field<uint8_t>([&b4](uint8_t v) { b4 = v; }));

    EXPECT_TRUE(deserializer.parse(buf));
    EXPECT_EQ(b1, 0xAA);
    EXPECT_EQ(b2, 0xBB);
    EXPECT_EQ(b3, 0xCC);
    EXPECT_EQ(b4, 0xDD);
}

TEST(compiled_deserializer, skip_error_on_insufficient_data)
{
    std::array<uint8_t, 3> data{0x01, 0x02, 0x03};
    std::span<uint8_t const> const buf{data};

    uint8_t value = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&value](uint8_t v) { value = v; }),
        skip<10>()  // Try to skip more bytes than available
    );

    auto const status = deserializer.parse(buf);

    EXPECT_FALSE(status);
    EXPECT_EQ(value, 0x01);  // First field succeeded
}

TEST(compiled_deserializer, skip_with_mixed_types)
{
    std::array<uint8_t, 20> data{
        0x01,  // uint8_t
        0x00,
        0x00,
        0x00,  // padding (skip 3)
        0x00,
        0x02,
        0x00,
        0x03,  // uint16_t values
        0x00,
        0x00,  // padding (skip 2)
        0x00,
        0x00,
        0x00,
        0x04  // uint32_t
    };
    std::span<uint8_t const> const buf{data};

    uint8_t b = 0;
    uint16_t w1 = 0, w2 = 0;
    uint32_t d = 0;

    auto const deserializer = make_deserializer(
        field<uint8_t>([&b](uint8_t v) { b = v; }),
        skip<3>(),
        field<uint16_t>([&w1](uint16_t v) { w1 = v; }),
        field<uint16_t>([&w2](uint16_t v) { w2 = v; }),
        skip<2>(),
        field<uint32_t>([&d](uint32_t v) { d = v; }));

    EXPECT_TRUE(deserializer.parse(buf));
    EXPECT_EQ(b, 0x01);
}

//
// buffer.cppm tests - CompiledSerializer and FieldSerializer
//

TEST(compiled_serializer, basic_field_serialization)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint8_t const field1 = 0x01;
    uint16_t const field2 = 0x0203;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&field1]() { return field1; }), serialize_field<uint16_t>([&field2]() { return field2; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.get_span()[0], 0x01);
}

TEST(compiled_serializer, reuse_across_multiple_buffers)
{
    // Define serializer once
    uint8_t type = 0xAA;
    uint16_t length = 0x0010;
    uint32_t payload = 0x12345678;

    auto const packet_serializer = make_serializer(
        serialize_field<uint8_t>([&type]() { return type; }),
        serialize_field<uint16_t>([&length]() { return length; }),
        serialize_field<uint32_t>([&payload]() { return payload; }));

    // Serialize to first buffer
    std::array<uint8_t, 10> data1{};
    MutableBuffer buf1{data1};
    auto const status1 = packet_serializer.serialize(buf1);

    EXPECT_TRUE(status1);
    EXPECT_EQ(buf1.size(), 7);
    EXPECT_EQ(buf1.get_span()[0], 0xAA);

    // Change values and reuse for second buffer
    type = 0xBB;
    length = 0x0020;
    payload = 0x87654321;

    std::array<uint8_t, 10> data2{};
    MutableBuffer buf2{data2};
    auto const status2 = packet_serializer.serialize(buf2);

    EXPECT_TRUE(status2);
    EXPECT_EQ(buf2.size(), 7);
    EXPECT_EQ(buf2.get_span()[0], 0xBB);
}

TEST(compiled_serializer, error_on_insufficient_space)
{
    std::array<uint8_t, 2> data{};
    MutableBuffer buf{data};

    uint8_t const v1 = 0x01;
    uint32_t const v2 = 0x12345678;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&v1]() { return v1; }), serialize_field<uint32_t>([&v2]() { return v2; }));  // Not enough space

    auto const status = serializer.serialize(buf);

    EXPECT_FALSE(status);
    EXPECT_EQ(buf.size(), 1);  // First field should succeed
}

TEST(compiled_serializer, sequential_serialization)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    std::array<uint8_t, 4> const values{0x01, 0x02, 0x03, 0x04};
    size_t index = 0;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&values, &index]() { return values[index++]; }),
        serialize_field<uint8_t>([&values, &index]() { return values[index++]; }),
        serialize_field<uint8_t>([&values, &index]() { return values[index++]; }),
        serialize_field<uint8_t>([&values, &index]() { return values[index++]; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 4);
    EXPECT_EQ(buf.get_span()[0], 0x01);
    EXPECT_EQ(buf.get_span()[1], 0x02);
    EXPECT_EQ(buf.get_span()[2], 0x03);
    EXPECT_EQ(buf.get_span()[3], 0x04);
}

TEST(compiled_serializer, lambda_supplier_functions)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint32_t counter = 1;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&counter]() { return static_cast<uint8_t>(counter++); }),
        serialize_field<uint8_t>([&counter]() { return static_cast<uint8_t>(counter++); }),
        serialize_field<uint8_t>([&counter]() { return static_cast<uint8_t>(counter++); }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.get_span()[0], 1);
    EXPECT_EQ(buf.get_span()[1], 2);
    EXPECT_EQ(buf.get_span()[2], 3);
}

TEST(compiled_serializer, empty_serializer)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    auto const serializer = make_serializer();  // No fields

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);  // Should succeed with no operations
    EXPECT_EQ(buf.size(), 0);
}

TEST(compiled_serializer, single_field)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint8_t const value = 0x42;

    auto const serializer = make_serializer(serialize_field<uint8_t>([&value]() { return value; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 1);
    EXPECT_EQ(buf.get_span()[0], 0x42);
}

TEST(compiled_serializer, mixed_types)
{
    std::array<uint8_t, 16> data{};
    MutableBuffer buf{data};

    uint8_t const b = 0x01;
    uint16_t const w = 0x0203;
    uint32_t const d = 0x04050607;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&b]() { return b; }),
        serialize_field<uint16_t>([&w]() { return w; }),
        serialize_field<uint32_t>([&d]() { return d; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 7);
    EXPECT_EQ(buf.get_span()[0], 0x01);
}

TEST(compiled_serializer, skip_bytes)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint8_t const first = 0xAA;
    uint8_t const after_skip = 0xBB;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&first]() { return first; }),
        serialize_skip<3>(),  // Write 3 zero bytes
        serialize_field<uint8_t>([&after_skip]() { return after_skip; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf.get_span()[0], 0xAA);
    EXPECT_EQ(buf.get_span()[1], 0x00);  // Padding
    EXPECT_EQ(buf.get_span()[2], 0x00);
    EXPECT_EQ(buf.get_span()[3], 0x00);
    EXPECT_EQ(buf.get_span()[4], 0xBB);
}

TEST(compiled_serializer, skip_multiple_segments)
{
    std::array<uint8_t, 20> data{};
    MutableBuffer buf{data};

    uint8_t const b1 = 0xAA, b2 = 0xBB, b3 = 0xCC, b4 = 0xDD;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&b1]() { return b1; }),
        serialize_skip<3>(),  // Padding
        serialize_field<uint8_t>([&b2]() { return b2; }),
        serialize_field<uint8_t>([&b3]() { return b3; }),
        serialize_skip<2>(),  // Padding
        serialize_field<uint8_t>([&b4]() { return b4; }));

    EXPECT_TRUE(serializer.serialize(buf));
    EXPECT_EQ(buf.size(), 9);
    EXPECT_EQ(buf.get_span()[0], 0xAA);
    EXPECT_EQ(buf.get_span()[4], 0xBB);
    EXPECT_EQ(buf.get_span()[5], 0xCC);
    EXPECT_EQ(buf.get_span()[8], 0xDD);
}

TEST(compiled_serializer, skip_error_on_insufficient_space)
{
    std::array<uint8_t, 3> data{};
    MutableBuffer buf{data};

    uint8_t const value = 0x01;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&value]() { return value; }),
        serialize_skip<10>()  // Try to write more bytes than available
    );

    auto const status = serializer.serialize(buf);

    EXPECT_FALSE(status);
    EXPECT_EQ(buf.size(), 1);  // First field succeeded
}

TEST(compiled_serializer, skip_with_mixed_types)
{
    std::array<uint8_t, 20> data{};
    MutableBuffer buf{data};

    uint8_t const b = 0x01;
    uint16_t const w1 = 0x0002, w2 = 0x0003;
    uint32_t const d = 0x00000004;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&b]() { return b; }),
        serialize_skip<3>(),  // Padding
        serialize_field<uint16_t>([&w1]() { return w1; }),
        serialize_field<uint16_t>([&w2]() { return w2; }),
        serialize_skip<2>(),  // Padding
        serialize_field<uint32_t>([&d]() { return d; }));

    EXPECT_TRUE(serializer.serialize(buf));
    EXPECT_EQ(buf.size(), 14);
    EXPECT_EQ(buf.get_span()[0], 0x01);
}

TEST(compiled_serializer, conditional_field_true)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint8_t const flags = 0x01;
    uint16_t const optional = 0xABCD;
    uint32_t const payload = 0x12345678;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&flags]() { return flags; }),
        serialize_conditional_field<uint16_t>([&flags]() { return (flags & 0x01) != 0; }, [&optional]() { return optional; }),
        serialize_field<uint32_t>([&payload]() { return payload; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 7);  // 1 + 2 + 4
    EXPECT_EQ(buf.get_span()[0], 0x01);
}

TEST(compiled_serializer, conditional_field_false)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    uint8_t const flags = 0x00;
    uint16_t const optional = 0xABCD;
    uint32_t const payload = 0x12345678;

    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&flags]() { return flags; }),
        serialize_conditional_field<uint16_t>([&flags]() { return (flags & 0x01) != 0; }, [&optional]() { return optional; }),
        serialize_field<uint32_t>([&payload]() { return payload; }));

    auto const status = serializer.serialize(buf);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 5);  // 1 + 0 + 4 (conditional field skipped)
    EXPECT_EQ(buf.get_span()[0], 0x00);
}

//
// Decoder safety: malformed/short inputs to the compiled deserializer
// pipeline. CompiledDeserializer is the primitive used by every modern
// wire-format codec in the codebase (IEEE, AVTP, ATDECC, etc.); these
// tests pin down the boundary behavior the codecs depend on.
//

TEST(compiled_deserializer_safety, empty_buffer_with_one_field_fails)
{
    std::array<uint8_t, 0> data{};
    uint8_t value = 0xFF;
    auto const deserializer = make_deserializer(field<uint8_t>([&value](uint8_t v) { value = v; }));
    auto const status = deserializer.parse(std::span<uint8_t const>{data});
    EXPECT_FALSE(status);
    EXPECT_EQ(value, uint8_t{0xFF});  // callback never fired
}

TEST(compiled_deserializer_safety, multi_field_failure_at_second_field_does_not_invoke_third)
{
    // Buffer can satisfy field 1 (1 byte) but not field 2 (4 bytes).
    // Field 3 must not be invoked, even though there's room for it.
    std::array<uint8_t, 3> data{0xAA, 0x01, 0x02};
    uint8_t b1 = 0;
    uint32_t b2 = 0xDEADBEEF;
    uint8_t b3 = 0xFF;
    auto const deserializer = make_deserializer(
        field<uint8_t>([&b1](uint8_t v) { b1 = v; }),
        field<uint32_t>([&b2](uint32_t v) { b2 = v; }),
        field<uint8_t>([&b3](uint8_t v) { b3 = v; }));
    auto const status = deserializer.parse(std::span<uint8_t const>{data});
    EXPECT_FALSE(status);
    EXPECT_EQ(b1, uint8_t{0xAA});         // first field ran
    EXPECT_EQ(b2, uint32_t{0xDEADBEEF});  // unchanged on failure
    EXPECT_EQ(b3, uint8_t{0xFF});         // third field never ran
}

TEST(compiled_deserializer_safety, skip_exactly_to_end_succeeds)
{
    // skip<N>() where N == buffer.size() should leave position at end
    // and not fail (boundary equality, not strict-greater).
    std::array<uint8_t, 4> data{1, 2, 3, 4};
    auto const deserializer = make_deserializer(skip<4>());
    EXPECT_TRUE(deserializer.parse(std::span<uint8_t const>{data}));
}

TEST(compiled_serializer_safety, multi_field_failure_at_second_does_not_run_third)
{
    // 3-byte buffer. First field fits, second overflows.
    std::array<uint8_t, 3> data{};
    MutableBuffer buf{data};
    uint8_t const f1 = 0xAA;
    uint32_t const f2 = 0xBBCCDDEE;
    bool f3_called = false;
    auto const serializer = make_serializer(
        serialize_field<uint8_t>([&f1]() { return f1; }),
        serialize_field<uint32_t>([&f2]() { return f2; }),
        serialize_field<uint8_t>([&f3_called]() {
            f3_called = true;
            return uint8_t{0xCC};
        }));
    EXPECT_FALSE(serializer.serialize(buf));
    EXPECT_EQ(buf.size(), size_t{1});  // only first field written
    EXPECT_FALSE(f3_called);           // third supplier never invoked
    EXPECT_EQ(buf.get_span()[0], uint8_t{0xAA});
}

//
// protocol::serialized_size(): the compiled serializers reserve wire bytes,
// not sizeof bytes. A fixed struct whose in-memory size exceeds its
// LENGTH (uint32 + uint8 pads to 8, the wire form is 5) tells the two
// apart.
//

struct PaddedFixedStruct
{
    static constexpr size_t LENGTH = 5;
    uint32_t word;
    uint8_t tail;
};
static_assert(sizeof(PaddedFixedStruct) > PaddedFixedStruct::LENGTH);

template <>
struct statusbar::traits::is_serializable_fixed_struct<PaddedFixedStruct> : std::true_type
{};

[[nodiscard]] auto store_unchecked(std::span<uint8_t> const buf, PaddedFixedStruct const& item) noexcept
{
    BufferSerializerBuilderWithBuffer{buf}.append_unchecked(item.word).append_unchecked(item.tail);
    return item.LENGTH;
}

TEST(serialized_size, scalars_measure_sizeof)
{
    static_assert(protocol::serialized_size(uint8_t{0}) == 1);
    static_assert(protocol::serialized_size(uint16_t{0}) == 2);
    static_assert(protocol::serialized_size(uint32_t{0}) == 4);
    static_assert(protocol::serialized_size(uint64_t{0}) == 8);
    EXPECT_EQ(protocol::serialized_size(double{0}), sizeof(double));
}

TEST(serialized_size, serializable_structs_measure_wire_size)
{
    PaddedFixedStruct const item{.word = 0x01020304, .tail = 0x05};
    EXPECT_EQ(protocol::serialized_size(item), size_t{5});
    EXPECT_NE(protocol::serialized_size(item), sizeof(item));
}

TEST(serialized_size, struct_field_fits_a_buffer_of_exactly_its_wire_size)
{
    // sizeof would demand 8 bytes and refuse this 5-byte buffer.
    std::array<uint8_t, 5> data{};
    MutableBuffer buf{data};
    auto const serializer =
        make_serializer(serialize_field<PaddedFixedStruct>([]() { return PaddedFixedStruct{.word = 0x01020304, .tail = 0x05}; }));
    EXPECT_TRUE(serializer.serialize(buf));
    EXPECT_EQ(buf.size(), size_t{5});
    // append_unchecked writes the raw word in host order; the tail lands
    // right behind it with no padding.
    uint32_t const word = 0x01020304;
    EXPECT_EQ(std::memcmp(buf.get_span().data(), &word, sizeof word), 0);
    EXPECT_EQ(buf.get_span()[4], uint8_t{0x05});

    // One byte short of the wire size still fails, and writes nothing.
    std::array<uint8_t, 4> small{};
    MutableBuffer small_buf{small};
    EXPECT_FALSE(serializer.serialize(small_buf));
    EXPECT_EQ(small_buf.size(), size_t{0});
}

TEST(serialized_size, conditional_struct_field_reserves_wire_size)
{
    std::array<uint8_t, 5> data{};
    MutableBuffer buf{data};
    bool const on = true;
    auto const serializer = make_serializer(serialize_conditional_field<PaddedFixedStruct>(
        [&on]() { return on; }, []() { return PaddedFixedStruct{.word = 0xAABBCCDD, .tail = 0xEE}; }));
    EXPECT_TRUE(serializer.serialize(buf));
    EXPECT_EQ(buf.size(), size_t{5});
    EXPECT_EQ(buf.get_span()[4], uint8_t{0xEE});
}

//
// A std::span is not a wire value: serializing one would write the view
// (pointer + length) instead of the bytes it views, and parsing into one
// would overwrite the view. None of the field factories accept it.
//

// Plain function-pointer callables: a lambda body is outside the immediate
// context, so an invalid `T{}` in one would be a hard error, not `false`.
template <typename T>
concept CanFieldExtract = requires { field<T>(std::declval<void (*)(T const&)>()); };
template <typename T>
concept CanSerializeField = requires { serialize_field<T>(std::declval<T (*)()>()); };
template <typename T>
concept CanSerializeConditionalField =
    requires { serialize_conditional_field<T>(std::declval<bool (*)()>(), std::declval<T (*)()>()); };

static_assert(CanFieldExtract<uint32_t>);
static_assert(CanSerializeField<uint32_t>);
static_assert(CanSerializeConditionalField<uint32_t>);
static_assert(CanSerializeField<PaddedFixedStruct>);
static_assert(!CanFieldExtract<std::span<uint8_t>>);
static_assert(!CanFieldExtract<std::span<uint8_t const>>);
static_assert(!CanSerializeField<std::span<uint8_t const>>);
static_assert(!CanSerializeField<std::span<uint8_t, 4>>);
static_assert(!CanSerializeConditionalField<std::span<uint8_t const>>);

// Main test runner function required by create_test_sourcelist
TEST_MAIN(statusbar_buffer, buffer_compiled_test)