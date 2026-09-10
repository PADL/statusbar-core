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
#include <system_error>
#include <vector>

using namespace statusbar;

TEST(buffer_builder_basic, append_chaining)
{
    BufferSerializerBuilderWithStorage<32> builder{};
    builder.append(uint8_t{0x01}).append(uint16_t{0x0203}).append(uint32_t{0x04050607});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 7);
    EXPECT_EQ(builder.get_span()[0], 0x01);
}

TEST(buffer_builder_basic, error_stops_chain)
{
    BufferSerializerBuilderWithStorage<4> builder{};
    builder
        .append(uint32_t{0x12345678})  // OK - fills buffer
        .append(uint8_t{0x99});        // Should fail

    EXPECT_FALSE(builder.status());
    EXPECT_NE(builder.error(), std::error_code{});
    EXPECT_EQ(builder.get_span().size(), 4);  // Only first append succeeded
}

TEST(buffer_builder_basic, get_buffer)
{
    BufferSerializerBuilderWithStorage<16> builder{};
    builder.append(uint8_t{0xAA});

    auto const& result_buf = builder.get_span();
    EXPECT_EQ(result_buf.size(), 1);
    EXPECT_EQ(result_buf[0], 0xAA);
}

TEST(buffer_builder_basic, bool_conversion)
{
    BufferSerializerBuilderWithStorage<16> builder{};
    builder.append(uint8_t{0x01});

    EXPECT_TRUE(static_cast<bool>(builder));
}

TEST(buffer_builder_with_buffer, wraps_external_buffer)
{
    std::array<uint8_t, 32> data{};
    BufferSerializerBuilderWithBuffer builder{std::span<uint8_t>{data}};

    builder.append(uint8_t{0xAA}).append(uint16_t{0xBBCC}).append(uint32_t{0xDDEEFF00});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 7);
    EXPECT_EQ(builder.get_span()[0], 0xAA);
    EXPECT_EQ(data[0], 0xAA);  // Verify it wrote to external buffer
    EXPECT_EQ(data[1], 0xCC);
    EXPECT_EQ(data[2], 0xBB);
}

TEST(buffer_builder_with_buffer, handles_errors)
{
    std::array<uint8_t, 4> data{};
    BufferSerializerBuilderWithBuffer builder{std::span<uint8_t>{data}};

    builder.append(uint32_t{0x12345678}).append(uint8_t{0x99});  // Second should fail

    EXPECT_FALSE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 4);
}

//
// Appending a span writes the bytes it views, never the span object.
//

TEST(buffer_builder_span, append_span_writes_viewed_bytes)
{
    std::array<uint8_t, 4> const payload{0xAA, 0xBB, 0xCC, 0xDD};
    std::span<uint8_t const> const payload_span{payload};

    BufferSerializerBuilderWithStorage<32> builder{};
    builder.append(uint8_t{0x01}).append(payload_span).append(uint8_t{0x02});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 6);
    EXPECT_EQ(builder.get_span()[0], 0x01);
    EXPECT_EQ(builder.get_span()[1], 0xAA);
    EXPECT_EQ(builder.get_span()[4], 0xDD);
    EXPECT_EQ(builder.get_span()[5], 0x02);
}

TEST(buffer_builder_span, append_mutable_span_and_vector)
{
    std::array<uint8_t, 2> data{0x11, 0x22};
    std::vector<uint8_t> const vec{0x33, 0x44, 0x55};

    BufferSerializerBuilderWithStorage<32> builder{};
    builder.append(std::span<uint8_t>{data}).append(vec);

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 5);
    EXPECT_EQ(builder.get_span()[0], 0x11);
    EXPECT_EQ(builder.get_span()[2], 0x33);
    EXPECT_EQ(builder.get_span()[4], 0x55);
}

TEST(buffer_builder_span, append_span_insufficient_space_writes_nothing)
{
    std::array<uint8_t, 8> const payload{};

    BufferSerializerBuilderWithStorage<4> builder{};
    builder.append(std::span<uint8_t const>{payload});

    EXPECT_FALSE(builder.status());
    EXPECT_EQ(builder.error(), std::error_code{BufferError::insufficient_space});
    EXPECT_EQ(builder.get_span().size(), 0);
}

TEST(buffer_builder_span, append_unchecked_span_writes_viewed_bytes)
{
    std::array<uint8_t, 3> const payload{0x0A, 0x0B, 0x0C};

    BufferSerializerBuilderWithStorage<8> builder{};
    builder.append_unchecked(std::span<uint8_t const>{payload});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.get_span().size(), 3);
    EXPECT_EQ(builder.get_span()[2], 0x0C);
}

// The templated append never sees a span (a span's own bytes are a pointer
// and a length): the only viable overload is the non-template one, whose
// parameter is std::span<uint8_t const>. So a span of anything but bytes
// cannot be appended at all.
template <typename T>
concept CanAppend = requires(BufferSerializerBuilder& b, T const& v) { b.append(v); };
template <typename T>
concept CanAppendUnchecked = requires(BufferSerializerBuilder& b, T const& v) { b.append_unchecked(v); };

static_assert(CanAppend<uint32_t>);
static_assert(CanAppend<std::array<uint8_t, 6>>);
static_assert(CanAppend<std::span<uint8_t const>>);
static_assert(CanAppend<std::span<uint8_t>>);
static_assert(CanAppend<std::vector<uint8_t>>);
static_assert(!CanAppend<std::span<uint16_t const>>);
static_assert(!CanAppend<std::span<uint32_t>>);
static_assert(CanAppendUnchecked<uint32_t>);
static_assert(CanAppendUnchecked<std::span<uint8_t const>>);
static_assert(!CanAppendUnchecked<std::span<uint16_t const>>);

// Parsing into a span would overwrite the view; refused at compile time.
template <typename T>
concept CanParse = requires(BufferDeserializer& d, T* p) { d.parse(p); };
template <typename T>
concept CanBuilderParse = requires(BufferDeserializerBuilder& d, T* p) { d.parse(p); };
template <typename T>
concept CanParseUnchecked = requires(BufferDeserializer& d, T* p) { d.parse_unchecked(p); };
template <typename T>
concept CanCanParse = requires(BufferDeserializer const& d, T const* p) { d.can_parse(p); };

static_assert(CanParse<uint32_t>);
static_assert(CanParse<std::array<uint8_t, 4>>);
static_assert(CanBuilderParse<uint32_t>);
static_assert(!CanParse<std::span<uint8_t>>);
static_assert(!CanParse<std::span<uint8_t const>>);
static_assert(!CanParse<std::span<uint8_t, 4>>);
static_assert(!CanBuilderParse<std::span<uint8_t>>);
static_assert(!CanParseUnchecked<std::span<uint8_t>>);
static_assert(!CanCanParse<std::span<uint8_t>>);

//
// MutableBuffer::rewind / set_span
//

TEST(mutable_buffer_rewind, rewind_empties_and_keeps_storage)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf{data};
    EXPECT_TRUE(buf.append(std::array<uint8_t, 3>{1, 2, 3}));
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.available_space(), 5);

    buf.rewind();

    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.available_space(), 8);
    EXPECT_EQ(buf.get_span().data(), data.data());
    EXPECT_EQ(data[0], 1);  // bytes are not cleared

    EXPECT_TRUE(buf.append(std::array<uint8_t, 1>{9}));
    EXPECT_EQ(buf.size(), 1);
    EXPECT_EQ(data[0], 9);
}

TEST(mutable_buffer_rewind, set_span_prefix)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf{data};
    buf.set_span(buf.total_buffer_span().first(5));
    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf.available_space(), 3);
    buf.set_span(buf.total_buffer_span().first(0));
    EXPECT_EQ(buf.available_space(), 8);
}

//
// buffer.cppm tests - BufferDeserializerBuilder
//

TEST(buffer_deserializer_builder_basic, parse_chaining)
{
    std::array<uint8_t, 10> data{0x01, 0x02, 0x03, 0x04, 0x05};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint16_t v2 = 0;

    BufferDeserializerBuilder deserializer{buf};
    deserializer.parse(&v1).skip(1).parse(&v2);

    EXPECT_TRUE(deserializer.status());
    EXPECT_EQ(v1, 0x01);
}

TEST(buffer_deserializer_builder_basic, error_stops_chain)
{
    std::array<uint8_t, 2> data{0x01, 0x02};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint32_t v2 = 0;

    BufferDeserializerBuilder deserializer{buf};
    deserializer.parse(&v1).parse(&v2);  // Second parse should fail

    EXPECT_FALSE(deserializer.status());
    EXPECT_EQ(v1, 0x01);  // First parse succeeded
}

TEST(buffer_deserializer_builder_basic, reset)
{
    std::array<uint8_t, 10> data{0x01, 0x02};
    //std::span<uint8_t const> buf{std::span<uint8_t const>(data)};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint8_t v2 = 0;

    BufferDeserializerBuilder deserializer{buf};
    deserializer.parse(&v1);
    deserializer.parse(&v2);

    EXPECT_EQ(v1, 0x01);
    EXPECT_EQ(v2, 0x02);

    deserializer.reset();
    deserializer.parse(&v1);
    deserializer.parse(&v2);

    EXPECT_EQ(v1, 0x01);  // Should re-parse from start
    EXPECT_EQ(v2, 0x02);
}

TEST(buffer_deserializer_builder_basic, seek_to_valid_position)
{
    std::array<uint8_t, 10> data{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    std::span<uint8_t const> const buf{data};

    uint8_t value = 0;
    BufferDeserializerBuilder deserializer{buf};
    deserializer.seek(Position{5}, Length{1}).parse(&value);

    EXPECT_TRUE(deserializer.status());
    EXPECT_EQ(value, 0x05);
}

TEST(buffer_deserializer_builder_basic, seek_with_multi_byte_parse)
{
    std::array<uint8_t, 10> data{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    std::span<uint8_t const> const buf{data};

    uint32_t value = 0;
    BufferDeserializerBuilder deserializer{buf};
    deserializer.seek(Position{3}, Length{4}).parse(&value);

    EXPECT_TRUE(deserializer.status());
}

TEST(buffer_deserializer_builder_basic, seek_insufficient_data)
{
    std::array<uint8_t, 10> data{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    std::span<uint8_t const> const buf{data};

    BufferDeserializerBuilder deserializer{buf};
    deserializer.seek(Position{8}, Length{4});  // Position 8 only has 2 bytes remaining

    EXPECT_FALSE(deserializer.status());
    EXPECT_NE(deserializer.error(), std::error_code{});
}

TEST(buffer_deserializer_builder_basic, seek_beyond_buffer)
{
    std::array<uint8_t, 10> data{0x00, 0x01, 0x02, 0x03, 0x04};
    std::span<uint8_t const> const buf{data};

    BufferDeserializerBuilder deserializer{buf};
    deserializer.seek(Position{15}, Length{1});  // Position 15 is beyond buffer size

    EXPECT_FALSE(deserializer.status());
}

TEST(buffer_deserializer_builder_basic, seek_chaining)
{
    std::array<uint8_t, 20> data{0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x24,
                                 0x30, 0x31, 0x32, 0x33, 0x34, 0x40, 0x41, 0x42, 0x43, 0x44};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint8_t v2 = 0;
    uint8_t v3 = 0;

    BufferDeserializerBuilder deserializer{buf};
    deserializer.seek(Position{0}, Length{1})
        .parse(&v1)
        .seek(Position{10}, Length{1})
        .parse(&v2)
        .seek(Position{15}, Length{1})
        .parse(&v3);

    EXPECT_TRUE(deserializer.status());
    EXPECT_EQ(v1, 0x10);
    EXPECT_EQ(v2, 0x30);
    EXPECT_EQ(v3, 0x40);
}

TEST(buffer_deserializer_builder_basic, seek_error_stops_chain)
{
    std::array<uint8_t, 10> data{0x01, 0x02, 0x03, 0x04, 0x05};
    std::span<uint8_t const> const buf{data};

    uint8_t v1 = 0;
    uint8_t v2 = 0xFF;  // Should remain unchanged

    BufferDeserializerBuilder deserializer{buf};
    deserializer
        .seek(Position{8}, Length{4})  // This should fail - insufficient data
        .parse(&v1)                    // Should be skipped
        .seek(Position{0}, Length{1})  // Should be skipped
        .parse(&v2);                   // Should be skipped

    EXPECT_FALSE(deserializer.status());
    EXPECT_EQ(v1, 0);     // Should not be modified
    EXPECT_EQ(v2, 0xFF);  // Should not be modified
}

//
// buffer.cppm tests - Error category
//

TEST(buffer_error, error_category_name)
{
    auto ec = make_error_code(BufferError::insufficient_space);
    EXPECT_EQ(std::string(ec.category().name()), "statusbar.buffer");
}

TEST(buffer_error, error_messages)
{
    auto ec1 = make_error_code(BufferError::insufficient_space);
    EXPECT_EQ(ec1.message(), "Insufficient space in buffer");

    auto ec2 = make_error_code(BufferError::invalid_offset);
    EXPECT_EQ(ec2.message(), "Invalid offset");
}

//
// buffer.cppm tests - Additional coverage tests
//

TEST(buffer_coverage, buffer_span_conversion)
{
    std::array<uint8_t, 10> data{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::span<uint8_t const> const buf{data};

    // Test implicit conversion to span
    std::span<uint8_t const> const s = buf;
    EXPECT_EQ(s.size(), 10);
    EXPECT_EQ(s[0], 0);
    EXPECT_EQ(s[9], 9);
}

TEST(buffer_coverage, mutable_buffer_store_buffer)
{
    std::array<uint8_t, 20> data{};
    MutableBuffer buf(make_span(data), 20);

    std::array<uint8_t, 5> src_data{0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    std::span<uint8_t const> const src_buf{src_data};

    auto const status = buf.store(5, src_buf);
    EXPECT_TRUE(status);
    EXPECT_EQ(buf.get_span()[5], 0xAA);
    EXPECT_EQ(buf.get_span()[9], 0xEE);
}

TEST(buffer_coverage, buffer_builder_buffer_method)
{
    BufferSerializerBuilderWithStorage<16> builder{};
    builder.append(uint32_t{0x12345678});

    // Test buffer() method
    auto const& result = builder.buffer();
    EXPECT_EQ(result.size(), 4);
}

TEST(buffer_coverage, buffer_deserializer_builder_bool_conversion)
{
    std::array<uint8_t, 10> data{0x01, 0x02};
    std::span<uint8_t const> const buf{data};

    BufferDeserializerBuilder deserializer{buf};
    uint8_t v = 0;
    deserializer.parse(&v);

    // Test bool conversion
    EXPECT_TRUE(static_cast<bool>(deserializer));
}

TEST(buffer_coverage, buffer_deserializer_builder_error_method)
{
    std::array<uint8_t, 2> data{0x01, 0x02};
    std::span<uint8_t const> const buf{data};

    uint32_t v = 0;
    BufferDeserializerBuilder deserializer{buf};
    deserializer.parse(&v);  // This will fail - insufficient data

    // Test error() method
    auto const err = deserializer.error();
    EXPECT_NE(err, std::error_code{});
    EXPECT_FALSE(static_cast<bool>(deserializer));
}

//
// buffer.cppm tests - CompiledDeserializer and FieldExtractor
//

//
// Main test runner
//

TEST_MAIN(statusbar_buffer, buffer_builder_test)