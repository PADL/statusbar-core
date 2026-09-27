// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/buffer.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

using namespace statusbar;
using namespace statusbar::protocol;

TEST(buffer_basic, construct_and_size)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t const> const buf{data};
    EXPECT_EQ(buf.size(), 10);
}

TEST(buffer_basic, default_constructor)
{
    std::span<uint8_t const> buf;
    EXPECT_EQ(buf.size(), 0);
}

TEST(buffer_basic, construct_from_const_array)
{
    std::array<uint8_t const, 5> data{10, 20, 30, 40, 50};
    std::span<uint8_t const> const buf{data};

    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf[0], 10);
    EXPECT_EQ(buf[4], 50);
}

TEST(buffer_basic, construct_from_mutable_array)
{
    std::array<uint8_t, 5> data{100, 101, 102, 103, 104};
    std::span<uint8_t const> const buf{data};

    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf[0], 100);
    EXPECT_EQ(buf[4], 104);
}

TEST(buffer_basic, slice_of_offset)
{
    std::array<uint8_t, 10> data{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::span<uint8_t const> const buf{data};

    auto const slice = get_slice(buf, 5);
    EXPECT_EQ(slice.size(), 5);
    EXPECT_EQ(slice[0], 5);
}

TEST(buffer_basic, slice_of_offset_and_length)
{
    std::array<uint8_t, 10> data{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::span<uint8_t const> const buf{data};

    auto const slice = get_slice(buf, 2, 5);
    EXPECT_EQ(slice.size(), 5);
    EXPECT_EQ(slice[0], 2);
    EXPECT_EQ(slice[4], 6);
}

TEST(buffer_basic, slice_out_of_bounds_returns_empty)
{
    std::array<uint8_t, 10> data{};
    std::span<uint8_t const> const buf{data};

    auto const slice = get_slice(buf, 15, 5);
    EXPECT_EQ(slice.size(), 0);

    auto const slice2 = get_slice(buf, 8, 5);  // 8 + 5 > 10
    EXPECT_EQ(slice2.size(), 0);
}

TEST(buffer_load_raw, load_uint8)
{
    std::array<uint8_t, 4> data{0x12, 0x34, 0x56, 0x78};
    std::span<uint8_t const> const buf{data};

    uint8_t value = 0;
    auto const offset_result = load(get_slice(buf, 0), &value);

    EXPECT_EQ(value, 0x12);
    EXPECT_TRUE(offset_result);
    EXPECT_EQ(offset_result.value(), 1);
}

TEST(buffer_load_raw, load_uint16)
{
    std::array<uint8_t, 4> data{0x12, 0x34, 0x56, 0x78};
    std::span<uint8_t const> const buf{data};

    uint16_t value = 0;
    auto const offset_result = load(get_slice(buf, 0), &value);

    // Raw load - no byte-order conversion
    // On little-endian: 0x3412, on big-endian: 0x1234
    EXPECT_TRUE(offset_result);  // Should succeed
    EXPECT_EQ(offset_result.value(), 2);
}

TEST(buffer_load_raw, load_uint32)
{
    std::array<uint8_t, 4> data{0x12, 0x34, 0x56, 0x78};
    std::span<uint8_t const> const buf{data};

    uint32_t value = 0;
    auto const offset_result = load(get_slice(buf, 0), &value);

    EXPECT_TRUE(offset_result);  // Should succeed
    EXPECT_EQ(offset_result.value(), 4);
}

TEST(buffer_load_raw, load_insufficient_data)
{
    std::array<uint8_t, 2> data{0x12, 0x34};
    std::span<uint8_t const> const buf{data};

    uint32_t value = 0;
    auto const offset_result = load(get_slice(buf, 0), &value);

    EXPECT_FALSE(offset_result);  // Should fail
}

TEST(buffer_load_raw, load_at_offset)
{
    std::array<uint8_t, 8> data{0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00};
    std::span<uint8_t const> const buf{data};

    uint32_t value = 0;
    auto const offset_result = load(get_slice(buf, 2), &value);

    EXPECT_TRUE(offset_result);
    EXPECT_EQ(offset_result.value(), 4);  // load() returns bytes read, not remaining bytes
}

TEST(buffer_load_raw, load_array_uint32)
{
    std::array<uint8_t, 12> data{
        0x01,
        0x02,
        0x03,
        0x04,  // First uint32
        0x05,
        0x06,
        0x07,
        0x08,  // Second uint32
        0x09,
        0x0A,
        0x0B,
        0x0C  // Third uint32
    };
    std::span<uint8_t const> const buf{data};

    std::array<uint32_t, 3> result{};
    auto const status = load(buf, &result);

    EXPECT_TRUE(status);
    EXPECT_EQ(status.value(), 12);  // 3 * 4 bytes

    // Values will be in machine byte order (little-endian on most systems)
    EXPECT_EQ(result[0], 0x04030201);
    EXPECT_EQ(result[1], 0x08070605);
    EXPECT_EQ(result[2], 0x0C0B0A09);
}

TEST(buffer_load_raw, load_unchecked_array_uint32)
{
    std::array<uint8_t, 12> data{
        0x11,
        0x22,
        0x33,
        0x44,  // First uint32
        0x55,
        0x66,
        0x77,
        0x88,  // Second uint32
        0x99,
        0xAA,
        0xBB,
        0xCC  // Third uint32
    };
    std::span<uint8_t const> const buf{data};

    std::array<uint32_t, 3> result{};
    auto const bytes_read = load_unchecked(buf, &result);

    EXPECT_EQ(bytes_read, 12);  // 3 * 4 bytes
    EXPECT_EQ(result[0], 0x44332211);
    EXPECT_EQ(result[1], 0x88776655);
    EXPECT_EQ(result[2], 0xCCBBAA99);
}

TEST(buffer_load_raw, load_array_insufficient_data)
{
    std::array<uint8_t, 8> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::span<uint8_t const> const buf{data};

    std::array<uint32_t, 3> result{};  // Need 12 bytes, only have 8
    auto const status = load(buf, &result);

    EXPECT_FALSE(status);
    EXPECT_EQ(status.error(), BufferError::insufficient_data);
}

//
// buffer.cppm tests - MutableBuffer basic operations
//

TEST(mutable_buffer_basic, construct_empty)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.available_space(), 10);
}

TEST(mutable_buffer_basic, construct_with_data)
{
    std::array<uint8_t, 10> data{1, 2, 3, 4, 5};
    MutableBuffer buf(make_span(data), 5);

    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf.available_space(), 5);
    EXPECT_EQ(buf.get_span()[0], 1);
    EXPECT_EQ(buf.get_span()[4], 5);
}

TEST(mutable_buffer_basic, can_append_success)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    auto const status = buf.can_append(5);
    EXPECT_TRUE(status);
}

TEST(mutable_buffer_basic, can_append_failure)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    auto const status = buf.can_append(15);
    EXPECT_FALSE(status);
}

TEST(mutable_buffer_basic, construct_from_std_array)
{
    std::array<uint8_t, 16> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    EXPECT_EQ(builder.position(), 0);
    EXPECT_EQ(builder.get_mutable_buffer().available_space(), 16);

    builder.append(uint32_t{0x12345678});
    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.position(), 4);
}

TEST(mutable_buffer_basic, construct_from_c_array)
{
    uint8_t data[20];
    BufferSerializerBuilderWithBuffer builder{data};

    EXPECT_EQ(builder.position(), 0);
    EXPECT_EQ(builder.get_mutable_buffer().available_space(), 20);

    builder.append(uint8_t{0xAB});
    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.position(), 1);
    EXPECT_EQ(builder.get_span()[0], 0xAB);
}

//
// buffer.cppm tests - MutableBuffer append operations
//

TEST(mutable_buffer_append, append_uint8)
{
    std::array<uint8_t, 10> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    builder.append(uint8_t{0x42});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.position(), 1);
    EXPECT_EQ(builder.get_span()[0], 0x42);
}

TEST(mutable_buffer_append, append_uint16)
{
    std::array<uint8_t, 10> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    builder.append(uint16_t{0x1234});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.position(), 2);
}

TEST(mutable_buffer_append, append_uint32)
{
    std::array<uint8_t, 10> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    builder.append(uint32_t{0x12345678});

    EXPECT_TRUE(builder.status());
    EXPECT_EQ(builder.position(), 4);
}

TEST(mutable_buffer_append, append_multiple)
{
    std::array<uint8_t, 10> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    builder.append(uint8_t{0x01}).append(uint16_t{0x0203}).append(uint8_t{0x04});

    EXPECT_EQ(builder.position(), 4);
    EXPECT_EQ(builder.get_span()[0], 0x01);
}

TEST(mutable_buffer_append, append_span)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    std::array<uint8_t, 3> src{0xAA, 0xBB, 0xCC};
    auto const status = buf.append(make_const_span(src));

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.get_span()[0], 0xAA);
    EXPECT_EQ(buf.get_span()[2], 0xCC);
}

TEST(mutable_buffer_append, append_buffer)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf{data};

    std::array<uint8_t, 3> src_data{0xAA, 0xBB, 0xCC};
    std::span<uint8_t const> const src{src_data};

    auto const status = buf.append(src);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 3);
}

TEST(mutable_buffer_append, append_insufficient_space)
{
    std::array<uint8_t, 2> data{};
    BufferSerializerBuilderWithBuffer builder{data};

    builder.append(uint32_t{0x12345678});

    EXPECT_FALSE(builder.status());
    EXPECT_EQ(builder.position(), 0);  // Should not have modified buffer
}

//
// buffer.cppm tests - MutableBuffer store operations
//

TEST(mutable_buffer_store, store_uint8)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 10);  // Pre-fill

    uint8_t const value = 0x42;
    auto const value_span = make_const_span(value);
    auto const status = buf.store(0, value_span);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.get_span()[0], 0x42);
}

TEST(mutable_buffer_store, store_uint32_at_offset)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 10);

    uint32_t const value = 0x12345678;
    auto const value_span = make_const_span(value);
    auto const status = buf.store(4, value_span);

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.size(), 10);  // Size unchanged
}

TEST(mutable_buffer_store, store_span)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 10);

    std::array<uint8_t, 3> src{0xAA, 0xBB, 0xCC};
    auto const status = buf.store(2, make_const_span(src));

    EXPECT_TRUE(status);
    EXPECT_EQ(buf.get_span()[2], 0xAA);
    EXPECT_EQ(buf.get_span()[4], 0xCC);
}

TEST(mutable_buffer_store, store_out_of_bounds)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 5);  // Only 5 bytes used

    uint32_t const value = 0x12345678;
    auto const value_span = make_const_span(value);
    auto const status = buf.store(4, value_span);  // 4 + 4 > 5

    EXPECT_FALSE(status);
}

TEST(mutable_buffer_store, can_store_success)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 10);

    auto const status = buf.can_store(0, 4);
    EXPECT_TRUE(status);
}

TEST(mutable_buffer_store, can_store_failure)
{
    std::array<uint8_t, 10> data{};
    MutableBuffer buf(make_span(data), 5);

    auto const status = buf.can_store(4, 4);  // 4 + 4 > 5
    EXPECT_FALSE(status);
}

//
// buffer.cppm tests - MutableBufferWithStorage
//

TEST(buffer_with_storage, basic_usage)
{
    BufferSerializerBuilderWithStorage<16> builder;

    EXPECT_EQ(builder.position(), 0);
    EXPECT_EQ(builder.get_mutable_buffer().available_space(), 16);

    builder.append(uint32_t{0x12345678});
    EXPECT_EQ(builder.position(), 4);
}

//
// buffer.cppm tests - BufferDeserializer
//

//
// MutableBuffer advance tests
//

TEST(mutable_buffer_advance, advance_success)
{
    std::array<uint8_t, 100> storage{};
    MutableBuffer buffer(storage);

    EXPECT_EQ(buffer.get_span().size(), 0);
    EXPECT_EQ(buffer.available_space(), 100);

    // Advance by 10 bytes
    auto result = buffer.advance(10);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 10);
    EXPECT_EQ(buffer.get_span().size(), 10);
    EXPECT_EQ(buffer.available_space(), 90);
}

TEST(mutable_buffer_advance, advance_insufficient_space)
{
    std::array<uint8_t, 10> storage{};
    MutableBuffer buffer(storage);

    // Try to advance beyond capacity
    auto result = buffer.advance(20);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(BufferError::insufficient_space));
    EXPECT_EQ(buffer.get_span().size(), 0);  // No change
}

TEST(mutable_buffer_advance, advance_multiple)
{
    std::array<uint8_t, 100> storage{};
    MutableBuffer buffer(storage);

    auto result1 = buffer.advance(25);
    EXPECT_TRUE(result1.has_value());
    EXPECT_EQ(buffer.get_span().size(), 25);

    auto result2 = buffer.advance(30);
    EXPECT_TRUE(result2.has_value());
    EXPECT_EQ(buffer.get_span().size(), 55);

    auto result3 = buffer.advance(45);
    EXPECT_TRUE(result3.has_value());
    EXPECT_EQ(buffer.get_span().size(), 100);

    // Now full, can't advance more
    auto result4 = buffer.advance(1);
    EXPECT_FALSE(result4.has_value());
}

TEST(mutable_buffer_advance, store_unchecked)
{
    std::array<uint8_t, 100> storage{};
    MutableBuffer buffer(storage);

    // First, advance to make room for the data
    auto advance_result = buffer.advance(20);
    EXPECT_TRUE(advance_result.has_value());

    std::array<uint8_t, 5> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Store at position 10 using store_unchecked (within the used portion)
    buffer.store_unchecked(10, make_const_span(data));

    // Verify the data was stored at the right position
    EXPECT_EQ(storage[10], 0x01);
    EXPECT_EQ(storage[11], 0x02);
    EXPECT_EQ(storage[12], 0x03);
    EXPECT_EQ(storage[13], 0x04);
    EXPECT_EQ(storage[14], 0x05);
}

//
// BufferDeserializerBuilder position tests
//

TEST(deserializer_builder_position, position_accessor)
{
    std::array<uint8_t, 20> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A};
    std::span<uint8_t const> data_span{data};
    BufferDeserializerBuilder builder{data_span};

    EXPECT_EQ(builder.position(), 0);

    // Skip 5 bytes
    (void)builder.skip(5);
    EXPECT_EQ(builder.position(), 5);

    // Read a uint32
    uint32_t value = 0;
    builder.parse(&value);
    EXPECT_TRUE(builder);  // Check no error
    EXPECT_EQ(builder.position(), 9);
}

//
// BufferSerializerBuilder get_span tests
//

TEST(serializer_builder_span, get_span_accessor)
{
    std::array<uint8_t, 100> storage{};
    MutableBuffer buffer(storage);
    BufferSerializerBuilder builder(buffer);

    // Initially empty
    auto span = builder.get_span();
    EXPECT_EQ(span.size(), 0);

    // Append some data
    builder.append(uint32_t{0x12345678});
    span = builder.get_span();
    EXPECT_EQ(span.size(), 4);

    builder.append(uint16_t{0xABCD});
    span = builder.get_span();
    EXPECT_EQ(span.size(), 6);
}

//
// Exhaustive error message coverage
//

TEST(buffer_error, all_errors_have_messages)
{
    // Verify every BufferError code produces a non-"Unknown" message
    auto check = [](BufferError e) {
        std::error_code ec = e;
        EXPECT_TRUE(!ec.message().empty());
        EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
    };
    check(BufferError::insufficient_space);
    check(BufferError::invalid_offset);
    check(BufferError::insufficient_data);
}

TEST(buffer_error, category_name)
{
    EXPECT_EQ(std::string_view{buffer_error_category().name()}, "statusbar.buffer");
}

//
// Main test runner
//

//
// Decoder safety: edge cases and arithmetic overflow guards. Buffer is
// the foundation for every wire-format codec; a bug here propagates
// silently. These tests pin down the boundary behavior callers rely on.
//

TEST(mutable_buffer_safety, ctor_with_data_size_larger_than_span_throws)
{
    std::array<uint8_t, 4> data{};
    bool threw = false;
    try {
        MutableBuffer bad(make_span(data), 5);  // data_size=5 > capacity=4
        (void)bad;
    } catch (std::system_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

TEST(mutable_buffer_safety, can_store_rejects_huge_length)
{
    // required_length > get_span().size() must short-circuit before the
    // (size - required_length) subtraction that would underflow.
    std::array<uint8_t, 8> data{};
    MutableBuffer buf(make_span(data), 8);
    EXPECT_FALSE(buf.can_store(0, std::numeric_limits<size_t>::max()));
}

TEST(mutable_buffer_safety, can_store_rejects_huge_offset_with_small_length)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf(make_span(data), 8);
    EXPECT_FALSE(buf.can_store(std::numeric_limits<size_t>::max(), 4));
}

TEST(mutable_buffer_safety, can_store_error_codes_distinguish_offset_and_space)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf(make_span(data), 4);
    // An offset beyond the used size is invalid_offset ...
    auto const bad_offset = buf.can_store(5, 1);
    EXPECT_FALSE(bad_offset);
    EXPECT_EQ(bad_offset.error(), make_error_code(BufferError::invalid_offset));
    // ... while a length that does not fit after a valid offset is
    // insufficient_space. store() reports identically (it delegates).
    auto const bad_length = buf.can_store(2, 3);
    EXPECT_FALSE(bad_length);
    EXPECT_EQ(bad_length.error(), make_error_code(BufferError::insufficient_space));
    std::array<uint8_t, 3> src{0xAA, 0xBB, 0xCC};
    auto const store_bad_length = buf.store(2, make_const_span(src));
    EXPECT_FALSE(store_bad_length);
    EXPECT_EQ(store_bad_length.error(), make_error_code(BufferError::insufficient_space));
}

// MutableBufferWithStorage owns its bytes; a defaulted copy or move would
// duplicate the storage while the MutableBuffer subobject's spans still
// referenced the SOURCE object's storage. Locked out at compile time.
static_assert(!std::is_copy_constructible_v<MutableBufferWithStorage<8>>);
static_assert(!std::is_copy_assignable_v<MutableBufferWithStorage<8>>);
static_assert(!std::is_move_constructible_v<MutableBufferWithStorage<8>>);
static_assert(!std::is_move_assignable_v<MutableBufferWithStorage<8>>);

TEST(mutable_buffer_safety, append_full_then_again_returns_failure)
{
    std::array<uint8_t, 4> data{};
    MutableBuffer buf(make_span(data));
    std::array<uint8_t, 4> first{0xAA, 0xBB, 0xCC, 0xDD};
    EXPECT_TRUE(buf.append(std::span<uint8_t const>(first)));
    EXPECT_EQ(buf.size(), size_t{4});
    std::array<uint8_t, 1> overflow{0xEE};
    EXPECT_FALSE(buf.append(std::span<uint8_t const>(overflow)));
    EXPECT_EQ(buf.size(), size_t{4});   // size unchanged on failure
    EXPECT_EQ(data[3], uint8_t{0xDD});  // backing storage unchanged
}

TEST(mutable_buffer_safety, advance_zero_is_no_op)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf(make_span(data));
    auto const r = buf.advance(0);
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(*r, size_t{0});
    EXPECT_EQ(buf.size(), size_t{0});
    EXPECT_EQ(buf.available_space(), size_t{8});
}

TEST(mutable_buffer_safety, append_empty_span_succeeds_no_change)
{
    std::array<uint8_t, 8> data{};
    MutableBuffer buf(make_span(data));
    std::array<uint8_t, 0> empty{};
    EXPECT_TRUE(buf.append(std::span<uint8_t const>(empty)));
    EXPECT_EQ(buf.size(), size_t{0});
}

TEST_MAIN(statusbar_buffer, buffer_basic_test)