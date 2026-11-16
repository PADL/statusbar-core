[← back to module index](README.md)

# buffer

Low-level byte-buffer primitives: bounds-checked read/write wrappers over
`std::span<uint8_t>`, fluent serializer/deserializer builders, traits that
classify what can be serialized, and compile-time field descriptors for
fixed-layout wire formats.

## Overview

The `buffer` module is the foundation every wire-format codec in the
codebase builds on. It does **not** define a packet protocol — it
provides the tools to write one. All operations work on
`std::span<uint8_t>` views into caller-owned storage; the module never
allocates on its own (the `*WithStorage<N>` helpers embed a
`std::array`).

There are three layers:

1. **Raw read/write.** `MutableBuffer` wraps a span and tracks how much
   has been written. Free functions `load()`, `load_unchecked()`, and
   `store_unchecked()` in `statusbar::protocol` handle plain types and
   serializable structs uniformly via the concepts in `buffer_traits.hpp`.
2. **Fluent builders.** `BufferSerializerBuilder` and
   `BufferDeserializerBuilder` chain `append()` / `parse()` / `skip()` /
   `seek()` calls with sticky error state — once any step fails, later
   calls short-circuit and the first error is reported via `status()` or
   the `explicit operator bool`.
3. **Compile-time structure.** `make_deserializer(field<T>(cb), …)` and
   `make_serializer(…)` describe a packet layout once; the resulting
   `CompiledDeserializer` / `CompiledSerializer` is reusable across many
   buffers without rebuilding the parse chain.

Byte order is **not** the module's concern: all operations are raw
`memcpy`. Network-order wrappers live in sibling modules and plug in
via `SerializableStruct` / `SerializableWireFixedStruct`.

## Key types

- `MutableBuffer` — span + write cursor; `append()`, `store(offset, …)`, `advance()`, `available_space()`, plus `*_unchecked` variants. `MutableBufferWithStorage<N>` adds an embedded `std::array`.
- `BufferSerializerBuilder` — fluent wrapper around `MutableBuffer`. `BufferSerializerBuilderWithStorage<N>` and `BufferSerializerBuilderWithBuffer` are the convenience constructors most callers use.
- `BufferDeserializer` / `BufferDeserializerBuilder` — sequential reader and fluent wrapper offering `parse()`, `peek()`, `consume()`, `skip()`, and `seek(Position, Length)` with strong-typedef argument guards; `remaining()` is the unparsed bytes as a span and `available()` their count.
- `fail(std::error_code)` on both builders records a failure of the codec's own - a refused value, a count the bytes cannot hold - as the chain's sticky error, so a codec needs no second error beside the builder's; the first error wins.
- `write_file_durably(path, bytes)` / `write_file_durably(dir_fd, path, bytes, mode)` (`file_write.hpp`) — a temporary beside the target, synced to the device (F_FULLFSYNC on Darwin), renamed over the target, the directory synced: a reader sees the old file or the new one, never a half-written one, and a failure leaves the target as it was.
- `BufferError` — `enum class` (`insufficient_space`, `invalid_offset`, `insufficient_data`) registered as `std::is_error_code_enum`; `buffer_error_category()` exposes the `"statusbar.buffer"` category.
- `PlainType`, `PlainElement`, `PlainLinearCollection` — concepts in `statusbar::traits` that classify trivially serializable types (arithmetic, enum, `std::array`/`std::span`/`std::vector` of plain elements, plus extended `__int128` integers when available).
- `SerializableStruct`, `SerializableFixedStruct`, `SerializableWireFixedStruct` — opt-in traits user types specialize to plug custom wire formats into `append()` / `parse()` via ADL on the `protocol` free functions.
- `CompiledDeserializer` / `CompiledSerializer` — reusable codecs built from `make_deserializer(field<T>(cb), skip<N>(), …)` / `make_serializer(…)`.

## Quick example

```cpp
#include "statusbar/buffer/buffer.hpp"

#include <array>
#include <cstdint>

using namespace statusbar;

int main()
{
    // Serialize three integers into a 16-byte arena.
    BufferSerializerBuilderWithStorage<16> writer;
    writer.append(uint8_t{0x01}).append(uint16_t{0x0203}).append(uint32_t{0x04050607});
    if (!writer.status()) {
        return 1;
    }

    // Read them back with the deserializer builder.
    BufferDeserializerBuilder reader{writer.get_span()};
    uint8_t a = 0;
    uint16_t b = 0;
    uint32_t c = 0;
    reader.parse(&a).parse(&b).parse(&c);
    return reader ? 0 : 1;
}
```

## Headers

- `statusbar/buffer/buffer.hpp` — module header; consumers `#include` this.
- `statusbar/buffer/buffer_error.hpp` — `BufferError`, category, `make_error_code`.
- `statusbar/buffer/buffer_traits.hpp` — `PlainElement`, `PlainType`, `SerializableStruct` and friends; `buffer_base.hpp` re-exports the `Plain*` aliases into `statusbar`.
- `statusbar/buffer/buffer_mutable_buffer.hpp` — `MutableBuffer`, `MutableBufferWithStorage<N>`.
- `statusbar/buffer/buffer_protocol.hpp` — `load()`, `load_unchecked()`, `store_unchecked()`, `can_load()`, `wire_size()` in `statusbar::protocol`.
- `statusbar/buffer/buffer_serializer_builder.hpp` / `buffer_deserializer_builder.hpp` — the builder classes plus `Position` / `Length`.
- `statusbar/buffer/buffer_serdes_compiled.hpp` — `CompiledDeserializer`, `CompiledSerializer`, `make_deserializer`, `make_serializer`, `field`, `skip`.
- `statusbar/buffer/span_utils.hpp` — `make_span`, `make_const_span`, `octet_range_t`, `span_copy`, `span_load`.
- `statusbar/buffer/stream_utils.hpp` — `stream_write` / `stream_read` adapters between byte spans and `std::ostream` / `std::istream`.

## Dependencies

- **Statusbar modules:** [`status`](STATUS_MODULE.md) (`Status`, `StatusValue<T>`, `failure()` / `success()` thread through every checked operation).
- **System / external:**
  - `sg14::inplace_vector` from `statusbar/sg14/inplace_vector.h` — used by `PlainInplaceVector` and `span_utils.hpp`.
  - `<span>`, `<array>`, `<vector>`, `<expected>`, `<system_error>`, `<concepts>`, `<istream>` / `<ostream>` from the C++20/23 standard library.

## Notes & caveats

- `MutableBuffer` uses **physical const**: `store(offset, …)` is `const` even though it writes through the span. This lets `BufferSerializerBuilder::buffer()` return a `MutableBuffer const&` that permits in-place patching but blocks `append()`.
- `*_unchecked` variants `assert()` their preconditions and skip the bounds check — only reach for them when the check is provably redundant.
- Builders are **non-copyable and non-movable**, and errors are sticky: after the first failure subsequent calls are no-ops. Inspect `status()` once at the end rather than after every step.
- `load()` and friends do **no byte-order conversion**. Network-order types are handled by wrapper structs that opt into `SerializableWireFixedStruct`.
- `can_store()` short-circuits when `required_length > size()` to avoid underflow in the subsequent subtraction; mirror that pattern in any custom overload.
- The `Position` / `Length` strong typedefs on `seek()` are deliberate — raw `size_t, size_t` pairs are too easy to swap.

## Further reading

- [Deserializer Guide](DESERIALIZER_GUIDE.md) — deep dive on `CompiledDeserializer`, `field<T>()`, `skip<N>()`, and the still-pending IEEE fast-path APIs.
- [`status`](STATUS_MODULE.md) — `Status` / `StatusValue<T>` returned by every checked operation here.
- [`statusbar/sg14/README.md`](../statusbar/sg14/README.md) — vendored `inplace_vector` header used by the trait machinery.
