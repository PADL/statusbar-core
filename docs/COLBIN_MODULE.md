[← back to module index](README.md)

# colbin

Append-only, mmap-backed columnar binary file format for fixed-width
row streams (telemetry, measurement logs, sample records).

## Overview

The `colbin` module defines a small on-disk format — magic +
endian-marker + version + schema text + fixed-size rows — and provides
a `Writer` that appends rows via `mmap` (no per-row syscalls) plus a
`Reader` that exposes a zero-copy view over committed rows.

A file is described by a list of `ColumnSpec` (name + `TypeCode`).
`resolve_schema()` lays those columns out into a packed row using
natural per-field alignment with `np.dtype(..., align=True)` semantics:
each field is bumped to its own alignment and the row size is rounded
up to the largest field's alignment so consecutive rows stay aligned.
The same layout is round-tripped through `serialize_schema()` /
`parse_schema()` for the on-disk schema text.

The writer publishes progress by calling `commit()`, which stores the
current row count into the header's `committed_rows` field. A `Reader`
opened concurrently sees rows up to the writer's most recent commit;
rows written but not yet committed are not visible. The mmap region
is grown geometrically (default factor 2, capped at
`WriterConfig::max_capacity_bytes`) via `ftruncate` plus
`mremap(MREMAP_MAYMOVE)` on Linux, or `munmap` + a fresh `mmap` on
Darwin/BSD, so `write_row` stays free of syscalls in the common case.

Errors come back as `StatusValue<T>` carrying a `ColbinError` mapped
through `colbin_error_category()` — bad magic, endian mismatch,
unsupported version, truncated header, schema problems, I/O failures,
and capacity-exceeded growth attempts.

## Key types

- `TypeCode` — on-disk type tag (`i8`/`u8`/`i16`/`u16`/`i32`/`u32`/`i64`/`u64`/`f32`/`f64`/`b8`). Numeric values are stable across format versions.
- `ColumnSpec` — schema entry: `name` plus `TypeCode`.
- `ResolvedColumn` / `ResolvedSchema` — a column list resolved against the row's byte layout (per-field `offset`/`size`, plus `row_size` and `row_align`).
- `Writer` — append-only mmap writer. `create()` opens (or re-opens for append), `write_row()` appends a `row_size`-byte record on the hot path, `commit()` publishes the row count into the header, `sync()` issues an optional `msync`.
- `WriterConfig` — `initial_capacity_bytes`, `max_capacity_bytes`, `grow_factor`.
- `Reader` — read-only mmap view. `open()` validates the header; `row(index)`, `all_rows()`, `row_count()`, `row_size()`, and `schema()` expose the data.
- `ColbinError` — error enum routed through `colbin_error_category()` / `make_error_code()` so it slots into `std::error_code`.

## Quick example

```cpp
#include "statusbar/colbin/colbin_reader.hpp"
#include "statusbar/colbin/colbin_writer.hpp"

namespace cb = statusbar::colbin;

int main()
{
    std::vector<cb::ColumnSpec> cols = {
        {"sequence", cb::TypeCode::u32},
        {"latency_ns", cb::TypeCode::i64},
    };
    auto w_or = cb::Writer::create("samples.colbin", cols);
    if (!w_or) return 1;
    auto w = std::move(*w_or);
    struct Row { uint32_t sequence; uint32_t pad; int64_t latency_ns; } row{};
    row.sequence = 42;
    row.latency_ns = 1'000'000;
    if (auto s = w.write_row({reinterpret_cast<uint8_t const*>(&row), sizeof(row)}); !s) return 1;
    if (auto s = w.commit(); !s) return 1;

    auto r_or = cb::Reader::open("samples.colbin");
    if (!r_or) return 1;
    return r_or->row_count() == 1 ? 0 : 1;
}
```

## Headers

- `statusbar/colbin/colbin.hpp` — format constants (`MAGIC`, `ENDIAN_MARKER`, `FORMAT_VERSION`, `HEADER_PREAMBLE_BYTES`), `TypeCode`, schema types, and the `resolve_schema` / `serialize_schema` / `parse_schema` helpers.
- `statusbar/colbin/colbin_writer.hpp` — `Writer` and `WriterConfig`.
- `statusbar/colbin/colbin_reader.hpp` — `Reader`.
- `statusbar/colbin/colbin_error.hpp` — `ColbinError`, `ColbinErrorCategory`, `make_error_code`.

## Dependencies

- **Statusbar modules:** [`status`](STATUS_MODULE.md) (`Writer::create` / `Reader::open` / `write_row` / `commit` / `sync` return `Status` or `StatusValue<T>`; `ColbinError` is exposed through `std::error_code`).
- **System / external:** POSIX `mmap` / `ftruncate` / `msync` for the writer's hot path, with `mremap(MREMAP_MAYMOVE)` on Linux and `munmap` + a fresh `mmap` on Darwin/BSD for growth; `<filesystem>`, `<span>`, `<system_error>` from the C++20/23 standard library.

## Notes & caveats

- `Writer` growth is Linux-optimized via `mremap(MREMAP_MAYMOVE)`; on Darwin/BSD, growth falls back to `munmap` + a fresh `mmap`. Either way growth can move the base address (`MREMAP_MAYMOVE` is exactly the permission to do so), invalidating any in-flight `std::span` views into the mapped buffer — don't hold spans into the writer's buffer across `write_row`/`commit` calls on any platform.
- `Writer` is movable but not copyable. `Reader` is also movable but not copyable.
- Rows are *not* visible to a `Reader` until `commit()` runs. The intended cadence is roughly once per second from the writer thread; pick a cadence that matches your durability and freshness needs.
- `write_row` requires the input span to be exactly `row_size()` bytes. The hot path is a bounds check plus a `memcpy`; there is no per-field conversion. Lay out your row struct to match `resolve_schema()`'s output (use `#pragma pack` plus explicit padding if needed — see `colbin_test.cpp`'s `SampleRow`).
- Re-opening an existing file with `Writer::create` appends from `committed_rows`. The schema you pass must round-trip to the same on-disk text and same row size; otherwise you get `invalid_schema` or `schema_row_size_mismatch`.
- `endian_mismatch` is a hard failure — `colbin` files are not portable across byte orders. The `ENDIAN_MARKER` check happens before any other parsing.
- The initial mmap size is `max(WriterConfig::initial_capacity_bytes, header + one row)` rounded up to a system page boundary, so even a tiny `initial_capacity_bytes` always leaves room for at least one row. Growing past `max_capacity_bytes` yields `capacity_exceeded`; an `mremap`/`mmap` failure during growth surfaces as `grow_failed`.
- `sync()` issues `msync(MS_ASYNC)` and is optional — the kernel will write back dirty pages on its own schedule.
- The `Reader::row(i)` span aliases the mmap region; do not retain it past the `Reader`'s lifetime.

## Further reading

- [`status`](STATUS_MODULE.md) — `Status` / `StatusValue<T>` returned from `Writer` and `Reader` entry points.
