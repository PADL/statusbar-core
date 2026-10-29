[← back to module index](README.md)

# toml

A pure TOML v1.0 parser paired with a value tree (`Value` / `Array` /
`Table`) used throughout statusbar to carry typed configuration.

## Overview

The `toml` module does two things: it parses TOML text into an
in-memory tree, and it provides the tagged-union value type that
higher-level modules pass around. `args` binds CLI options to entries
in a `Table`; `config` reads, merges, and writes TOML files. Both
operate on the same value type defined here.

A `Value` is a discriminated union (null, string, integer, float,
boolean, datetime, array, table). Type checks use the `is_*`
predicates; extraction uses either the `as_*` accessors (return
`std::optional` / nullable pointer) or the `get_*` accessors (return
`StatusValue<T>` from the [`status`](STATUS_MODULE.md) module).
`Table` keeps a `std::map`-backed store with `get_path("a.b.c")` for
dotted lookup; `Array` exposes bounds-checked `at()` alongside
`operator[]`.

Parsing entry points are the free functions `parse()` (string input)
and `parse_file()` (filesystem input). Both return
`StatusValue<Table>` with errors expressed as `TomlError` codes
wrapped in `std::error_code`. For diagnostics, construct a `Parser`
directly and call `parse_document_public()`; on failure
`error_line()` and `error_column()` report the position.

The module is intentionally narrow: TOML syntax and TOML values,
nothing else. File search paths, environment overrides, and CLI
binding live in other modules.

## Key types

- `Value` — tagged-union holding any TOML value. Type queries via
  `type()` and `is_string()` / `is_integer()` / `is_float()` /
  `is_boolean()` / `is_datetime()` / `is_array()` / `is_table()`.
  Extract with `as_*()` (optional / nullable pointer) or `get_*()`
  (returns `StatusValue<T>` for chaining). `Value::Type` enumerates
  the cases.
- `Table` — ordered key/value map. `set()`, `contains()`, `get()`,
  `get_path()` (dotted lookup), `get_or_create_table()`, `erase()`,
  plus `Iterator` / `ConstIterator` for range-for traversal.
- `Array` — ordered list of `Value`. `push_back()`, `operator[]`,
  and bounds-checked `at()` returning `StatusValue<Value*>`.
- `DateTime` — ISO 8601 datetime, stored as a string (no calendar
  arithmetic).
- `Parser` — TOML v1.0 parser. Static `parse()` / `parse_file()`
  cover one-shot use; the explicit constructor plus
  `parse_document_public()` exposes `error_line()` / `error_column()`.
- `TomlError` — enumeration of parsing and lookup errors;
  `make_error_code()` adapts it to `std::error_code` via
  `TomlErrorCategory` (category name `"statusbar.toml"`).
- `parse_value_string()` — coerce one already-tokenised string into a
  typed `Value` (booleans, `0x` / `0o` / `0b` / decimal integers,
  floats, quoted/unquoted strings). Used by CLI override layers.
- `get_list<T>(table, key)` — pull a `std::vector<T>` from a key
  whether it holds an array or a single scalar; missing key yields
  empty, element-level type mismatches are skipped.

## Quick example

```cpp
#include "statusbar/toml/toml.hpp"

#include <print>

using namespace statusbar::toml;

int main()
{
    auto result = parse(
        "[server]\n"
        "host = \"localhost\"\n"
        "port = 8080\n");
    if (!result.has_value()) {
        std::println("parse failed: {}", result.error().message());
        return 1;
    }

    Table const& root = *result;
    auto host = root.get_path("server.host")->string_or("0.0.0.0");
    auto port = root.get_path("server.port")->integer_or(80);
    std::println("listening on {}:{}", host, port);
    return 0;
}
```

## Headers

- `statusbar/toml/toml.hpp` — module header; pulls in the three
  pieces below. Consumers should `#include` this.
- `statusbar/toml/toml_value.hpp` — `Value`, `Array`, `Table`,
  `DateTime`, `parse_value_string`, `get_list`.
- `statusbar/toml/toml_parser.hpp` — `Parser` class plus the free
  `parse()` / `parse_file()` functions.
- `statusbar/toml/toml_error.hpp` — `TomlError`, `TomlErrorCategory`,
  `make_error_code`.

## Dependencies

- **Statusbar modules:** [`status`](STATUS_MODULE.md) (the module
  returns `StatusValue<Table>` from parsing and `StatusValue<T>` from
  `get_*` accessors; `failure(TomlError::…)` produces the error half).
- **System / external:** `<variant>`, `<map>`, `<vector>`,
  `<optional>`, `<expected>`, `<memory>` (`unique_ptr` breaks the
  `Value`/`Array`/`Table` cycle), `<string>` / `<string_view>`,
  `<chrono>`, `<system_error>`, `<charconv>`, `<fstream>`.

## Notes & caveats

- `Value`, `Array`, and `Table` form a recursive structure. The
  containers store `std::unique_ptr<Value>` internally to break the
  cycle, so the copy constructor / copy-assign perform a deep copy;
  prefer moves when shuffling large trees.
- `Value::Type` is kept in sync with the underlying `std::variant`
  via `static_assert`s in `toml_value.hpp`. Don't reorder the
  variant alternatives without updating the enum.
- `as_float()` accepts integer values and returns them as `double`
  (handy for "either 5 or 5.0 is fine" config keys). `as_integer()`
  does *not* accept floats.
- `as_boolean()` is strict: a TOML integer `1` does not satisfy it.
- `Table::get_path()` walks dotted paths through nested tables; it
  returns `nullptr` at the first missing key or non-table interior.
- **A quoted key may contain a dot, and that dot is part of the key.**
  `[port."eth0.100"]` is one table named `eth0.100` inside `port` — not
  three tables — which matters because `eth0.100` is how a VLAN
  subinterface is named. The parser therefore carries a key path as
  segments, and `get_or_create_table()` / `get_path()` each have a
  `std::span<std::string const>` overload that takes one key per level.
  The `std::string_view` overloads split on every dot and so cannot
  address such a key: use the span form, or `get()` one level at a time.
  `Config`'s own dotted-string API (`get_integer("a.b.c")`, `set()`)
  keeps splitting by design. Writing quotes such keys back
  (`Config::to_toml_string()`), so a load/save round trip preserves the
  document. See BUG-004.
- A table header under an array of tables (`[s.x]` after `[[s]]`) attaches
  to the element `[[s]]` last appended, and `[[s.t]]` resolves `s` the same
  way. Only *headers* descend into an array: TOML does not allow a dotted
  key to extend one, so `s.y = 2` with `s` an array stays a
  `type_mismatch`, and the descent lives in the parser rather than in
  `Table::get_or_create_table()`. A header under an empty array
  (`s = []`, then `[s.x]`) has no element to attach to and fails. See
  BUG-006.
- `get_list<T>` skips elements whose type doesn't match `T`. Pre-
  validate the array shape if strict typing matters.
- `parse_value_string()` is for CLI overrides that aren't TOML
  documents; for full TOML text use `parse()`.

## Further reading

- [`config`](CONFIG_MODULE.md) — loads and merges TOML files into the
  `Table` consumed by the rest of the system.
- [`args`](ARGS_MODULE.md) — binds CLI options against entries in a
  `toml::Table`.
- [`status`](STATUS_MODULE.md) — `Status` / `StatusValue` returned by
  the parser and accessors.
