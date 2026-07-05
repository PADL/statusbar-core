[← back to docs index](README.md)

# Build system

The `cmake/` directory holds seven reusable `.cmake` scripts plus one
package-specific template. The scripts — `toolchain-clang.cmake`,
`toolchain-clang-aarch64.cmake` (cross-compile variant: same Clang +
libc++ setup targeting aarch64-linux-gnu with multiarch
`find_root_path` / `PKG_CONFIG_LIBDIR` handling), `module.cmake`,
`sanitizers.cmake`, `coverage.cmake`, `fuzzing.cmake`, and
`clang_tidy.cmake` — are reusable build scripts.
`statusbar-coreConfig.cmake.in` is this package's `find_package`
template. Several helper shell scripts (`coverage-*.sh`,
`run-clang-tidy*.sh`, `fuzz-*.sh`) back the custom targets those
scripts register.

`toolchain-clang.cmake` is mandatory: it pins Clang + libc++ and C++23.
A build with the default compiler or stdlib will not work. The
toolchain file itself transitively `include()`s the sanitizer,
coverage, and fuzzing scripts, so passing
`--toolchain cmake/toolchain-clang.cmake` is all that is needed to wire
them up.

The aggregate-build mechanics (`STATUSBAR_AGGREGATE_BUILD`,
`find_package` redirects, the unified `statusbar_test` binary) are
summarised in the "Aggregate-build interaction" section at the bottom
of this file. The rest of this document is the reference for what the
cmake scripts themselves provide.

## `toolchain-clang.cmake`

The mandatory toolchain file. Pass it as
`--toolchain cmake/toolchain-clang.cmake` (or set
`CMAKE_TOOLCHAIN_FILE`). Guarded against re-processing via
`_STATUSBAR_TOOLCHAIN_LOADED`.

**Compiler resolution.** On macOS, the LLVM prefix comes from the
`LLVM_PATH` environment variable. On Linux, the script runs
`readlink -f /usr/bin/clang` and walks two directories up to find the
LLVM prefix (e.g. `/usr/bin/clang` → `/usr/lib/llvm-19/bin/clang` →
prefix `/usr/lib/llvm-19`). `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER`
are then set to `<prefix>/bin/clang` and `<prefix>/bin/clang++`.

**ccache.** Auto-detected via `find_program`. If present, set as
`CMAKE_C_COMPILER_LAUNCHER` and `CMAKE_CXX_COMPILER_LAUNCHER` — speeds
up rebuilds across build variants.

**Language standard.** C++23 with extensions off:
`CMAKE_CXX_STANDARD=23`, `CMAKE_CXX_STANDARD_REQUIRED=ON`,
`CMAKE_CXX_EXTENSIONS=OFF`.

**Module scanning disabled.** `CMAKE_CXX_SCAN_FOR_MODULES=OFF`. The
project uses no C++20 modules (no `import`, no `export module`, no
`.cppm`/`.ixx`). With CMake 3.31+ the scanner runs on every C++20+
translation unit by default and emits empty `@<tu>.cpp.o.modmap`
response files into `compile_commands.json`. clangd 22.x mis-parses
these and reports spurious *different definitions in different
modules* errors on libc++ headers like `<format>`. Re-enable per-target
if an actual module is ever introduced.

**Build type.** Defaults to `Debug` if not set. The cache entry's
valid strings are `Debug`, `Release`, `RelWithDebInfo`, `MinSizeRel`.

**Flags.** `-stdlib=libc++ -fstack-protector-strong` are appended to
`CMAKE_CXX_FLAGS`. `-Wno-c23-extensions` is also added so C23 `#embed`
works in C++23 mode (used to embed BPF object files). Per-config:

| Build type       | Flags                  |
|------------------|------------------------|
| `Debug`          | `-g -O0 -DDEBUG`       |
| `Release`        | `-O3 -DNDEBUG`         |
| `RelWithDebInfo` | `-O2 -g -DNDEBUG`      |
| `MinSizeRel`     | `-Os -DNDEBUG`         |

`STATUSBAR_STDLIB` is cached as `"libc++"` for reference; no exported
config file currently consumes it, so downstream builds get no
automatic libc++/libstdc++ ABI-mismatch guard.

**Platform branches.**

- *macOS:* `CMAKE_OSX_DEPLOYMENT_TARGET=14.0`. If `CMAKE_OSX_SYSROOT`
  is unset, the script runs `xcrun --show-sdk-path` and adds the
  result via `-isysroot` to `CMAKE_CXX_FLAGS`.
- *Linux:* `--rtlib=compiler-rt` is appended to
  `CMAKE_EXE_LINKER_FLAGS`. Debian's default runtime (libgcc) lacks
  `__muloti4`, needed for UBSan-instrumented `__int128` arithmetic on
  aarch64.

Architecture-specific SIMD flags are *not* set here. They live in each
package's root `CMakeLists.txt` after `project()`, where
`CMAKE_SYSTEM_PROCESSOR` is available.

**Options provided by this file.**

| Option                       | Default | Effect                                       |
|------------------------------|---------|----------------------------------------------|
| `ENABLE_CLANG_TIDY`          | `OFF`   | Sets `CMAKE_CXX_CLANG_TIDY` to clang-tidy.   |
| `ENABLE_WARNINGS_AS_ERRORS`  | `ON`    | Adds `-Werror` to `CMAKE_CXX_FLAGS`.         |

**Transitive includes.** At the bottom, `toolchain-clang.cmake`
includes `sanitizers.cmake`, `coverage.cmake`, `fuzzing.cmake`, and
`clang_tidy.cmake`. Their options become available without any extra
`include()` from the project.

## `module.cmake` — `statusbar_add_module()`

The helper every per-module `CMakeLists.txt` calls to declare its
library. Signature:

```cmake
statusbar_add_module(
  NAME    <module-name>             # required; target becomes statusbar-<NAME>
  SOURCES <file>...                 # .cpp files; omit when INTERFACE is set
  DEPS    <target>...               # public deps (PUBLIC link, propagated)
  PRIVATE_DEPS <target>...          # private deps (PRIVATE link, not propagated)
  INTERFACE                         # header-only flag — INTERFACE library
  TESTS   <file>...                 # test .cpp files; pushed onto a global property
)
```

Any other keyword is a configure-time `FATAL_ERROR` (install
registration happens unconditionally, so there is no `INSTALL` flag).
The target name is `statusbar-<NAME>`. An alias `statusbar::<NAME>` is
also created so consumers can write either form.

For non-`INTERFACE` modules, a static library is created with C++23 as
a `PUBLIC` compile feature, extensions off, and an include directory
of `PROJECT_SOURCE_DIR` at build time / `CMAKE_INSTALL_INCLUDEDIR` at
install time (so consumers include as `statusbar/<module>/...`).
`DEPS` link PUBLIC; `PRIVATE_DEPS` link PRIVATE.

For `INTERFACE` modules, an INTERFACE library is created with the same
include layout. `PRIVATE_DEPS` does not apply. The target is still
appended to `STATUSBAR_INSTALL_TARGETS` for export compatibility.

`TESTS` are resolved to absolute paths (relative to
`CMAKE_CURRENT_LIST_DIR`) and appended to the global property
`STATUSBAR_TEST_FILES`. The package-level CMakeLists reads this property
and feeds it to `create_test_sourcelist`, producing the single
`statusbar_test` executable plus one ctest entry per file (named like
`statusbar/<module>/<file>_test`) plus a `statusbar_all_test` entry
that runs them all. Under an aggregate build, an outer project reads
the accumulated property after every package has populated it.

`STATUSBAR_INSTALL_TARGETS` is appended to unconditionally; the
package-level CMakeLists reads it for its install set. Under an
aggregate build, an outer project reads the accumulated set instead.

**Worked example.** From `core/statusbar/buffer/CMakeLists.txt`:

```cmake
statusbar_add_module(
  NAME
  buffer
  SOURCES
  buffer_error.cpp
  DEPS
  statusbar-status
  TESTS
  buffer_basic_test.cpp
  buffer_builder_test.cpp
  buffer_compiled_test.cpp
  buffer_deserializer_test.cpp
  buffer_protocol_test.cpp
  buffer_traits_test.cpp)
```

The result: a static `statusbar-buffer` library aliased as
`statusbar::buffer`, linking publicly against `statusbar-status`, with
six test files registered into `STATUSBAR_TEST_FILES`.

See "Aggregate-build interaction" below for the contract an
aggregate-build consumer uses to read `STATUSBAR_TEST_FILES` and
`STATUSBAR_INSTALL_TARGETS`.

## `sanitizers.cmake`

Options for Clang sanitizers. Pulled in by the toolchain file.

| Option         | Default | Adds to `CMAKE_CXX_FLAGS`                                 | Adds to linker          |
|----------------|---------|-----------------------------------------------------------|-------------------------|
| `ENABLE_ASAN`  | `OFF`   | `-fsanitize=address -fno-omit-frame-pointer -g`           | `-fsanitize=address`    |
| `ENABLE_UBSAN` | `OFF`   | `-fsanitize=undefined -fno-sanitize-recover=undefined -g` | `-fsanitize=undefined`  |
| `ENABLE_TSAN`  | `OFF`   | `-fsanitize=thread -fno-omit-frame-pointer -g`            | `-fsanitize=thread`     |

All three sanitizers propagate to `CMAKE_EXE_LINKER_FLAGS`,
`CMAKE_SHARED_LINKER_FLAGS`, and `CMAKE_MODULE_LINKER_FLAGS` so any
linked artifact picks up the instrumented runtime.

Enabling more than one at once is a `FATAL_ERROR`: *"ASAN, UBSAN, and
TSAN are mutually exclusive. Use separate build directories."*
Configure separate build dirs (e.g. `build-asan/`, `build-ubsan/`,
`build-tsan/`) instead.

## `coverage.cmake`

LLVM source-based coverage. Pulled in by the toolchain file.

| Option            | Default | Effect                                                              |
|-------------------|---------|---------------------------------------------------------------------|
| `ENABLE_COVERAGE` | `OFF`   | Adds `-fprofile-instr-generate -fcoverage-mapping` to compile/link. |

Running an instrumented binary writes `.profraw` files. When
`ENABLE_COVERAGE` is on (and `llvm-profdata` / `llvm-cov` are found),
the script registers three chained custom targets backed by
`cmake/coverage-collect.sh`, `coverage-report.sh`, and
`coverage-html.sh`:

| Target             | What it does                                                            |
|--------------------|-------------------------------------------------------------------------|
| `coverage-collect` | Builds and runs `statusbar_test`, merges `.profraw` into `combined.profdata` |
| `coverage-report`  | Prints a text line-coverage report                                      |
| `coverage-html`    | Generates an HTML report under `<build>/coverage/html/`                 |

Each depends on the previous, so `cmake --build build-cov --target
coverage-html` runs the whole pipeline (see the README's Coverage
section for the full walkthrough).

## `fuzzing.cmake`

libFuzzer support via Clang's built-in `-fsanitize=fuzzer`. Pulled in
by the toolchain file.

| Option           | Default | Effect                                                           |
|------------------|---------|------------------------------------------------------------------|
| `ENABLE_FUZZING` | `OFF`   | Defines `HAS_LIBFUZZER=1` and exports the cache variables below. |

When enabled, the script sets the following internal cache variables
for fuzzer-target CMake code to read:

| Variable                          | Value                                              |
|-----------------------------------|----------------------------------------------------|
| `HAS_LIBFUZZER`                   | `TRUE`                                             |
| `TOOLCHAIN_USE_FSANITIZE_FUZZER`  | `TRUE`                                             |
| `FUZZER_EXTRA_LINK_OPTIONS`       | `LINKER:-lstdc++` on Linux, empty on macOS         |

The Linux `LINKER:-lstdc++` workaround exists because Debian and
Ubuntu ship `libclang_rt.fuzzer` built against libstdc++, but the
project uses libc++. Fuzzer targets must link libstdc++ to satisfy the
runtime's internal symbols, and the clang driver strips `-lstdc++`
when `-stdlib=libc++` is active — so the flag must be passed directly
through the linker.

`-fsanitize=fuzzer` itself is always available with Clang and is
compatible with `-stdlib=libc++`, so no separate libFuzzer detection
is needed.

## `statusbar-coreConfig.cmake.in`

This package's `find_package` template.

CMake's package-export machinery substitutes `@PACKAGE_INIT@` and
other `@var@` placeholders to produce the installed
`statusbar-coreConfig.cmake`, which is what downstream
`find_package(statusbar-core)` consumes in standalone builds.

Aggregate builds bypass this file: the outer project writes empty
redirect configs into `CMAKE_FIND_PACKAGE_REDIRECTS_DIR` so each
package's in-tree `find_package(statusbar-<dep> REQUIRED)` call
resolves without searching the system.

## Aggregate-build interaction

The cmake scripts above are the *producer* side. An outer CMake project
that consumes this package via `add_subdirectory()` can opt into an
aggregate build by setting `STATUSBAR_AGGREGATE_BUILD=ON` before adding
any package. In that mode this package skips its own package INTERFACE
target, install rules, CPack config, and aggregate test executable —
the outer project owns those and stitches together a single combined
build covering every aggregated package.

The contract is small:

- **`STATUSBAR_AGGREGATE_BUILD`** — when `ON`, per-package CMake skips
  the code blocks guarded by `if(NOT STATUSBAR_AGGREGATE_BUILD)`.
- **`STATUSBAR_TEST_FILES`** (GLOBAL property, populated by
  `statusbar_add_module(... TESTS ...)`) — the outer project reads it,
  feeds it to `create_test_sourcelist`, and builds one `statusbar_test`
  executable with one `ctest` entry per file.
- **`STATUSBAR_INSTALL_TARGETS`** (GLOBAL property, populated by every
  `statusbar_add_module()` call) — the outer project reads it to
  construct the unified install set for `cmake --install`.
