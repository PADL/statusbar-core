# statusbar-core

Foundational C++23 utilities — error handling, zero-copy buffers, IEEE and networking primitives, state machines, inter-thread communication, real-time scheduling, and terminal UI.

Version 1.3.0.

> Portions of this repository were developed with assistance from Claude,
> an AI model by Anthropic. All reference material used in this process
> came from my own original open source implementations of these
> utilities, with Claude assisting in refactoring and in validating
> conformance against the relevant IEEE 802, IP, and TSN definitions. All
> architectural decisions, final implementations, and engineering
> judgments are my own, and any errors are mine alone.

## Overview

`statusbar-core` is the foundation the rest of the statusbar stack is built
on — the one package with no `statusbar-*` dependencies of its own. It
collects a broad set of small, independently testable C++23 modules, each
compiled into its own static (or header-only) library so consumers link only
what they use.

The modules cluster into a few areas: data handling (zero-copy buffers,
columnar-binary and CSV output, TOML config, descriptive stats, bounded
containers), wire formats and I/O (IEEE 802 / IP / TSN structures, pcap
read-write, a `poll()`-driven socket reactor, raw-frame capture), and
concurrency and timing (lock-free inter-thread primitives, compile-time state
machines, hard-real-time scheduling and timers). Smaller utilities round it
out — CLI argument parsing, a terminal-UI helper, `std::expected`-based error
handling, overflow-checked arithmetic, and secure random bytes.

It targets developers building low-latency audio and networking systems, and
is written to that bar throughout: zero-copy and zero-heap data paths,
lock-free structures where they matter, and a mandatory Clang + libc++ C++23
toolchain with `-Werror`, sanitizers, coverage, and clang-tidy wired in.

## Quick start

```bash
# Local build + unit tests (Clang+libc++ toolchain is mandatory; applied automatically)
./local-build.sh && ctest --test-dir build

# Reproducible Debian .deb in ../deb-output/ (no dependencies)
./container-build.sh

# Sanitizers (mutually exclusive — use separate build dirs)
./local-build.sh -DENABLE_ASAN=ON     # AddressSanitizer
./local-build.sh -DENABLE_UBSAN=ON    # UndefinedBehaviorSanitizer
./local-build.sh -DENABLE_TSAN=ON     # ThreadSanitizer
```

No fuzz harnesses live in this package — see `statusbar-crypto` and `statusbar-avb` for those. Standalone build has no `statusbar-*` dependencies. See the sections below for details.

## Modules

- `args`
- `benchmark`
- `bpf`
- `buffer`
- `checksum`
- `colbin`
- `config`
- `container`
- `csv`
- `ieee`
- `ip`
- `itc`
- `net`
- `pcap`
- `realtime`
- `safe_arith`
- `secure_random`
- `sm`
- `stats`
- `status`
- `test`
- `toml`
- `tsn`
- `tui`

`statusbar/sg14/` vendors single-header utilities from the ISO C++
SG14 Low-Latency study group (`inplace_vector`, `inplace_function`) and
is not exported as its own CMake target — link consumers transitively.

Per-module overviews and topic guides live under [docs/](docs/README.md).

## Requirements

- A C++23 toolchain. The bundled toolchain file selects Clang with
  libc++ (`clang++ -stdlib=libc++`); GCC is not currently tested.
- CMake 3.31 or newer, Ninja.
- Linux or macOS host. The `bpf` module has Linux and macOS backends;
  everything else builds cross-platform.

## Building

This package has no statusbar dependencies — it builds on its own.

**Quick path:** run `./local-build.sh`. It configures, builds, and runs
ctest; extra arguments are forwarded to cmake configure
(`./local-build.sh -DENABLE_ASAN=ON`). The script echoes its final cmake
invocation via `set -x` so users configuring an IDE can copy the exact
flags into their CMake settings.

**Manual / IDE configuration.** The only required flag is the bundled
toolchain file (Clang + libc++, C++23, `-Werror`):

```
cmake -S . -B build -G Ninja --toolchain cmake/toolchain-clang.cmake
cmake --build build
ctest --test-dir build
```

## Benchmarks

Micro-benchmark executables ship with core:

| Binary | Source | CMake target |
|---|---|---|
| `statusbar-buffer-bench` | `statusbar/buffer/buffer_bench_tool.cpp` | `run-buffer-bench` |
| `statusbar-ieee-bench` | `statusbar/ieee/ieee_bench_tool.cpp` | `run-ieee-bench` |

Run a single bench through CMake (it'll rebuild if stale, then execute):

```
cmake --build build --target run-buffer-bench
cmake --build build --target run-ieee-bench
```

Or directly after a build:

```
./build/statusbar/buffer/statusbar-buffer-bench
./build/statusbar/ieee/statusbar-ieee-bench
```

Each bench prints mean / median / std-dev / min / max / p95 / p99 for every
named case.

## Coverage

Line/region coverage is wired through LLVM source-based profiling
(`-fprofile-instr-generate -fcoverage-mapping`). Enable via
`-DENABLE_COVERAGE=ON`, ideally in a separate build directory:

```
cmake -S . -B build-cov -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_COVERAGE=ON
```

Three CMake custom targets become available after configure (they
require `llvm-profdata` and `llvm-cov` on `PATH`):

| Target | What it does |
|---|---|
| `coverage-collect` | Builds and runs `statusbar_test`, merges `.profraw` into `combined.profdata` |
| `coverage-report` | Prints a text line-coverage report |
| `coverage-html`   | Generates an HTML report under `build-cov/coverage/html/` |

Each target depends on the previous, so a single invocation runs the
whole pipeline:

```
cmake --build build-cov --target coverage-html
xdg-open build-cov/coverage/html/index.html   # or `open` on macOS
```

`*_test.cpp` / `test.hpp` files are excluded by default. Override with
`-DSTATUSBAR_COVERAGE_IGNORE='<regex>'` if you want a different filter.

## Fuzz testing

This package ships no fuzz harnesses of its own.

## Sanitizers

`cmake/sanitizers.cmake` exposes three mutually exclusive sanitizer options.
Use a **separate build directory per sanitizer** — the instrumentation
flags change ABI / runtime expectations:

```
cmake -S . -B build-asan -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_ASAN=ON
cmake --build build-asan
ctest --test-dir build-asan
```

| Option | Adds | Use for |
|---|---|---|
| `-DENABLE_ASAN=ON`  | `-fsanitize=address`                       | Out-of-bounds, use-after-free, leaks |
| `-DENABLE_UBSAN=ON` | `-fsanitize=undefined -fno-sanitize-recover` | Integer overflow, alignment, UB |
| `-DENABLE_TSAN=ON`  | `-fsanitize=thread`                        | Data races (useful for SPSC + triple-buffer code) |

Enabling more than one of the three at configure time is a hard error.

## Static analysis (clang-tidy)

Two modes are available:

**In-compile** — `clang-tidy` runs as part of every translation unit:

```
cmake -S . -B build-tidy -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_CLANG_TIDY=ON
cmake --build build-tidy
```

Slow (every TU lints), but findings show up alongside the compile output.

**Separate aggregate run** — runs `clang-tidy` in parallel against the
existing build's `compile_commands.json`:

```
cmake --build build                         # normal build first
cmake --build build --target clang-tidy     # runs against build/compile_commands.json
```

The `clang-tidy` target uses `cmake/run-clang-tidy-all.sh` to fan out
across cores (8 jobs by default), skips `*_test.cpp` / `*_tool.cpp` /
`*_example.cpp` / `*_fuzzer.cpp`, and writes combined findings to
`build/clang-tidy-findings.txt`. The `.clang-tidy` config at the
submodule root drives check selection.

## Installing

```
cmake --install build --prefix <prefix>
```

## Packaging

A standalone build configures CPack — TGZ and ZIP archives on every
platform, plus DEB and (when `rpmbuild` is present) RPM on Linux.
Run `cpack` from the build directory:

```
cd build && cpack
```

This produces `statusbar-core` (runtime: tools) and `statusbar-core-dev` / `-devel` (headers, static libraries, CMake config).

### Reproducible Debian packages

`./container-build.sh` builds this package's `.deb`s inside a Debian
container — no local toolchain needed. Output lands in `../deb-output/`
(override with `DEB_OUTPUT`); the base image is configurable with
`DEBIAN_VERSION=...`. `statusbar-core` has no `statusbar-*` dependencies,
so the standalone command needs nothing else.

## License

MIT. See [LICENSE](LICENSE).
