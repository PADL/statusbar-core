[← back to module index](README.md)

# test

Lightweight self-registering unit-test framework used by every other
statusbar module's `*_test.cpp` files.

## Overview

The `test` module is intentionally tiny: one header of macros, one cpp
with the registry implementation, and a standalone `main()` for Buck2
binaries. There is no fluent DSL, no fixtures, no parameterised tests —
just `TEST(group, name) { ... }` blocks that self-register at
static-initialisation time and a handful of `EXPECT_*` assertion macros
that throw `TestFailedException` on failure.

A test binary is produced one of two ways:

- **Single-section runner** — the test file ends with `TEST_MAIN(path,
  section)`, which expands to the entry function that CMake's
  `create_test_sourcelist` expects. The macro asserts at compile time
  that `section` matches `__FILE_NAME__` minus `.cpp`, then calls
  `TestRegister::run_section(__FILE_NAME__)` so only tests defined in
  that translation unit run.
- **Multi-file runner** — link several `*_test.cpp` files plus
  `test_main.cpp`; its `main()` calls `TestRegister::run_all()` and every
  registered test runs in registration order.

Every assertion failure prints a one-line diagnostic (filename, line,
expression text, and — for arithmetic types — the actual values) and
throws `TestFailedException`. `TestRegister::run()` catches *any*
exception and counts the test as failed. A final `print_report()`
summarises registered / ran / passed / failed counts.

The framework has no dependencies on the rest of the statusbar codebase,
which is what lets it sit at the bottom of the dependency graph.

## Key types

All types live in `namespace statusbar::test`. Test files normally
reach them only through the macros (which expand to fully-qualified
names), but a custom main may name them directly as
`::statusbar::test::TestRegister::run_section(...)` etc.

- `statusbar::test::TestInfo` — POD describing one test: `section`
  (auto-filled with `__FILE_NAME__`), `group`, `name`, and a
  `void(*)()` function pointer.
- `statusbar::test::TestFailedException` — empty `std::exception`
  subclass thrown by the `EXPECT_*` macros to signal failure.
- `statusbar::test::TestRegister` — owns the global
  `std::vector<TestInfo>`; each `TEST(...)` block creates one
  `static TestRegister` whose constructor appends to the vector. Entry
  points: `run_all()`, `run_section()`, `run()`, `print_report()`,
  plus counter statics (`g_registered_test_count`, `g_test_passed`,
  `g_test_failed`, ...).
- `statusbar::test::section_matches(sec, file)` — `constexpr` helper
  that strips a trailing `.cpp` from either side before comparing;
  used at runtime to filter tests and at compile time by
  `TEST_MAIN`'s `static_assert`.
- `TEST(group, name)` — declares and self-registers a test function.
- `EXPECT_TRUE(expr)` / `EXPECT_FALSE(expr)` — boolean assertions.
- `EXPECT_EQ(a, b)` / `EXPECT_NE(a, b)` — equality assertions; if both
  sides are arithmetic, the failure diagnostic prints the actual values.
- `TEST_MAIN(path_name, section)` — defines the `int path_name##_##section(int, char**)`
  entry function that runs only tests from this translation unit.
- `do_not_optimize(value)` (`test_util.hpp`) — inline-asm barrier to
  prevent the compiler from eliding a benchmark result.
- `hex_to_bytes<N>(hex)` (`test_util.hpp`) — turn a `2*N`-char hex
  string into a `std::array<uint8_t, N>` for test fixtures.

## Quick example

Adapted from `core/statusbar/status/status_test.cpp` — a typical
`*_test.cpp` looks like this:

```cpp
#include "statusbar/status/status.hpp"
#include "statusbar/test/test.hpp"

#include <system_error>

using namespace statusbar;

TEST(statusbar_status, status_success_construction)
{
    Status s = success();
    EXPECT_TRUE(s);
    EXPECT_TRUE(s.has_value());
}

TEST(statusbar_status, status_failure_construction_errc)
{
    Status s = failure(std::errc::permission_denied);
    EXPECT_FALSE(s);
    EXPECT_EQ(s.error(), std::errc::permission_denied);
}

TEST_MAIN(statusbar_status, status_test)
```

The file's name must be `status_test.cpp` for the `TEST_MAIN` static
assertion to pass.

## Headers

- `statusbar/test/test.hpp` — module header. Defines
  `statusbar::test::TestInfo`, `statusbar::test::TestFailedException`,
  `statusbar::test::TestRegister`, `statusbar::test::section_matches`,
  and the `TEST` / `EXPECT_*` / `TEST_MAIN` macros (these macros are
  declared at global scope and expand to fully-qualified names). This
  is what test files `#include`.
- `statusbar/test/test_util.hpp` — optional `do_not_optimize` and
  `hex_to_bytes` helpers; include on demand.
- `statusbar/test/test_data.hpp` — `functional_test_data()`: where a
  functional test finds a data file, on the build machine or a target.

## Dependencies

- **Statusbar modules:** none. The framework is the root of the
  dependency graph so every other module's tests can link it.
- **System / external:** `<exception>`, `<print>`, `<stdexcept>`,
  `<string>`, `<string_view>`, `<type_traits>`, `<vector>` from the
  C++23 standard library, plus `<array>` and `<cstdint>` for the
  utilities in `test_util.hpp`.

## Notes & caveats

- **Two kinds of test, kept apart.** A module's `TESTS` are unit tests:
  they test logic, told its inputs and its time. They open no socket,
  sleep for nothing and assert nothing about how long anything took, so a
  loaded build host cannot fail them. A module's `FUNCTIONAL_TESTS`
  exercise the real thing end to end (real sockets, a real kernel, real
  waits). They build into a binary of their own (CMake target
  `statusbar_functional_test`, file `statusbar-<pkg>-functional-test`),
  and each carries the ctest label
  `functional`: `ctest -LE functional` runs the unit tests alone,
  `ctest -L functional` the rest. When logic is tangled with I/O, split
  it out (as `http::HttpEngine` is split from `HttpServer`, and
  `realtime::TimerSchedule` from `Timer`) and unit-test the logic on a
  told stand-in such as `net::ToldConnectionTransport`.
- **Who runs which.** A build (`local-build.sh`, and so CI) builds
  everything and makes two test runs, kept apart: the unit tests,
  `ctest -LE functional`, then the functional tests,
  `ctest -L functional`. Both count: a failure in either fails the build.
  `STATUSBAR_SKIP_FUNCTIONAL_TESTS=1` leaves the functional run out, for
  a host that cannot run them, and the unit tests still run. The
  umbrella's test presets come in pairs for the same reason: `default`
  is the unit tests and `default-functional` the functional ones.
- **Before a commit, if you want it.** The pre-commit hook checks
  formatting and the block rule. The umbrella's
  `install-hooks.sh --functional` adds a
  third step, core's `run-functional-tests.sh`, which builds the repo's
  configured build directory and runs `ctest -L functional` when the
  staged change touches C++ or CMake. It is off unless asked for.
  Without a configured build directory it says so and lets the commit
  through; `STATUSBAR_SKIP_FUNCTIONAL_TESTS=1` skips it for one commit;
  `sh run-functional-tests.sh --always` runs it by hand, which is also
  the way in a core checkout on its own (it has no hook installer). The
  script reads `STATUSBAR_BUILD_DIR` (the build directory),
  `STATUSBAR_FUNCTIONAL_TESTS_TIMEOUT` (seconds per test, 300) and
  `STATUSBAR_FUNCTIONAL_TESTS_STRICT`.
- **Functional tests on a target.** Each package's development package
  (`statusbar-<pkg>-dev`) installs its functional tests as
  `statusbar-<pkg>-functional-test`: `-A` runs all of them, a ctest name
  (`statusbar/<module>/<file without .cpp>`) one file. An `-A` run exits
  0 whatever the tests did, so judge it by its output (no `FAIL: ` line,
  and `All tests finished.` at the end); a single named file exits
  non-zero when it fails. A test that reads
  a data file from beside its source names it in its module's
  `FUNCTIONAL_TEST_DATA` and finds it with
  `statusbar::test::functional_test_data(__FILE__, "testdata/x.bin")`
  (`statusbar/test/test_data.hpp`): beside the source where there is a
  source tree, else under the installed data directory, which the
  environment variable `STATUSBAR_FUNCTIONAL_TEST_DATA_DIR` overrides.
- **This is the test framework every other statusbar module uses.** It
  has no `*_test.cpp` of its own — exercising the framework is what the
  rest of the codebase does. Treat changes here as cross-cutting: a
  regression breaks every module's test build.
- `TestRegister::tests` is filled by static constructors; ordering
  across translation units is unspecified, so don't write tests that
  depend on each other's side effects.
- `EXPECT_*` macros throw, so they must run on a path the framework
  catches — inside the function defined by `TEST(...)`.
- `EXPECT_EQ` / `EXPECT_NE` print operand values only when both sides
  are `std::is_arithmetic_v`; for other types you get the expression
  text and source location but not runtime values.
- `TestRegister::run()` catches `...`, so any uncaught exception type
  (not just `TestFailedException`) marks the test failed.
- Counters reset on `run_section()` but not on `run_all()`; calling
  `run_all()` twice accumulates the report numbers.
- `TEST_MAIN` is required for CMake `create_test_sourcelist` targets;
  standalone Buck2 `cxx_test` binaries get their entry point from
  `test_main.cpp` (a hook for downstream non-CMake build systems;
  intentionally not referenced from this project's CMake) and must not
  define `TEST_MAIN`.

## Further reading

- Any `*_test.cpp` in the repository — for example
  [`core/statusbar/status/status_test.cpp`](../statusbar/status/status_test.cpp)
  — is a concrete usage example.
