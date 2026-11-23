#! /bin/bash
# Standalone build helper for statusbar-core.
#
# core has no statusbar dependencies, so this is just a thin wrapper that
# configures with the bundled clang/libc++ toolchain, builds, and runs
# tests. Extra args are forwarded to `cmake` configure:
#
#   ./local-build.sh                  # configure + build + the unit tests
#   ./local-build.sh -DENABLE_ASAN=ON # forward cmake args
#
# IDE users: the configure line below (echoed by `set -x`) is exactly what
# you should give your IDE. The only required flag is the toolchain file —
# everything else is optional.

set -e
set -x
cmake -S . -B build -G Ninja --toolchain cmake/toolchain-clang.cmake "$@"
cmake --build build
# Everything is built, the functional tests among it, and the unit tests are
# run. The functional tests (real sockets, a real kernel) run when committing:
# core's run-functional-tests.sh, from the pre-commit hook, or by hand with
#   ctest --test-dir build -L functional
ctest --test-dir build -LE functional
