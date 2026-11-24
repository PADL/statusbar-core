#! /bin/bash
# Standalone build helper for statusbar-core.
#
# core has no statusbar dependencies, so this is just a thin wrapper that
# configures with the bundled clang/libc++ toolchain, builds, and runs
# tests. Extra args are forwarded to `cmake` configure:
#
#   ./local-build.sh                  # configure + build + unit tests + functional tests
#   STATUSBAR_SKIP_FUNCTIONAL_TESTS=1 ./local-build.sh   # without the functional tests
#   ./local-build.sh -DENABLE_ASAN=ON # forward cmake args
#
# IDE users: the configure line below (echoed by `set -x`) is exactly what
# you should give your IDE. The only required flag is the toolchain file —
# everything else is optional.

set -e
set -x
cmake -S . -B build -G Ninja --toolchain cmake/toolchain-clang.cmake "$@"
cmake --build build
# Two test runs, kept apart. The unit tests first: they test logic, open no
# socket and wait for nothing.
ctest --test-dir build -LE functional
# Then the functional tests (real sockets, a real kernel). They count the same:
# one that fails fails the build. STATUSBAR_SKIP_FUNCTIONAL_TESTS=1 leaves them
# out, for a host that cannot run them; the unit tests above still run.
if [ "${STATUSBAR_SKIP_FUNCTIONAL_TESTS:-0}" = "1" ]; then
    set +x
    echo "local-build: STATUSBAR_SKIP_FUNCTIONAL_TESTS=1, the functional tests are not run" >&2
else
    ctest --test-dir build -L functional
fi
