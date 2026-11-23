#! /bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Run a repository's functional tests before a commit. What the pre-commit
# hook runs when it was installed with `install-hooks.sh --functional`.
#
#   default:    build, then run the functional tests, when the staged change
#               touches C++ or CMake
#   --always:   the same whatever is staged (a run by hand)
#
# Unit tests test logic: they open no socket and wait for nothing. Functional
# tests exercise the real thing end to end (real sockets, a real kernel, real
# waits). A build runs both, the unit tests first (local-build.sh, and so CI),
# and a failure of either fails it. This script is for whoever wants the
# functional tests run on their own machine as well, before the commit is
# made: the hook step is optional and off unless asked for.
#
# They are the tests a module lists as FUNCTIONAL_TESTS, plus any ctest entry
# labelled "functional": this runs `ctest -L functional`.
#
# The repository tested is the one the caller stands in (a pre-commit hook
# runs at its repo's root), not the one this script lives in: core's copy
# serves every sibling package. The build directory is STATUSBAR_BUILD_DIR,
# else the repository's own build/, else the build/ of an umbrella it sits in,
# where the functional tests of every package run together.
#
# What is built and tested is the working tree, which is what the build
# directory knows; with a partly staged change that is more than the commit.
#
# Exits 0 without running anything when there is no configured build
# directory, or it has no functional tests: a check that cannot run must not
# block a commit, but it says so. STATUSBAR_FUNCTIONAL_TESTS_STRICT=1 makes
# that a failure. STATUSBAR_SKIP_FUNCTIONAL_TESTS=1 skips the run for one
# commit, and says so too.

set -e

STRICT="${STATUSBAR_FUNCTIONAL_TESTS_STRICT:-0}"
TIMEOUT="${STATUSBAR_FUNCTIONAL_TESTS_TIMEOUT:-300}"

always=0
case "${1:-}" in
    --always) always=1 ;;
    "") ;;
    *)
        echo "usage: $0 [--always]" >&2
        exit 2
        ;;
esac

if [ "${STATUSBAR_SKIP_FUNCTIONAL_TESTS:-0}" = "1" ]; then
    echo "run-functional-tests: STATUSBAR_SKIP_FUNCTIONAL_TESTS=1 — skipping" >&2
    exit 0
fi

# The repository being tested: the caller's, falling back to this script's.
REPO=$(git rev-parse --show-toplevel 2>/dev/null || true)
[ -n "$REPO" ] || REPO="$(cd "$(dirname "$0")" && pwd)"

unavailable() {
    if [ "$STRICT" = "1" ]; then
        echo "run-functional-tests: $1" >&2
        exit 1
    fi
    echo "run-functional-tests: $1 — skipping" >&2
    exit 0
}

# A change that touches no code cannot change what these tests see.
if [ "$always" = "0" ]; then
    touched=$(git -C "$REPO" diff --cached --name-only --diff-filter=ACMR -- \
        '*.cpp' '*.hpp' '*.h' '*.c' '*.cmake' 'CMakeLists.txt' '*/CMakeLists.txt')
    [ -n "$touched" ] || exit 0
fi

BUILD_DIR="${STATUSBAR_BUILD_DIR:-}"
if [ -z "$BUILD_DIR" ]; then
    for candidate in "$REPO/build" "$REPO/../build"; do
        if [ -f "$candidate/CMakeCache.txt" ]; then
            BUILD_DIR="$candidate"
            break
        fi
    done
fi
[ -n "$BUILD_DIR" ] || unavailable "no configured build directory under $REPO"
[ -f "$BUILD_DIR/CMakeCache.txt" ] || unavailable "no CMakeCache.txt in $BUILD_DIR"
command -v ctest >/dev/null 2>&1 || unavailable "no ctest on PATH"

# Up to date first: a stale binary would test yesterday's code.
echo "run-functional-tests: building $BUILD_DIR" >&2
if ! cmake --build "$BUILD_DIR" >"$BUILD_DIR/functional-tests-build.log" 2>&1; then
    tail -n 40 "$BUILD_DIR/functional-tests-build.log" >&2
    echo "run-functional-tests: the build failed (log: $BUILD_DIR/functional-tests-build.log)" >&2
    exit 1
fi

count=$(ctest --test-dir "$BUILD_DIR" -N -L functional 2>/dev/null | sed -n 's/^Total Tests: //p')
if [ -z "$count" ] || [ "$count" = "0" ]; then
    unavailable "no functional tests in $BUILD_DIR"
fi

echo "run-functional-tests: $count functional test(s) in $BUILD_DIR" >&2
if ! ctest --test-dir "$BUILD_DIR" -L functional --timeout "$TIMEOUT" --output-on-failure; then
    echo "" >&2
    echo "run-functional-tests: a functional test failed." >&2
    echo "Run it again by hand with: ctest --test-dir $BUILD_DIR -L functional --output-on-failure" >&2
    exit 1
fi
