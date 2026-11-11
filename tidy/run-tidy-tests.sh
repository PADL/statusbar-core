#! /bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Behaviour tests for the statusbar-block-statements clang-tidy plugin.
#
# Asserts the EXACT set of reported lines against the fixtures, rather than
# just "it ran": every exemption in the check exists because its absence was
# a false positive, so each one is a line that must stay silent.
#
# Usage: run-tidy-tests.sh <plugin.so> [clang-tidy]

set -e

PLUGIN="${1:?usage: run-tidy-tests.sh <plugin.so> [clang-tidy]}"
CLANG_TIDY="${2:-clang-tidy}"
DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$DIR/tests/block_statements_fixture.cpp"
FIXTURE_TEST="$DIR/tests/block_statements_fixture_test.cpp"
FIXTURE_HEADER="$DIR/tests/block_statements_header_fixture.hpp"
GATE="$DIR/../check-block-statements.sh"

if [ ! -f "$PLUGIN" ]; then
    echo "run-tidy-tests: no plugin at $PLUGIN" >&2
    exit 1
fi
# Absolute, because the gate case below runs from another directory.
case "$PLUGIN" in
    /*) ;;
    *) PLUGIN="$(pwd)/$PLUGIN" ;;
esac

# Report only the line numbers the check fires on, in order.
findings() {
    "$CLANG_TIDY" -load="$PLUGIN" --checks='-*,statusbar-block-statements' \
        --quiet "$1" -- -std=c++23 2>/dev/null |
        grep "statusbar-block-statements" |
        sed 's|^.*fixture[^:]*:\([0-9]*\):.*|\1|' |
        tr '\n' ' ' | sed 's/ $//'
}

fail=0
expect() {
    name="$1"
    want="$2"
    got="$3"
    if [ "$want" = "$got" ]; then
        echo "PASS: $name"
    else
        echo "FAIL: $name — expected lines [$want], got [$got]" >&2
        fail=1
    fi
}

# five()'s opening brace, line 17, is the only thing in the fixture that may
# be reported. Every other block in that file is a case that must stay
# silent: four() at 8, nested() at 27 (its inner block counted as one
# statement), the switch body at 41 (six cases), the implicit copy assignment
# located at struct SixMembers on 75, and the NOLINT-ed block at 95.
expect "only the five-statement block is reported" "17" "$(findings "$FIXTURE")"

# Same file under a _test.cpp name: nothing at all.
expect "a _test.cpp file is exempt entirely" "" "$(findings "$FIXTURE_TEST")"

# Tightening the bound must move the boundary, which proves the option is
# read rather than the 4 being baked in: four()'s block and the nested
# block's 4-statement interior join the list, making three.
findings_max3() {
    "$CLANG_TIDY" -load="$PLUGIN" --checks='-*,statusbar-block-statements' \
        --config='{CheckOptions: {statusbar-block-statements.MaxStatements: 3}}' \
        --quiet "$FIXTURE" -- -std=c++23 2>/dev/null |
        grep -c "statusbar-block-statements" || true
}
expect "MaxStatements is honoured" "3" "$(findings_max3)"

# The gate itself, in files mode, over a compile database of one entry: the
# header fixture reaches clang-tidy through the gate's one-line translation
# unit, and its block at line 15 must come back -- which it only does
# because the gate names the header filter rather than trusting clang-tidy's
# default (empty before 22, everything from 22 on). The .cpp fixture through
# the same path pins that the main file is still reported the same way.
# MAX=4 matches the plugin's own default so the expectations line up.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/compile_commands.json" <<EOF
[{"directory": "$DIR/tests", "file": "$DIR/tests/block_statements_fixture.cpp",
  "arguments": ["clang++", "-std=c++23", "-c", "block_statements_fixture.cpp"]}]
EOF
gate_findings() {
    (cd "$DIR/.." && STATUSBAR_BUILD_DIR="$TMP" STATUSBAR_TIDY_PLUGIN="$PLUGIN" CLANG_TIDY_EXE="$CLANG_TIDY" \
        STATUSBAR_BLOCK_STATEMENTS_MAX=4 STATUSBAR_BLOCK_STATEMENTS_STRICT=1 "$GATE" "$1" 2>&1 || true) |
        grep "statusbar-block-statements\]" |
        sed 's|^.*fixture[^:]*:\([0-9]*\):.*|\1|' |
        tr '\n' ' ' | sed 's/ $//'
}
expect "the gate reports a block in a header" "15" "$(gate_findings "$FIXTURE_HEADER")"
expect "the gate reports the main file as before" "17" "$(gate_findings "$FIXTURE")"

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "run-tidy-tests: FAILED" >&2
    exit 1
fi
echo "run-tidy-tests: all checks passed"
