#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Run clang-tidy on every non-test .cpp in parallel.
#
# Extracts .cpp files from compile_commands.json (excluding test, tool,
# and example translation units), runs clang-tidy in parallel via xargs
# -P, and combines per-file findings into a single output file.
#
# Usage: run-clang-tidy-all.sh <clang_tidy> <build_dir> <jobs> <output_file>

set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 <clang_tidy> <build_dir> <jobs> <output_file>" >&2
    exit 1
fi

CLANG_TIDY="$1"
BUILD_DIR="$2"
JOBS="$3"
OUTPUT_FILE="$4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="$BUILD_DIR/.clang-tidy-tmp"

if [ ! -x "$CLANG_TIDY" ]; then
    echo "Error: clang-tidy not executable at $CLANG_TIDY" >&2
    exit 1
fi

if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
    echo "Error: $BUILD_DIR/compile_commands.json not found — build first" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 required but not found" >&2
    exit 1
fi

echo "Running clang-tidy ($JOBS parallel jobs)..."

rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

files=$(python3 -c "import json,sys; \
    entries=json.load(open('$BUILD_DIR/compile_commands.json')); \
    files=[e['file'] for e in entries \
        if e['file'].endswith('.cpp') \
        and not e['file'].endswith(('_test.cpp','_tool.cpp','_example.cpp','test.cpp','_fuzzer.cpp'))]; \
    sys.stdout.write('\n'.join(sorted(set(files))))")
if [ -z "$files" ]; then
    # Guarded by hand: GNU xargs (unlike BSD) still invokes the command once
    # on empty input, handing run-clang-tidy.sh an empty filename.
    echo "No non-test .cpp files found in compile_commands.json" >&2
    rm -rf "$TMPDIR"
    exit 0
fi
printf '%s\n' "$files" \
    | xargs -P "$JOBS" -I {} \
    sh "$SCRIPT_DIR/run-clang-tidy.sh" "$CLANG_TIDY" "$BUILD_DIR" "$TMPDIR" {}

echo "Combining results into $OUTPUT_FILE..."
cat "$TMPDIR"/*.txt 2>/dev/null | grep -v '^$' > "$OUTPUT_FILE" || true
rm -rf "$TMPDIR"

if [ -s "$OUTPUT_FILE" ]; then
    echo "Findings written to $OUTPUT_FILE"
    cat "$OUTPUT_FILE"
else
    echo "No clang-tidy findings."
    rm -f "$OUTPUT_FILE"
fi
