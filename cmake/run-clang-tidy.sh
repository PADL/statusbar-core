#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Helper for parallel clang-tidy execution: lints a single source file
# against the project's compile_commands.json and writes findings to a
# per-file text file under output_dir. Filters out the noisy
# "N warnings generated" / "Error while processing" trailing lines.
#
# clang-tidy's exit status is deliberately discarded (the trailing `|| true`):
# the contract is the findings file, not the exit code — the aggregate
# `clang-tidy` target always "succeeds" and the caller inspects the combined
# findings output.
#
# Usage: run-clang-tidy.sh <clang-tidy> <build-dir> <output-dir> <source-file>

CLANG_TIDY="$1"
BUILD_DIR="$2"
OUTPUT_DIR="$3"
SOURCE_FILE="$4"

outfile="$OUTPUT_DIR/$(echo "$SOURCE_FILE" | tr '/' '_').txt"

"$CLANG_TIDY" -p "$BUILD_DIR" "$SOURCE_FILE" 2>&1 \
    | grep -v 'warnings generated\|errors generated\|Error while processing' \
    > "$outfile" || true
