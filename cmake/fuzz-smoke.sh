#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Smoke-run every fuzzer once with a random seed.
#
# Usage: fuzz-smoke.sh <fuzz_bin_dir> <seeds_dir>
#
# Fuzzers are auto-discovered: every executable matching *_fuzzer under
# fuzz_bin_dir is run once with a 256-byte random seed. Stays in sync with
# CMake's add_*_fuzzer() calls without a hand-maintained list.

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <fuzz_bin_dir> <seeds_dir>" >&2
    exit 1
fi

FUZZ_BIN_DIR="$1"
SEEDS_DIR="$2"

mkdir -p "$SEEDS_DIR"

# One fuzzer per line via a temp file: `for f in $(find ...)` would word-split
# paths containing spaces, and piping find into a while loop would run the
# loop in a subshell, losing the counters.
fuzzer_list=$(mktemp)
trap 'rm -f "$fuzzer_list"' EXIT
find "$FUZZ_BIN_DIR" -type f -name '*_fuzzer' 2>/dev/null | sort > "$fuzzer_list"
if [ ! -s "$fuzzer_list" ]; then
    echo "ERROR: no *_fuzzer executables found under $FUZZ_BIN_DIR" >&2
    echo "       Did you build with -DENABLE_FUZZING=ON?" >&2
    exit 1
fi

failed=0
count=0
while IFS= read -r fuzzer; do
    count=$((count + 1))
    name=$(basename "$fuzzer")
    seed="$SEEDS_DIR/${name}_seed.bin"
    head -c 256 /dev/urandom > "$seed"
    echo "[$count] Running $name with random seed..."
    # Capture the fuzzer's exit status before truncating its output: piping
    # straight into tail would make the pipeline's status tail's (POSIX sh has
    # no pipefail), silently turning every crash into a pass.
    status=0
    out=$("$fuzzer" -runs=1 -timeout=5 -close_fd_mask=3 "$seed" 2>&1) || status=$?
    printf '%s\n' "$out" | tail -3
    if [ "$status" -ne 0 ]; then
        echo "  FAILED: $name" >&2
        failed=$((failed + 1))
    fi
done < "$fuzzer_list"

echo ""
echo "Smoke ran $count fuzzer(s); $failed failure(s)."
# Not `exit $failed`: shell exit codes wrap mod 256, so 256 failures would
# report success.
[ "$failed" -eq 0 ] || exit 1
