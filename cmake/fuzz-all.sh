#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Extended fuzzing of every *_fuzzer with platform-specific strategies.
#
# Linux (libFuzzer):     mutation-based fuzzing with persistent corpus
#                        directories under <corpus_dir>/<fuzzer_name>/.
# macOS (standalone):    random-input testing with ASAN/UBSAN.
#
# Usage: fuzz-all.sh <fuzz_bin_dir> <corpus_dir> <duration> <max_len> <count>
#
# Arguments:
#   fuzz_bin_dir  Root directory containing fuzzer executables (searched recursively)
#   corpus_dir    Directory to store corpus files (one subdir per fuzzer)
#   duration      Seconds per fuzzer (Linux libFuzzer; 0 = unlimited)
#   max_len       Max input size in bytes
#   count         Number of random inputs per fuzzer (macOS only)

set -e

if [ $# -ne 5 ]; then
    echo "Usage: $0 <fuzz_bin_dir> <corpus_dir> <duration> <max_len> <count>" >&2
    exit 1
fi

FUZZ_BIN_DIR="$1"
CORPUS_DIR="$2"
DURATION="$3"
MAX_LEN="$4"
COUNT="$5"

mkdir -p "$CORPUS_DIR"

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

uname_s=$(uname -s)
total=0
failed=0
while IFS= read -r fuzzer; do
    total=$((total + 1))
    name=$(basename "$fuzzer")
    corpus="$CORPUS_DIR/$name"
    mkdir -p "$corpus"
    echo ""
    echo "=== $name ==="
    case "$uname_s" in
        Linux)
            # libFuzzer: mutation-based, bounded by duration
            if ! "$fuzzer" -max_total_time="$DURATION" -max_len="$MAX_LEN" \
                          -timeout=10 -close_fd_mask=3 "$corpus"; then
                echo "FAILED: $name" >&2
                failed=$((failed + 1))
            fi
            ;;
        Darwin|*)
            # Standalone driver: feed N random inputs
            i=0
            while [ $i -lt "$COUNT" ]; do
                seed=$(mktemp)
                head -c "$MAX_LEN" /dev/urandom > "$seed"
                if ! "$fuzzer" "$seed" > /dev/null 2>&1; then
                    echo "FAILED at input $i: $name" >&2
                    failed=$((failed + 1))
                    rm -f "$seed"
                    break
                fi
                rm -f "$seed"
                i=$((i + 1))
            done
            ;;
    esac
done < "$fuzzer_list"

echo ""
echo "Ran $total fuzzer(s); $failed failure(s)."
# Not `exit $failed`: shell exit codes wrap mod 256, so 256 failures would
# report success.
[ "$failed" -eq 0 ] || exit 1
