#! /bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

# Gate for the statusbar-block-statements house rule.
#
#   default:        check the staged C++ (what the pre-commit hook runs)
#   --since <ref>:  check everything changed since <ref>
#   <files...>:     check these files, every line of them
#
# Only a flagged block whose lines THIS change touches fails the gate. That
# is the whole design: a new rule applied to an existing tree whole is
# thousands of findings and gets switched off within the day, while a rule
# applied to the lines being edited makes the tree improve where it is worked
# on and blocks nobody anywhere else.
#
# The gate enforces STATUSBAR_BLOCK_STATEMENTS_MAX (default 6); the clang-tidy
# target reports at the check's own default of 4. The slack is deliberate --
# the warning teaches on the way past before the gate bites.
#
# An exception goes on the opening brace's line and must carry a reason:
#
#     {  // NOLINT(statusbar-block-statements) one table, read top to bottom
#
# A bare NOLINT on a touched line fails the gate even though clang-tidy itself
# would honour it: an unexplained suppression is the thing this rule is for.
#
# Exits 0 without checking anything when the tools are not available (no
# plugin, no compile_commands.json): a gate that cannot run must not block a
# commit. Say STATUSBAR_BLOCK_STATEMENTS_STRICT=1 to make that a failure.

set -e

MAX="${STATUSBAR_BLOCK_STATEMENTS_MAX:-6}"
CLANG_TIDY="${CLANG_TIDY_EXE:-clang-tidy}"
STRICT="${STATUSBAR_BLOCK_STATEMENTS_STRICT:-0}"
ROOT="$(cd "$(dirname "$0")" && pwd)"

mode=staged
since_ref=""
case "${1:-}" in
    --since)
        mode=since
        since_ref="${2:?--since needs a ref}"
        ;;
    --staged | "") mode=staged ;;
    -*)
        echo "usage: $0 [--staged | --since <ref> | <files...>]" >&2
        exit 2
        ;;
    *) mode=files ;;
esac

unavailable() {
    if [ "$STRICT" = "1" ]; then
        echo "check-block-statements: $1" >&2
        exit 1
    fi
    echo "check-block-statements: $1 — skipping" >&2
    exit 0
}

# ---- the build directory, for compile flags -------------------------------
BUILD_DIR="${STATUSBAR_BUILD_DIR:-}"
if [ -z "$BUILD_DIR" ]; then
    for candidate in "$ROOT/build" "$ROOT/build-fix" "$ROOT/../build"; do
        if [ -f "$candidate/compile_commands.json" ]; then
            BUILD_DIR="$candidate"
            break
        fi
    done
fi
[ -n "$BUILD_DIR" ] || unavailable "no build directory with compile_commands.json"

# ---- the plugin ----------------------------------------------------------
PLUGIN="${STATUSBAR_TIDY_PLUGIN:-$BUILD_DIR/statusbar-tidy-block-statements.so}"
[ -f "$PLUGIN" ] || unavailable "no plugin at $PLUGIN (build the statusbar-tidy-block-statements target)"
command -v "$CLANG_TIDY" >/dev/null 2>&1 || unavailable "no clang-tidy on PATH"

# ---- what changed --------------------------------------------------------
# -U0 so each hunk header names exactly the lines this change introduces.
case "$mode" in
    staged) diff_cmd="git -C $ROOT diff --cached -U0 --diff-filter=ACMR --" ;;
    since) diff_cmd="git -C $ROOT diff -U0 --diff-filter=ACMR $since_ref -- " ;;
    files) diff_cmd="" ;;
esac

if [ "$mode" = "files" ]; then
    files="$*"
else
    files=$($diff_cmd '*.cpp' '*.hpp' '*.h' | awk '/^\+\+\+ b\//{ sub("^\\+\\+\\+ b/", ""); print }')
fi
[ -n "$files" ] || exit 0

# Lines the change touches in one file, as "start end" pairs. For an explicit
# file list every line counts.
touched_ranges() {
    if [ "$mode" = "files" ]; then
        echo "1 999999"
        return
    fi
    $diff_cmd "$1" | awk '
        /^@@/ {
            # @@ -old,n +new,m @@  — m may be absent (means 1)
            match($0, /\+[0-9]+(,[0-9]+)?/)
            spec = substr($0, RSTART + 1, RLENGTH - 1)
            n = split(spec, a, ",")
            start = a[1] + 0
            count = (n > 1) ? a[2] + 0 : 1
            if (count > 0) print start, start + count - 1
        }'
}

fail=0
for f in $files; do
    [ -f "$ROOT/$f" ] || [ -f "$f" ] || continue
    path="$f"
    [ -f "$ROOT/$f" ] && path="$ROOT/$f"

    ranges=$(touched_ranges "$f")
    [ -n "$ranges" ] || continue

    # A suppression without a reason, on a line this change touches.
    bare=$(awk -v ranges="$ranges" '
        BEGIN { n = split(ranges, r, "\n") }
        {
            for (i = 1; i <= n; i++) {
                split(r[i], b, " ")
                if (NR >= b[1] && NR <= b[2]) {
                    if ($0 ~ /NOLINT(NEXTLINE)?\(statusbar-block-statements\)[[:space:]]*$/) {
                        printf "%s:%d: NOLINT(statusbar-block-statements) with no reason\n", FILENAME, NR
                    }
                    break
                }
            }
        }' "$path")
    if [ -n "$bare" ]; then
        echo "$bare" >&2
        fail=1
    fi

    findings=$("$CLANG_TIDY" -load="$PLUGIN" \
        --checks='-*,statusbar-block-statements' \
        --config="{CheckOptions: {statusbar-block-statements.MaxStatements: $MAX}}" \
        --quiet -p "$BUILD_DIR" "$path" 2>/dev/null |
        grep "statusbar-block-statements" || true)
    [ -n "$findings" ] || continue

    # Keep only findings in THIS file, on lines this change touches.
    # clang-tidy lints a whole translation unit, so a block in any header it
    # includes is reported too; matching on the line alone keeps those
    # whenever their line number happens to fall inside a touched range of
    # the .cpp -- which it did, the first time this gate was run in anger. A
    # header you did change is still caught, on the pass for whichever .cpp
    # includes it, because that pass tests the header's own ranges.
    kept=$(printf '%s\n' "$findings" | awk -v ranges="$ranges" -v want="$path" '
        BEGIN { n = split(ranges, r, "\n") }
        {
            if (!match($0, /:[0-9]+:[0-9]+:/)) { next }
            file = substr($0, 1, RSTART - 1)
            if (file != want) { next }
            line = substr($0, RSTART + 1)
            sub(/:.*/, "", line)
            for (i = 1; i <= n; i++) {
                split(r[i], b, " ")
                if (line + 0 >= b[1] && line + 0 <= b[2]) { print; break }
            }
        }')
    if [ -n "$kept" ]; then
        echo "$kept" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "check-block-statements: a block you touched holds more than $MAX statements." >&2
    echo "Split it, or mark the brace: { // NOLINT(statusbar-block-statements) <reason>" >&2
    exit 1
fi
exit 0
