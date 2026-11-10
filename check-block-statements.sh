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
# The repository checked is the one the caller stands in (a pre-commit hook
# runs at its repo's root), not the one this script lives in: core's copy
# serves every sibling package. Each checked file is linted as the content the
# change actually holds -- the staged blob, not the working tree, so `git add
# -p` and the gate agree -- with the compile flags compile_commands.json
# records for it, or for a header or a file the build has not configured yet,
# those of a neighbouring .cpp. A header is linted through a one-line
# translation unit that includes it, so a header-only change is checked like
# any other.
#
# Exits 0 without checking anything when the tools are not available (no
# plugin, no compile_commands.json, a clang-tidy that cannot load the plugin,
# a file that does not parse): a gate that cannot run must not block a commit,
# but it always says so. Say STATUSBAR_BLOCK_STATEMENTS_STRICT=1 to make that
# a failure instead.

set -e

MAX="${STATUSBAR_BLOCK_STATEMENTS_MAX:-6}"
STRICT="${STATUSBAR_BLOCK_STATEMENTS_STRICT:-0}"

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

# The repository being checked: the caller's, falling back to this script's.
REPO=$(git rev-parse --show-toplevel 2>/dev/null || true)
[ -n "$REPO" ] || REPO="$(cd "$(dirname "$0")" && pwd)"

unavailable() {
    if [ "$STRICT" = "1" ]; then
        echo "check-block-statements: $1" >&2
        exit 1
    fi
    echo "check-block-statements: $1 — skipping" >&2
    exit 0
}

# ---- what changed --------------------------------------------------------
# -U0 so each hunk header names exactly the lines this change introduces.
# Paths from git are relative to the repo root whatever the cwd. The output is
# pinned against the user's configuration: diff.mnemonicPrefix or
# diff.noprefix would rename the b/ prefix, color.diff=always would colour the
# hunk headers, and an external diff would replace the patch altogether.
diff_opts="--no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ -U0 --diff-filter=ACMR"
case "$mode" in
    staged) diff_cmd="git -C $REPO diff --cached $diff_opts" ;;
    since) diff_cmd="git -C $REPO diff $diff_opts $since_ref" ;;
    files) diff_cmd="" ;;
esac

if [ "$mode" = "files" ]; then
    files=""
    for f in "$@"; do
        case "$f" in
            /*) abs="$f" ;;
            *) abs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")" ;;
        esac
        rel="${abs#"$REPO"/}"
        if [ "$rel" = "$abs" ]; then
            echo "check-block-statements: $f is outside $REPO — ignored" >&2
            continue
        fi
        files="$files $rel"
    done
else
    # The names alone: no patch to parse, so a rename, a new empty file or a mode change lists too.
    files=$($diff_cmd --name-only -- '*.cpp' '*.hpp' '*.h')
fi
# Nothing to check: say nothing, need nothing.
[ -n "$(echo "$files" | tr -d ' \n')" ] || exit 0

# ---- the build directory, for compile flags -------------------------------
# The plugin lands in the build directory of whichever CMakeLists registered
# the clang-tidy target: the top of a standalone build, core/ of the umbrella's.
plugin_in() {
    find "$1" -maxdepth 2 -name statusbar-tidy-block-statements.so 2>/dev/null | head -n 1
}

# The first candidate holding both compile_commands.json and the plugin; one
# holding only the compile database is kept to name in the message.
BUILD_DIR="${STATUSBAR_BUILD_DIR:-}"
PLUGIN="${STATUSBAR_TIDY_PLUGIN:-}"
if [ -z "$BUILD_DIR" ]; then
    db_only=""
    for candidate in "$REPO/build" "$REPO/build-fix" "$REPO/../build"; do
        [ -f "$candidate/compile_commands.json" ] || continue
        if [ -n "$PLUGIN" ] || [ -n "$(plugin_in "$candidate")" ]; then
            BUILD_DIR="$candidate"
            break
        fi
        [ -n "$db_only" ] || db_only="$candidate"
    done
    [ -n "$BUILD_DIR" ] || BUILD_DIR="$db_only"
fi
[ -n "$BUILD_DIR" ] || unavailable "no build directory with compile_commands.json under $REPO"
[ -f "$BUILD_DIR/compile_commands.json" ] || unavailable "no compile_commands.json in $BUILD_DIR"

# ---- the plugin, and the clang-tidy it was built for -----------------------
[ -n "$PLUGIN" ] || PLUGIN=$(plugin_in "$BUILD_DIR")
if [ -z "$PLUGIN" ] || [ ! -f "$PLUGIN" ]; then
    unavailable "no statusbar-tidy-block-statements.so under $BUILD_DIR (build the statusbar-tidy-block-statements target)"
fi

# The plugin only loads into the clang-tidy whose headers it was built
# against, which is the one the build recorded -- not whatever is on PATH.
CLANG_TIDY="${CLANG_TIDY_EXE:-}"
if [ -z "$CLANG_TIDY" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    CLANG_TIDY=$(sed -n 's/^CLANG_TIDY_EXE:[A-Z]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -n 1)
    case "$CLANG_TIDY" in *-NOTFOUND) CLANG_TIDY="" ;; esac
fi
[ -n "$CLANG_TIDY" ] || CLANG_TIDY=clang-tidy
command -v "$CLANG_TIDY" >/dev/null 2>&1 || unavailable "no clang-tidy: $CLANG_TIDY"
command -v python3 >/dev/null 2>&1 || unavailable "no python3 to read compile_commands.json"

# Prove the check is registered before trusting an empty report: a plugin
# that fails to load is one line on stderr and a clean exit.
listed=$("$CLANG_TIDY" -load="$PLUGIN" --checks='-*,statusbar-block-statements' --list-checks 2>&1 || true)
if ! printf '%s\n' "$listed" | grep -q '^[[:space:]]*statusbar-block-statements$'; then
    unavailable "$CLANG_TIDY does not load $PLUGIN: $(printf '%s' "$listed" | tr '\n' ' ')"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The copies under test live in $TREE, linted with the repository's own
# .clang-tidy plus the gate's bound; the header filter always admits the copy,
# so a header is reported like a source (--config would drop the repo's).
TREE="$TMP/tree"
mkdir -p "$TREE"
[ ! -f "$REPO/.clang-tidy" ] || cp "$REPO/.clang-tidy" "$TMP/.clang-tidy"
printf 'InheritParentConfig: true\nCheckOptions:\n  statusbar-block-statements.MaxStatements: %s\n' "$MAX" > "$TREE/.clang-tidy"

# The compile command for a source file, from compile_commands.json: prints the
# directory to run in, then the flags shell-quoted on one line -- without the
# compiler, the source, the output and the dependency-file flags. For a
# header, or a .cpp the build has not configured yet, the flags of a .cpp from
# the same directory, else the same top-level directory, else any: only the
# flags are borrowed, the content under test is always our own copy.
compile_flags() {
    python3 - "$BUILD_DIR/compile_commands.json" "$REPO" "$1" <<'PY'
import json, os, shlex, sys

db, repo, rel = sys.argv[1], sys.argv[2], sys.argv[3]
want = os.path.realpath(os.path.join(repo, rel))

def source_of(entry):
    f = entry["file"]
    if not os.path.isabs(f):
        f = os.path.join(entry["directory"], f)
    return os.path.realpath(f)

def rank(entry):
    src = source_of(entry)
    if src == want:
        return 0
    if not src.endswith(".cpp"):
        return 8
    if src.endswith(("_test.cpp", "_fuzzer.cpp")):
        return 9
    if os.path.dirname(src) == os.path.dirname(want):
        return 1
    top = rel.split("/", 1)[0]
    if src.startswith(os.path.realpath(os.path.join(repo, top)) + os.sep):
        return 2
    return 3

with open(db) as fh:
    entries = json.load(fh)
entries.sort(key=rank)
if not entries:
    sys.exit(1)
entry = entries[0]

args = entry.get("arguments") or shlex.split(entry["command"])
src = source_of(entry)
out, skip = [], 0
for a in args[1:]:
    if skip:
        skip -= 1
        continue
    if a in ("-o", "-MF", "-MT", "-MQ"):
        skip = 1
        continue
    if a in ("-c", "-MD", "-MMD", "-M", "-MM", "-MP") or a.startswith(("-MF", "-MT", "-MQ")):
        continue
    p = a if os.path.isabs(a) else os.path.join(entry["directory"], a)
    if os.path.realpath(p) == src:
        continue
    out.append(a)
print(entry["directory"])
print(shlex.join(out))
PY
}

# Lines the change touches in one file, as "start end" pairs separated by
# ";" (awk -v takes no newlines on macOS). For an explicit file list every
# line counts.
touched_ranges() {
    if [ "$mode" = "files" ]; then
        echo "1 999999"
        return
    fi
    $diff_cmd -- "$1" | awk '
        /^@@/ {
            # @@ -old,n +new,m @@  — m may be absent (means 1)
            match($0, /\+[0-9]+(,[0-9]+)?/)
            spec = substr($0, RSTART + 1, RLENGTH - 1)
            n = split(spec, a, ",")
            start = a[1] + 0
            count = (n > 1) ? a[2] + 0 : 1
            if (count > 0) print start, start + count - 1
        }' | paste -s -d ';' -
}

# The content this change holds for one file: the staged blob, or the file.
content_of() {
    if [ "$mode" = "staged" ]; then
        git -C "$REPO" show ":$1"
    else
        cat "$REPO/$1"
    fi
}

# A file the gate could not check: says so, and fails only when strict.
skipped() {
    echo "check-block-statements: $1" >&2
    if [ "$STRICT" = "1" ]; then
        unchecked=1
    fi
}

fail=0
unchecked=0
for f in $files; do
    ranges=$(touched_ranges "$f")
    [ -n "$ranges" ] || continue

    # The content under test lives in a copy of the tree, so a staged .cpp
    # that includes a staged header sees the staged header.
    copy="$TREE/$f"
    mkdir -p "$(dirname "$copy")"
    content_of "$f" > "$copy"

    # A suppression without a reason, on a line this change touches.
    bare=$(awk -v ranges="$ranges" -v name="$f" '
        BEGIN { n = split(ranges, r, ";") }
        {
            for (i = 1; i <= n; i++) {
                split(r[i], b, " ")
                if (NR >= b[1] && NR <= b[2]) {
                    if ($0 ~ /NOLINT(NEXTLINE)?\(statusbar-block-statements\)[[:space:]]*$/) {
                        printf "%s:%d: NOLINT(statusbar-block-statements) with no reason\n", name, NR
                    }
                    break
                }
            }
        }' "$copy")
    if [ -n "$bare" ]; then
        echo "$bare" >&2
        fail=1
    fi

    if ! flags=$(compile_flags "$f"); then
        skipped "$f: $BUILD_DIR/compile_commands.json is empty"
        continue
    fi
    run_dir=$(printf '%s\n' "$flags" | sed -n 1p)
    eval "set -- $(printf '%s\n' "$flags" | sed -n 2p)"

    # The translation unit: the .cpp itself, or one line that includes the
    # header. Includes resolve in the copy first (-I, and the copy's own
    # directory), then beside the original (-iquote), then as the build says.
    case "$f" in
        *.cpp) tu="$copy" ;;
        *)
            tu="$copy.tu.cpp"
            printf '#include "%s"\n' "$f" > "$tu"
            ;;
    esac
    report="$TMP/report.txt"
    (cd "$run_dir" && "$CLANG_TIDY" -load="$PLUGIN" \
        --checks='-*,statusbar-block-statements' \
        --warnings-as-errors='-*' --header-filter="^$TREE/" \
        --quiet "$tu" -- -I"$TREE" -iquote "$REPO/$(dirname "$f")" "$@") > "$report" 2>&1 || true

    # A file clang-tidy could not parse was not checked; say so rather than
    # read an empty report as a clean one.
    errors=$(grep -E '(^|[[:space:]])error: |^Error |^Error while processing' "$report" || true)
    if [ -n "$errors" ]; then
        skipped "$f did not parse: $(printf '%s\n' "$errors" | head -n 3 | sed "s|$TREE/||g" | tr '\n' ' ')"
        continue
    fi

    # Keep only findings in THIS file whose block this change touches. A
    # finding sits on the opening brace and the check follows it with a note
    # on the closing brace; the change touches the block if any touched
    # range meets that extent, so editing a body without its braces counts.
    # clang-tidy lints a whole translation unit, so a block in any header it
    # includes is reported too; the file under test is always reported at its
    # path in the copy, which is what the name is matched on.
    kept=$(grep -E ':[0-9]+:[0-9]+: (warning|note): ' "$report" | awk -v ranges="$ranges" -v want="$copy" -v name="$f" '
        BEGIN { n = split(ranges, r, ";"); start = 0 }
        function touched(lo, hi,    i, b) {
            for (i = 1; i <= n; i++) {
                split(r[i], b, " ")
                if (b[2] + 0 >= lo && b[1] + 0 <= hi) { return 1 }
            }
            return 0
        }
        # The pending finding, matched against its block: to the closing
        # brace when the note arrived, to the opening brace alone otherwise.
        function flush(end) {
            if (start && touched(start, end)) {
                sub(/^[^:]*:/, name ":", text)
                print text
            }
            start = 0
        }
        {
            match($0, /:[0-9]+:[0-9]+: /)
            file = substr($0, 1, RSTART - 1)
            line = substr($0, RSTART + 1)
            sub(/:.*/, "", line)
            if (index($0, "[statusbar-block-statements]")) {
                flush(start)
                if (file == want) { start = line + 0; text = $0 }
                next
            }
            if (index($0, "note: the block ends here")) { flush(line + 0) }
        }
        END { flush(start) }' || true)
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
if [ "$unchecked" -ne 0 ]; then
    echo "check-block-statements: not every file could be checked, and STATUSBAR_BLOCK_STATEMENTS_STRICT=1" >&2
    exit 1
fi
exit 0
