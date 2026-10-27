#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Hold changed C++ to the house block size: run clang-tidy's statusbar-block-statements check
# (the plugin clang_tidy.cmake builds) over the files a change touches, and fail on any block whose
# lines the change touches that holds more than STATUSBAR_BLOCK_STATEMENTS_MAX statements (default 6:
# aim for 4). A changed header is checked through its own .cpp, or else every .cpp beside it.
#
# Usage: check-block-statements.sh <build-dir> [--staged | <base-ref>]   (default --staged)
# Run in the repository to check; <build-dir> holds compile_commands.json and libstatusbar-tidy.so.
# Exits 0, saying so, when the plugin or compile_commands.json is missing.

set -e

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <build-dir> [--staged | <base-ref>]" >&2
    exit 2
fi
BUILD_DIR=$(cd "$1" && pwd)
SINCE=${2:---staged}
MAX=${STATUSBAR_BLOCK_STATEMENTS_MAX:-6}
PLUGIN="$BUILD_DIR/libstatusbar-tidy.so"
CLANG_TIDY=$(sed -n 's/^CLANG_TIDY_EXE:FILEPATH=//p' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null)
CLANG_TIDY=${CLANG_TIDY:-clang-tidy}

if [ ! -f "$PLUGIN" ] || [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
    echo "check-block-statements: skipped (build the clang-tidy target once for $PLUGIN)" >&2
    exit 0
fi
[ "$SINCE" = "--staged" ] && SINCE=--cached

exec python3 - "$BUILD_DIR" "$PLUGIN" "$CLANG_TIDY" "$MAX" "$SINCE" <<'PY'
import json, os, re, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
build, plugin, tidy, limit, since = sys.argv[1:]
root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
diff = subprocess.check_output(["git", "diff", "-U0", since, "--", "*.cpp", "*.hpp", "*.h"], text=True, cwd=root)
changed, path = {}, None
for line in diff.splitlines():
    if line.startswith("+++ "):
        path = None if line.endswith("/dev/null") else os.path.realpath(os.path.join(root, line[6:]))
    elif line.startswith("@@") and path:
        start, _, count = re.match(r"@@ -\S+ \+(\d+)(,(\d+))?", line).groups()
        start, count = int(start), int(count if count is not None else 1)
        if count:
            changed.setdefault(path, []).append((start, start + count - 1))
if not changed:
    sys.exit(0)
units = {os.path.realpath(os.path.join(e["directory"], e["file"])) for e in json.load(open(os.path.join(build, "compile_commands.json")))}
runs = set()
for f in changed:
    if f in units:
        runs.add(f)
    else:
        stem, folder = os.path.splitext(f)[0], os.path.dirname(f)
        own = [u for u in units if os.path.splitext(u)[0] == stem]
        runs.update(own or [u for u in units if os.path.dirname(u) == folder])
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as cfg:
    cfg.write(f"Checks: '-*,statusbar-block-statements'\nCheckOptions:\n  statusbar-block-statements.MaxStatements: {limit}\n")
pattern = re.compile(r"^(.*?):(\d+):\d+: warning: block \(lines (\d+)-(\d+)\).*\[statusbar-block-statements\]$")
def lint(unit):
    return subprocess.run([tidy, "-p", build, "--quiet", f"--load={plugin}", f"--config-file={cfg.name}",
                           f"--header-filter={re.escape(root)}/.*", unit], capture_output=True, text=True).stdout
found = set()
with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    outputs = list(pool.map(lint, sorted(runs)))
for line in "\n".join(outputs).splitlines():
    m = pattern.match(line)
    if m and any(a <= int(m[4]) and b >= int(m[3]) for a, b in changed.get(os.path.realpath(m[1]), [])):
        found.add(line)
os.unlink(cfg.name)
for line in sorted(found):
    print(line, file=sys.stderr)
if found:
    print(f"\ncheck-block-statements: {len(found)} changed block(s) hold more than {limit} statements.\n"
          "Split them into functions, or mark a real exception on the opening brace's line:\n"
          "  // NOLINT(statusbar-block-statements): <reason>", file=sys.stderr)
    sys.exit(1)
PY
