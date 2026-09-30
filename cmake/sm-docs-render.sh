#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Generate per-state-machine Markdown + an SVG diagram per SM, embedded
# in the Markdown via an image link. Driven by a statusbar::sm::sm_tool
# binary which auto-discovers its registered state machines.
#
# Workflow:
#   1. Run <tool> --format=markdown --output-dir=<dst>  -> *.md
#   2. Run <tool> --format=dot      --output-dir=<dst>  -> *.dot
#   3. Render each *.dot to *.svg via `dot -Tsvg`
#   4. Prepend an ![diagram](<name>.svg) image link to each *.md
#   5. Remove the *.dot files
#
# Usage: sm-docs-render.sh <tool_binary> <output_dir>
#
# Requires `dot` (graphviz) on PATH.

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <tool_binary> <output_dir>" >&2
    exit 1
fi

TOOL="$1"
DST="$2"

if [ ! -x "$TOOL" ]; then
    echo "Error: $TOOL is not executable" >&2
    exit 1
fi

if ! command -v dot >/dev/null 2>&1; then
    echo 'Error: graphviz `dot` not found on PATH' >&2
    exit 1
fi

mkdir -p "$DST"
"$TOOL" --format=markdown --output-dir="$DST" >/dev/null
"$TOOL" --format=dot --output-dir="$DST" >/dev/null

for dot_file in "$DST"/*.dot; do
    [ -f "$dot_file" ] || continue
    name=$(basename "$dot_file" .dot)
    svg_file="$DST/$name.svg"
    md_file="$DST/$name.md"

    # Render SVG
    dot -Tsvg "$dot_file" -o "$svg_file"

    # Prepend image link to the .md if not already present.
    # The .md starts with a "# Title" line; inject the image right under it.
    if [ -f "$md_file" ] && ! grep -q "^!\[" "$md_file"; then
        # Use awk to insert after the first line
        awk -v link="![diagram]($name.svg)" 'NR==1 {print; print ""; print link; print ""; next} {print}' \
            "$md_file" > "$md_file.tmp" && mv "$md_file.tmp" "$md_file"
    fi

    rm "$dot_file"
done

echo "Generated $(find "$DST" -maxdepth 1 -name '*.md' | wc -l) Markdown file(s) with SVG diagrams in $DST"
