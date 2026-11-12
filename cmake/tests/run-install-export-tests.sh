#!/bin/sh
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Pins statusbar_package_install_export()'s header root: the fixture package
# beside this script is configured and installed into a scratch prefix once
# with the default and once with INCLUDE_DIR other, and the installed include
# tree must hold exactly the chosen root. A third configure with an unknown
# keyword must be refused.
#
# Usage: run-install-export-tests.sh [cmake] [module.cmake]
set -eu
cmake=${1:-cmake}
here=$(cd "$(dirname "$0")" && pwd)
module=${2:-$here/../module.cmake}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sb-install-export.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
fail=0
say_fail() { echo "FAIL: $*" >&2; fail=1; }

# configure_and_install <name> [extra -D...]: leaves <prefix> in $prefix.
configure_and_install() {
  name=$1; shift
  build=$scratch/$name-build; prefix=$scratch/$name-prefix
  "$cmake" -S "$here/install-export" -B "$build" -DSTATUSBAR_MODULE_CMAKE="$module" "$@" >"$scratch/$name.log" 2>&1 || {
    say_fail "$name: configure failed (see below)"; cat "$scratch/$name.log" >&2; return 1; }
  "$cmake" --install "$build" --prefix "$prefix" >>"$scratch/$name.log" 2>&1 || {
    say_fail "$name: install failed (see below)"; cat "$scratch/$name.log" >&2; return 1; }
}

if configure_and_install default; then
  [ -f "$prefix/include/statusbar/kept.hpp" ] || say_fail "default: statusbar/kept.hpp not installed"
  [ ! -e "$prefix/include/other" ] || say_fail "default: other/ was installed"
fi

if configure_and_install other -DFIXTURE_INCLUDE_DIR=other; then
  [ -f "$prefix/include/other/moved.hpp" ] || say_fail "other: other/moved.hpp not installed"
  [ ! -e "$prefix/include/statusbar" ] || say_fail "other: statusbar/ was installed"
fi

if "$cmake" -S "$here/install-export" -B "$scratch/bad-build" -DSTATUSBAR_MODULE_CMAKE="$module" -DFIXTURE_BAD_KEYWORD=yes >"$scratch/bad.log" 2>&1; then
  say_fail "an unknown keyword was accepted"
elif ! grep -q 'unknown keyword' "$scratch/bad.log"; then
  say_fail "the unknown keyword was refused for another reason:"; cat "$scratch/bad.log" >&2
fi

[ $fail -eq 0 ] && echo "install-export tests: PASS"
exit $fail
