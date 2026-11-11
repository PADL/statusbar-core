// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Fixture for run-tidy-tests.sh: a header whose one block (five statements,
// over the plugin's default of four and under the gate's six, so the gate
// passes this file on commit) must be reported when it reaches clang-tidy
// through the gate's one-line translation unit.
// The gate passes --header-filter='.*' for exactly this; without it a
// clang-tidy before 22 reports nothing outside the main file. Line numbers
// are asserted, so edits here move the expectations in run-tidy-tests.sh.

#pragma once

inline int five_in_a_header(int a)
{
    int b = a + 1;
    int c = b + 1;
    int d = c + 1;
    int e = d + 1;
    return e;
}
