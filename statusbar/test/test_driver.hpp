#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The statusbar_test driver's command-line hook (create_test_sourcelist's FUNCTION): run with no arguments, the
/// binary runs every test (-A) instead of CMake's prompt for a test number, which waits on stdin.

namespace statusbar::test {

/// Rewrites a bare invocation (`*ac` 1) to `<argv[0]> -A`; leaves any other command line alone. The driver calls it
/// once, before it looks at the arguments.
inline void run_all_without_arguments(int* const ac, char*** const av)
{
    static char run_all[] = "-A";
    static char* args[] = {nullptr, run_all, nullptr};
    if (*ac != 1) {
        return;
    }
    args[0] = (*av)[0];
    *ac = 2;
    *av = args;
}

}  // namespace statusbar::test
