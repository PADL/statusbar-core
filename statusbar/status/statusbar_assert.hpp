#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// STATUSBAR_ASSERT(expr) — checked precondition with optimizer hint.
//
// Three modes, selected at compile time:
//
// - Hardened (STATUSBAR_HARDENED defined): emits a REAL runtime check that
//   traps (__builtin_trap) on violation, in every build including release.
//   Opt-in defense in depth for production deployments where a violated
//   precondition should fail closed (deterministic abort) instead of becoming
//   undefined behaviour. Costs a branch per assertion. Wired to the CMake
//   `ENABLE_HARDENING` option (OFF by default; this macro is undefined unless
//   that option turns it on).
//
// - Release (NDEBUG defined, not hardened): only [[assume(expr)]] is emitted —
//   the compiler may rely on `expr` being true to eliminate downstream branches
//   but never evaluates it. Violating the precondition is undefined behaviour.
//   This is the documented contract of the "unchecked" helpers: callers must
//   validate first (e.g. via the paired load()).
//
// - Debug (neither defined): runs the runtime check via assert(expr), then
//   issues [[assume(expr)]] so the compiler verifies that `expr` is
//   side-effect-free. The expression evaluates twice in debug, which is
//   intentional — the predicate is required to be pure.
//
// Putting [[assume(expr)]] in the non-hardened branches is deliberate: every
// call site goes through the same side-effect / pure-function analysis, so a
// predicate that accidentally calls a non-pure function is diagnosed (clang's
// -Wassume) — a hard build error under -DENABLE_WARNINGS_AS_ERRORS (the
// standalone package default), a warning otherwise — where it would otherwise
// silently mutate state in debug but evaporate in release.
//
// Variadic so a predicate containing a bare comma (template argument lists:
// STATUSBAR_ASSERT(check<A, B>(x))) survives the preprocessor; the expansion
// re-joins the pieces, and a genuine top-level comma expression still fails to
// compile inside [[assume]].

#include <cassert>

#if defined(STATUSBAR_HARDENED)
#    define STATUSBAR_ASSERT(...)                                                                                                  \
        do {                                                                                                                       \
            if (!(__VA_ARGS__)) {                                                                                                  \
                __builtin_trap();                                                                                                  \
            }                                                                                                                      \
        } while (false)
#elif defined(NDEBUG)
#    define STATUSBAR_ASSERT(...) [[assume((__VA_ARGS__))]]
#else
#    define STATUSBAR_ASSERT(...)                                                                                                  \
        do {                                                                                                                       \
            assert((__VA_ARGS__));                                                                                                 \
            [[assume((__VA_ARGS__))]];                                                                                             \
        } while (false)
#endif
