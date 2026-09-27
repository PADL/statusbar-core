#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// throw_or_abort: the single boundary where an error-as-value (Status /
/// std::error_code) is turned into a fatal failure. With C++ exceptions enabled
/// it throws std::system_error (existing behavior — callers may catch). Under
/// -fno-exceptions it logs the error to stderr and calls std::terminate(), so an
/// integrator can install a std::set_terminate() handler for controlled fault
/// behavior (watchdog reset, crash capture, ...).
///
/// This header holds the ONLY runtime `__cpp_exceptions` switch in the library;
/// every site that previously wrote `throw` calls one of these overloads, so the
/// whole tree compiles and runs with or without exceptions.

#include "statusbar/status/status.hpp"

#include <climits>
#include <cstdio>
#include <exception>
#include <string>
#include <string_view>
#include <system_error>

namespace statusbar {

/// Fatal failure carrying an error_code (and optional context string).
[[noreturn]] inline void throw_or_abort(std::error_code ec, std::string_view context = {})
{
#if __cpp_exceptions
    throw std::system_error(ec, std::string{context});
#else
    if (context.empty()) {
        std::fprintf(stderr, "fatal: %s\n", ec.message().c_str());
    } else {
        // %.*s takes an int: clamp rather than let a pathological context's
        // size wrap negative in the cast.
        auto const context_len = static_cast<int>(context.size() > INT_MAX ? INT_MAX : context.size());
        std::fprintf(stderr, "fatal: %.*s: %s\n", context_len, context.data(), ec.message().c_str());
    }
    std::terminate();
#endif
}

/// Convenience for a std::errc.
[[noreturn]] inline void throw_or_abort(std::errc ec, std::string_view context = {})
{
    throw_or_abort(std::make_error_code(ec), context);
}

/// Convenience for the result of statusbar::failure(...), which is a
/// std::unexpected<std::error_code>.
[[noreturn]] inline void throw_or_abort(std::unexpected<std::error_code> const& err, std::string_view context = {})
{
    throw_or_abort(err.error(), context);
}

}  // namespace statusbar
