#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// catch_or_status / run_guarded: the catch-direction boundary that turns an
/// escaping C++ exception back into an error-as-value (Status / StatusValue) or
/// contains it inside a worker thread. This is the inverse of throw_or_abort,
/// and like that header it is a centralized `__cpp_exceptions` switch — the only
/// place callers need to write try/catch. Under -fno-exceptions nothing can
/// throw, so the wrapped body is simply invoked (no try/catch is compiled).
///
/// Use `catch_or_status` to wrap a fallible call that returns a Status or
/// StatusValue<T>; use `run_guarded` at every std::thread/jthread entry point
/// (an exception escaping a thread entry calls std::terminate and aborts the
/// whole process — there is no caller to catch it).

#include "statusbar/status/status.hpp"

#include <climits>
#include <cstdio>
#include <exception>
#include <functional>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace statusbar {

/// Invoke `fn` and convert any escaping exception into an error-as-value.
///
/// `fn` must return a Status or StatusValue<T> (anything constructible from
/// statusbar::failure(...)). On a normal return its result is forwarded
/// unchanged. A thrown std::system_error keeps its .code() — so a value that was
/// turned into an exception by throw_or_abort(ec) round-trips back to
/// failure(ec). Any other exception maps to `ec_on_exception`.
///
/// Always noexcept: it is the boundary that guarantees no exception propagates
/// past it. Under -fno-exceptions the body is called directly.
template <typename Fn>
[[nodiscard]] auto catch_or_status(Fn&& fn, std::error_code ec_on_exception) noexcept -> std::invoke_result_t<Fn>
{
    using Result = std::invoke_result_t<Fn>;
    static_assert(
        std::is_constructible_v<Result, std::unexpected<std::error_code>>,
        "catch_or_status: fn must return a Status or StatusValue<T> (constructible from statusbar::failure(...))");
#if __cpp_exceptions
    try {
        // std::invoke, matching the std::invoke_result_t in the signature —
        // a bare fn() would reject the pointer-to-member callables the trait
        // accepts.
        return std::invoke(std::forward<Fn>(fn));
    } catch (std::system_error const& e) {
        return Result{failure(e.code())};
    } catch (...) {
        return Result{failure(ec_on_exception)};
    }
#else
    return std::invoke(std::forward<Fn>(fn));
#endif
}

/// Convenience overload: map any exception to a std::errc.
template <typename Fn>
[[nodiscard]] auto catch_or_status(Fn&& fn, std::errc ec_on_exception) noexcept -> std::invoke_result_t<Fn>
{
    return catch_or_status(std::forward<Fn>(fn), std::make_error_code(ec_on_exception));
}

/// Run a worker-thread body so that no exception can escape the thread entry
/// (which would call std::terminate and abort the process). Any exception is
/// logged with `thread_name` and swallowed; the thread then ends cleanly.
///
/// Logging uses std::fprintf (noexcept) deliberately: std::print/println can
/// throw, which inside the handler would re-escape and defeat the barrier.
/// Under -fno-exceptions the body is called directly.
template <typename Fn>
void run_guarded(std::string_view thread_name, Fn&& fn) noexcept
{
    // %.*s takes an int: clamp rather than let a pathological name's size
    // wrap negative in the cast.
    auto const name_len = static_cast<int>(thread_name.size() > INT_MAX ? INT_MAX : thread_name.size());
#if __cpp_exceptions
    try {
        std::invoke(std::forward<Fn>(fn));
    } catch (std::exception const& e) {
        std::fprintf(stderr, "%.*s exited via exception: %s\n", name_len, thread_name.data(), e.what());
    } catch (...) {
        std::fprintf(stderr, "%.*s exited via unknown exception\n", name_len, thread_name.data());
    }
#else
    std::invoke(std::forward<Fn>(fn));
#endif
}

}  // namespace statusbar
