// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Compile-time format-string parsing for statusbar::fmt. The format string is
/// a non-type template parameter (detail::literal); worst_case<Fmt, Args...>()
/// is consteval and both validates the string against the argument types and
/// computes the exact worst-case output length used to size fixed_str<N>.
/// Any malformed spec, arg/type mismatch, or unsupported argument is a hard
/// compile error (a throw in a consteval context).

#pragma once

#include "statusbar/fmt/fmt_fixed_str.hpp"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace statusbar::fmt::detail {

/// Structural string-literal wrapper enabling the format string as an NTTP.
template <std::size_t N>
struct literal
{
    char data[N]{};
    consteval literal(char const (&s)[N]) noexcept
    {
        for (std::size_t i = 0; i < N; ++i) {
            data[i] = s[i];
        }
    }
    [[nodiscard]] constexpr std::string_view view() const noexcept
    {
        return std::string_view{data, N - 1};  // exclude trailing NUL
    }
};

/// Compile-time failure for the consteval validators below. With exceptions
/// enabled it throws (so the message surfaces in the compile error); under
/// -fno-exceptions it makes the enclosing constant evaluation ill-formed without
/// a throw expression, so the validators still compile. Either way an invalid
/// format string / argument is a hard compile error — never a runtime fault.
[[noreturn]] consteval void fail([[maybe_unused]] char const* message)
{
#if __cpp_exceptions
    throw message;
#else
    __builtin_unreachable();
#endif
}

/// Parsed field spec: ['0'] [width] type.
struct Spec
{
    std::size_t width = 0;
    bool zero = false;
    char type = '\0';  // '\0' == default
};

/// Parse a "{...}" field. `i` points at '{' (and is not "{{"). Fills `sp` and
/// returns the index just past '}'. (Caller validates a '}' was present by
/// checking the returned position; see worst_case.)
constexpr std::size_t parse_field(std::string_view f, std::size_t i, Spec& sp) noexcept
{
    sp = Spec{};
    ++i;  // past '{'
    if (i < f.size() && f[i] == ':') {
        ++i;
        if (i < f.size() && f[i] == '0') {
            sp.zero = true;
            ++i;
        }
        while (i < f.size() && f[i] >= '0' && f[i] <= '9') {
            sp.width = (sp.width * 10) + static_cast<std::size_t>(f[i] - '0');
            ++i;
        }
        if (i < f.size() && (f[i] == 'd' || f[i] == 'x' || f[i] == 'X' || f[i] == 'b' || f[i] == 'B' || f[i] == 's')) {
            sp.type = f[i];
            ++i;
        }
    }
    if (i < f.size() && f[i] == '}') {
        ++i;
    }
    return i;
}

enum class ArgKind : std::uint8_t
{
    integer,
    bounded_string,
    character,
    unsupported
};

struct ArgInfo
{
    ArgKind kind = ArgKind::unsupported;
    std::size_t size = 0;       // sizeof(T) for integer
    bool is_signed = false;     // for integer
    std::size_t str_bound = 0;  // for bounded_string / character
};

template <typename Arg>
consteval ArgInfo arg_info() noexcept
{
    using U = std::remove_cvref_t<Arg>;
    if constexpr (std::is_same_v<U, bool>) {
        return {.kind = ArgKind::unsupported};
    } else if constexpr (std::is_same_v<U, char>) {
        return {.kind = ArgKind::character, .str_bound = 1};
    } else if constexpr (std::is_integral_v<U>) {
        return {.kind = ArgKind::integer, .size = sizeof(U), .is_signed = std::is_signed_v<U>};
    } else if constexpr (std::is_bounded_array_v<U> && std::is_same_v<std::remove_extent_t<U>, char>) {
        return {.kind = ArgKind::bounded_string, .str_bound = std::extent_v<U> - 1};  // exclude NUL
    } else if constexpr (is_fixed_str<U>::value) {
        return {.kind = ArgKind::bounded_string, .str_bound = fixed_str_capacity<U>};
    } else {
        return {.kind = ArgKind::unsupported};
    }
}

/// Decimal digits in the largest magnitude of an integer of `bytes` bytes.
consteval std::size_t max_decimal_digits(std::size_t bytes) noexcept
{
    switch (bytes) {
        case 1:
            return 3;  // 255
        case 2:
            return 5;  // 65535
        case 4:
            return 10;  // 4294967295
        default:
            return 20;  // 18446744073709551615
    }
}

/// Worst-case length contributed by one field formatting one argument.
/// Validates the conversion type against the argument kind.
consteval std::size_t field_bound(Spec sp, ArgInfo a)
{
    char const t = sp.type;
    if (a.kind == ArgKind::integer) {
        if (t == 's') {
            fail("statusbar::fmt: {:s} used with an integer argument");
        }
        // Signed arguments emit a leading '-' in every base, so the bound
        // must include it or the most-negative values silently truncate.
        std::size_t const sign = a.is_signed ? 1 : 0;
        std::size_t natural = 0;
        if (t == 'x' || t == 'X') {
            natural = 2 * a.size + sign;
        } else if (t == 'b' || t == 'B') {
            natural = 8 * a.size + sign;
        } else {  // 'd' or default
            natural = max_decimal_digits(a.size) + sign;
        }
        return natural > sp.width ? natural : sp.width;
    }
    if (a.kind == ArgKind::bounded_string) {
        if (t != '\0' && t != 's') {
            fail("statusbar::fmt: numeric spec used with a string argument");
        }
        return a.str_bound > sp.width ? a.str_bound : sp.width;
    }
    if (a.kind == ArgKind::character) {
        if (t != '\0' && t != 's') {
            fail("statusbar::fmt: numeric spec used with a char argument");
        }
        return sp.width > 1 ? sp.width : 1;
    }
    fail("statusbar::fmt: unsupported argument type (use an integer, string "
         "literal, fixed_str, or char; not float/bool/pointer/string_view)");
}

/// consteval: validate Fmt against Args and return the exact worst-case length.
template <literal Fmt, typename... Args>
consteval std::size_t worst_case()
{
    std::string_view const f = Fmt.view();
    constexpr std::size_t NA = sizeof...(Args);
    std::array<ArgInfo, NA == 0 ? 1 : NA> info{};
    {
        std::size_t k = 0;
        ((info[k++] = arg_info<Args>()), ...);
    }

    std::size_t total = 0;
    std::size_t ai = 0;
    std::size_t i = 0;
    while (i < f.size()) {
        char const c = f[i];
        if (c == '{') {
            if (i + 1 < f.size() && f[i + 1] == '{') {
                total += 1;
                i += 2;
                continue;
            }
            if (ai >= NA) {
                fail("statusbar::fmt: more '{}' fields than arguments");
            }
            Spec sp;
            std::size_t const j = parse_field(f, i, sp);
            if (j == 0 || f[j - 1] != '}') {
                fail("statusbar::fmt: missing '}' in field");
            }
            total += field_bound(sp, info[ai]);
            ++ai;
            i = j;
        } else if (c == '}') {
            if (i + 1 < f.size() && f[i + 1] == '}') {
                total += 1;
                i += 2;
                continue;
            }
            fail("statusbar::fmt: stray '}' (use '}}' for a literal brace)");
        } else {
            total += 1;
            ++i;
        }
    }
    if (ai != NA) {
        fail("statusbar::fmt: more arguments than '{}' fields");
    }
    return total;
}

}  // namespace statusbar::fmt::detail
