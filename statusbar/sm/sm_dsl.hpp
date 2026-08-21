#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Compile-time string DSL for defining state machine transition tables.
///
/// A consteval parser turns an arrow-grammar description into the exact
/// TransitionTable<Def> the hand-written builder lambdas produce — same
/// engine, same DOT/Markdown generation, same observers. The grammar reads
/// like the transition list in a spec document (and like the DOT output the
/// library generates):
///
///   # comments run to end of line; blank lines are ignored
///   state Running { entry: start_stream, exit: stop_stream }
///
///   Idle    -> Running : Go   / log_go
///   Running -> Idle    : Stop
///   Running -> Running : Kick            # self-loop; hooks re-run
///   Start   -> Idle    : UCT  / init
///
/// Line forms:
///   FROM -> TO : EVENT [/ ACTION]          one transition per line
///   state NAME { entry: FN [, exit: FN] }  per-state hooks (either or both,
///                                          in either order, one line)
///
/// Name resolution is fully compile-time and needs no C++26 reflection:
///   - State and event names resolve through EnumNamesFor (the existing
///     source_location-based enum reflection in sm_base.hpp).
///   - Action and hook names resolve through a caller-supplied registry:
///     list the functions once and the names are extracted automatically:
///
///       using A = sm::DslActions<Def, init, log_go, start_stream, stop_stream>;
///       inline constexpr auto table = sm::parse_transition_table<Def, A>(R"(
///           ...grammar...
///       )");
///
/// Errors (unknown state/event/action name, syntax error, duplicate
/// transition or hook) fail the build: the parser calls a deliberately
/// non-constexpr function whose name states the problem, so the compiler's
/// constant-evaluation backtrace reads e.g. "call to non-constexpr function
/// 'statusbar::sm::detail::dsl_unknown_event_name'" at the offending
/// parse_transition_table call.
///
/// Phase 2 (when a P2996-reflection toolchain is adopted): the name
/// resolution internals swap to std::meta::enumerators_of / identifier_of —
/// the grammar and this API stay unchanged.

#include "statusbar/sm/sm_base.hpp"
#include "statusbar/sm/sm_core.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace statusbar::sm {

//
// Action registry
//

/// One DSL-resolvable action: a name and the function it binds to.
template <typename Context>
struct DslActionEntry
{
    std::string_view name{};
    void (*fn)(Context&, TimePoint){nullptr};
};

/// The action registry for a machine: list every transition action and
/// entry/exit hook function once; names are extracted at compile time via
/// function_name. Order does not matter.
template <typename Def, auto... Fns>
struct DslActions
{
    using Context = typename Def::Context;
    static constexpr std::array<DslActionEntry<Context>, sizeof...(Fns)> table{DslActionEntry<Context>{function_name<Fns>, Fns}...};
};

namespace detail {

// Deliberately non-constexpr: calling any of these during constant
// evaluation fails the build, and the function's name is the diagnostic.
[[noreturn]] inline void dsl_unknown_state_name()
{
    __builtin_trap();
}
[[noreturn]] inline void dsl_unknown_event_name()
{
    __builtin_trap();
}
[[noreturn]] inline void dsl_unknown_action_name()
{
    __builtin_trap();
}
[[noreturn]] inline void dsl_syntax_error()
{
    __builtin_trap();
}
[[noreturn]] inline void dsl_duplicate_transition()
{
    __builtin_trap();
}
[[noreturn]] inline void dsl_duplicate_hook()
{
    __builtin_trap();
}

consteval auto dsl_is_space(char c) -> bool
{
    return c == ' ' || c == '\t' || c == '\r';
}

consteval auto dsl_is_ident_char(char c) -> bool
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

consteval auto dsl_trim(std::string_view s) -> std::string_view
{
    while (!s.empty() && dsl_is_space(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && dsl_is_space(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

/// Cursor over one line of DSL text.
struct DslCursor
{
    std::string_view line;
    size_t pos{0};

    consteval void skip_spaces()
    {
        while (pos < line.size() && dsl_is_space(line[pos])) {
            ++pos;
        }
    }

    /// Read an identifier; empty result means "no identifier here".
    consteval auto read_ident() -> std::string_view
    {
        skip_spaces();
        size_t const start = pos;
        while (pos < line.size() && dsl_is_ident_char(line[pos])) {
            ++pos;
        }
        return line.substr(start, pos - start);
    }

    /// Consume an exact token (after skipping spaces); false if absent.
    consteval auto consume(std::string_view token) -> bool
    {
        skip_spaces();
        if (line.substr(pos).starts_with(token)) {
            pos += token.size();
            return true;
        }
        return false;
    }

    [[nodiscard]] consteval auto at_end() -> bool
    {
        skip_spaces();
        return pos >= line.size();
    }
};

/// Resolve an enum name via the EnumNamesFor reflection table.
template <typename E>
consteval auto dsl_state_value(std::string_view name) -> E
{
    using Names = EnumNamesFor<E, E::Count>;
    for (size_t i = 0; i < Names::size; ++i) {
        if (Names::names[i] == name) {
            return static_cast<E>(i);
        }
    }
    dsl_unknown_state_name();
}

template <typename E>
consteval auto dsl_event_value(std::string_view name) -> E
{
    using Names = EnumNamesFor<E, E::Count>;
    for (size_t i = 0; i < Names::size; ++i) {
        if (Names::names[i] == name) {
            return static_cast<E>(i);
        }
    }
    dsl_unknown_event_name();
}

/// Resolve an action/hook name via the caller's DslActions registry.
template <typename Actions>
consteval auto dsl_action(std::string_view name) -> DslActionEntry<typename Actions::Context>
{
    for (auto const& entry : Actions::table) {
        if (entry.name == name) {
            return entry;
        }
    }
    dsl_unknown_action_name();
}

/// Parse `FROM -> TO : EVENT [/ ACTION]` into the table.
template <typename Def, typename Actions>
consteval void dsl_parse_transition(TransitionTable<Def>& t, std::string_view line)
{
    using Context = typename Def::Context;
    using State = typename Def::State;

    DslCursor c{.line = line};
    auto const from_name = c.read_ident();
    if (from_name.empty() || !c.consume("->")) {
        dsl_syntax_error();
    }
    auto const to_name = c.read_ident();
    if (to_name.empty() || !c.consume(":")) {
        dsl_syntax_error();
    }
    auto const event_name = c.read_ident();
    if (event_name.empty()) {
        dsl_syntax_error();
    }

    Transition<Context, State> tr{};
    tr.next_state = dsl_state_value<State>(to_name);
    tr.valid = true;
    if (c.consume("/")) {
        auto const action_name = c.read_ident();
        if (action_name.empty()) {
            dsl_syntax_error();
        }
        auto const entry = dsl_action<Actions>(action_name);
        tr.action = entry.fn;
        tr.action_name = entry.name;
    }
    if (!c.at_end()) {
        dsl_syntax_error();
    }

    auto const from = dsl_state_value<State>(from_name);
    auto const event = dsl_event_value<typename Def::Event>(event_name);
    if (t.get(from, event).is_valid()) {
        dsl_duplicate_transition();
    }
    t.at(from, event) = tr;
}

/// Parse `state NAME { entry: FN [, exit: FN] }` (either or both keys,
/// either order) into the table's hook arrays.
template <typename Def, typename Actions>
consteval void dsl_parse_state_hooks(TransitionTable<Def>& t, std::string_view line)
{
    using State = typename Def::State;

    DslCursor c{.line = line};
    if (c.read_ident() != "state") {
        dsl_syntax_error();
    }
    auto const state_name = c.read_ident();
    if (state_name.empty() || !c.consume("{")) {
        dsl_syntax_error();
    }
    auto const state = dsl_state_value<State>(state_name);

    bool first = true;
    while (!c.consume("}")) {
        if (!first && !c.consume(",")) {
            dsl_syntax_error();
        }
        first = false;
        auto const key = c.read_ident();
        if (!c.consume(":")) {
            dsl_syntax_error();
        }
        auto const fn_name = c.read_ident();
        if (fn_name.empty()) {
            dsl_syntax_error();
        }
        auto const entry = dsl_action<Actions>(fn_name);
        if (key == "entry") {
            if (t.get_entry_hook(state).is_set()) {
                dsl_duplicate_hook();
            }
            t.on_entry(state) = StateHook<typename Def::Context>{.fn = entry.fn, .name = entry.name};
        } else if (key == "exit") {
            if (t.get_exit_hook(state).is_set()) {
                dsl_duplicate_hook();
            }
            t.on_exit(state) = StateHook<typename Def::Context>{.fn = entry.fn, .name = entry.name};
        } else {
            dsl_syntax_error();
        }
    }
    if (!c.at_end()) {
        dsl_syntax_error();
    }
}

}  // namespace detail

/// Parse a DSL description (see the file comment for the grammar) into a
/// TransitionTable<Def>. Evaluated entirely at compile time; any grammar or
/// name error fails the build via a named non-constexpr call.
template <typename Def, typename Actions = DslActions<Def>>
consteval auto parse_transition_table(std::string_view src) -> TransitionTable<Def>
{
    TransitionTable<Def> t{};

    size_t pos = 0;
    while (pos <= src.size()) {
        size_t eol = src.find('\n', pos);
        if (eol == std::string_view::npos) {
            eol = src.size();
        }
        std::string_view line = src.substr(pos, eol - pos);
        pos = eol + 1;

        auto const hash = line.find('#');
        if (hash != std::string_view::npos) {
            line = line.substr(0, hash);
        }
        line = detail::dsl_trim(line);
        if (line.empty()) {
            continue;
        }

        if (line.starts_with("state ") || line.starts_with("state\t")) {
            detail::dsl_parse_state_hooks<Def, Actions>(t, line);
        } else {
            detail::dsl_parse_transition<Def, Actions>(t, line);
        }
    }

    return t;
}

}  // namespace statusbar::sm
