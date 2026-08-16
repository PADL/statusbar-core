#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/sm/sm_base.hpp"
#include "statusbar/sm/sm_core.hpp"

#include <cstddef>

namespace statusbar::sm {

/// Generate Markdown table from a StateMachine type
/// Columns: states, Rows: events
/// Cell format: action() (if any) / next_state, or "-x-" if no transition
/// When any state has entry/exit hooks, a "State hooks" table is emitted
/// above the transition table.
/// Template parameters:
///   - Machine: the StateMachine type (provides table, state_name, event_name, etc.)
///   - Capacity: maximum output size (default 16384)
template <typename Machine, size_t Capacity = 16384>
constexpr auto generate_markdown_table() -> FixedString<Capacity>
{
    FixedString<Capacity> out;

    // Optional state-hooks table (only when the machine defines any hooks)
    if constexpr (Machine::has_hooks) {
        out.append("| State | Entry | Exit |\n");
        out.append("|-------|-------|------|\n");
        for (size_t i = 0; i < Machine::num_states; ++i) {
            auto const state = static_cast<Machine::State>(i);
            auto const& entry_hook = Machine::table.get_entry_hook(state);
            auto const& exit_hook = Machine::table.get_exit_hook(state);
            if (!entry_hook.is_set() && !exit_hook.is_set()) {
                continue;
            }
            out.append("| ");
            out.append(Machine::state_name(state));
            out.append(" | ");
            if (entry_hook.is_set()) {
                out.append(entry_hook.name);
                out.append("()");
            } else {
                out.append("-");
            }
            out.append(" | ");
            if (exit_hook.is_set()) {
                out.append(exit_hook.name);
                out.append("()");
            } else {
                out.append("-");
            }
            out.append(" |\n");
        }
        out.append("\n");
    }

    // Header row: | Event | State1 | State2 | ...
    out.append("| Event |");
    for (size_t state = 0; state < Machine::num_states; ++state) {
        out.append(" ");
        out.append(Machine::state_name(static_cast<Machine::State>(state)));
        out.append(" |");
    }
    out.append("\n");

    // Separator row: |-------|--------|--------|...
    out.append("|-------|");
    for (size_t state = 0; state < Machine::num_states; ++state) {
        out.append("--------|");
    }
    out.append("\n");

    // Data rows: one per event
    for (size_t event = 0; event < Machine::num_events; ++event) {
        out.append("| ");
        out.append(Machine::event_name(static_cast<Machine::Event>(event)));
        out.append(" |");

        for (size_t state = 0; state < Machine::num_states; ++state) {
            auto const& t = Machine::table.get(static_cast<Machine::State>(state), static_cast<Machine::Event>(event));

            out.append(" ");
            if (!t.is_valid()) {
                out.append("-x-");
            } else {
                if (!t.action_name.empty()) {
                    out.append(t.action_name);
                    out.append("()<br/>");
                }
                out.append("-> ");
                out.append(Machine::state_name(t.next_state));
            }
            out.append(" |");
        }
        out.append("\n");
    }

    return out;
}

}  // namespace statusbar::sm
