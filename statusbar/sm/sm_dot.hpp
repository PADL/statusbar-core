#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/sm/sm_base.hpp"
#include "statusbar/sm/sm_core.hpp"

#include <cstddef>

namespace statusbar::sm {

/// Generate DOT graph from a StateMachine type
/// Template parameters:
///   - Machine: the StateMachine type (provides table, state_name, event_name, name, etc.)
///   - Capacity: maximum output size (default 8192)
template <typename Machine, size_t Capacity = 8192>
constexpr auto generate_dot() -> FixedString<Capacity>
{
    FixedString<Capacity> out;

    out.append("digraph ");
    out.append(Machine::name);
    out.append(" {\n");
    out.append("    node [fontname=\"Arial\" fontsize=12];\n");
    out.append("    edge [fontname=\"Arial\" fontsize=7];\n");

    // First state (index 0) is rendered as a point (start marker)
    out.append("    ");
    out.append(Machine::state_name(static_cast<Machine::State>(0)));
    out.append(" [shape=\"point\"];\n");

    // Remaining states as ellipses; states with entry/exit hooks get them
    // rendered inside the node, per-state-box style.
    for (size_t i = 1; i < Machine::num_states; ++i) {
        auto const state = static_cast<Machine::State>(i);
        auto const& entry_hook = Machine::table.get_entry_hook(state);
        auto const& exit_hook = Machine::table.get_exit_hook(state);
        out.append("    ");
        out.append(Machine::state_name(state));
        if (entry_hook.is_set() || exit_hook.is_set()) {
            out.append(" [shape=\"ellipse\" label=<");
            out.append(Machine::state_name(state));
            if (entry_hook.is_set()) {
                out.append("<br/><i>entry / ");
                out.append(entry_hook.name);
                out.append("()</i>");
            }
            if (exit_hook.is_set()) {
                out.append("<br/><i>exit / ");
                out.append(exit_hook.name);
                out.append("()</i>");
            }
            out.append(">];\n");
        } else {
            out.append(" [shape=\"ellipse\"];\n");
        }
    }

    // Generate edges for all valid transitions
    for (size_t state = 0; state < Machine::num_states; ++state) {
        for (size_t event = 0; event < Machine::num_events; ++event) {
            auto const& t = Machine::table.get(static_cast<Machine::State>(state), static_cast<Machine::Event>(event));
            if (!t.is_valid()) {
                continue;
            }

            out.append("    ");
            out.append(Machine::state_name(static_cast<Machine::State>(state)));
            out.append(" -> ");
            out.append(Machine::state_name(t.next_state));
            out.append(" [label=<<u>");
            out.append(Machine::event_name(static_cast<Machine::Event>(event)));
            if (!t.action_name.empty()) {
                out.append("</u><br/>");
                out.append(t.action_name);
                out.append("()");
            } else {
                out.append("</u>");
            }
            out.append(">];\n");
        }
    }

    out.append("}\n");
    return out;
}

}  // namespace statusbar::sm
