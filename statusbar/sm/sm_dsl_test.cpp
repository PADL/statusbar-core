// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the compile-time string DSL: a DSL-parsed table must be
// cell-for-cell identical to the equivalent hand-built table (transitions,
// actions, action names, entry/exit hooks), the parser must tolerate
// comments and loose whitespace, and the resulting machine must run.

#include "statusbar/sm/sm_dsl.hpp"

#include "statusbar/sm/sm.hpp"
#include "statusbar/test/test.hpp"

#include <string>
#include <vector>

using namespace statusbar::sm;

namespace dsl_machine {

struct Context
{
    std::vector<std::string> trace{};
};

struct Def
{
    using Context = dsl_machine::Context;
    enum class State : uint8_t
    {
        Start = 0,
        Idle,
        Running,
        Count
    };
    enum class Event : uint8_t
    {
        UCT = 0,
        Go,
        Stop,
        Kick,
        Count
    };
};

inline void init(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("init");
}

inline void log_go(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("log_go");
}

inline void enter_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("enter_running");
}

inline void exit_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("exit_running");
}

using Actions = DslActions<Def, init, log_go, enter_running, exit_running>;

inline constexpr auto dsl_table = parse_transition_table<Def, Actions>(R"(
    # The demo machine from the sm module docs, DSL edition.
    state Running { entry: enter_running, exit: exit_running }

    Start   -> Idle    : UCT   / init
    Idle    -> Running : Go    / log_go
    Running -> Idle    : Stop
    Running -> Running : Kick          # self-loop: hooks re-run
)");

/// The same machine, built with the hand-written builder API.
inline constexpr auto hand_table = [] {
    using State = Def::State;
    using Event = Def::Event;
    using T = Transitions<Def>;

    TransitionTable<Def> t{};
    t.at(State::Start, Event::UCT) = T::action<init>(State::Idle);
    t.at(State::Idle, Event::Go) = T::action<log_go>(State::Running);
    t.at(State::Running, Event::Stop) = T::transition(State::Idle);
    t.at(State::Running, Event::Kick) = T::transition(State::Running);
    t.on_entry(State::Running) = T::hook<enter_running>();
    t.on_exit(State::Running) = T::hook<exit_running>();
    return t;
}();

/// Cell-for-cell table equivalence, checked at compile time.
consteval auto tables_identical(TransitionTable<Def> const& a, TransitionTable<Def> const& b) -> bool
{
    using State = Def::State;
    using Event = Def::Event;
    for (size_t s = 0; s < TransitionTable<Def>::num_states; ++s) {
        for (size_t e = 0; e < TransitionTable<Def>::num_events; ++e) {
            auto const& ta = a.get(static_cast<State>(s), static_cast<Event>(e));
            auto const& tb = b.get(static_cast<State>(s), static_cast<Event>(e));
            if (ta.valid != tb.valid || ta.next_state != tb.next_state || ta.action != tb.action ||
                ta.action_name != tb.action_name) {
                return false;
            }
        }
    }
    for (size_t s = 0; s < TransitionTable<Def>::num_states; ++s) {
        auto const& ea = a.get_entry_hook(static_cast<State>(s));
        auto const& eb = b.get_entry_hook(static_cast<State>(s));
        auto const& xa = a.get_exit_hook(static_cast<State>(s));
        auto const& xb = b.get_exit_hook(static_cast<State>(s));
        if (ea.fn != eb.fn || ea.name != eb.name || xa.fn != xb.fn || xa.name != xb.name) {
            return false;
        }
    }
    return true;
}

static_assert(tables_identical(dsl_table, hand_table), "DSL table must match the hand-built table exactly");

using Machine = StateMachine<Def, dsl_table>;
static_assert(Machine::has_hooks, "DSL hooks populate the table");

}  // namespace dsl_machine

TEST(sm_dsl, parsed_machine_runs_with_actions_and_hooks)
{
    dsl_machine::Context ctx;
    dsl_machine::Machine machine;

    // UCT: Start -> Idle (init); Go: Idle -> Running (log_go + entry hook)
    machine.handle_event(ctx, dsl_machine::Def::Event::Go);

    EXPECT_EQ(machine.current_state(), dsl_machine::Def::State::Running);
    EXPECT_EQ(ctx.trace.size(), 3);
    EXPECT_EQ(ctx.trace[0], "init");
    EXPECT_EQ(ctx.trace[1], "log_go");
    EXPECT_EQ(ctx.trace[2], "enter_running");
}

TEST(sm_dsl, self_loop_reruns_hooks)
{
    dsl_machine::Context ctx;
    dsl_machine::Machine machine;

    machine.handle_event(ctx, dsl_machine::Def::Event::Go);
    ctx.trace.clear();

    machine.handle_event(ctx, dsl_machine::Def::Event::Kick);

    EXPECT_EQ(ctx.trace.size(), 2);
    EXPECT_EQ(ctx.trace[0], "exit_running");
    EXPECT_EQ(ctx.trace[1], "enter_running");
}

TEST(sm_dsl, action_names_flow_into_docs)
{
    constexpr auto dot = generate_dot<dsl_machine::Machine>();
    auto const view = dot.view();
    EXPECT_TRUE(view.find("log_go") != std::string_view::npos);
    EXPECT_TRUE(view.find("<i>entry / enter_running()</i>") != std::string_view::npos);
    EXPECT_TRUE(view.find("<i>exit / exit_running()</i>") != std::string_view::npos);

    constexpr auto md = generate_markdown_table<dsl_machine::Machine>();
    EXPECT_TRUE(md.view().find("| Running | enter_running() | exit_running() |") != std::string_view::npos);
}

namespace dsl_whitespace {

using dsl_machine::Def;

// Same transitions, hostile formatting: tabs, packed tokens, trailing
// comments, no-space arrows.
inline constexpr auto table = parse_transition_table<Def, dsl_machine::Actions>(R"(
	state	Running	{	exit:	exit_running	,	entry:	enter_running	}
Start->Idle:UCT/init# packed
   Idle  ->  Running   :   Go / log_go   ###
Running->Idle:Stop
Running	->	Running	:	Kick
)");

static_assert(dsl_machine::tables_identical(table, dsl_machine::hand_table), "whitespace and comment variants parse identically");

}  // namespace dsl_whitespace

TEST(sm_dsl, whitespace_and_comment_tolerance)
{
    // The static_asserts above are the real test; confirm at runtime too.
    EXPECT_TRUE(dsl_machine::tables_identical(dsl_whitespace::table, dsl_machine::hand_table));
}

TEST_MAIN(statusbar_sm, sm_dsl_test)
