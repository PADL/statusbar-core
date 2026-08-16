// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Unit tests for State Machine module
// Tests state machines with and without UCT, DOT and Markdown generation

#include "statusbar/sm/sm.hpp"

#include "statusbar/sm/sm_test_support.hpp"
#include "statusbar/sm/sm_tool.hpp"
#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace statusbar::sm;

//
// Test State Machine WITH UCT (Unconditional Transitions)
//

namespace with_uct {

struct Context
{
    int action_count{0};
    std::string last_action{};
};

struct Def
{
    using Context = with_uct::Context;
    enum class State : uint8_t
    {
        Start = 0,
        Ready,
        Running,
        Stopped,
        Count
    };
    enum class Event : uint8_t
    {
        UCT = 0,
        Go,
        Stop,
        Reset,
        Count
    };
};

inline void initialize(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.action_count++;
    ctx.last_action = "initialize";
}

inline void start_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.action_count++;
    ctx.last_action = "start_running";
}

inline void stop_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.action_count++;
    ctx.last_action = "stop_running";
}

inline void do_reset(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.action_count++;
    ctx.last_action = "do_reset";
}

inline constexpr auto table = [] {
    using State = Def::State;
    using Event = Def::Event;
    using T = Transitions<Def>;

    TransitionTable<Def> t{};

    // UCT from Start -> Ready with initialize action
    t.at(State::Start, Event::UCT) = T::action<initialize>(State::Ready);

    // From Ready
    t.at(State::Ready, Event::Go) = T::action<start_running>(State::Running);
    t.at(State::Ready, Event::Reset) = T::transition(State::Ready);

    // From Running
    t.at(State::Running, Event::Stop) = T::action<stop_running>(State::Stopped);
    t.at(State::Running, Event::Reset) = T::action<do_reset>(State::Ready);

    // From Stopped
    t.at(State::Stopped, Event::Go) = T::action<start_running>(State::Running);
    t.at(State::Stopped, Event::Reset) = T::action<do_reset>(State::Ready);

    return t;
}();

using Machine = StateMachine<Def, table>;

}  // namespace with_uct

//
// Test State Machine WITHOUT UCT
//

namespace without_uct {

struct Context
{
    int value{0};
};

struct Def
{
    using Context = without_uct::Context;
    enum class State : uint8_t
    {
        Idle = 0,
        Active,
        Count
    };
    enum class Event : uint8_t
    {
        Activate = 0,
        Deactivate,
        Count
    };
};

inline void set_active(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.value = 1;
}

inline void set_idle(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.value = 0;
}

inline constexpr auto table = [] {
    using State = Def::State;
    using Event = Def::Event;
    using T = Transitions<Def>;

    TransitionTable<Def> t{};

    t.at(State::Idle, Event::Activate) = T::action<set_active>(State::Active);
    t.at(State::Active, Event::Deactivate) = T::action<set_idle>(State::Idle);

    return t;
}();

using Machine = StateMachine<Def, table>;

}  // namespace without_uct

//
// Test State Machine with an action-bearing SELF-transition
//

namespace self_action {

struct Context
{
    int ticks{0};
};

struct Def
{
    using Context = self_action::Context;
    enum class State : uint8_t
    {
        Running = 0,
        Count
    };
    enum class Event : uint8_t
    {
        Tick = 0,
        Count
    };
};

inline void on_tick(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.ticks++;
}

inline constexpr auto table = [] {
    using State = Def::State;
    using Event = Def::Event;
    using T = Transitions<Def>;

    TransitionTable<Def> t{};

    // Self-transition WITH an action: Running --Tick--> Running, runs on_tick.
    t.at(State::Running, Event::Tick) = T::action<on_tick>(State::Running);

    return t;
}();

using Machine = StateMachine<Def, table>;

}  // namespace self_action

//
// Test State Machine with entry/exit hooks
//

namespace with_hooks {

struct Context
{
    std::vector<std::string> trace{};
};

struct Def
{
    using Context = with_hooks::Context;
    enum class State : uint8_t
    {
        Begin = 0,
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

inline void enter_idle(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("enter_idle");
}

inline void enter_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("enter_running");
}

inline void exit_running(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("exit_running");
}

inline void go_action(Def::Context& ctx, TimePoint /*event_time*/)
{
    ctx.trace.emplace_back("go_action");
}

inline constexpr auto table = [] {
    using State = Def::State;
    using Event = Def::Event;
    using T = Transitions<Def>;

    TransitionTable<Def> t{};

    t.at(State::Begin, Event::UCT) = T::transition(State::Idle);
    t.at(State::Idle, Event::Go) = T::action<go_action>(State::Running);
    t.at(State::Running, Event::Stop) = T::transition(State::Idle);
    // Self-transition with no action: hooks alone make it observable
    t.at(State::Running, Event::Kick) = T::transition(State::Running);

    t.on_entry(State::Idle) = T::hook<enter_idle>();
    t.on_entry(State::Running) = T::hook<enter_running>();
    t.on_exit(State::Running) = T::hook<exit_running>();

    return t;
}();

using Machine = StateMachine<Def, table>;

}  // namespace with_hooks

//
// Recording Observer for Testing (shared utility)
//

using statusbar::sm::test::RecordingObserver;

//
// Static Assert Tests for Compile-time Verification
//

// extract_name tests
static_assert(extract_name("foo::bar::Baz") == "Baz", "extract last component");
static_assert(extract_name("Baz") == "Baz", "no :: returns input");
static_assert(extract_name("::Baz") == "Baz", "leading :: extracts correctly");
static_assert(extract_name("a::b") == "b", "simple namespace");
static_assert(extract_name("") == "", "empty string");

// enum_name tests
static_assert(enum_name<with_uct::Def::State::Start> == "Start", "enum_name Start");
static_assert(enum_name<with_uct::Def::State::Ready> == "Ready", "enum_name Ready");
static_assert(enum_name<with_uct::Def::State::Running> == "Running", "enum_name Running");
static_assert(enum_name<with_uct::Def::State::Stopped> == "Stopped", "enum_name Stopped");
static_assert(enum_name<with_uct::Def::Event::UCT> == "UCT", "enum_name UCT");
static_assert(enum_name<with_uct::Def::Event::Go> == "Go", "enum_name Go");
static_assert(enum_name<without_uct::Def::State::Idle> == "Idle", "enum_name Idle");
static_assert(enum_name<without_uct::Def::State::Active> == "Active", "enum_name Active");

// has_uct concept tests
static_assert(HasUct<with_uct::Def::Event>, "with_uct Event has UCT");
static_assert(!HasUct<without_uct::Def::Event>, "without_uct Event no UCT");
static_assert(!HasUct<with_uct::Def::State>, "State enum has no UCT");

// has_count concept tests
static_assert(HasCount<with_uct::Def::State>, "State has Count");
static_assert(HasCount<with_uct::Def::Event>, "Event has Count");
static_assert(HasCount<without_uct::Def::State>, "without_uct State has Count");
static_assert(HasCount<without_uct::Def::Event>, "without_uct Event has Count");

// enum_count trait tests
static_assert(enum_count<with_uct::Def::State>::value == 4, "with_uct State count");
static_assert(enum_count<with_uct::Def::Event>::value == 4, "with_uct Event count");
static_assert(enum_count<without_uct::Def::State>::value == 2, "without_uct State count");
static_assert(enum_count<without_uct::Def::Event>::value == 2, "without_uct Event count");

// enum_uct trait tests
static_assert(enum_uct<with_uct::Def::Event>::value == with_uct::Def::Event::UCT, "enum_uct value");

// EnumNamesFor tests
static_assert(with_uct::Machine::StateNames::size == 4, "StateNames size");
static_assert(with_uct::Machine::EventNames::size == 4, "EventNames size");
static_assert(without_uct::Machine::StateNames::size == 2, "without_uct StateNames size");

// FixedString compile-time tests
static_assert(
    [] {
        FixedString<16> s;
        return s.empty() && s.size() == 0;
    }(),
    "FixedString default empty");

static_assert(
    [] {
        FixedString<16> s;
        s.append("Hi");
        return s.size() == 2 && s.view() == "Hi";
    }(),
    "FixedString append string_view");

static_assert(
    [] {
        FixedString<16> s;
        s.append('X');
        return s.size() == 1 && s.view() == "X";
    }(),
    "FixedString append char");

static_assert(
    [] {
        FixedString<8> s;
        s.append("Hello World");  // Overflow - truncates at capacity-1
        return s.size() == 7;     // Capacity is 8, so max 7 chars
    }(),
    "FixedString overflow truncates");

// Transition validity tests
static_assert(
    [] {
        Transition<with_uct::Context, with_uct::Def::State> t{};
        return !t.is_valid();  // Default is invalid
    }(),
    "Default transition invalid");

static_assert(
    [] {
        using T = Transitions<with_uct::Def>;
        auto t = T::transition(with_uct::Def::State::Ready);
        return t.is_valid() && t.next_state == with_uct::Def::State::Ready && t.action == nullptr;
    }(),
    "Transitions::transition creates valid entry");

// TransitionTable compile-time tests
static_assert(TransitionTable<with_uct::Def>::num_states == 4, "TransitionTable num_states");
static_assert(TransitionTable<with_uct::Def>::num_events == 4, "TransitionTable num_events");

// StateMachine static members
static_assert(with_uct::Machine::num_states == 4, "Machine num_states");
static_assert(with_uct::Machine::num_events == 4, "Machine num_events");
static_assert(with_uct::Machine::has_uct_event, "Machine has_uct_event");
static_assert(!without_uct::Machine::has_uct_event, "Machine no UCT");

// DOT generation compile-time test
static_assert(generate_dot<with_uct::Machine>().size() > 100, "DOT generates content");
static_assert(generate_dot<without_uct::Machine>().size() > 50, "DOT small machine");

// Markdown generation compile-time test
static_assert(generate_markdown_table<with_uct::Machine>().size() > 100, "Markdown generates content");
static_assert(generate_markdown_table<without_uct::Machine>().size() > 50, "Markdown small machine");

//
// Base Partition Tests - Reflection
//

TEST(sm_base, enum_name_reflection)
{
    // Test enum name reflection
    EXPECT_EQ(enum_name<with_uct::Def::State::Start>, "Start");
    EXPECT_EQ(enum_name<with_uct::Def::State::Ready>, "Ready");
    EXPECT_EQ(enum_name<with_uct::Def::State::Running>, "Running");
    EXPECT_EQ(enum_name<with_uct::Def::State::Stopped>, "Stopped");
}

TEST(sm_base, enum_names_for)
{
    using StateNames = EnumNamesFor<with_uct::Def::State, with_uct::Def::State::Count>;

    EXPECT_EQ(StateNames::get(with_uct::Def::State::Start), "Start");
    EXPECT_EQ(StateNames::get(with_uct::Def::State::Ready), "Ready");
    EXPECT_EQ(StateNames::get(with_uct::Def::State::Running), "Running");
    EXPECT_EQ(StateNames::get(with_uct::Def::State::Stopped), "Stopped");
}

TEST(sm_base, type_name_reflection)
{
    // Type name should extract the short name
    EXPECT_EQ(type_name<with_uct::Def>, "Def");
    EXPECT_EQ(type_name<without_uct::Def>, "Def");
}

TEST(sm_base, has_uct_concept)
{
    // with_uct::Def::Event has UCT member
    static_assert(HasUct<with_uct::Def::Event>);

    // without_uct::Def::Event does NOT have UCT member
    static_assert(!HasUct<without_uct::Def::Event>);

    EXPECT_TRUE(true);  // Static asserts passed
}

TEST(sm_base, has_count_concept)
{
    // Both enums have Count member
    static_assert(HasCount<with_uct::Def::State>);
    static_assert(HasCount<with_uct::Def::Event>);
    static_assert(HasCount<without_uct::Def::State>);
    static_assert(HasCount<without_uct::Def::Event>);

    EXPECT_TRUE(true);  // Static asserts passed
}

TEST(sm_base, enum_count_trait)
{
    EXPECT_EQ(enum_count<with_uct::Def::State>::value, 4);
    EXPECT_EQ(enum_count<with_uct::Def::Event>::value, 4);
    EXPECT_EQ(enum_count<without_uct::Def::State>::value, 2);
    EXPECT_EQ(enum_count<without_uct::Def::Event>::value, 2);
}

TEST(sm_base, fixed_string)
{
    FixedString<32> str;
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.size(), 0);

    str.append("Hello");
    EXPECT_EQ(str.size(), 5);
    EXPECT_EQ(str.view(), "Hello");

    str.append(' ');
    str.append("World");
    EXPECT_EQ(str.view(), "Hello World");
}

TEST(sm_base, fixed_string_overflow)
{
    FixedString<8> str;
    str.append("Hello World!");  // 12 chars into 8-capacity buffer

    // Should truncate to capacity-1 (7 chars)
    EXPECT_EQ(str.size(), 7);
    EXPECT_EQ(str.view(), "Hello W");

    // Appending more should have no effect
    str.append('X');
    EXPECT_EQ(str.size(), 7);
    EXPECT_EQ(str.view(), "Hello W");
}

TEST(sm_base, enum_names_for_out_of_bounds)
{
    using StateNames = EnumNamesFor<with_uct::Def::State, with_uct::Def::State::Count>;

    // Valid indices
    EXPECT_EQ(StateNames::get(with_uct::Def::State::Start), "Start");
    EXPECT_EQ(StateNames::get(with_uct::Def::State::Stopped), "Stopped");

    // Out-of-bounds should return "UNKNOWN"
    EXPECT_EQ(StateNames::get(static_cast<with_uct::Def::State>(100)), "UNKNOWN");
    EXPECT_EQ(StateNames::get(static_cast<with_uct::Def::State>(255)), "UNKNOWN");
}

TEST(sm_base, extract_name_runtime)
{
    // Runtime verification of extract_name
    EXPECT_EQ(extract_name("foo::bar::Baz"), "Baz");
    EXPECT_EQ(extract_name("Baz"), "Baz");
    EXPECT_EQ(extract_name("::Baz"), "Baz");
    EXPECT_EQ(extract_name("a::b"), "b");
    EXPECT_EQ(extract_name(""), "");
    EXPECT_EQ(extract_name("::"), "");
}

//
// Core Partition Tests - State Machine with UCT
//

TEST(sm_core, initial_state_with_uct)
{
    with_uct::Context ctx;
    with_uct::Machine machine;

    // Before any event, state should be Start
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Start);
    EXPECT_EQ(ctx.action_count, 0);
}

TEST(sm_core, uct_auto_initialization)
{
    with_uct::Context ctx;
    with_uct::Machine machine;

    // First event should trigger UCT chain first (Start -> Ready via initialize)
    machine.handle_event(ctx, with_uct::Def::Event::Go);

    // Should have transitioned Start -> Ready (UCT) -> Running (Go)
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Running);
    EXPECT_EQ(ctx.action_count, 2);  // initialize + start_running
}

TEST(sm_core, transitions_with_uct)
{
    with_uct::Context ctx;
    with_uct::Machine machine;

    // Trigger UCT + Go
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Running);

    // Stop
    machine.handle_event(ctx, with_uct::Def::Event::Stop);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Stopped);
    EXPECT_EQ(ctx.last_action, "stop_running");

    // Reset back to Ready
    machine.handle_event(ctx, with_uct::Def::Event::Reset);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Ready);
    EXPECT_EQ(ctx.last_action, "do_reset");
}

TEST(sm_core, ignored_events_with_uct)
{
    with_uct::Context ctx;
    with_uct::Machine machine;

    // Trigger UCT + Go to get to Running
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    int count_before = ctx.action_count;

    // Go event in Running state should be ignored (no transition defined)
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Running);
    EXPECT_EQ(ctx.action_count, count_before);  // No action executed
}

TEST(sm_core, reset_state_machine)
{
    with_uct::Context ctx;
    with_uct::Machine machine;

    // Get to Running state
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Running);

    // Reset the state machine
    machine.reset();
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Start);
}

//
// Core Partition Tests - State Machine without UCT
//

TEST(sm_core, initial_state_without_uct)
{
    without_uct::Context ctx;
    without_uct::Machine machine;

    // State should remain Idle (no UCT to auto-advance)
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Idle);
    EXPECT_EQ(ctx.value, 0);
}

TEST(sm_core, transitions_without_uct)
{
    without_uct::Context ctx;
    without_uct::Machine machine;

    // Activate
    machine.handle_event(ctx, without_uct::Def::Event::Activate);
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Active);
    EXPECT_EQ(ctx.value, 1);

    // Deactivate
    machine.handle_event(ctx, without_uct::Def::Event::Deactivate);
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Idle);
    EXPECT_EQ(ctx.value, 0);
}

TEST(sm_core, ignored_events_without_uct)
{
    without_uct::Context ctx;
    without_uct::Machine machine;

    // Deactivate in Idle state should be ignored
    machine.handle_event(ctx, without_uct::Def::Event::Deactivate);
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Idle);

    // Activate to get to Active
    machine.handle_event(ctx, without_uct::Def::Event::Activate);
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Active);

    // Activate again in Active state should be ignored
    ctx.value = 99;  // Change value to verify no action
    machine.handle_event(ctx, without_uct::Def::Event::Activate);
    EXPECT_EQ(machine.current_state(), without_uct::Def::State::Active);
    EXPECT_EQ(ctx.value, 99);  // Value unchanged
}

//
// Core Partition Tests - Observer
//

TEST(sm_core, observer_records_transitions)
{
    using Obs = RecordingObserver<with_uct::Def>;
    std::vector<Obs::Transition> transitions;
    Obs obs{&transitions};

    with_uct::Context ctx;
    StateMachine<with_uct::Def, with_uct::table, Obs> machine{obs};

    // First event triggers UCT + Go
    machine.handle_event(ctx, with_uct::Def::Event::Go);

    // Should have recorded two transitions
    EXPECT_EQ(transitions.size(), 2);

    // First: Start -> Ready (UCT with initialize)
    EXPECT_EQ(transitions[0].old_state, with_uct::Def::State::Start);
    EXPECT_EQ(transitions[0].event, with_uct::Def::Event::UCT);
    EXPECT_EQ(transitions[0].action_name, "initialize");
    EXPECT_EQ(transitions[0].new_state, with_uct::Def::State::Ready);

    // Second: Ready -> Running (Go with start_running)
    EXPECT_EQ(transitions[1].old_state, with_uct::Def::State::Ready);
    EXPECT_EQ(transitions[1].event, with_uct::Def::Event::Go);
    EXPECT_EQ(transitions[1].action_name, "start_running");
    EXPECT_EQ(transitions[1].new_state, with_uct::Def::State::Running);
}

TEST(sm_core, observer_no_notification_on_ignored_event)
{
    using Obs = RecordingObserver<with_uct::Def>;
    std::vector<Obs::Transition> transitions;
    Obs obs{&transitions};

    with_uct::Context ctx;
    StateMachine<with_uct::Def, with_uct::table, Obs> machine{obs};

    // Get to Running state
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    size_t count_after_go = transitions.size();

    // Go in Running is ignored - should not record
    machine.handle_event(ctx, with_uct::Def::Event::Go);
    EXPECT_EQ(transitions.size(), count_after_go);
}

TEST(sm_core, noop_self_transition_no_observer_notification)
{
    // A self-transition with NO action (same state, no side effect) does NOT
    // notify the observer - there is nothing to report.
    using Obs = RecordingObserver<with_uct::Def>;
    std::vector<Obs::Transition> transitions;
    Obs obs{&transitions};

    with_uct::Context ctx;
    StateMachine<with_uct::Def, with_uct::table, Obs> machine{obs};

    // Get to Ready state (UCT transition)
    machine.handle_event(ctx, with_uct::Def::Event::Reset);

    // The table has: t.at(State::Ready, Event::Reset) = T::transition(State::Ready)
    // This is a self-transition (Ready -> Ready with no action)
    size_t count_after_uct = transitions.size();
    EXPECT_EQ(count_after_uct, 1);  // Just the UCT Start->Ready

    // Reset in Ready is a no-action self-transition
    machine.handle_event(ctx, with_uct::Def::Event::Reset);

    // Observer should NOT be notified (state didn't change and no action ran)
    EXPECT_EQ(transitions.size(), count_after_uct);
    EXPECT_EQ(machine.current_state(), with_uct::Def::State::Ready);
}

TEST(sm_core, action_self_transition_notifies_observer)
{
    // A self-transition WITH an action DOES notify the observer, even though
    // old_state == new_state - the action ran, so there is something to report.
    using Obs = RecordingObserver<self_action::Def>;
    std::vector<Obs::Transition> transitions;
    Obs obs{&transitions};

    self_action::Context ctx;
    StateMachine<self_action::Def, self_action::table, Obs> machine{obs};

    machine.handle_event(ctx, self_action::Def::Event::Tick, TimePoint{});

    EXPECT_EQ(transitions.size(), 1u);
    if (transitions.size() == 1) {
        EXPECT_EQ(transitions[0].old_state, self_action::Def::State::Running);
        EXPECT_EQ(transitions[0].new_state, self_action::Def::State::Running);
        EXPECT_EQ(transitions[0].action_name, "on_tick");
    }
    EXPECT_EQ(ctx.ticks, 1);
}

//
// DOT Generation Tests
//

TEST(sm_dot, generates_valid_dot)
{
    constexpr auto dot = generate_dot<with_uct::Machine>();

    std::string_view view = dot.view();

    // Should start with digraph
    EXPECT_TRUE(view.find("digraph") != std::string_view::npos);

    // Should contain state names
    EXPECT_TRUE(view.find("Start") != std::string_view::npos);
    EXPECT_TRUE(view.find("Ready") != std::string_view::npos);
    EXPECT_TRUE(view.find("Running") != std::string_view::npos);
    EXPECT_TRUE(view.find("Stopped") != std::string_view::npos);

    // Should contain event names
    EXPECT_TRUE(view.find("UCT") != std::string_view::npos);
    EXPECT_TRUE(view.find("Go") != std::string_view::npos);
    EXPECT_TRUE(view.find("Stop") != std::string_view::npos);

    // Should contain action names
    EXPECT_TRUE(view.find("initialize") != std::string_view::npos);
    EXPECT_TRUE(view.find("start_running") != std::string_view::npos);

    // Should end with closing brace
    EXPECT_TRUE(view.find("}") != std::string_view::npos);
}

TEST(sm_dot, start_state_is_point)
{
    constexpr auto dot = generate_dot<with_uct::Machine>();

    std::string_view view = dot.view();

    // Start state should be rendered as point
    EXPECT_TRUE(view.find("Start [shape=\"point\"]") != std::string_view::npos);
}

TEST(sm_dot, other_states_are_ellipse)
{
    constexpr auto dot = generate_dot<with_uct::Machine>();

    std::string_view view = dot.view();

    // Other states should be ellipses
    EXPECT_TRUE(view.find("Ready [shape=\"ellipse\"]") != std::string_view::npos);
    EXPECT_TRUE(view.find("Running [shape=\"ellipse\"]") != std::string_view::npos);
    EXPECT_TRUE(view.find("Stopped [shape=\"ellipse\"]") != std::string_view::npos);
}

TEST(sm_dot, compile_time_generation)
{
    // Verify DOT generation is constexpr
    constexpr auto dot = generate_dot<without_uct::Machine>();
    static_assert(dot.size() > 0);

    EXPECT_TRUE(dot.size() > 50);  // Should have some content
}

//
// Markdown Generation Tests
//

TEST(sm_markdown, generates_valid_table)
{
    constexpr auto md = generate_markdown_table<with_uct::Machine>();

    std::string_view view = md.view();

    // Should have header row with Event and state names
    EXPECT_TRUE(view.find("| Event |") != std::string_view::npos);
    EXPECT_TRUE(view.find("Start") != std::string_view::npos);
    EXPECT_TRUE(view.find("Ready") != std::string_view::npos);

    // Should have separator row
    EXPECT_TRUE(view.find("|-------|") != std::string_view::npos);

    // Should have event rows
    EXPECT_TRUE(view.find("| UCT |") != std::string_view::npos);
    EXPECT_TRUE(view.find("| Go |") != std::string_view::npos);
    EXPECT_TRUE(view.find("| Stop |") != std::string_view::npos);
}

TEST(sm_markdown, shows_no_transition_marker)
{
    constexpr auto md = generate_markdown_table<with_uct::Machine>();

    std::string_view view = md.view();

    // Should have -x- for cells with no transition
    EXPECT_TRUE(view.find("-x-") != std::string_view::npos);
}

TEST(sm_markdown, shows_action_names)
{
    constexpr auto md = generate_markdown_table<with_uct::Machine>();

    std::string_view view = md.view();

    // Should contain action names with ()
    EXPECT_TRUE(view.find("initialize()") != std::string_view::npos);
    EXPECT_TRUE(view.find("start_running()") != std::string_view::npos);
}

TEST(sm_markdown, shows_arrow_to_next_state)
{
    constexpr auto md = generate_markdown_table<with_uct::Machine>();

    std::string_view view = md.view();

    // Should have arrows pointing to next states
    EXPECT_TRUE(view.find("-> Ready") != std::string_view::npos);
    EXPECT_TRUE(view.find("-> Running") != std::string_view::npos);
}

TEST(sm_markdown, compile_time_generation)
{
    // Verify Markdown generation is constexpr
    constexpr auto md = generate_markdown_table<without_uct::Machine>();
    static_assert(md.size() > 0);

    EXPECT_TRUE(md.size() > 50);  // Should have some content
}

//
// Transition Table Tests
//

TEST(sm_core, transition_table_access)
{
    using State = with_uct::Def::State;
    using Event = with_uct::Def::Event;

    // Verify table access
    auto const& uct_start = with_uct::table.get(State::Start, Event::UCT);
    EXPECT_TRUE(uct_start.is_valid());
    EXPECT_EQ(uct_start.next_state, State::Ready);
    EXPECT_EQ(uct_start.action_name, "initialize");

    // Non-existent transition
    auto const& invalid = with_uct::table.get(State::Ready, Event::Stop);
    EXPECT_FALSE(invalid.is_valid());
}

TEST(sm_core, transitions_helper_with_action)
{
    using T = Transitions<with_uct::Def>;
    using State = with_uct::Def::State;

    auto trans = T::action<with_uct::initialize>(State::Ready);
    EXPECT_EQ(trans.next_state, State::Ready);
    EXPECT_TRUE(trans.action != nullptr);
    EXPECT_EQ(trans.action_name, "initialize");
    EXPECT_TRUE(trans.is_valid());
}

TEST(sm_core, transitions_helper_without_action)
{
    using T = Transitions<with_uct::Def>;
    using State = with_uct::Def::State;

    auto trans = T::transition(State::Ready);
    EXPECT_EQ(trans.next_state, State::Ready);
    EXPECT_TRUE(trans.action == nullptr);
    EXPECT_TRUE(trans.action_name.empty());
    EXPECT_TRUE(trans.is_valid());
}

//
// Machine Static Members Tests
//

TEST(sm_core, machine_static_members)
{
    // Verify static members are correctly set
    EXPECT_EQ(with_uct::Machine::num_states, 4);
    EXPECT_EQ(with_uct::Machine::num_events, 4);
    EXPECT_TRUE(with_uct::Machine::has_uct_event);

    EXPECT_EQ(without_uct::Machine::num_states, 2);
    EXPECT_EQ(without_uct::Machine::num_events, 2);
    EXPECT_FALSE(without_uct::Machine::has_uct_event);
}

TEST(sm_core, machine_name_lookup)
{
    // Verify name lookup functions work
    EXPECT_EQ(with_uct::Machine::state_name(with_uct::Def::State::Start), "Start");
    EXPECT_EQ(with_uct::Machine::state_name(with_uct::Def::State::Ready), "Ready");
    EXPECT_EQ(with_uct::Machine::event_name(with_uct::Def::Event::UCT), "UCT");
    EXPECT_EQ(with_uct::Machine::event_name(with_uct::Def::Event::Go), "Go");
}

// ===========================================================================
// DOT and Markdown generation tests (coverage for generate_dot/generate_markdown_table)
// ===========================================================================

TEST(sm_dot_gen, generate_dot_with_uct)
{
    auto dot = statusbar::sm::generate_dot<with_uct::Machine>();
    EXPECT_TRUE(!dot.empty());
    EXPECT_TRUE(dot.size() > 0);
    auto sv = dot.view();
    // DOT output should contain "digraph"
    EXPECT_TRUE(sv.find("digraph") != std::string_view::npos);
    // Should mention state names
    EXPECT_TRUE(sv.find("Start") != std::string_view::npos);
    EXPECT_TRUE(sv.find("Ready") != std::string_view::npos);
}

TEST(sm_dot_gen, generate_dot_without_uct)
{
    auto dot = statusbar::sm::generate_dot<without_uct::Machine>();
    EXPECT_TRUE(!dot.empty());
    auto sv = dot.view();
    EXPECT_TRUE(sv.find("digraph") != std::string_view::npos);
}

TEST(sm_markdown_gen, generate_markdown_with_uct)
{
    auto md = statusbar::sm::generate_markdown_table<with_uct::Machine>();
    EXPECT_TRUE(!md.empty());
    EXPECT_TRUE(md.size() > 0);
    auto sv = md.view();
    // Markdown table should contain "|" separators
    EXPECT_TRUE(sv.find("|") != std::string_view::npos);
    // Should mention state names
    EXPECT_TRUE(sv.find("Start") != std::string_view::npos);
}

TEST(sm_markdown_gen, generate_markdown_without_uct)
{
    auto md = statusbar::sm::generate_markdown_table<without_uct::Machine>();
    EXPECT_TRUE(!md.empty());
    auto sv = md.view();
    EXPECT_TRUE(sv.find("|") != std::string_view::npos);
}

//
// Tests: sm_registry (StateMachineInfo + make_sm_info + output_machine_to_file)
//

namespace {

auto sm_registry_temp_path(std::string_view suffix) -> std::filesystem::path
{
    char buf[96];
    std::snprintf(
        buf, sizeof(buf), "sm_registry_test_%d_%d_%.*s", ::getpid(), std::rand(), static_cast<int>(suffix.size()), suffix.data());
    return std::filesystem::temp_directory_path() / buf;
}

auto read_file_contents(std::filesystem::path const& p) -> std::string
{
    std::ifstream in(p);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

TEST(sm_registry, make_sm_info_populates_fields_without_reference)
{
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT State Machine");
    EXPECT_TRUE(info.symbol_name == "with_uct_sm");
    EXPECT_TRUE(info.human_name == "With UCT State Machine");
    EXPECT_TRUE(info.reference.empty());
    EXPECT_TRUE(info.output_to_stdout != nullptr);
    EXPECT_TRUE(info.output_to_file != nullptr);
}

TEST(sm_registry, make_sm_info_populates_fields_with_reference)
{
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT", "IEEE 1722.1-2021 Clause 8.2.3");
    EXPECT_TRUE(info.reference == "IEEE 1722.1-2021 Clause 8.2.3");
}

TEST(sm_registry, output_machine_to_file_writes_dot)
{
    auto const path = sm_registry_temp_path("dot");
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "WithUCT");

    bool const ok = info.output_to_file(OutputFormat::Dot, info.human_name, info.reference, path);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(std::filesystem::exists(path));

    auto const contents = read_file_contents(path);
    EXPECT_TRUE(contents.find("digraph") != std::string::npos);
    EXPECT_TRUE(contents.find("Start") != std::string::npos);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST(sm_registry, output_machine_to_file_writes_markdown_with_title)
{
    auto const path = sm_registry_temp_path("md");
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "WithUCT Title");

    bool const ok = info.output_to_file(OutputFormat::Markdown, info.human_name, info.reference, path);
    EXPECT_TRUE(ok);

    auto const contents = read_file_contents(path);
    EXPECT_TRUE(contents.find("# WithUCT Title") != std::string::npos);
    EXPECT_TRUE(contents.find('|') != std::string::npos);
    // Without a reference, no "Implements:" line should appear.
    EXPECT_TRUE(contents.find("Implements:") == std::string::npos);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST(sm_registry, output_machine_to_file_writes_markdown_with_reference)
{
    auto const path = sm_registry_temp_path("md_ref");
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "WithUCT", "RFC-XYZ Clause 4");

    bool const ok = info.output_to_file(OutputFormat::Markdown, info.human_name, info.reference, path);
    EXPECT_TRUE(ok);

    auto const contents = read_file_contents(path);
    EXPECT_TRUE(contents.find("**Implements:** RFC-XYZ Clause 4") != std::string::npos);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST(sm_registry, output_machine_to_file_returns_false_on_unwritable_path)
{
    constexpr auto info = make_sm_info<with_uct::Machine>("with_uct_sm", "WithUCT");
    std::filesystem::path const bad_path{"/nonexistent_dir_for_sm_registry_test/out.md"};
    bool const ok = info.output_to_file(OutputFormat::Markdown, info.human_name, info.reference, bad_path);
    EXPECT_FALSE(ok);
}

TEST(sm_registry, span_of_state_machine_info_iterates_all_entries)
{
    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
        make_sm_info<without_uct::Machine>("without_uct_sm", "Without UCT"),
    };
    std::span<StateMachineInfo const> span{registry};
    EXPECT_EQ(span.size(), 2U);
    EXPECT_TRUE(span[0].symbol_name == "with_uct_sm");
    EXPECT_TRUE(span[1].symbol_name == "without_uct_sm");

    // Type-erased call invokes the right specialization for each entry.
    auto const path0 = sm_registry_temp_path("span0");
    auto const path1 = sm_registry_temp_path("span1");
    EXPECT_TRUE(span[0].output_to_file(OutputFormat::Dot, span[0].human_name, span[0].reference, path0));
    EXPECT_TRUE(span[1].output_to_file(OutputFormat::Dot, span[1].human_name, span[1].reference, path1));

    auto const c0 = read_file_contents(path0);
    auto const c1 = read_file_contents(path1);
    // with_uct has 4 states (Start/Ready/Running/Stopped); without_uct has 2 (Idle/Active).
    EXPECT_TRUE(c0.find("Running") != std::string::npos);
    EXPECT_TRUE(c1.find("Idle") != std::string::npos);
    EXPECT_TRUE(c1.find("Running") == std::string::npos);

    std::error_code ec;
    std::filesystem::remove(path0, ec);
    std::filesystem::remove(path1, ec);
}

//
// Tests: sm_tool (detail helpers + end-to-end via argv)
//

TEST(sm_tool, should_output_empty_machines_means_all)
{
    SmToolConfig config;
    EXPECT_TRUE(detail::should_output(config, "anything"));
    EXPECT_TRUE(detail::should_output(config, ""));
}

TEST(sm_tool, should_output_filters_by_configured_machine_names)
{
    SmToolConfig config;
    config.machines = {"alpha", "beta"};
    EXPECT_TRUE(detail::should_output(config, "alpha"));
    EXPECT_TRUE(detail::should_output(config, "beta"));
    EXPECT_FALSE(detail::should_output(config, "gamma"));
    EXPECT_FALSE(detail::should_output(config, ""));
}

TEST(sm_tool, validate_machines_passes_when_all_names_known)
{
    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
        make_sm_info<without_uct::Machine>("without_uct_sm", "Without UCT"),
    };

    SmToolConfig config;
    config.machines = {"with_uct_sm"};
    EXPECT_TRUE(detail::validate_machines(config, registry));

    config.machines = {"with_uct_sm", "without_uct_sm"};
    EXPECT_TRUE(detail::validate_machines(config, registry));
}

TEST(sm_tool, validate_machines_fails_on_unknown_name)
{
    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
    };

    SmToolConfig config;
    config.machines = {"does_not_exist"};
    // Side effect: prints to stderr. We only assert the return value.
    EXPECT_FALSE(detail::validate_machines(config, registry));
}

TEST(sm_tool, has_help_arg_detects_all_help_forms)
{
    char prog[] = "sm_tool";
    {
        char a[] = "--help";
        char* argv[] = {prog, a};
        EXPECT_TRUE(detail::has_help_arg(2, argv));
    }
    {
        char a[] = "-h";
        char* argv[] = {prog, a};
        EXPECT_TRUE(detail::has_help_arg(2, argv));
    }
    {
        char a[] = "-help";
        char* argv[] = {prog, a};
        EXPECT_TRUE(detail::has_help_arg(2, argv));
    }
    {
        char a[] = "--format=dot";
        char* argv[] = {prog, a};
        EXPECT_FALSE(detail::has_help_arg(2, argv));
    }
    {
        char* argv[] = {prog};
        EXPECT_FALSE(detail::has_help_arg(1, argv));
    }
}

TEST(sm_tool, output_machines_writes_one_file_per_machine_into_directory)
{
    auto const out_dir = sm_registry_temp_path("tool_outdir");
    std::error_code ec;
    std::filesystem::remove_all(out_dir, ec);  // ensure clean start

    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
        make_sm_info<without_uct::Machine>("without_uct_sm", "Without UCT"),
    };

    SmToolConfig config;
    config.output_dir = out_dir.string();
    config.output_all_files = true;
    config.format = OutputFormat::Markdown;

    EXPECT_TRUE(detail::output_machines(config, registry));
    EXPECT_TRUE(std::filesystem::exists(out_dir / "with_uct_sm.md"));
    EXPECT_TRUE(std::filesystem::exists(out_dir / "without_uct_sm.md"));

    auto const c = read_file_contents(out_dir / "with_uct_sm.md");
    EXPECT_TRUE(c.find("With UCT") != std::string::npos);

    std::filesystem::remove_all(out_dir, ec);
}

TEST(sm_tool, output_machines_respects_machine_filter)
{
    auto const out_dir = sm_registry_temp_path("tool_filter");
    std::error_code ec;
    std::filesystem::remove_all(out_dir, ec);

    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
        make_sm_info<without_uct::Machine>("without_uct_sm", "Without UCT"),
    };

    SmToolConfig config;
    config.output_dir = out_dir.string();
    config.output_all_files = true;
    config.format = OutputFormat::Dot;
    config.machines = {"without_uct_sm"};

    EXPECT_TRUE(detail::output_machines(config, registry));
    EXPECT_FALSE(std::filesystem::exists(out_dir / "with_uct_sm.dot"));
    EXPECT_TRUE(std::filesystem::exists(out_dir / "without_uct_sm.dot"));

    std::filesystem::remove_all(out_dir, ec);
}

TEST(sm_tool, sm_tool_returns_zero_on_help_argument)
{
    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
    };

    char prog[] = "sm_tool";
    char help[] = "--help";
    char* argv[] = {prog, help};
    // Note: prints usage to stdout; functionally we only assert exit code.
    EXPECT_EQ(sm_tool(2, argv, registry), 0);
}

TEST(sm_tool, sm_tool_returns_nonzero_for_unknown_machine)
{
    constexpr auto registry = std::array{
        make_sm_info<with_uct::Machine>("with_uct_sm", "With UCT"),
    };

    char prog[] = "sm_tool";
    char arg[] = "--machine=missing";
    char* argv[] = {prog, arg};
    EXPECT_NE(sm_tool(2, argv, registry), 0);
}

//
// Entry / Exit hook tests
//

static_assert(!with_uct::Machine::has_hooks, "hook-free machine reports has_hooks == false");
static_assert(!without_uct::Machine::has_hooks, "hook-free machine reports has_hooks == false");
static_assert(with_hooks::Machine::has_hooks, "hooked machine reports has_hooks == true");

TEST(sm_hooks, uct_and_transition_fire_hooks_in_uml_order)
{
    with_hooks::Context ctx;
    with_hooks::Machine machine;

    // UCT chain: Begin -> Idle fires entry(Idle); then Go: Idle -> Running
    // fires go_action then entry(Running). Idle has no exit hook.
    machine.handle_event(ctx, with_hooks::Def::Event::Go);

    EXPECT_EQ(ctx.trace.size(), 3);
    EXPECT_EQ(ctx.trace[0], "enter_idle");
    EXPECT_EQ(ctx.trace[1], "go_action");
    EXPECT_EQ(ctx.trace[2], "enter_running");
    EXPECT_EQ(machine.current_state(), with_hooks::Def::State::Running);
}

TEST(sm_hooks, exit_runs_before_entry_on_transition)
{
    with_hooks::Context ctx;
    with_hooks::Machine machine;

    machine.handle_event(ctx, with_hooks::Def::Event::Go);
    ctx.trace.clear();

    // Running -> Idle: exit(Running) then entry(Idle)
    machine.handle_event(ctx, with_hooks::Def::Event::Stop);

    EXPECT_EQ(ctx.trace.size(), 2);
    EXPECT_EQ(ctx.trace[0], "exit_running");
    EXPECT_EQ(ctx.trace[1], "enter_idle");
    EXPECT_EQ(machine.current_state(), with_hooks::Def::State::Idle);
}

TEST(sm_hooks, self_transition_reruns_exit_and_entry)
{
    with_hooks::Context ctx;
    with_hooks::Machine machine;

    machine.handle_event(ctx, with_hooks::Def::Event::Go);
    ctx.trace.clear();

    // Kick loops Running -> Running with no action: the state box re-executes
    machine.handle_event(ctx, with_hooks::Def::Event::Kick);

    EXPECT_EQ(ctx.trace.size(), 2);
    EXPECT_EQ(ctx.trace[0], "exit_running");
    EXPECT_EQ(ctx.trace[1], "enter_running");
    EXPECT_EQ(machine.current_state(), with_hooks::Def::State::Running);
}

TEST(sm_hooks, hook_only_self_transition_notifies_observer)
{
    using Obs = RecordingObserver<with_hooks::Def>;
    std::vector<Obs::Transition> transitions;
    Obs obs{&transitions};

    with_hooks::Context ctx;
    StateMachine<with_hooks::Def, with_hooks::table, Obs> machine{obs};

    machine.handle_event(ctx, with_hooks::Def::Event::Go);
    size_t const count_after_go = transitions.size();

    // Kick has no action and no state change, but hooks ran -> notify
    machine.handle_event(ctx, with_hooks::Def::Event::Kick);

    EXPECT_EQ(transitions.size(), count_after_go + 1);
    EXPECT_EQ(transitions.back().old_state, with_hooks::Def::State::Running);
    EXPECT_EQ(transitions.back().new_state, with_hooks::Def::State::Running);
    EXPECT_TRUE(transitions.back().action_name.empty());
}

TEST(sm_hooks, start_runs_initial_entry_hook_and_uct_chain)
{
    with_hooks::Context ctx;
    with_hooks::Machine machine;

    // Begin has no entry hook; the UCT chain lands in Idle firing its hook
    machine.start(ctx);

    EXPECT_EQ(ctx.trace.size(), 1);
    EXPECT_EQ(ctx.trace[0], "enter_idle");
    EXPECT_EQ(machine.current_state(), with_hooks::Def::State::Idle);
}

TEST(sm_hooks, reset_is_hard_and_runs_no_hooks)
{
    with_hooks::Context ctx;
    with_hooks::Machine machine;

    machine.handle_event(ctx, with_hooks::Def::Event::Go);
    ctx.trace.clear();

    machine.reset();

    EXPECT_TRUE(ctx.trace.empty());
    EXPECT_EQ(machine.current_state(), with_hooks::Def::State::Begin);
}

TEST(sm_hooks, dot_renders_hooks_in_state_nodes)
{
    constexpr auto dot = generate_dot<with_hooks::Machine>();
    auto const view = dot.view();

    EXPECT_TRUE(view.find("<i>entry / enter_running()</i>") != std::string_view::npos);
    EXPECT_TRUE(view.find("<i>exit / exit_running()</i>") != std::string_view::npos);
    // Hook-free machines keep the plain node form
    constexpr auto plain = generate_dot<with_uct::Machine>();
    EXPECT_TRUE(plain.view().find("entry /") == std::string_view::npos);
}

TEST(sm_hooks, markdown_emits_state_hooks_table)
{
    constexpr auto md = generate_markdown_table<with_hooks::Machine>();
    auto const view = md.view();

    EXPECT_TRUE(view.find("| State | Entry | Exit |") != std::string_view::npos);
    EXPECT_TRUE(view.find("| Running | enter_running() | exit_running() |") != std::string_view::npos);
    EXPECT_TRUE(view.find("| Idle | enter_idle() | - |") != std::string_view::npos);

    // Hook-free machines emit no hooks table
    constexpr auto plain = generate_markdown_table<with_uct::Machine>();
    EXPECT_TRUE(plain.view().find("| State | Entry | Exit |") == std::string_view::npos);
}

// Main test runner function required by create_test_sourcelist
TEST_MAIN(statusbar_sm, sm_test)