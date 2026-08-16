#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/sm/sm_base.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <utility>

namespace statusbar::sm {

//
// Time Types
//

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

//
// Transition Structure
//

/// A transition entry: next state + optional action function pointer
/// Action functions receive context and event_time
template <typename Context, typename StateEnum>
struct Transition
{
    using ActionFn = void (*)(Context&, TimePoint);

    StateEnum next_state{};
    ActionFn action{nullptr};
    std::string_view action_name{};
    bool valid{false};  // Explicit validity flag - false means no transition defined

    [[nodiscard]] constexpr auto is_valid() const noexcept -> bool { return valid; }
};

/// Helper to create a transition with automatic action name extraction
template <typename Context, typename StateEnum, void (*ActionFn)(Context&, TimePoint)>
constexpr auto make_transition(StateEnum next_state) -> Transition<Context, StateEnum>
{
    return Transition<Context, StateEnum>{
        .next_state = next_state,
        .action = ActionFn,
        .action_name = function_name<ActionFn>,
        .valid = true,
    };
}

//
// State Hooks
//

/// Optional per-state entry/exit hook — same signature as transition actions.
/// A default-constructed hook (fn == nullptr) means "no hook".
template <typename Context>
struct StateHook
{
    using ActionFn = void (*)(Context&, TimePoint);

    ActionFn fn{nullptr};
    std::string_view name{};

    [[nodiscard]] constexpr auto is_set() const noexcept -> bool { return fn != nullptr; }
};

//
// Transitions Helper
//

/// Helper struct to create transitions for a specific definition type
/// Usage: using T = sm::Transitions<MyDef>;
///        t.at(...) = T::action<my_func>(State::Next);
///        t.at(...) = T::transition(State::Next);
template <typename Def>
struct Transitions
{
    using Context = Def::Context;
    using State = Def::State;

    /// Create a transition with an action
    /// Action functions receive (Context&, TimePoint)
    /// @param next_state State to transition to after executing the action
    template <void (*ActionFn)(Context&, TimePoint)>
    static constexpr auto action(State next_state) -> Transition<Context, State>
    {
        return Transition<Context, State>{
            .next_state = next_state,
            .action = ActionFn,
            .action_name = function_name<ActionFn>,
            .valid = true,
        };
    }

    /// Create a transition without an action
    /// @param next_state State to transition to
    static constexpr auto transition(State next_state) -> Transition<Context, State>
    {
        return Transition<Context, State>{
            .next_state = next_state,
            .action = nullptr,
            .action_name = {},
            .valid = true,
        };
    }

    /// Create a state entry/exit hook with automatic name extraction.
    /// Usage: t.on_entry(State::Running) = T::hook<start_stream>();
    template <void (*Fn)(Context&, TimePoint)>
    static constexpr auto hook() -> StateHook<Context>
    {
        return StateHook<Context>{.fn = Fn, .name = function_name<Fn>};
    }
};

//
// Transition Table
//

/// Transition table: 2D array of transitions indexed by [state][event]
/// Takes a Def struct that provides Context, State, Event
template <typename Def>
struct TransitionTable
{
    using Context = Def::Context;
    using State = Def::State;
    using Event = Def::Event;
    using TransitionType = Transition<Context, State>;

    static constexpr size_t num_states = enum_count<State>::value;
    static constexpr size_t num_events = enum_count<Event>::value;

    std::array<std::array<TransitionType, num_events>, num_states> data{};

    /// Optional per-state entry/exit hooks (UML semantics: a transition runs
    /// exit(old) -> action -> entry(new); self-transitions re-run both, the
    /// way an IEEE 802.1-style diagram re-executes a state box on re-entry).
    /// Default-empty, so tables that never set hooks behave exactly as before.
    std::array<StateHook<Context>, num_states> entry_hooks{};
    std::array<StateHook<Context>, num_states> exit_hooks{};

    constexpr auto at(State state, Event event) noexcept -> TransitionType&
    {
        return data[static_cast<size_t>(state)][static_cast<size_t>(event)];
    }

    [[nodiscard]] constexpr auto get(State state, Event event) const noexcept -> TransitionType const&
    {
        return data[static_cast<size_t>(state)][static_cast<size_t>(event)];
    }

    constexpr auto on_entry(State state) noexcept -> StateHook<Context>& { return entry_hooks[static_cast<size_t>(state)]; }

    constexpr auto on_exit(State state) noexcept -> StateHook<Context>& { return exit_hooks[static_cast<size_t>(state)]; }

    [[nodiscard]] constexpr auto get_entry_hook(State state) const noexcept -> StateHook<Context> const&
    {
        return entry_hooks[static_cast<size_t>(state)];
    }

    [[nodiscard]] constexpr auto get_exit_hook(State state) const noexcept -> StateHook<Context> const&
    {
        return exit_hooks[static_cast<size_t>(state)];
    }

    /// True when any state has an entry or exit hook set. Lets the engine
    /// compile the hook paths out entirely for hook-free machines.
    [[nodiscard]] constexpr auto any_hooks() const noexcept -> bool
    {
        for (auto const& h : entry_hooks) {
            if (h.is_set()) {
                return true;
            }
        }
        for (auto const& h : exit_hooks) {
            if (h.is_set()) {
                return true;
            }
        }
        return false;
    }
};

//
// Transition Observers
//

/// Default no-op observer - zero overhead when not observing
struct NullObserver
{
    template <typename State, typename Event>
    constexpr void operator()(
        State /*old_state*/, Event /*event*/, std::string_view /*action_name*/, State /*new_state*/) const noexcept
    {}
};

//
// State Machine
//

/// Standalone state machine - context is a separate struct passed by reference
/// Template parameters:
///   - Def: a struct providing Context, State, Event
///   - Table: the transition table (constexpr reference)
///   - Observer: callable with signature (State old, Event event, string_view action, State new)
template <typename Def, auto const& Table, typename Observer = NullObserver>
class StateMachine
{
  public:
    using Context = Def::Context;
    using State = Def::State;
    using Event = Def::Event;

    // Expose definition type name for DOT generation
    static constexpr std::string_view name = type_name<Def>;

    // Expose table and counts for generation utilities
    static constexpr auto const& table = Table;
    static constexpr size_t num_states = enum_count<State>::value;
    static constexpr size_t num_events = enum_count<Event>::value;
    static constexpr bool has_uct_event = HasUct<Event>;
    static constexpr bool has_hooks = Table.any_hooks();

    // Name lookup using EnumNamesFor
    using StateNames = EnumNamesFor<State, State::Count>;
    using EventNames = EnumNamesFor<Event, Event::Count>;
    static constexpr auto state_name = StateNames::get;
    static constexpr auto event_name = EventNames::get;

    constexpr explicit StateMachine(Observer obs = Observer{}) noexcept
        : observer_{obs}
    {}

    /// Handle an event, performing UCT chain before and after (if UCT is supported)
    /// event_time defaults to current time if not specified
    /// @param ctx Mutable reference to the state machine context
    /// @param event The event to process
    /// @param event_time Timestamp for the event (defaults to now)
    void handle_event(Context& ctx, Event event, TimePoint event_time = Clock::now())
    {
        if constexpr (has_uct_event) {
            process_uct_chain(ctx, event_time);
        }
        process_one_event(ctx, event, event_time);
        if constexpr (has_uct_event) {
            process_uct_chain(ctx, event_time);
        }
    }

    /// Get current state
    [[nodiscard]] constexpr auto current_state() const noexcept -> State { return state_; }

    /// Reset to initial state. A hard reset: no exit/entry hooks run — this
    /// is "teleport to the initial state", typically used in error recovery.
    constexpr void reset() noexcept { state_ = State{}; }

    /// Optionally announce startup: runs the current (initial) state's entry
    /// hook, then the UCT chain. Machines using the Start-state + UCT idiom
    /// get their real initial state's entry hook via that first UCT
    /// transition and don't need to call this.
    void start(Context& ctx, TimePoint event_time = Clock::now())
    {
        if constexpr (has_hooks) {
            auto const& entry_hook = Table.get_entry_hook(state_);
            if (entry_hook.is_set()) {
                entry_hook.fn(ctx, event_time);
            }
        }
        if constexpr (has_uct_event) {
            process_uct_chain(ctx, event_time);
        }
    }

  private:
    void process_one_event(Context& ctx, Event event, TimePoint event_time)
    {
        auto const& transition = Table.get(state_, event);
        if (!transition.is_valid()) {
            return;
        }
        State const old_state = state_;
        bool hooks_ran = false;
        // UML ordering: exit(old) -> transition action -> entry(new).
        // Self-transitions re-run both hooks (a diagram arrow looping back
        // into a state box re-executes the box on re-entry).
        if constexpr (has_hooks) {
            auto const& exit_hook = Table.get_exit_hook(old_state);
            if (exit_hook.is_set()) {
                exit_hook.fn(ctx, event_time);
                hooks_ran = true;
            }
        }
        if (transition.action != nullptr) {
            transition.action(ctx, event_time);
        }
        state_ = transition.next_state;
        if constexpr (has_hooks) {
            auto const& entry_hook = Table.get_entry_hook(state_);
            if (entry_hook.is_set()) {
                entry_hook.fn(ctx, event_time);
                hooks_ran = true;
            }
        }
        // Notify observer when the transition did something: the state
        // changed, an action ran, or a hook ran (self-transitions with an
        // action or hooks still notify). Pure no-op self-loops stay silent.
        if (old_state != state_ || transition.action != nullptr || hooks_ran) {
            observer_(old_state, event, transition.action_name, state_);
        }
    }

    void process_uct_chain(Context& ctx, TimePoint event_time)
        requires has_uct_event
    {
        constexpr Event uct_event = enum_uct<Event>::value;
        bool changed = false;
        do {
            auto old = state_;
            process_one_event(ctx, uct_event, event_time);
            changed = (old != state_);
        } while (changed);
    }

    State state_{};
    [[no_unique_address]] Observer observer_{};
};

}  // namespace statusbar::sm
