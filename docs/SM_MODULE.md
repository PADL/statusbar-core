[← back to module index](README.md)

# sm

A C++23 compile-time finite state machine framework with zero-overhead
transitions, optional unconditional-transition (UCT) chains, pluggable
observers, and constexpr DOT/Markdown documentation generation.

## Overview

The shape of the machine — states, events, transition table — is fixed
at compile time; runtime overhead is an array lookup and an indirect
function call. You describe the machine with a `Def` struct naming a
`Context` type and `State` / `Event` enums (each ending in `Count`). A
`constexpr` `TransitionTable<Def>` holds the edges, populated through
`Transitions<Def>` so each action function pointer is paired with its
compile-time-reflected name. `StateMachine<Def, table>` instances carry
only the current state byte plus an optional observer.

`handle_event()` looks up the `(state, event)` slot, calls the action,
advances the state, and notifies the observer when the transition does
something — the state changed or an action ran. If `Event::UCT` is
present the machine also auto-fires that event in a chain before and
after each external event — a state can declare "as soon as you arrive,
immediately move on with this action."

Because the table and enum names are compile-time data,
`generate_dot()` and `generate_markdown_table()` render documentation as
constexpr `FixedString` blobs. The `:registry` and `:tool` layers
type-erase a heterogeneous set of machines so a single binary can dump
DOT or Markdown for every machine in a project.

## Key types

The module header `sm.hpp` partitions the module into six layers; the
types below are grouped to match.

- **:base** — `HasUct` / `HasCount` concepts and `enum_uct` /
  `enum_count` traits; `enum_name<V>` / `type_name<T>` /
  `function_name<F>` constexpr reflections on `std::source_location`;
  `EnumNamesFor<E, Count>`; `FixedString<Capacity>`.
- **:core** — `Clock` / `TimePoint` (`std::chrono::steady_clock`, the
  control-plane clock, deliberately not `CLOCK_MONOTONIC_RAW`: a machine
  is told its `TimePoint` and never reads the clock itself); `Transition<Context, StateEnum>`
  (next state + action pointer + reflected name + valid flag);
  `Transitions<Def>` helper exposing `action<Fn>()` and `transition()`;
  `TransitionTable<Def>` indexed by `[state][event]`; `NullObserver`;
  `StateMachine<Def, Table, Observer>` with `handle_event()`,
  `current_state()`, and `reset()`.
- **:dot** — `generate_dot<Machine, Capacity>()` returns Graphviz source
  as a `FixedString`.
- **:markdown** — `generate_markdown_table<Machine, Capacity>()` returns
  a state-vs-event table.
- **:registry** — `OutputFormat` enum, `StateMachineInfo` type-erased
  descriptor, and the `make_sm_info<Machine>(symbol, human)` consteval
  factory.
- **:tool** — `SmToolConfig` and `sm_tool(argc, argv, machines)` (span
  and `std::array` overloads) wire the registry into `args` to produce
  a documentation binary.

## Quick example

```cpp
#include "statusbar/sm/sm.hpp"
using namespace statusbar::sm;

struct Light {
    struct Context { int toggles{0}; };
    enum class State : uint8_t { Off = 0, On, Count };
    enum class Event : uint8_t { Flip = 0, Count };
};
inline void on_flip(Light::Context& ctx, TimePoint) { ++ctx.toggles; }

inline constexpr auto light_table = [] {
    using T = Transitions<Light>;
    TransitionTable<Light> t{};
    t.at(Light::State::Off, Light::Event::Flip) = T::action<on_flip>(Light::State::On);
    t.at(Light::State::On,  Light::Event::Flip) = T::action<on_flip>(Light::State::Off);
    return t;
}();

int main() {
    StateMachine<Light, light_table> sm;
    Light::Context ctx;
    sm.handle_event(ctx, Light::Event::Flip);  // Off -> On
    sm.handle_event(ctx, Light::Event::Flip);  // On  -> Off
    return ctx.toggles == 2 ? 0 : 1;
}
```

## Headers

- `statusbar/sm/sm.hpp` — module header; consumers usually `#include` only this.
- `statusbar/sm/sm_base.hpp` — enum traits, source-location reflection, `FixedString`.
- `statusbar/sm/sm_core.hpp` — `Transition`, `Transitions`, `TransitionTable`, `NullObserver`, `StateMachine`.
- `statusbar/sm/sm_dot.hpp` — `generate_dot()`.
- `statusbar/sm/sm_markdown.hpp` — `generate_markdown_table()`.
- `statusbar/sm/sm_registry.hpp` — `OutputFormat`, `StateMachineInfo`, `make_sm_info()`.
- `statusbar/sm/sm_tool.hpp` — `SmToolConfig` and `sm_tool()`.
- `statusbar/sm/sm_test_support.hpp` — test-only helpers (namespace `statusbar::sm::test`): `RecordingObserver` (full transition log), `ActionRecorder` (most recent action name), and the `Observed<Def, Table>` machine+recorder fixture.

## Dependencies

- **Statusbar modules:** [`args`](ARGS_MODULE.md) — used by `sm_tool.hpp` to build its CLI.
- **System / external:** `<source_location>` drives the compile-time name reflection; `<chrono>` provides `Clock` / `TimePoint`; the registry/tool layers also use `<filesystem>`, `<fstream>`, `<print>`, `<span>`, `<expected>`, `<vector>`, `<string>`.

## Notes & caveats

- `State` and `Event` enums must end with a `Count` member; `enum_count`
  reads dimensions from it, so don't leave gaps below `Count`.
- Naming `UCT` opts in to automatic chains. `handle_event()` fires UCT
  before and after every external event and keeps firing until the
  state stops changing — don't build UCT cycles.
- Slots default to `valid == false`; an unmatched event is silently
  ignored — no "unhandled event" callback.
- Observers fire when a transition does something: the state changed or
  an action ran. A self-transition that runs an action still notifies
  (the observer sees `old_state == new_state`); only a no-op self-loop
  (same state, no action) is invisible to the observer.
- A machine is **told the time**: `handle_event(ctx, event, now)` and
  `start(ctx, now)` take the `TimePoint` of the frame or tick being
  handled, and every action receives it. The defaulted `Clock::now()`
  argument is for setup and edge calls that own no tick; production
  drivers (reactor handlers, timers) always pass the time they were
  told. See core's [TIME_POLICY.md](TIME_POLICY.md).
- Actions have signature `void(Context&, TimePoint)`. The name shown in
  DOT/Markdown comes from `function_name<Fn>`, which parses
  `std::source_location::current().function_name()` for both Clang and
  GCC mangling.
- `generate_dot()` and `generate_markdown_table()` write into a
  `FixedString<Capacity>`; overflow is silently truncated. Bump
  `Capacity` (defaults 8192 / 16384) for large machines.
- `generate_dot()` renders state index 0 as a Graphviz `point` (entry
  marker) — order the `State` enum with the start state at 0.
- `StateMachine` stores `[[no_unique_address]] Observer`, so
  `NullObserver` costs zero bytes. The `Table` non-type parameter is a
  reference; declare the table at namespace scope so it has linkage.

## Further reading

- [`args`](ARGS_MODULE.md) — CLI argument layer used by `sm_tool`.
