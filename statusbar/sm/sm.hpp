#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

//
// State Machine Module
//
// A modern C++23 compile-time state machine framework with:
// - Zero-overhead abstraction using constexpr transition tables
// - Compile-time reflection for enum/type/function names
// - Optional UCT (Unconditional Transition) handling
// - Optional per-state entry/exit hooks (UML ordering: exit -> action ->
//   entry; self-transitions re-run both; compiled out when unused)
// - Pluggable observers for instrumentation/logging
// - Compile-time DOT graph and Markdown table generation
// - Compile-time string DSL (sm_dsl.hpp): arrow-grammar text parsed by a
//   consteval front-end into the same TransitionTable
//
// Module structure:
//   :base     - Enum traits, reflection helpers, FixedString
//   :core     - Transition, TransitionTable, Observer, StateMachine
//   :dsl      - consteval string-grammar parser producing TransitionTable
//   :dot      - DOT graph generation
//   :markdown - Markdown table generation
//   :registry - Type-erased registry for documentation tools
//   :tool     - Reusable CLI tool for generating SM documentation

#include "statusbar/sm/sm_base.hpp"
#include "statusbar/sm/sm_core.hpp"
#include "statusbar/sm/sm_dot.hpp"
#include "statusbar/sm/sm_dsl.hpp"
#include "statusbar/sm/sm_markdown.hpp"
#include "statusbar/sm/sm_registry.hpp"
#include "statusbar/sm/sm_tool.hpp"

namespace statusbar::sm {}
