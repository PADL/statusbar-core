# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  sm
  SOURCES
  sm_tool.cpp
  DEPS
  statusbar-args
  statusbar-config
  TESTS
  sm_test.cpp
  sm_dsl_test.cpp)
