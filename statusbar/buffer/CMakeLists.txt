# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  buffer
  SOURCES
  buffer_error.cpp
  DEPS
  statusbar-status
  TESTS
  buffer_basic_test.cpp
  buffer_builder_test.cpp
  buffer_compiled_test.cpp
  buffer_deserializer_test.cpp
  buffer_protocol_test.cpp
  buffer_traits_test.cpp
  span_utils_test.cpp)

add_executable(buffer_bench_tool
               ${CMAKE_CURRENT_LIST_DIR}/buffer_bench_tool.cpp)
target_link_libraries(buffer_bench_tool PRIVATE statusbar)
set_target_properties(buffer_bench_tool PROPERTIES OUTPUT_NAME
                                                   statusbar-buffer-bench)

# Runnable target for invoking the benchmark from the Makefile.
add_custom_target(
  run-buffer-bench
  COMMAND $<TARGET_FILE:buffer_bench_tool>
  DEPENDS buffer_bench_tool
  USES_TERMINAL VERBATIM)
add_dependencies(run-all-benches run-buffer-bench)
