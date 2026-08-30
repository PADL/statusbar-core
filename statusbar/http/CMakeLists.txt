# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  http
  SOURCES
  http_parser.cpp
  http_server.cpp
  http_sha1.cpp
  http_static.cpp
  http_ws.cpp
  DEPS
  statusbar-net
  statusbar-toml
  TESTS
  http_alloc_gate_test.cpp
  http_handler_test.cpp
  http_parser_fuzz_test.cpp
  http_parser_test.cpp
  http_server_test.cpp
  http_static_test.cpp
  http_ws_test.cpp)

add_executable(http_server_example http_server_example.cpp)
target_link_libraries(http_server_example PRIVATE statusbar)
set_target_properties(http_server_example
                      PROPERTIES OUTPUT_NAME statusbar-http-server-example)

add_executable(http_bench_tool ${CMAKE_CURRENT_LIST_DIR}/http_bench_tool.cpp)
target_link_libraries(http_bench_tool PRIVATE statusbar)
set_target_properties(http_bench_tool PROPERTIES OUTPUT_NAME
                                                 statusbar-http-bench)

# Regression gate: enforced in optimized builds, reports SKIP otherwise.
add_test(NAME statusbar_http_bench_check COMMAND http_bench_tool --check)

# Runnable target for invoking the benchmark from the Makefile.
add_custom_target(
  run-http-bench
  COMMAND $<TARGET_FILE:http_bench_tool>
  DEPENDS http_bench_tool
  USES_TERMINAL)
add_dependencies(run-all-benches run-http-bench)
