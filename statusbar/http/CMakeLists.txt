# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  http
  SOURCES
  http_parser.cpp
  http_server.cpp
  http_static.cpp
  DEPS
  statusbar-net
  statusbar-toml
  TESTS
  http_parser_test.cpp
  http_server_test.cpp
  http_static_test.cpp)

add_executable(http_server_example http_server_example.cpp)
target_link_libraries(http_server_example PRIVATE statusbar)
set_target_properties(http_server_example
                      PROPERTIES OUTPUT_NAME statusbar-http-server-example)
