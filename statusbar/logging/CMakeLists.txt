# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  logging
  INTERFACE
  DEPS
  statusbar-itc
  TESTS
  logging_test.cpp)

# Worked example: two RT-ish producer threads, one collector thread, stderr
# sink, runtime verbosity, and the drop-counting overflow policy.
add_executable(logging_example logging_example.cpp)
target_link_libraries(logging_example PRIVATE statusbar)
set_target_properties(logging_example PROPERTIES OUTPUT_NAME
                                                 statusbar-logging-example)
set_property(GLOBAL APPEND PROPERTY STATUSBAR_INSTALL_TARGETS logging_example)
