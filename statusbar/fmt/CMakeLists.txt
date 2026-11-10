# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(NAME fmt INTERFACE TESTS fmt_test.cpp)
# The libc++ format_to overlay's test (cmake/toolchain-clang.cmake).
set_property(
  GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES
                         ${CMAKE_CURRENT_LIST_DIR}/fmt_format_to_test.cpp)
