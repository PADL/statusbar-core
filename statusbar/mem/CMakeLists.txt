# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  mem
  SOURCES
  mem_mapped_file.cpp
  DEPS
  statusbar::status
  TESTS
  mem_pmr_unique_test.cpp
  mem_mapped_file_test.cpp)
