# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  container
  INTERFACE
  TESTS
  container_flat_trie_test.cpp
  container_presentation_slot_map_test.cpp
  container_slot_table_test.cpp)
