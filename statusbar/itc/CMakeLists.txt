# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  itc
  SOURCES
  itc_atomic_triple_buffer_base.cpp
  itc_stop_token.cpp
  TESTS
  itc_atomic_triple_buffer_base_test.cpp
  itc_atomic_triple_buffer_test.cpp
  itc_message_pipe_test.cpp
  itc_published_test.cpp
  itc_rt_callback_slot_test.cpp
  itc_spin_lock_test.cpp
  itc_stop_token_test.cpp
  itc_telemetry_counter_test.cpp)
