# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  realtime
  SOURCES
  realtime_base.cpp
  realtime_base_impl.cpp
  realtime_cpu_idle.cpp
  realtime_monotonic_raw_line.cpp
  realtime_timer_base.cpp
  realtime_timer_impl.cpp
  realtime_tripwire.cpp
  realtime_tripwire_impl.cpp
  DEPS
  statusbar-args
  statusbar-container
  statusbar-stats
  statusbar-itc
  statusbar-tsn
  TESTS
  realtime_base_test.cpp
  realtime_clock_test.cpp
  realtime_cpu_idle_test.cpp
  realtime_monotonic_raw_line_test.cpp
  realtime_stats_test.cpp
  realtime_timer_test.cpp
  realtime_tripwire_test.cpp)

add_executable(realtime_timer_example realtime_timer_example.cpp)
target_link_libraries(realtime_timer_example PRIVATE statusbar)
set_target_properties(realtime_timer_example
                      PROPERTIES OUTPUT_NAME statusbar-realtime-timer)
set_property(GLOBAL APPEND PROPERTY STATUSBAR_INSTALL_TARGETS
                                    realtime_timer_example)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # -static-libstdc++ was historically passed here but the toolchain forces
  # -stdlib=libc++, so libstdc++ is never linked in the first place — the flag
  # is a no-op. -static-libgcc still does useful work (pins the libgcc runtime
  # statically so the example can be dropped on a host without matching
  # libgcc_s).
  target_link_options(realtime_timer_example PRIVATE -static-libgcc)
endif()

add_core_fuzzer(${CMAKE_CURRENT_LIST_DIR}/realtime_cpu_list_fuzzer.cpp)
