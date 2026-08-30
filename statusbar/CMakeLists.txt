include(${PROJECT_SOURCE_DIR}/cmake/module.cmake)

# Package INTERFACE library — re-exports every module target in this package's
# build. Module tool executables link `statusbar`. Under an outer aggregate
# build (STATUSBAR_AGGREGATE_BUILD), an outer project provides a single shared
# `statusbar` target covering all aggregated packages.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  add_library(statusbar INTERFACE)
endif()

# Add this package's source root to the package INTERFACE library's include path
# so tool and example sources can #include headers ("statusbar/<dir>/...") that
# live inside this package. Under an outer aggregate build the same target
# accumulates the include path from every package.
target_include_directories(statusbar
                           INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>)

define_property(
  GLOBAL
  PROPERTY STATUSBAR_TEST_FILES
  BRIEF_DOCS "test sources"
  FULL_DOCS "accumulated test sources")
define_property(
  GLOBAL
  PROPERTY STATUSBAR_INSTALL_TARGETS
  BRIEF_DOCS "install targets"
  FULL_DOCS "accumulated install targets")
# A standalone build resets these per package. Under an outer aggregate build,
# the outer project initialises them once and lets them accumulate across every
# aggregated package.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  set_property(GLOBAL PROPERTY STATUSBAR_TEST_FILES "")
  set_property(GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS "")
endif()

# Module subdirectories — dependency order.
add_subdirectory(status)
add_subdirectory(safe_arith)
add_subdirectory(secure_random)
add_subdirectory(fmt)
add_subdirectory(buffer)
add_subdirectory(ieee)
add_subdirectory(test)
add_subdirectory(stats)
add_subdirectory(benchmark)
add_subdirectory(tsn)
add_subdirectory(args)
add_subdirectory(config)
add_subdirectory(toml)
add_subdirectory(container)
add_subdirectory(pcap)
add_subdirectory(ip)
if(STATUSBAR_ENABLE_BPF)
  add_subdirectory(bpf)
endif()
add_subdirectory(colbin)
add_subdirectory(csv)
add_subdirectory(itc)
add_subdirectory(logging)
add_subdirectory(mem)
add_subdirectory(net)
add_subdirectory(http)
add_subdirectory(realtime)
add_subdirectory(sm)
add_subdirectory(tui)

# Populate the package INTERFACE library — skipped under an outer aggregate
# build, where the outer project populates a single shared `statusbar` covering
# every aggregated package.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  target_link_libraries(
    statusbar
    INTERFACE statusbar-status
              statusbar-safe_arith
              statusbar-secure_random
              statusbar-fmt
              statusbar-buffer
              statusbar-ieee
              statusbar-test
              statusbar-stats
              statusbar-benchmark
              statusbar-tsn
              statusbar-args
              statusbar-config
              statusbar-toml
              statusbar-container
              statusbar-pcap
              statusbar-ip
              statusbar-colbin
              statusbar-csv
              statusbar-itc
              statusbar-mem
              statusbar-net
              statusbar-http
              statusbar-realtime
              statusbar-sm
              statusbar-tui)
  if(STATUSBAR_ENABLE_BPF)
    target_link_libraries(statusbar INTERFACE statusbar-bpf)
  endif()
endif()

# Aggregate test binary built from every module's test sources. Skipped under an
# outer aggregate build, where the outer project builds one combined
# statusbar_test from every aggregated package.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  get_property(STATUSBAR_TEST_FILES_ABS GLOBAL PROPERTY STATUSBAR_TEST_FILES)
  set(STATUSBAR_TEST_FILES "")
  foreach(TEST_FILE_ABS ${STATUSBAR_TEST_FILES_ABS})
    file(RELATIVE_PATH TEST_FILE_REL "${PROJECT_SOURCE_DIR}" "${TEST_FILE_ABS}")
    list(APPEND STATUSBAR_TEST_FILES "${TEST_FILE_REL}")
  endforeach()
  list(SORT STATUSBAR_TEST_FILES)
  if(STATUSBAR_TEST_FILES)
    create_test_sourcelist(STATUSBAR_TEST_SOURCES statusbar_test.cpp
                           ${STATUSBAR_TEST_FILES})
    add_executable(statusbar_test ${CMAKE_CURRENT_BINARY_DIR}/statusbar_test.cpp
                                  ${STATUSBAR_TEST_FILES_ABS})
    target_include_directories(statusbar_test PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_link_libraries(statusbar_test PRIVATE statusbar)
    foreach(TEST_FILE ${STATUSBAR_TEST_FILES})
      string(REPLACE ".cpp" "" TEST_NAME "${TEST_FILE}")
      add_test(NAME ${TEST_NAME} COMMAND statusbar_test ${TEST_NAME})
    endforeach()
    add_test(NAME statusbar_all_test COMMAND statusbar_test -A)
    statusbar_register_coverage_targets(statusbar_test)
  endif()
endif()
