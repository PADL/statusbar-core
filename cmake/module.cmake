# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Helper function to create a per-module static (or INTERFACE) library.
#
# Usage: statusbar_add_module( NAME            <module-name>            # e.g.
# "buffer" → target statusbar-buffer [SOURCES        <file>...]               #
# .cpp files; omit for INTERFACE [DEPS           <target>...]             #
# public statusbar-* deps [PRIVATE_DEPS   <target>...]             #
# private-only deps [INTERFACE]                              # header-only
# module [TESTS          <file>...])              # test .cpp files
#
# Always registers the created target into the global STATUSBAR_INSTALL_TARGETS
# property and sets its EXPORT_NAME to the module-name (so the exported alias
# becomes statusbar::<module-name>).

# Where the shared statusbar cmake files live — the core source tree for in-tree
# builds, or core-dev's installed lib/cmake/statusbar-core/ (this file travels
# with statusbar-coreConfig.cmake) for standalone dependents. Consumers use it
# to reach the bundled scripts (sm-docs-render.sh, ...).
set(STATUSBAR_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

# Build-helper modules (sanitizer/coverage/fuzzing options and the
# statusbar_register_* target helpers). Included here — the one file every
# package already includes — so a package configures under ANY toolchain (or
# none), instead of relying on a toolchain file to pull them in. The COMMAND
# guard makes this a no-op when an outer aggregate build (or a toolchain)
# already included them at a wider directory scope, which also keeps their flag
# appends from running twice.
if(NOT COMMAND statusbar_register_fuzz_targets)
  include(${CMAKE_CURRENT_LIST_DIR}/sanitizers.cmake)
  include(${CMAKE_CURRENT_LIST_DIR}/coverage.cmake)
  include(${CMAKE_CURRENT_LIST_DIR}/fuzzing.cmake)
  include(${CMAKE_CURRENT_LIST_DIR}/clang_tidy.cmake)
endif()

function(statusbar_add_module)
  cmake_parse_arguments(ARG "INTERFACE" "NAME"
                        "SOURCES;DEPS;PRIVATE_DEPS;TESTS" ${ARGN})

  if(NOT ARG_NAME)
    message(FATAL_ERROR "statusbar_add_module: NAME is required")
  endif()
  if(ARG_UNPARSED_ARGUMENTS)
    message(
      FATAL_ERROR
        "statusbar_add_module(${ARG_NAME}): unknown keyword(s): "
        "${ARG_UNPARSED_ARGUMENTS}. "
        "Valid keywords are NAME, SOURCES, DEPS, PRIVATE_DEPS, INTERFACE, TESTS."
    )
  endif()

  set(_target "statusbar-${ARG_NAME}")

  if(ARG_INTERFACE)
    add_library(${_target} INTERFACE)
    target_compile_features(${_target} INTERFACE cxx_std_23)
    set_target_properties(${_target} PROPERTIES CXX_EXTENSIONS OFF)
    target_include_directories(
      ${_target} INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
                           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    if(ARG_DEPS)
      target_link_libraries(${_target} INTERFACE ${ARG_DEPS})
    endif()
  else()
    add_library(${_target} STATIC ${ARG_SOURCES})
    target_compile_features(${_target} PUBLIC cxx_std_23)
    set_target_properties(${_target} PROPERTIES CXX_EXTENSIONS OFF)
    target_include_directories(
      ${_target} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
                        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    if(ARG_DEPS)
      target_link_libraries(${_target} PUBLIC ${ARG_DEPS})
    endif()
    if(ARG_PRIVATE_DEPS)
      target_link_libraries(${_target} PRIVATE ${ARG_PRIVATE_DEPS})
    endif()
  endif()

  # Register the target for install + set the export-side alias.
  set_target_properties(${_target} PROPERTIES EXPORT_NAME ${ARG_NAME})
  set_property(GLOBAL APPEND PROPERTY STATUSBAR_INSTALL_TARGETS ${_target})

  # Local-build alias for namespaced usage
  add_library(statusbar::${ARG_NAME} ALIAS ${_target})

  # Register test files
  if(ARG_TESTS)
    set(_abs_tests "")
    foreach(_t ${ARG_TESTS})
      if(IS_ABSOLUTE "${_t}")
        list(APPEND _abs_tests "${_t}")
      else()
        list(APPEND _abs_tests "${CMAKE_CURRENT_LIST_DIR}/${_t}")
      endif()
    endforeach()
    set_property(GLOBAL APPEND PROPERTY STATUSBAR_TEST_FILES ${_abs_tests})
  endif()
endfunction()

#
# SM documentation registry — decouples the workspace `docs-sm` target from the
# packages that own state-machine tools. A tool's own CMakeLists calls
# statusbar_register_sm_doc() with a package-relative docs directory; the
# top-level (aggregate) or standalone-package CMakeLists then calls
# statusbar_register_sm_docs_target() to build one `docs-sm` target from every
# registered pair, without naming any tool itself.
#

# Register one SM tool and the docs/sm/ directory its output is committed to.
# Entries are stored as "<tool>|<docs_dir>" ('|' because ';' is the CMake list
# separator and paths never contain '|').
function(statusbar_register_sm_doc tool docs_dir)
  set_property(GLOBAL APPEND PROPERTY STATUSBAR_SM_DOCS "${tool}|${docs_dir}")
endfunction()

# Create the `docs-sm` custom target from every registered pair. Call once,
# after all add_subdirectory() calls, passing the sm-docs-render.sh to use.
# No-op when a docs-sm target already exists (an outer aggregate build owns it)
# or when no tool registered.
function(statusbar_register_sm_docs_target)
  # Optional argument: the sm-docs-render.sh to use; defaults to the shared copy
  # beside this file.
  if(ARGC GREATER 0)
    set(render_script "${ARGV0}")
  else()
    set(render_script "${STATUSBAR_CMAKE_DIR}/sm-docs-render.sh")
  endif()
  if(TARGET docs-sm)
    return()
  endif()
  get_property(_sm_entries GLOBAL PROPERTY STATUSBAR_SM_DOCS)
  if(NOT _sm_entries)
    return()
  endif()
  set(_commands "")
  set(_tools "")
  foreach(_entry IN LISTS _sm_entries)
    string(REPLACE "|" ";" _pair "${_entry}")
    list(GET _pair 0 _tool)
    list(GET _pair 1 _docs_dir)
    list(APPEND _commands COMMAND ${render_script} $<TARGET_FILE:${_tool}>
         ${_docs_dir})
    list(APPEND _tools ${_tool})
  endforeach()
  add_custom_target(
    docs-sm
    ${_commands}
    DEPENDS ${_tools}
    COMMENT
      "Regenerating per-SM Markdown + SVG for every registered SM tool (needs graphviz)"
    VERBATIM USES_TERMINAL)
endfunction()

#
# Package boilerplate — the blocks below were previously duplicated verbatim in
# every package's CMakeLists. Each function runs in the CALLER's directory
# scope, so install()/add_test()/add_executable() attach to the package, not to
# this file.
#

# The head of every <pkg>/statusbar/CMakeLists.txt: the package INTERFACE
# library (standalone builds only — the aggregate provides a shared one), its
# include path, and the global accumulation properties.
function(statusbar_package_module_init)
  if(NOT STATUSBAR_AGGREGATE_BUILD)
    add_library(statusbar INTERFACE)
  endif()
  # This package's source root joins the package INTERFACE library's include
  # path so tools and examples can #include "statusbar/<dir>/..." headers from
  # this package. Under an aggregate the shared target accumulates the path from
  # every package.
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
  # A standalone build resets these per package. Under an outer aggregate build
  # the outer project initialises them once and lets them accumulate across
  # every aggregated package.
  if(NOT STATUSBAR_AGGREGATE_BUILD)
    set_property(GLOBAL PROPERTY STATUSBAR_TEST_FILES "")
    set_property(GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS "")
  endif()
endfunction()

# The tail of every <pkg>/statusbar/CMakeLists.txt: the standalone per-package
# statusbar_test binary built from every registered module test. Skipped under
# an outer aggregate build, where the outer project builds one combined
# statusbar_test from every aggregated package.
function(statusbar_package_test_binary)
  if(STATUSBAR_AGGREGATE_BUILD)
    return()
  endif()
  get_property(STATUSBAR_TEST_FILES_ABS GLOBAL PROPERTY STATUSBAR_TEST_FILES)
  set(STATUSBAR_TEST_FILES "")
  foreach(TEST_FILE_ABS ${STATUSBAR_TEST_FILES_ABS})
    file(RELATIVE_PATH TEST_FILE_REL "${PROJECT_SOURCE_DIR}" "${TEST_FILE_ABS}")
    list(APPEND STATUSBAR_TEST_FILES "${TEST_FILE_REL}")
  endforeach()
  list(SORT STATUSBAR_TEST_FILES)
  if(NOT STATUSBAR_TEST_FILES)
    return()
  endif()
  create_test_sourcelist(STATUSBAR_TEST_SOURCES statusbar_test.cpp
                         ${STATUSBAR_TEST_FILES})
  add_executable(statusbar_test ${CMAKE_CURRENT_BINARY_DIR}/statusbar_test.cpp
                                ${STATUSBAR_TEST_FILES_ABS})
  target_include_directories(statusbar_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(statusbar_test PRIVATE statusbar)
  foreach(TEST_FILE ${STATUSBAR_TEST_FILES})
    string(REPLACE ".cpp" "" TEST_NAME "${TEST_FILE}")
    add_test(NAME ${TEST_NAME} COMMAND statusbar_test ${TEST_NAME})
  endforeach()
  add_test(NAME statusbar_all_test COMMAND statusbar_test -A)
  # The -A run-all branch of CMake's create_test_sourcelist driver cannot fail:
  # it `return 0`s unconditionally, and it only prints "not ok" when a test
  # function returns -1 -- but TestRegister::run_section() returns 1. Judge the
  # run by the harness's own output instead of the driver's exit code: no FAIL:
  # line, and the run must reach the end (so a crash part-way through cannot
  # pass either).
  set_tests_properties(
    statusbar_all_test
    PROPERTIES FAIL_REGULAR_EXPRESSION "FAIL: " PASS_REGULAR_EXPRESSION
               "All tests finished\\.")
  statusbar_register_coverage_targets(statusbar_test)
endfunction()

# Give every installed executable a statusbar- prefixed on-disk name, so the
# bin/ directory is uniform (tools that set no OUTPUT_NAME, and examples, would
# otherwise install unprefixed).
function(statusbar_prefix_tool_names)
  get_property(_exe_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
  foreach(_t ${_exe_targets})
    if(NOT TARGET ${_t})
      continue()
    endif()
    get_target_property(_t_type ${_t} TYPE)
    if(NOT _t_type STREQUAL "EXECUTABLE")
      continue()
    endif()
    get_target_property(_t_name ${_t} OUTPUT_NAME)
    if(NOT _t_name)
      set(_t_name "${_t}")
    endif()
    if(NOT _t_name MATCHES "^statusbar-")
      string(REPLACE "_" "-" _t_name "${_t_name}")
      set_target_properties(${_t} PROPERTIES OUTPUT_NAME "statusbar-${_t_name}")
    endif()
  endforeach()
endfunction()

# The standalone install + export block every package carried verbatim: targets
# (runtime/devel components), the export set (installed AND exported into the
# build tree so a sibling package can use -Dstatusbar-<name>_DIR=<build-dir>
# without an install step), headers, the find_package() config + version files,
# and docs when present. Skipped under an outer aggregate build, which builds
# but does not install — the outer project owns the install set.
function(statusbar_package_install_export)
  cmake_parse_arguments(ARG "" "NAME" "" ${ARGN})
  if(NOT ARG_NAME)
    message(FATAL_ERROR "statusbar_package_install_export: NAME is required")
  endif()
  if(STATUSBAR_AGGREGATE_BUILD)
    return()
  endif()
  set(_pkg "statusbar-${ARG_NAME}")
  get_property(_install_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
  install(
    TARGETS ${_install_targets}
    EXPORT ${_pkg}Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT devel
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime)
  install(
    EXPORT ${_pkg}Targets
    FILE ${_pkg}Targets.cmake
    NAMESPACE statusbar::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${_pkg}
    COMPONENT devel)
  export(
    EXPORT ${_pkg}Targets
    FILE ${_pkg}Targets.cmake
    NAMESPACE statusbar::)
  install(
    DIRECTORY statusbar/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/statusbar
    COMPONENT devel
    FILES_MATCHING
    PATTERN "*.hpp"
    PATTERN "*.h")
  configure_package_config_file(
    cmake/${_pkg}Config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${_pkg}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${_pkg})
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${_pkg}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${_pkg}Config.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/${_pkg}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${_pkg}
    COMPONENT devel)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    install(
      DIRECTORY docs/
      DESTINATION ${CMAKE_INSTALL_DOCDIR}
      COMPONENT devel
      FILES_MATCHING
      PATTERN "*.md"
      PATTERN "*.svg"
      PATTERN "*.png")
  endif()
endfunction()

# The CPack variables every package sets identically. A MACRO, not a function:
# CPack reads plain variables from the scope that runs include(CPack), so they
# must land in the caller. The caller sets its package-specific variables
# (dependency floors, sections, control extras, ...) after this and then
# includes CPack itself. NO_RPM leaves every RPM variable unset and never
# appends the RPM generator (private DEB-only packages). Skipped under an outer
# aggregate build.
macro(statusbar_package_cpack_defaults)
  cmake_parse_arguments(_CPACK "NO_RPM" "NAME;DESCRIPTION" "" ${ARGN})
  if(NOT _CPACK_NAME)
    message(FATAL_ERROR "statusbar_package_cpack_defaults: NAME is required")
  endif()
  if(NOT STATUSBAR_AGGREGATE_BUILD)
    set(CPACK_PACKAGE_NAME "statusbar-${_CPACK_NAME}")
    set(CPACK_PACKAGE_VENDOR "Jeff Koftinoff")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${_CPACK_DESCRIPTION}")
    set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER
        "Jeff Koftinoff <jeff.koftinoff@statusbar.com>")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
      set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    endif()
    set(CPACK_DEB_COMPONENT_INSTALL ON)
    set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
    # Name DEB/RPM files the package-manager-conventional way
    # (<name>_<version>_<arch>.deb), so dependent builds and the orchestrator
    # locate them by package name.
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
    set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "statusbar-${_CPACK_NAME}")
    set(CPACK_COMPONENT_RUNTIME_DESCRIPTION
        "Command-line tools and executables")
    set(CPACK_COMPONENTS_ALL runtime devel)
    set(CPACK_DEBIAN_DEVEL_PACKAGE_NAME "statusbar-${_CPACK_NAME}-dev")
    set(CPACK_COMPONENT_DEVEL_DESCRIPTION
        "C++ headers, static libraries and CMake package config")
    set(CPACK_GENERATOR "TGZ;ZIP")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      list(APPEND CPACK_GENERATOR "DEB")
    endif()
    if(NOT _CPACK_NO_RPM)
      set(CPACK_RPM_PACKAGE_LICENSE "MIT")
      set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")
      set(CPACK_RPM_PACKAGE_AUTOREQ ON)
      set(CPACK_RPM_COMPONENT_INSTALL ON)
      set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
      set(CPACK_RPM_RUNTIME_PACKAGE_NAME "statusbar-${_CPACK_NAME}")
      set(CPACK_RPM_DEVEL_PACKAGE_NAME "statusbar-${_CPACK_NAME}-devel")
      if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        find_program(_rpmbuild rpmbuild)
        if(_rpmbuild)
          list(APPEND CPACK_GENERATOR "RPM")
        endif()
      endif()
    endif()
  endif()
endmacro()
