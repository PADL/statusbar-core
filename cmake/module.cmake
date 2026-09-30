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
function(statusbar_register_sm_docs_target render_script)
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
