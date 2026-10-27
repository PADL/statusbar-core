# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Optional `clang-tidy` aggregate target. Independent of the ENABLE_CLANG_TIDY
# in-compile integration (defined in toolchain-clang.cmake), this provides a
# separate `clang-tidy` make target that runs clang-tidy in parallel against
# compile_commands.json from the top-level build directory.
#
# Requires `clang-tidy` and `python3` on PATH. With clang-tidy's development
# headers installed, it also builds and loads the house-style plugin and reports
# statusbar-block-statements as warnings.
#
# Call statusbar_register_clang_tidy_target() once from the top-level
# CMakeLists.txt after all add_subdirectory() invocations.

function(statusbar_register_clang_tidy_target)
  if(TARGET clang-tidy)
    return()
  endif()
  # Prefer the toolchain's own clang-tidy (CMAKE_LLVM_PATH is set by
  # toolchain-clang.cmake) over whatever PATH offers: a PATH clang-tidy from a
  # different LLVM generation than the build compiler produces noisy or wrong
  # findings against this compile_commands.json.
  find_program(
    CLANG_TIDY_EXE
    NAMES clang-tidy
    HINTS "${CMAKE_LLVM_PATH}/bin")
  if(NOT CLANG_TIDY_EXE)
    return()
  endif()
  find_program(PYTHON3_EXE NAMES python3)
  if(NOT PYTHON3_EXE)
    return()
  endif()

  set(_scripts_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
  set(_jobs 8)
  set(_output "${CMAKE_BINARY_DIR}/clang-tidy-findings.txt")

  statusbar_tidy_plugin(_plugin)
  set(_plugin_env)
  set(_plugin_depends)
  if(_plugin)
    set(_plugin_env STATUSBAR_TIDY_PLUGIN=${_plugin})
    set(_plugin_depends statusbar-tidy-plugin)
  endif()
  add_custom_target(
    clang-tidy
    COMMAND
      ${CMAKE_COMMAND} -E env ${_plugin_env}
      ${_scripts_dir}/run-clang-tidy-all.sh ${CLANG_TIDY_EXE}
      ${CMAKE_BINARY_DIR} ${_jobs} ${_output}
    DEPENDS ${_plugin_depends}
    COMMENT
      "Running clang-tidy on every non-test .cpp from compile_commands.json (${_jobs} parallel jobs)"
    VERBATIM USES_TERMINAL)
endfunction()

# The house-style plugin (tidy/statusbar_tidy_block_statements.cpp), built
# against the clang-tidy binary's own LLVM and C++ library rather than the
# project toolchain's: `<out>` is its path, or empty when clang-tidy's
# development headers are not installed (libclang-dev).
function(statusbar_tidy_plugin out)
  set(${out}
      ""
      PARENT_SCOPE)
  get_filename_component(_bin "${CLANG_TIDY_EXE}" REALPATH)
  get_filename_component(_bin "${_bin}" DIRECTORY)
  find_program(
    _llvm_config
    NAMES llvm-config
    HINTS "${_bin}"
    NO_DEFAULT_PATH NO_CACHE)
  find_program(
    _clangxx
    NAMES clang++
    HINTS "${_bin}"
    NO_DEFAULT_PATH NO_CACHE)
  if(NOT _llvm_config OR NOT _clangxx)
    return()
  endif()
  execute_process(
    COMMAND ${_llvm_config} --includedir
    OUTPUT_VARIABLE _include
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT EXISTS "${_include}/clang-tidy/ClangTidyCheck.h")
    return()
  endif()
  execute_process(
    COMMAND ${_llvm_config} --cxxflags
    OUTPUT_VARIABLE _flags
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  separate_arguments(_flags UNIX_COMMAND "${_flags}")
  list(REMOVE_ITEM _flags -fno-exceptions)
  set(_source
      "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/tidy/statusbar_tidy_block_statements.cpp"
  )
  set(_plugin "${CMAKE_BINARY_DIR}/libstatusbar-tidy.so")
  add_custom_command(
    OUTPUT "${_plugin}"
    COMMAND ${_clangxx} ${_flags} -fPIC -shared -o "${_plugin}" "${_source}"
    DEPENDS "${_source}"
    COMMENT "clang-tidy plugin statusbar-block-statements"
    VERBATIM)
  # In the default build, so the pre-commit block-size gate finds it in a fresh
  # tree.
  add_custom_target(statusbar-tidy-plugin ALL DEPENDS "${_plugin}")
  set(${out}
      "${_plugin}"
      PARENT_SCOPE)
endfunction()
