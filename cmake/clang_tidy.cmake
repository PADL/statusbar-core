# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Optional `clang-tidy` aggregate target. Independent of the ENABLE_CLANG_TIDY
# in-compile integration (defined in toolchain-clang.cmake), this provides a
# separate `clang-tidy` make target that runs clang-tidy in parallel against
# compile_commands.json from the top-level build directory.
#
# Requires `clang-tidy` and `python3` on PATH.
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

  add_custom_target(
    clang-tidy
    COMMAND ${_scripts_dir}/run-clang-tidy-all.sh ${CLANG_TIDY_EXE}
            ${CMAKE_BINARY_DIR} ${_jobs} ${_output}
    COMMENT
      "Running clang-tidy on every non-test .cpp from compile_commands.json (${_jobs} parallel jobs)"
    VERBATIM USES_TERMINAL)
endfunction()
