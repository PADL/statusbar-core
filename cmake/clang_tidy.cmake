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

# Build the house-rule plugin (statusbar-block-statements) against the headers
# belonging to the very clang-tidy that will load it, and hand back its path. A
# plugin built against another LLVM generation does not load, so the include
# directory is derived from the binary rather than searched for.
#
# Those headers ship separately (clang-tools-extra-devel on Fedora,
# libclang-tidy-dev on Debian). Without them this returns an empty path and says
# so once: a plain build of this project has no business requiring a clang-tidy
# development package.
function(statusbar_build_tidy_plugin clang_tidy_exe out_plugin)
  set(${out_plugin}
      ""
      PARENT_SCOPE)
  # CMAKE_CURRENT_FUNCTION_LIST_DIR, as the target function below uses for its
  # scripts: it resolves to core/cmake wherever the caller lives, while
  # STATUSBAR_CMAKE_DIR belongs to the directory scope that included
  # module.cmake and is not visible from every package's top level.
  set(_src
      "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tidy/statusbar_tidy_block_statements.cpp"
  )
  if(NOT EXISTS "${_src}")
    return()
  endif()

  if(TARGET statusbar-tidy-block-statements)
    set(${out_plugin}
        "$<TARGET_FILE:statusbar-tidy-block-statements>"
        PARENT_SCOPE)
    return()
  endif()

  # <prefix>/bin/clang-tidy -> <prefix>/include/clang-tidy/...
  get_filename_component(_tidy_real "${clang_tidy_exe}" REALPATH)
  get_filename_component(_tidy_bin "${_tidy_real}" DIRECTORY)
  get_filename_component(_tidy_prefix "${_tidy_bin}" DIRECTORY)
  find_path(
    STATUSBAR_CLANG_TIDY_INCLUDE_DIR
    NAMES clang-tidy/ClangTidyCheck.h
    HINTS "${_tidy_prefix}/include"
    NO_DEFAULT_PATH)
  if(NOT STATUSBAR_CLANG_TIDY_INCLUDE_DIR)
    message(
      STATUS
        "clang-tidy headers not under ${_tidy_prefix}/include — house checks "
        "(statusbar-block-statements) skipped; install clang-tools-extra-devel "
        "to enable them")
    return()
  endif()

  add_library(statusbar-tidy-block-statements MODULE EXCLUDE_FROM_ALL "${_src}")
  target_include_directories(statusbar-tidy-block-statements SYSTEM
                             PRIVATE "${STATUSBAR_CLANG_TIDY_INCLUDE_DIR}")
  # Matching LLVM's own build, not this project's: no RTTI, and the standard
  # library clang-tidy was linked against. A plugin compiled against libc++
  # cannot hand a std::string to a libstdc++ clang-tidy.
  target_compile_options(statusbar-tidy-block-statements PRIVATE -fno-rtti
                                                                 -fPIC)
  if(NOT APPLE)
    target_compile_options(statusbar-tidy-block-statements
                           PRIVATE -stdlib=libstdc++)
    target_link_options(statusbar-tidy-block-statements PRIVATE
                        -stdlib=libstdc++)
  endif()
  # Undefined symbols are resolved out of the clang-tidy binary at load time, as
  # for any LLVM plugin. GNU ld allows that in a shared object by default; ld64
  # has to be told.
  if(APPLE)
    target_link_options(statusbar-tidy-block-statements PRIVATE
                        -Wl,-undefined,dynamic_lookup)
  endif()
  set_target_properties(
    statusbar-tidy-block-statements
    PROPERTIES CXX_STANDARD 20
               CXX_STANDARD_REQUIRED ON
               POSITION_INDEPENDENT_CODE ON
               PREFIX "")
  set(${out_plugin}
      "$<TARGET_FILE:statusbar-tidy-block-statements>"
      PARENT_SCOPE)
endfunction()

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

  statusbar_build_tidy_plugin("${CLANG_TIDY_EXE}" _plugin)

  add_custom_target(
    clang-tidy
    COMMAND ${_scripts_dir}/run-clang-tidy-all.sh ${CLANG_TIDY_EXE}
            ${CMAKE_BINARY_DIR} ${_jobs} ${_output} ${_plugin}
    COMMENT
      "Running clang-tidy on every non-test .cpp from compile_commands.json (${_jobs} parallel jobs)"
    VERBATIM USES_TERMINAL)
  if(_plugin)
    add_dependencies(clang-tidy statusbar-tidy-block-statements)
  endif()
endfunction()
