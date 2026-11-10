# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# libFuzzer detection and configuration. Defaults OFF; enable with
# -DENABLE_FUZZING=ON (Clang on Linux). On Apple each package's add_*_fuzzer()
# builds the fuzzer source as a plain executable, which does not link yet.
option(ENABLE_FUZZING
       "Enable fuzzing toolchain defaults (try to locate libFuzzer)" OFF)

if(ENABLE_FUZZING)
  message(STATUS "Fuzzing toolchain enabled")

  # Clang provides built-in fuzzer support via -fsanitize=fuzzer that's always
  # available and compatible with our stdlib=libc++ setting
  message(
    STATUS
      "Using clang built-in fuzzer support via -fsanitize=fuzzer (compatible with libc++)"
  )
  add_compile_definitions(HAS_LIBFUZZER=1)
  set(HAS_LIBFUZZER
      TRUE
      CACHE INTERNAL "libFuzzer support enabled via compiler flags")
  set(TOOLCHAIN_USE_FSANITIZE_FUZZER
      TRUE
      CACHE INTERNAL "Use -fsanitize=fuzzer (built-in to clang)")

  # Debian/Ubuntu ship libclang_rt.fuzzer built against libstdc++, but we use
  # libc++. On Linux, fuzzer targets must also link libstdc++ to satisfy the
  # runtime's internal symbols. The clang driver strips -lstdc++ when
  # -stdlib=libc++ is active, so we pass it directly via LINKER:.
  if(NOT APPLE)
    set(FUZZER_EXTRA_LINK_OPTIONS
        "LINKER:-lstdc++"
        CACHE
          INTERNAL
          "Extra link options for fuzzer targets (libstdc++ for Debian fuzzer runtime)"
    )
  else()
    set(FUZZER_EXTRA_LINK_OPTIONS
        ""
        CACHE INTERNAL "Extra link options for fuzzer targets")
  endif()

  # ASan builds only: the libraries a harness calls get libFuzzer's coverage
  # too, every executable linking its callbacks (fuzzer-no-link). Not a MODULE
  # library: the clang-tidy plugin is loaded into a plain clang-tidy.
  if(NOT APPLE AND ENABLE_ASAN)
    add_compile_options(
      "$<$<NOT:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>:-fsanitize=fuzzer-no-link>"
    )
    add_link_options(
      "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fsanitize=fuzzer-no-link>"
    )
  endif()
endif()

# Register the fuzz-smoke and fuzz-all custom make targets. Both auto-discover
# every executable matching *_fuzzer under the build tree, so the targets stay
# in sync with add_*_fuzzer() calls without a hand-maintained list. Call from
# the top-level CMakeLists.txt after add_subdirectory(...) of every package.
function(statusbar_register_fuzz_targets)
  if(NOT ENABLE_FUZZING)
    return()
  endif()
  if(TARGET fuzz-smoke)
    # An outer (aggregate) build already registered these.
    return()
  endif()

  set(_scripts_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
  set(_corpus_dir "${CMAKE_BINARY_DIR}/fuzz/corpus")
  set(_seeds_dir "${CMAKE_BINARY_DIR}/fuzz/seeds")

  add_custom_target(
    fuzz-smoke
    COMMAND ${_scripts_dir}/fuzz-smoke.sh ${CMAKE_BINARY_DIR} ${_seeds_dir}
    COMMENT "Smoke-running every *_fuzzer binary once with a random seed"
    VERBATIM USES_TERMINAL)

  # Defaults tuned for a quick check; tune via env vars or override the
  # arguments below for serious campaigns.
  set(_fuzz_duration "30") # seconds per fuzzer (Linux libFuzzer)
  set(_fuzz_max_len "4096") # max input size
  set(_fuzz_count "1000") # random inputs per fuzzer (macOS standalone)

  add_custom_target(
    fuzz-all
    COMMAND ${_scripts_dir}/fuzz-all.sh ${CMAKE_BINARY_DIR} ${_corpus_dir}
            ${_fuzz_duration} ${_fuzz_max_len} ${_fuzz_count}
    COMMENT
      "Running every *_fuzzer (${_fuzz_duration}s each on Linux; ${_fuzz_count} random inputs on macOS)"
    VERBATIM USES_TERMINAL)
endfunction()
