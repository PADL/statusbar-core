# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Core toolchain: compiler selection, C++23, platform settings (Clang)

# Guard against CMake processing this toolchain file multiple times within a
# single configure pass (e.g. if a CMakeLists also include()s it after CMake
# itself already loaded it via --toolchain). Directory-scope, not CACHE — using
# a cache variable would suppress the toolchain on every *reconfigure*, breaking
# the include()s for sanitizers/fuzzing/etc. at the bottom of this file.
if(STATUSBAR_TOOLCHAIN_LOADED)
  return()
endif()
set(STATUSBAR_TOOLCHAIN_LOADED TRUE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler selection and LLVM path detection. LLVM_PATH (env var) wins on both
# platforms, providing a single override knob. Otherwise: - macOS: leave
# CMAKE_LLVM_PATH empty (the project requires Homebrew's clang; callers should
# set LLVM_PATH via the Makefile / environment). - Linux: find `clang` on PATH
# and walk back to its prefix. CMake's find_program + REALPATH is portable and
# handles symlinks of any depth, Homebrew on Linux, custom prefixes — unlike the
# old `readlink -f /usr/bin/clang` which was GNU-only and hardcoded /usr/bin.
if(DEFINED ENV{LLVM_PATH})
  set(CMAKE_LLVM_PATH "$ENV{LLVM_PATH}")
elseif(APPLE)
  set(CMAKE_LLVM_PATH "")
else()
  find_program(_clang_exe clang DOC "Clang C compiler")
  if(_clang_exe)
    get_filename_component(_clang_real "${_clang_exe}" REALPATH)
    get_filename_component(_clang_bin "${_clang_real}" DIRECTORY)
    get_filename_component(CMAKE_LLVM_PATH "${_clang_bin}" DIRECTORY)
  else()
    set(CMAKE_LLVM_PATH "/usr") # last resort
  endif()
endif()

set(CMAKE_C_COMPILER "${CMAKE_LLVM_PATH}/bin/clang")
set(CMAKE_CXX_COMPILER "${CMAKE_LLVM_PATH}/bin/clang++")

# Compiler cache (ccache) — speeds up rebuilds across build variants
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

# C++23 Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Debug"
      CACHE STRING "Choose build type")
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                               "RelWithDebInfo" "MinSizeRel")
endif()

# LLVM Tools
option(ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)

if(ENABLE_CLANG_TIDY)
  message(STATUS "clang-tidy enabled")
  set(CMAKE_CXX_CLANG_TIDY "${CMAKE_LLVM_PATH}/bin/clang-tidy")
endif()

# Compiler flags. Collected into a list so the per-flag separator is enforced by
# list(JOIN) at the bottom of this section instead of by the brittle
# leading-space convention you get when repeatedly using `string(APPEND
# CMAKE_CXX_FLAGS " -foo")`.
set(_STATUSBAR_CXX_FLAGS
    -stdlib=libc++ -fstack-protector-strong
    # Allow C23 #embed in C++23 mode (used to embed BPF object files).
    -Wno-c23-extensions)
set(_STATUSBAR_LINKER_FLAGS "") # appended to EXE / SHARED / MODULE link kinds

# Record stdlib for statusbarConfig.cmake consumer ABI check. The `if(NOT ...)`
# guard treats an explicitly-empty cache value as "use the default" too (a bare
# `set(... CACHE STRING ...)` would skip the assignment only when the cache key
# already exists, even if the value is empty).
if(NOT STATUSBAR_STDLIB)
  set(STATUSBAR_STDLIB
      "libc++"
      CACHE STRING "C++ standard library")
endif()

# Per-configuration flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -DNDEBUG")

# Platform-specific settings
if(APPLE)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")
  if(NOT CMAKE_OSX_SYSROOT)
    # Cache the xcrun result so re-configures don't re-shell out. The cache is
    # invalidated by the user (e.g. on Xcode upgrade) via `-UCMAKE_OSX_SYSROOT`
    # or by editing the CMakeCache.txt entry.
    execute_process(
      COMMAND xcrun --show-sdk-path
      OUTPUT_VARIABLE _xcrun_sdk_path
      OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(_xcrun_sdk_path)
      set(CMAKE_OSX_SYSROOT
          "${_xcrun_sdk_path}"
          CACHE PATH "macOS SDK path")
    endif()
  endif()
  if(CMAKE_OSX_SYSROOT)
    list(APPEND _STATUSBAR_CXX_FLAGS -isysroot ${CMAKE_OSX_SYSROOT})
  endif()
else()
  # Use compiler-rt builtins on Linux. Debian's default runtime (libgcc) lacks
  # __muloti4 needed for UBSan-instrumented __int128 arithmetic on aarch64.
  list(APPEND _STATUSBAR_LINKER_FLAGS --rtlib=compiler-rt)
endif()

# Architecture-specific SIMD baseline. The dsp SIMDVec AVX backends are gated on
# __AVX__/__FMA__, so without these flags they preprocess to nothing on x86_64
# and every SIMD op silently falls back to scalar. Applied globally (every TU,
# not just the dsp target): two TUs that both include the SIMD headers but
# disagree on -mavx2 pick different inline definitions - an ODR hazard. NEON is
# baseline on ARMv8, so aarch64 needs no flag. The cross toolchain sets
# CMAKE_SYSTEM_PROCESSOR=aarch64 before including this file; a native x86_64
# build leaves it empty here, which the else branch covers.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm")
  # ARMv8 NEON is mandatory - nothing to add.
else()
  list(APPEND _STATUSBAR_CXX_FLAGS -mavx2 -mfma)
endif()

# Warnings
option(ENABLE_WARNINGS_AS_ERRORS "Warning is an error" ON)
if(ENABLE_WARNINGS_AS_ERRORS)
  list(APPEND _STATUSBAR_CXX_FLAGS -Werror)
endif()

# Join collected lists and append to CMake's flag variables exactly once.
list(JOIN _STATUSBAR_CXX_FLAGS " " _STATUSBAR_CXX_FLAGS_STR)
if(_STATUSBAR_CXX_FLAGS_STR)
  string(APPEND CMAKE_CXX_FLAGS " ${_STATUSBAR_CXX_FLAGS_STR}")
endif()
if(_STATUSBAR_LINKER_FLAGS)
  list(JOIN _STATUSBAR_LINKER_FLAGS " " _STATUSBAR_LINKER_FLAGS_STR)
  # --rtlib=compiler-rt is a clang *driver* option — it tells clang which
  # runtime to link against; clang then expands it into the right -lclang_rt.*
  # at the linker step. The driver consumes it on the link command line, so
  # CMAKE_*_LINKER_FLAGS (which CMake appends to the clang link command) is the
  # correct home. Propagate to every link kind so future shared libraries and
  # loadable modules inherit the same runtime.
  string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
  string(APPEND CMAKE_MODULE_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
endif()

# Include optional toolchain components
include("${CMAKE_CURRENT_LIST_DIR}/sanitizers.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/coverage.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/fuzzing.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/clang_tidy.cmake")

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")
