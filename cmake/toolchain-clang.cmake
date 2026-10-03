# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Core toolchain: compiler selection, C++23, platform settings (Clang)

# Guard against CMake processing this toolchain file multiple times within a
# single configure pass (e.g. if a CMakeLists also include()s it after CMake
# itself already loaded it via --toolchain). Directory-scope, not CACHE — using
# a cache variable would suppress the toolchain (compiler/flags) on every
# *reconfigure*.
if(STATUSBAR_TOOLCHAIN_LOADED)
  return()
endif()
set(STATUSBAR_TOOLCHAIN_LOADED TRUE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler selection. CMAKE_LLVM_PATH is the prefix holding bin/clang and
# bin/clang++. Precedence: 1. LLVM_PATH (environment) — the single override knob
# on every platform. 2. `clang` located by find_program, looking first in the
# Homebrew LLVM prefixes (/opt/homebrew/opt/llvm, /usr/local/opt/llvm — the
# newer toolchain this project prefers on macOS) and then on PATH, which on a
# Mac with only the Xcode Command Line Tools installed is Apple's
# /usr/bin/clang. A fresh machine therefore configures with no environment at
# all. The binary is resolved through symlinks (REALPATH) and walked back to its
# prefix, which also handles Homebrew on Linux, custom prefixes and ccache shim
# directories. 3. /usr as a last resort.
if(DEFINED ENV{LLVM_PATH})
  set(CMAKE_LLVM_PATH "$ENV{LLVM_PATH}")
else()
  find_program(
    _clang_exe clang
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    DOC "Clang C compiler")
  if(_clang_exe)
    get_filename_component(_clang_real "${_clang_exe}" REALPATH)
    get_filename_component(_clang_bin "${_clang_real}" DIRECTORY)
    get_filename_component(CMAKE_LLVM_PATH "${_clang_bin}" DIRECTORY)
  else()
    set(CMAKE_LLVM_PATH "/usr") # last resort
  endif()
endif()
message(STATUS "Clang toolchain prefix: ${CMAKE_LLVM_PATH}")

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
# disagree on -mavx2 pick different inline definitions — an ODR hazard. NEON is
# baseline on ARMv8, so aarch64 needs no flag.
#
# ENABLE_AVX (default ON) lets a build opt out of the AVX/FMA baseline — e.g. to
# target an older x86 CPU without AVX2, or to produce a portable binary. It only
# has an effect on x86 targets; on non-x86 the flags are never added regardless.
option(ENABLE_AVX "Enable the AVX2/FMA SIMD baseline on x86 targets" ON)

# Resolve the *target* processor. On a cross build the cross toolchain sets
# CMAKE_SYSTEM_PROCESSOR before including this file; on a native build it is
# still empty during the toolchain pass (CMake probes the system only at
# project() time), so fall back to CMAKE_HOST_SYSTEM_PROCESSOR, which CMake
# populates before the first toolchain inclusion. Add AVX only when the target
# is *positively* identified as x86 — treating "anything not ARM" as x86 wrongly
# enabled -mavx2/-mfma on a native aarch64 host (clang rejects them), and would
# also misfire on other non-x86 arches.
if(CMAKE_SYSTEM_PROCESSOR)
  set(_STATUSBAR_TARGET_PROC "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(_STATUSBAR_TARGET_PROC "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()
if(ENABLE_AVX AND _STATUSBAR_TARGET_PROC MATCHES "x86_64|AMD64|amd64|i[3-6]86")
  list(APPEND _STATUSBAR_CXX_FLAGS -mavx2 -mfma)
endif()

# Warnings. Default ON everywhere (standalone packages and the aggregate alike)
# so a new diagnostic fails the build where it is introduced instead of
# surfacing later in a stricter context. Consumers or IDE builds on a compiler
# other than the pinned one opt out with -DENABLE_WARNINGS_AS_ERRORS=OFF.
# Statically link the C++ runtime into executables. One flag pair covers both
# toolchains: GCC links libstdc++ and libgcc; clang links libc++, libc++abi and
# the libgcc unwinder. Either way the C++ runtime leaves the binary's dynamic
# dependencies entirely.
#
# This decouples the build compiler from the runtime present on the target. A
# C++26 GCC 16 binary needs GLIBCXX_3.4.36, which Debian trixie (libstdc++
# 14.2.0) does not provide, so a dynamically linked package will not even
# install there; the same applies to a newer clang's libc++ without shipping a
# matching libc++1. With this ON the generated .deb drops its libstdc++6 and
# libgcc-s1 dependencies and installs on an older target unchanged. Costs
# roughly 1.4 MB per executable.
#
# Executables only, deliberately. Giving each shared object a private copy of
# the C++ runtime breaks exception propagation and type identity across .so
# boundaries. Every statusbar module is a STATIC library, so executables are the
# only place this belongs.
option(ENABLE_STATIC_CXX_RUNTIME
       "Statically link the C++ runtime into executables" OFF)
set(_STATUSBAR_EXE_LINKER_FLAGS "")
if(ENABLE_STATIC_CXX_RUNTIME)
  message(STATUS "Static C++ runtime enabled (executables)")
  list(APPEND _STATUSBAR_EXE_LINKER_FLAGS -static-libstdc++ -static-libgcc)
endif()

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

# NOTE: the sanitizer / coverage / fuzzing / clang-tidy helper modules are NOT
# included here. They are project build logic (options + statusbar_register_*
# target helpers), not compiler selection: the umbrella includes them at its top
# scope, and cmake/module.cmake includes them (guarded) for standalone package
# builds — so every build configures under any CMAKE_TOOLCHAIN_FILE (or none),
# as a single-project IDE build requires.

if(_STATUSBAR_EXE_LINKER_FLAGS)
  list(JOIN _STATUSBAR_EXE_LINKER_FLAGS " " _STATUSBAR_EXE_LINKER_FLAGS_STR)
  string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_STATUSBAR_EXE_LINKER_FLAGS_STR}")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")
