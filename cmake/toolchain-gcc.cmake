# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Core toolchain: compiler selection, C++26, platform settings (GCC)
#
# Sibling of toolchain-clang.cmake, selectable per build directory. GCC 16 has
# more complete C++26 support than the clang the project is otherwise pinned to,
# so this toolchain defaults to -std=c++26 where the clang one defaults to
# c++23. Everything else mirrors the clang toolchain as closely as the two
# compilers allow; the deltas are called out inline.
#
# libstdc++ and libc++ objects cannot be mixed, so a GCC build must use its own
# build directory, separate from any clang-toolchain build of this package.

# Guard against CMake processing this toolchain file multiple times within a
# single configure pass (e.g. if a CMakeLists also include()s it after CMake
# itself already loaded it via --toolchain). Directory-scope, not CACHE — using
# a cache variable would suppress the toolchain (compiler/flags) on every
# *reconfigure*. Shares the variable name with toolchain-clang.cmake: exactly
# one of the two is ever loaded in a given build tree.
if(STATUSBAR_TOOLCHAIN_LOADED)
  return()
endif()
set(STATUSBAR_TOOLCHAIN_LOADED TRUE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler selection, in precedence order:
#
# 1. CMAKE_CXX_COMPILER already set — a cross toolchain that include()s this file
#    names the cross binaries itself, and -DCMAKE_CXX_COMPILER=g++-16 likewise
#    wins. Never overwritten.
# 2. CXX / CC environment variables. Debian ships versioned binaries with no
#    unversioned g++, so CXX=g++-16 works with no prefix layout needed.
# 3. GCC_PATH — a prefix containing bin/gcc and bin/g++ (a self-built or Homebrew
#    GCC), mirroring LLVM_PATH in the clang toolchain.
# 4. g++ found on PATH, walked back to its prefix via REALPATH, which handles
#    symlinks of any depth and ccache shim directories.
if(NOT CMAKE_CXX_COMPILER)
  if(DEFINED ENV{CXX})
    set(CMAKE_CXX_COMPILER "$ENV{CXX}")
  elseif(DEFINED ENV{GCC_PATH})
    set(CMAKE_CXX_COMPILER "$ENV{GCC_PATH}/bin/g++")
  else()
    find_program(
      _gxx_exe
      NAMES g++
      DOC "GNU C++ compiler")
    if(_gxx_exe)
      get_filename_component(_gxx_real "${_gxx_exe}" REALPATH)
      get_filename_component(_gxx_bin "${_gxx_real}" DIRECTORY)
      get_filename_component(_gcc_prefix "${_gxx_bin}" DIRECTORY)
    else()
      set(_gcc_prefix "/usr") # last resort
    endif()
    set(CMAKE_CXX_COMPILER "${_gcc_prefix}/bin/g++")
  endif()
endif()
if(NOT CMAKE_C_COMPILER)
  if(DEFINED ENV{CC})
    set(CMAKE_C_COMPILER "$ENV{CC}")
  elseif(DEFINED ENV{GCC_PATH})
    set(CMAKE_C_COMPILER "$ENV{GCC_PATH}/bin/gcc")
  else()
    find_program(
      _gcc_exe
      NAMES gcc
      DOC "GNU C compiler")
    if(_gcc_exe)
      set(CMAKE_C_COMPILER "${_gcc_exe}")
    else()
      set(CMAKE_C_COMPILER "/usr/bin/gcc") # last resort
    endif()
  endif()
endif()

# Fail early and legibly on a GCC too old for the C++26 default. Without this
# the build dies in a flood of syntax errors several hundred lines deep.
# CMAKE_CXX_COMPILER_VERSION is not populated until project() runs compiler
# detection, so ask the driver directly.
execute_process(
  COMMAND "${CMAKE_CXX_COMPILER}" -dumpfullversion -dumpversion
  OUTPUT_VARIABLE _gxx_version
  OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(_gxx_version AND _gxx_version VERSION_LESS 15)
  message(
    FATAL_ERROR
      "toolchain-gcc.cmake: found GCC ${_gxx_version} at ${CMAKE_CXX_COMPILER}, "
      "but C++26 support requires GCC 15 or newer. Set GCC_PATH to a newer "
      "prefix, or configure with -DSTATUSBAR_CXX_STANDARD=23.")
endif()

# Compiler cache (ccache) — speeds up rebuilds across build variants
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

# C++26 Standard — the reason this toolchain exists. Exposed as a cache variable
# so a GCC build can be pinned back to 23 to compare against the clang toolchain
# without editing this file. (The per-module target_compile_features(...
# cxx_std_23) calls set a *floor*, not a ceiling, so they do not cap this.)
set(STATUSBAR_CXX_STANDARD
    "26"
    CACHE STRING "C++ standard for the GCC toolchain (23 or 26)")
set_property(CACHE STATUSBAR_CXX_STANDARD PROPERTY STRINGS "23" "26")
set(CMAKE_CXX_STANDARD ${STATUSBAR_CXX_STANDARD})
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

# Compiler flags. Collected into a list so the per-flag separator is enforced by
# list(JOIN) at the bottom of this section instead of by the brittle
# leading-space convention you get when repeatedly using `string(APPEND
# CMAKE_CXX_FLAGS " -foo")`.
#
# Deltas from toolchain-clang.cmake: -stdlib=libc++        dropped; GCC has only
# libstdc++. --rtlib=compiler-rt   dropped; that exists to get __muloti4 for
# UBSan-instrumented __int128 on aarch64, which is exactly what libgcc (GCC's
# own default) provides. -Wno-c23-extensions   dropped; a clang-only spelling.
# GCC 16 accepts #embed and --embed-dir= in C++26 mode with no diagnostic, so
# there is nothing to suppress.
set(_STATUSBAR_CXX_FLAGS -fstack-protector-strong)
set(_STATUSBAR_LINKER_FLAGS "") # appended to EXE / SHARED / MODULE link kinds

# Record stdlib for statusbarConfig.cmake consumer ABI check. The `if(NOT ...)`
# guard treats an explicitly-empty cache value as "use the default" too (a bare
# `set(... CACHE STRING ...)` would skip the assignment only when the cache key
# already exists, even if the value is empty).
if(NOT STATUSBAR_STDLIB)
  set(STATUSBAR_STDLIB
      "libstdc++"
      CACHE STRING "C++ standard library")
endif()

# Per-configuration flags. Identical spellings to the clang toolchain.
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
#
# -mavx2 / -mfma are spelled identically by GCC and clang, so this block is a
# verbatim copy of the clang toolchain's.
option(ENABLE_AVX "Enable the AVX2/FMA SIMD baseline on x86 targets" ON)

# Resolve the *target* processor. On a cross build the cross toolchain sets
# CMAKE_SYSTEM_PROCESSOR before including this file; on a native build it is
# still empty during the toolchain pass (CMake probes the system only at
# project() time), so fall back to CMAKE_HOST_SYSTEM_PROCESSOR, which CMake
# populates before the first toolchain inclusion. Add AVX only when the target
# is *positively* identified as x86 — treating "anything not ARM" as x86 wrongly
# enabled -mavx2/-mfma on a native aarch64 host, and would also misfire on other
# non-x86 arches.
if(CMAKE_SYSTEM_PROCESSOR)
  set(_STATUSBAR_TARGET_PROC "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(_STATUSBAR_TARGET_PROC "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()
if(ENABLE_AVX AND _STATUSBAR_TARGET_PROC MATCHES "x86_64|AMD64|amd64|i[3-6]86")
  list(APPEND _STATUSBAR_CXX_FLAGS -mavx2 -mfma)
endif()

# CPU crypto acceleration baseline for statusbar-crypto. crypto's CMakeLists
# defaults this to clang's "-mcpu=native+aes+sha2+sha3" on aarch64, a spelling
# GCC rejects outright ("unknown value 'native+aes+sha2+sha3' for '-mcpu'") —
# GCC takes no feature modifiers on `native`. Plain -mcpu=native already defines
# every macro the accelerated code gates on (__ARM_FEATURE_AES, _SHA2, _SHA3,
# _CRYPTO) since it reads them off the host CPU.
#
# Seeded here as a CACHE entry, which crypto's own `set(... CACHE ...)` then
# leaves untouched — so this needs no change in the crypto submodule and does
# not affect a clang build. Cross builds and x86 are left alone: crypto's
# cross-compile default (-march=armv8-a+crypto) and its x86 flags (-maes
# -mpclmul -msha -msse4.1) are accepted by GCC as-is.
#
# Native builds only, and the native test is deliberately NOT
# CMAKE_CROSSCOMPILING: CMake does not define that until project() runs, so on
# the first toolchain pass it is empty and `NOT CMAKE_CROSSCOMPILING` is true
# even for a cross build — which would seed -mcpu=native for a cross compiler
# that cannot read the target CPU off the build host. Compare the resolved
# target against the host instead. A cross toolchain sets CMAKE_SYSTEM_PROCESSOR
# before including this file, so the two differ there and crypto's own cross
# default applies untouched.
if(_STATUSBAR_TARGET_PROC MATCHES "aarch64|arm64|ARM64"
   AND _STATUSBAR_TARGET_PROC STREQUAL "${CMAKE_HOST_SYSTEM_PROCESSOR}")
  set(STATUSBAR_CRYPTO_ARCH_FLAGS
      "-mcpu=native"
      CACHE
        STRING
        "Compiler flags enabling CPU crypto acceleration in statusbar-crypto")
endif()

# libFuzzer is a clang feature; GCC has no -fsanitize=fuzzer. fuzzing.cmake
# already defaults ENABLE_FUZZING off for a non-clang CMAKE_CXX_COMPILER, but
# pin it in the cache so an explicit -DENABLE_FUZZING=ON fails at configure time
# with this message rather than at link time with an unresolved main().
if(ENABLE_FUZZING)
  message(
    FATAL_ERROR
      "toolchain-gcc.cmake: ENABLE_FUZZING requires clang's -fsanitize=fuzzer, "
      "which GCC does not provide. Build fuzzers with cmake/toolchain-clang.cmake."
  )
endif()
set(ENABLE_FUZZING
    OFF
    CACHE BOOL "Fuzzing requires clang; disabled for GCC builds")

# Coverage is wired to LLVM source-based coverage (-fprofile-instr-generate
# -fcoverage-mapping, llvm-profdata, llvm-cov), none of which GCC understands.
# The GCC equivalent is --coverage + gcov/gcovr and would need its own branch in
# coverage.cmake; until then, fail loudly instead of emitting flags GCC rejects.
if(ENABLE_COVERAGE)
  message(
    FATAL_ERROR
      "toolchain-gcc.cmake: ENABLE_COVERAGE uses LLVM source-based coverage, "
      "which GCC does not support. Build coverage with cmake/toolchain-clang.cmake."
  )
endif()

# Warnings. ON by default, matching this package's toolchain-clang.cmake. GCC's
# diagnostic set differs from clang's, so this is the flag most likely to need
# -DENABLE_WARNINGS_AS_ERRORS=OFF on a compiler upgrade. Statically link the C++
# runtime into executables. One flag pair covers both toolchains: GCC links
# libstdc++ and libgcc; clang links libc++, libc++abi and the libgcc unwinder.
# Either way the C++ runtime leaves the binary's dynamic dependencies entirely.
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
  string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
  string(APPEND CMAKE_MODULE_LINKER_FLAGS " ${_STATUSBAR_LINKER_FLAGS_STR}")
endif()

# Include optional toolchain components, matching toolchain-clang.cmake.
# sanitizers.cmake needs no GCC-specific changes (GCC and clang spell the
# ASan/UBSan/TSan flags identically). coverage.cmake and fuzzing.cmake are
# LLVM-only, but both are inert here: ENABLE_COVERAGE/ENABLE_FUZZING are pinned
# off above, and an explicit -D...=ON was already rejected with a pointer to the
# clang toolchain. clang_tidy.cmake only defines
# statusbar_register_clang_tidy_target(), which this package's CMakeLists calls.
include("${CMAKE_CURRENT_LIST_DIR}/sanitizers.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/coverage.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/fuzzing.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/clang_tidy.cmake")

if(_STATUSBAR_EXE_LINKER_FLAGS)
  list(JOIN _STATUSBAR_EXE_LINKER_FLAGS " " _STATUSBAR_EXE_LINKER_FLAGS_STR)
  string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_STATUSBAR_EXE_LINKER_FLAGS_STR}")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD} (GCC ${_gxx_version})")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")
