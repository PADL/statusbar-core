# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
#
# Cross-compile toolchain: x86_64 host -> aarch64 Linux, using Debian's
# aarch64-linux-gnu GCC cross compiler and multiarch :arm64 dev packages. Wraps
# the standard toolchain (toolchain-gcc.cmake) — only adds the cross-targeting
# bits so the two stay in sync.
#
# The clang counterpart uses one clang binary with --target=; GCC has no
# multi-target driver, so this needs a genuinely separate cross compiler
# (Debian's g++-<ver>-aarch64-linux-gnu). That is the only structural difference
# between the two cross toolchains.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(_STATUSBAR_CROSS_TRIPLE "aarch64-linux-gnu")

# The cross compiler, named explicitly. toolchain-gcc.cmake leaves
# CMAKE_CXX_COMPILER alone when it is already set, so these win.
# STATUSBAR_CROSS_GCC_SUFFIX selects the version: Debian installs
# aarch64-linux-gnu-g++-16 and, from the same package, an unsuffixed
# aarch64-linux-gnu-g++ symlink is NOT guaranteed, so the suffix is explicit and
# overridable.
if(NOT STATUSBAR_CROSS_GCC_SUFFIX)
  set(STATUSBAR_CROSS_GCC_SUFFIX
      "-16"
      CACHE STRING "Version suffix of the aarch64 cross GCC (e.g. -16)")
endif()
find_program(
  _statusbar_cross_gxx
  NAMES "${_STATUSBAR_CROSS_TRIPLE}-g++${STATUSBAR_CROSS_GCC_SUFFIX}"
        "${_STATUSBAR_CROSS_TRIPLE}-g++"
  DOC "aarch64 cross C++ compiler")
find_program(
  _statusbar_cross_gcc
  NAMES "${_STATUSBAR_CROSS_TRIPLE}-gcc${STATUSBAR_CROSS_GCC_SUFFIX}"
        "${_STATUSBAR_CROSS_TRIPLE}-gcc"
  DOC "aarch64 cross C compiler")
if(NOT _statusbar_cross_gxx OR NOT _statusbar_cross_gcc)
  message(
    FATAL_ERROR
      "toolchain-gcc-aarch64.cmake: no ${_STATUSBAR_CROSS_TRIPLE} GCC cross "
      "compiler on PATH. Install Debian's "
      "g++${STATUSBAR_CROSS_GCC_SUFFIX}-${_STATUSBAR_CROSS_TRIPLE}, or set "
      "STATUSBAR_CROSS_GCC_SUFFIX to a version that is installed.")
endif()
set(CMAKE_C_COMPILER "${_statusbar_cross_gcc}")
set(CMAKE_CXX_COMPILER "${_statusbar_cross_gxx}")

# find_library / find_path / find_package must search the arm64 multiarch tree
# (/usr/lib/aarch64-linux-gnu, /usr/include/aarch64-linux-gnu) instead of the
# host amd64 paths.
set(CMAKE_LIBRARY_ARCHITECTURE "${_STATUSBAR_CROSS_TRIPLE}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
# PACKAGE=BOTH so find_package() can locate cross-built sibling packages
# installed under /usr/local in the cross builder (statusbar-coreConfig.cmake
# etc.) — standard system paths are needed since we have no separate sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

# pkg-config: same multiarch dance. PKG_CONFIG_LIBDIR overrides the default
# search path so we only see arm64 .pc files (otherwise pkg-config returns amd64
# paths that link-fail at the very end).
set(ENV{PKG_CONFIG_LIBDIR}
    "/usr/lib/${_STATUSBAR_CROSS_TRIPLE}/pkgconfig:/usr/share/pkgconfig")

# Cross-built fuzzers can't run on the build host, and libFuzzer is clang-only
# in any case. Pin it off before toolchain-gcc.cmake's own guard sees it.
set(ENABLE_FUZZING
    OFF
    CACHE BOOL "Fuzzing disabled by default for cross-builds")

# Pull in the standard GCC toolchain (C++26, build type, warnings, static
# runtime option, the crypto arch-flag seeding). It uses string(APPEND) on
# CMAKE_*_FLAGS and leaves an already-set CMAKE_CXX_COMPILER alone, so the
# cross-targeting above is preserved.
include("${CMAKE_CURRENT_LIST_DIR}/toolchain-gcc.cmake")
