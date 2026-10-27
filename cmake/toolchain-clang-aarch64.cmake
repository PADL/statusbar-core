# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
#
# Cross-compile toolchain: x86_64 host -> aarch64 Linux, using clang's built-in
# multi-target support and Debian multiarch :arm64 dev packages. Wraps the
# standard toolchain (toolchain-clang.cmake) — only adds the cross-targeting
# bits so the two stay in sync.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(_STATUSBAR_CROSS_TRIPLE "aarch64-linux-gnu")

# Compile side: CMake passes --target= to the clang compile invocation.
set(CMAKE_C_COMPILER_TARGET "${_STATUSBAR_CROSS_TRIPLE}")
set(CMAKE_CXX_COMPILER_TARGET "${_STATUSBAR_CROSS_TRIPLE}")

# Link side: CMAKE_<LANG>_COMPILER_TARGET doesn't reach the link line, so add
# --target there explicitly and pin lld (system bfd may not cross).
# --unwindlib=libunwind: the standard toolchain sets --rtlib=compiler-rt for the
# builtins, but clang's default unwinder is still libgcc_s; in the cross image
# the .so symlink isn't on lld's search path, so the link fails with "unable to
# find library -lgcc_s". libunwind:arm64 is installed and is the idiomatic
# pairing with libc++.
foreach(_lflag CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS
               CMAKE_MODULE_LINKER_FLAGS)
  string(
    APPEND ${_lflag}
    " --target=${_STATUSBAR_CROSS_TRIPLE} -fuse-ld=lld --unwindlib=libunwind")
endforeach()

# Optional sysroot (STATUSBAR_SYSROOT, cache or environment): the target's
# /usr/include, /usr/lib/<triple> and the libc++/compiler-rt dev packages copied
# from an arm64 Debian/Ubuntu install, for hosts without :arm64 multiarch.
if(NOT STATUSBAR_SYSROOT AND DEFINED ENV{STATUSBAR_SYSROOT})
  set(STATUSBAR_SYSROOT "$ENV{STATUSBAR_SYSROOT}")
endif()
set(STATUSBAR_SYSROOT
    "${STATUSBAR_SYSROOT}"
    CACHE PATH "Target root for the aarch64 cross build (empty: multiarch)")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES STATUSBAR_SYSROOT)
if(STATUSBAR_SYSROOT)
  set(CMAKE_SYSROOT "${STATUSBAR_SYSROOT}")
endif()

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
    "${CMAKE_SYSROOT}/usr/lib/${_STATUSBAR_CROSS_TRIPLE}/pkgconfig:${CMAKE_SYSROOT}/usr/share/pkgconfig"
)
if(CMAKE_SYSROOT)
  set(ENV{PKG_CONFIG_SYSROOT_DIR} "${CMAKE_SYSROOT}")
endif()

# Cross-built fuzzers can't run on the build host, and Debian's
# libclang_rt.fuzzer was built against libstdc++ — which the cross-builder
# container doesn't ship (only libc++:${TARGET_ARCH}). Default fuzzing OFF here
# so cross-build scripts don't trip over -lstdc++ in fuzzer link lines.
set(ENABLE_FUZZING
    OFF
    CACHE BOOL "Fuzzing disabled by default for cross-builds")

# Pull in the standard clang toolchain (compiler discovery, libc++, build type,
# warnings, sanitizers). It uses string(APPEND) on CMAKE_*_FLAGS, so our
# cross-targeting additions above are preserved.
include("${CMAKE_CURRENT_LIST_DIR}/toolchain-clang.cmake")

# The host clang ships compiler-rt only for its own arch; with a sysroot, link
# against the target's copy (libclang-rt-<N>-dev) under the same resource path.
if(CMAKE_SYSROOT)
  execute_process(
    COMMAND "${CMAKE_CXX_COMPILER}" -print-resource-dir
    OUTPUT_VARIABLE _STATUSBAR_RESOURCE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  set(_STATUSBAR_RT "${CMAKE_SYSROOT}${_STATUSBAR_RESOURCE_DIR}")
  if(NOT EXISTS "${_STATUSBAR_RT}/lib/linux/libclang_rt.builtins-aarch64.a")
    message(FATAL_ERROR "no aarch64 compiler-rt under ${_STATUSBAR_RT}; "
                        "install libclang-rt-<N>-dev in the sysroot")
  endif()
  foreach(_lflag CMAKE_EXE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS
                 CMAKE_MODULE_LINKER_FLAGS)
    string(APPEND ${_lflag} " -resource-dir=${_STATUSBAR_RT}")
  endforeach()
endif()
