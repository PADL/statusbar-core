cmake_minimum_required(VERSION 3.31)
project(
  statusbar-core
  VERSION 2.1.0
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
enable_testing()

# Opt-out switches for system dependencies. Defaults preserve the historical
# all-features-on behaviour. Setting any of these to OFF lets a consumer build
# statusbar-core without the corresponding dev package installed — useful for
# slim containers, embedded targets, or CI matrices that don't need raw-packet /
# AF_XDP functionality.
option(
  STATUSBAR_ENABLE_BPF
  "Build the bpf/ module (Berkeley Packet Filter device wrapper, Linux+macOS)"
  ON)
option(STATUSBAR_ENABLE_XDP
       "Enable AF_XDP support in net/ (requires libbpf + libxdp on Linux)" ON)

# Modules register bench tools into this aggregate target. When this package is
# included by an outer CMake project that sets STATUSBAR_AGGREGATE_BUILD=ON, the
# outer project supplies a single shared target instead.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  add_custom_target(run-all-benches)
endif()

# The whole-build switches (ENABLE_NO_EXCEPTIONS, ENABLE_HARDENING,
# ENABLE_PACKET_QDISC_BYPASS) come from cmake/build_switches.cmake, declared
# once by module.cmake at this build's widest scope — the umbrella's top level
# under an aggregate, statusbar/ here.

add_subdirectory(statusbar)

# EXPORT_NAME for each module target is set by statusbar_add_module() in
# cmake/module.cmake — no per-module enumeration needed here.

# Uniform statusbar- prefixed on-disk names for installed executables
# (statusbar_prefix_tool_names in cmake/module.cmake).
statusbar_prefix_tool_names()

# ---- install + export ----
# Standalone install/export boilerplate lives in
# statusbar_package_install_export (cmake/module.cmake); no-op under an outer
# aggregate build.
statusbar_package_install_export(NAME core)

# statusbar-core is the single source of truth for the shared build machinery
# (helper modules, toolchains, build-time scripts). Two homes, both beside the
# package config so statusbar-coreConfig.cmake can include() them relative to
# itself: - installed, for dependents building against the core-dev package; -
# staged into this build tree, for dependents building against
# -Dstatusbar-core_DIR=<core-build-dir> without an install step.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  set(_statusbar_cmake_modules
      cmake/module.cmake
      cmake/build_switches.cmake
      cmake/sanitizers.cmake
      cmake/coverage.cmake
      cmake/fuzzing.cmake
      cmake/clang_tidy.cmake
      cmake/toolchain-clang.cmake
      cmake/toolchain-gcc.cmake
      cmake/toolchain-clang-aarch64.cmake
      cmake/toolchain-gcc-aarch64.cmake)
  set(_statusbar_cmake_scripts
      cmake/coverage-collect.sh
      cmake/coverage-html.sh
      cmake/coverage-report.sh
      cmake/fuzz-all.sh
      cmake/fuzz-smoke.sh
      cmake/run-clang-tidy-all.sh
      cmake/run-clang-tidy.sh
      cmake/sm-docs-render.sh)
  install(
    FILES ${_statusbar_cmake_modules}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-core
    COMPONENT devel)
  install(
    PROGRAMS ${_statusbar_cmake_scripts}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-core
    COMPONENT devel)
  file(COPY ${_statusbar_cmake_modules} ${_statusbar_cmake_scripts}
       DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()

# ---- packaging (CPack: TGZ + ZIP, plus DEB/RPM on Linux) ----
# Standalone builds only — run `cpack` from the build directory to produce this
# package's archives. Common variables come from
# statusbar_package_cpack_defaults (cmake/module.cmake); only the
# package-specific dependency floors remain here.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  statusbar_package_cpack_defaults(
    NAME
    core
    DESCRIPTION
    "Foundational C++23 utilities — error handling, zero-copy buffers, IEEE and networking primitives, state machines, inter-thread communication, real-time scheduling, and terminal UI."
  )
  # -dev's cmake config exports IMPORTED targets pointing at runtime binaries
  # (statusbar-net-tcp-echo-example etc.), so installing -dev without the
  # runtime breaks find_package() on the consumer side. >= (not =) so an
  # auto-incremented Debian revision (1.3.0-<rev>, see the container-build
  # scripts) still satisfies the runtime dependency.
  set(CPACK_DEBIAN_DEVEL_PACKAGE_DEPENDS
      "statusbar-core (>= ${PROJECT_VERSION})")
  set(CPACK_RPM_DEVEL_PACKAGE_REQUIRES "statusbar-core >= ${PROJECT_VERSION}")
  include(CPack)
endif()

# Auto-discovering fuzz-smoke / fuzz-all targets (no-op unless ENABLE_FUZZING).
statusbar_register_fuzz_targets()

# clang-tidy aggregate target (no-op unless clang-tidy is on PATH).
statusbar_register_clang_tidy_target()
