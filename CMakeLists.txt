cmake_minimum_required(VERSION 3.31)
project(
  statusbar-core
  VERSION 1.6.1
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

# Hardened build: STATUSBAR_ASSERT() traps on a violated precondition even in
# release (defense in depth; default is [[assume]] under NDEBUG). For aggregate
# builds the umbrella declares this option and applies the definition globally;
# here it covers the standalone statusbar-core build.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  option(
    ENABLE_HARDENING
    "Make STATUSBAR_ASSERT trap on violation in all builds (defense in depth)"
    OFF)
  if(ENABLE_HARDENING)
    add_compile_definitions(STATUSBAR_HARDENED)
  endif()

  # See the umbrella CMakeLists for rationale. OFF = full local-capture
  # visibility node (no qdisc bypass + promiscuous RawnetContext sockets).
  option(
    ENABLE_PACKET_QDISC_BYPASS
    "Use PACKET_QDISC_BYPASS for opted-in TX sockets (OFF = all TX visible to local capture + promiscuous RX)"
    ON)
  if(NOT ENABLE_PACKET_QDISC_BYPASS)
    add_compile_definitions(STATUSBAR_NO_QDISC_BYPASS)
  endif()
endif()

add_subdirectory(statusbar)

# EXPORT_NAME for each module target is set by statusbar_add_module() in
# cmake/module.cmake — no per-module enumeration needed here.

# Give every installed executable a statusbar- prefixed on-disk name, so the
# bin/ directory is uniform (tools that set no OUTPUT_NAME, and examples, would
# otherwise install unprefixed).
get_property(_exe_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
foreach(_t ${_exe_targets})
  if(NOT TARGET ${_t})
    continue()
  endif()
  get_target_property(_t_type ${_t} TYPE)
  if(NOT _t_type STREQUAL "EXECUTABLE")
    continue()
  endif()
  get_target_property(_t_name ${_t} OUTPUT_NAME)
  if(NOT _t_name)
    set(_t_name "${_t}")
  endif()
  if(NOT _t_name MATCHES "^statusbar-")
    string(REPLACE "_" "-" _t_name "${_t_name}")
    set_target_properties(${_t} PROPERTIES OUTPUT_NAME "statusbar-${_t_name}")
  endif()
endforeach()

# ---- install + export ----
# Skipped under an aggregate build (STATUSBAR_AGGREGATE_BUILD), which builds but
# doesn't install — the outer project owns the install set. Install rules are
# split into runtime (tools / shared libs) and devel (static libs, headers,
# CMake config) components for CPack.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  get_property(_install_targets GLOBAL PROPERTY STATUSBAR_INSTALL_TARGETS)
  install(
    TARGETS ${_install_targets}
    EXPORT statusbar-coreTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT devel
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime)
  install(
    EXPORT statusbar-coreTargets
    FILE statusbar-coreTargets.cmake
    NAMESPACE statusbar::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-core
    COMPONENT devel)
  # Also export the build tree, so a sibling package can find this one without
  # an install step: pass -Dstatusbar-core_DIR=<build-dir>.
  export(
    EXPORT statusbar-coreTargets
    FILE statusbar-coreTargets.cmake
    NAMESPACE statusbar::)
  install(
    DIRECTORY statusbar/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/statusbar
    COMPONENT devel
    FILES_MATCHING
    PATTERN "*.hpp"
    PATTERN "*.h")
  configure_package_config_file(
    cmake/statusbar-coreConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/statusbar-coreConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-core)
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/statusbar-coreConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/statusbar-coreConfig.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/statusbar-coreConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/statusbar-core
    COMPONENT devel)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    install(
      DIRECTORY docs/
      DESTINATION ${CMAKE_INSTALL_DOCDIR}
      COMPONENT devel
      FILES_MATCHING
      PATTERN "*.md"
      PATTERN "*.svg"
      PATTERN "*.png")
  endif()
endif()

# ---- packaging (CPack: TGZ + ZIP, plus DEB/RPM on Linux) ----
# Standalone builds only — run `cpack` from the build directory to produce this
# package's archives.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  set(CPACK_PACKAGE_NAME "statusbar-core")
  set(CPACK_PACKAGE_VENDOR "Jeff Koftinoff")
  set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
      "Foundational C++23 utilities — error handling, zero-copy buffers, IEEE and networking primitives, state machines, inter-thread communication, real-time scheduling, and terminal UI."
  )
  set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER
      "Jeff Koftinoff <jeff.koftinoff@statusbar.com>")
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_RPM_PACKAGE_LICENSE "MIT")
  set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")
  set(CPACK_RPM_PACKAGE_AUTOREQ ON)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
  endif()
  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_RPM_COMPONENT_INSTALL ON)
  set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
  # Name DEB/RPM files the package-manager-conventional way
  # (<name>_<version>_<arch>.deb), so dependent builds and the orchestrator
  # locate them by package name.
  set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
  set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "statusbar-core")
  set(CPACK_RPM_RUNTIME_PACKAGE_NAME "statusbar-core")
  set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "Command-line tools and executables")
  set(CPACK_COMPONENTS_ALL runtime devel)
  set(CPACK_DEBIAN_DEVEL_PACKAGE_NAME "statusbar-core-dev")
  set(CPACK_RPM_DEVEL_PACKAGE_NAME "statusbar-core-devel")
  # -dev's cmake config exports IMPORTED targets pointing at runtime binaries
  # (statusbar-net-tcp-echo-example etc.), so installing -dev without the
  # runtime breaks find_package() on the consumer side. >= (not =) so an
  # auto-incremented Debian revision (1.3.0-<rev>, see the container-build
  # scripts) still satisfies the runtime dependency.
  set(CPACK_DEBIAN_DEVEL_PACKAGE_DEPENDS
      "statusbar-core (>= ${PROJECT_VERSION})")
  set(CPACK_RPM_DEVEL_PACKAGE_REQUIRES "statusbar-core >= ${PROJECT_VERSION}")
  set(CPACK_COMPONENT_DEVEL_DESCRIPTION
      "C++ headers, static libraries and CMake package config")
  set(CPACK_GENERATOR "TGZ;ZIP")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CPACK_GENERATOR "DEB")
    find_program(_rpmbuild rpmbuild)
    if(_rpmbuild)
      list(APPEND CPACK_GENERATOR "RPM")
    endif()
  endif()
  include(CPack)
endif()

# Auto-discovering fuzz-smoke / fuzz-all targets (no-op unless ENABLE_FUZZING).
statusbar_register_fuzz_targets()

# clang-tidy aggregate target (no-op unless clang-tidy is on PATH).
statusbar_register_clang_tidy_target()
