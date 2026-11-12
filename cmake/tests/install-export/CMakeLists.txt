# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Fixture package for run-install-export-tests.sh: one header-only module whose
# headers sit under BOTH statusbar/ and other/, so an install shows which root
# statusbar_package_install_export() picked. STATUSBAR_MODULE_CMAKE names the
# module.cmake under test; FIXTURE_INCLUDE_DIR, when set, is passed through as
# INCLUDE_DIR; FIXTURE_BAD_KEYWORD, when set, passes an unknown keyword.
cmake_minimum_required(VERSION 3.31)
project(
  statusbar-fixture
  VERSION 0.0.1
  LANGUAGES CXX)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(${STATUSBAR_MODULE_CMAKE})
statusbar_add_module(NAME fixture INTERFACE)
set(_extra "")
if(FIXTURE_INCLUDE_DIR)
  list(APPEND _extra INCLUDE_DIR ${FIXTURE_INCLUDE_DIR})
endif()
if(FIXTURE_BAD_KEYWORD)
  list(APPEND _extra NO_SUCH_KEYWORD yes)
endif()
statusbar_package_install_export(NAME fixture ${_extra})
