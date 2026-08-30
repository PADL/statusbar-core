# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  net
  SOURCES
  net_address.cpp
  net_bpf_port.cpp
  net_error.cpp
  net_linux_mmap.cpp
  net_linux_xdp.cpp
  net_message_reactor.cpp
  net_rawnet.cpp
  net_ring_buffer_base.cpp
  net_tap_bridge.cpp
  net_tcp_server.cpp
  net_util.cpp
  net_test_port.cpp
  net_traffic_classifier.cpp
  DEPS
  statusbar-buffer
  statusbar-config
  statusbar-ieee
  statusbar-ip
  statusbar-pcap
  statusbar-status
  statusbar-itc
  TESTS
  net_cbpf_emit_test.cpp
  net_zephyr_eth_concept_test.cpp
  net_compiled_rule_test.cpp
  net_ethernet_port_test.cpp
  net_link_monitor_test.cpp
  net_linux_xdp_test.cpp
  net_tcam_classifier_test.cpp
  net_tcp_server_test.cpp
  net_test.cpp
  net_xdp_abi_test.cpp
  net_xdp_equiv_test.cpp)

add_executable(net_tcp_echo_example net_tcp_echo_example.cpp)
target_link_libraries(net_tcp_echo_example PRIVATE statusbar)
set_target_properties(net_tcp_echo_example
                      PROPERTIES OUTPUT_NAME statusbar-net-tcp-echo-example)

add_executable(net_udp_echo_example net_udp_echo_example.cpp)
target_link_libraries(net_udp_echo_example PRIVATE statusbar)
set_target_properties(net_udp_echo_example
                      PROPERTIES OUTPUT_NAME statusbar-net-udp-echo-example)

add_executable(net_raw_example net_raw_example.cpp)
target_link_libraries(net_raw_example PRIVATE statusbar)
set_target_properties(net_raw_example PROPERTIES OUTPUT_NAME
                                                 statusbar-net-raw-example)

add_executable(net_classifier_example net_classifier_example.cpp)
target_link_libraries(net_classifier_example PRIVATE statusbar)
set_target_properties(net_classifier_example
                      PROPERTIES OUTPUT_NAME statusbar-net-classifier-example)

set_property(
  GLOBAL APPEND
  PROPERTY STATUSBAR_INSTALL_TARGETS net_tcp_echo_example net_udp_echo_example
           net_raw_example net_classifier_example)

# Optional: libbpf/libxdp for AF_XDP support (Linux only)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBBPF libbpf)
    pkg_check_modules(LIBXDP libxdp)
  endif()
  if(LIBBPF_FOUND AND LIBXDP_FOUND)
    execute_process(
      COMMAND dpkg-architecture -qDEB_HOST_MULTIARCH
      OUTPUT_VARIABLE DEB_HOST_MULTIARCH
      OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
      RESULT_VARIABLE DPKG_RESULT)
    if(DPKG_RESULT EQUAL 0)
      set(MULTIARCH_INCLUDE "-I/usr/include/${DEB_HOST_MULTIARCH}")
    else()
      execute_process(
        COMMAND ${CMAKE_C_COMPILER} -dumpmachine
        OUTPUT_VARIABLE _GCC_MACHINE
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
        RESULT_VARIABLE _GCC_RESULT)
      if(_GCC_RESULT EQUAL 0 AND EXISTS "/usr/include/${_GCC_MACHINE}")
        set(MULTIARCH_INCLUDE "-I/usr/include/${_GCC_MACHINE}")
      else()
        set(MULTIARCH_INCLUDE "")
      endif()
    endif()

    find_program(BPF_CLANG clang HINTS ${LLVM_PATH}/bin)
    if(NOT BPF_CLANG)
      message(WARNING "clang not found - cannot compile XDP BPF program")
    endif()

    set(XDP_BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/xdp_filter.bpf.c")
    set(XDP_BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/xdp_filter.bpf.o")

    add_custom_command(
      OUTPUT ${XDP_BPF_OBJ}
      COMMAND ${BPF_CLANG} -target bpf -O2 -g -I${LIBBPF_INCLUDE_DIRS}
              ${MULTIARCH_INCLUDE} -c ${XDP_BPF_SRC} -o ${XDP_BPF_OBJ}
      DEPENDS ${XDP_BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/net_tcam_bpf_abi.h
      COMMENT "Compiling XDP BPF program"
      VERBATIM)

    add_custom_target(xdp_bpf_obj DEPENDS ${XDP_BPF_OBJ})
    add_dependencies(statusbar-net xdp_bpf_obj)

    target_sources(statusbar-net
                   PRIVATE ${CMAKE_CURRENT_LIST_DIR}/xdp_filter_bpf_embed.cpp)
    set_source_files_properties(
      ${CMAKE_CURRENT_LIST_DIR}/xdp_filter_bpf_embed.cpp
      PROPERTIES OBJECT_DEPENDS "${XDP_BPF_OBJ}")

    # HAVE_XDP must be visible to consumers so the gated parts of
    # net_linux_xdp.hpp compile in their TUs too.
    target_compile_definitions(statusbar-net PUBLIC HAVE_XDP=1)
    # The --embed-dir flag is only needed when compiling
    # xdp_filter_bpf_embed.cpp, which is the only TU using #embed. Scope it to
    # that source rather than the whole library.
    set_source_files_properties(
      ${CMAKE_CURRENT_LIST_DIR}/xdp_filter_bpf_embed.cpp
      PROPERTIES COMPILE_OPTIONS "--embed-dir=${CMAKE_CURRENT_BINARY_DIR}")
    # libbpf/libxdp leak through net_linux_xdp.hpp (a public header), so
    # consumers of statusbar::net must also see the headers and link the
    # libraries. PUBLIC propagates both for usage and for the exported target.
    # The $<BUILD_INTERFACE:…> binary-dir entry is build-only (needed for the
    # embed) and stays out of the install interface.
    target_link_libraries(statusbar-net PUBLIC ${LIBBPF_LIBRARIES}
                                               ${LIBXDP_LIBRARIES})
    target_include_directories(statusbar-net PUBLIC ${LIBBPF_INCLUDE_DIRS}
                                                    ${LIBXDP_INCLUDE_DIRS})
    target_include_directories(
      statusbar-net PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

    add_executable(net_xdp_example net_xdp_example.cpp)
    target_link_libraries(net_xdp_example PRIVATE statusbar)
    set_target_properties(net_xdp_example PROPERTIES OUTPUT_NAME
                                                     statusbar-net-xdp-example)
    set_property(GLOBAL APPEND PROPERTY STATUSBAR_INSTALL_TARGETS
                                        net_xdp_example)
  endif()
endif()
