# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT

statusbar_add_module(
  NAME
  net
  SOURCES
  net_address.cpp
  net_bpf_port.cpp
  net_error.cpp
  net_interface_info.cpp
  net_linux_mmap.cpp
  net_linux_xdp.cpp
  net_message_reactor.cpp
  net_netlink.cpp
  net_netdev_features.cpp
  net_rawnet.cpp
  net_ring_buffer_base.cpp
  net_rss.cpp
  net_tap_bridge.cpp
  net_tc_launch_time.cpp
  net_tc_qdisc.cpp
  net_tcp_server.cpp
  net_util.cpp
  net_vlan_link.cpp
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
  net_rawnet_filter_test.cpp
  net_rss_test.cpp
  net_zephyr_eth_concept_test.cpp
  net_compiled_rule_test.cpp
  net_ethernet_port_test.cpp
  net_link_monitor_test.cpp
  net_linux_xdp_test.cpp
  net_netdev_features_test.cpp
  net_launch_order_test.cpp
  net_tc_launch_time_test.cpp
  net_tc_qdisc_test.cpp
  net_tcam_classifier_test.cpp
  net_tcp_server_test.cpp
  net_test.cpp
  net_vlan_link_test.cpp
  net_vlan_link_veth_test.cpp
  net_xdp_abi_test.cpp
  net_xdp_equiv_test.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  statusbar_add_fuzzer(${CMAKE_CURRENT_LIST_DIR}/net_netdev_features_fuzzer.cpp)
endif()

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
  # The netdev uapi constants net_netdev_features.cpp asserts against, where the
  # headers have them (xsk-features from 6.8, tx-launch-time-fifo from 6.15).
  include(CheckCXXSourceCompiles)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  check_cxx_source_compiles(
    "#include <linux/netdev.h>
    static_assert(NETDEV_A_DEV_XSK_FEATURES > NETDEV_A_DEV_XDP_RX_METADATA_FEATURES);"
    STATUSBAR_HAVE_NETDEV_XSK_FEATURES)
  check_cxx_source_compiles(
    "#include <linux/netdev.h>
    static_assert(NETDEV_XSK_FLAGS_TX_LAUNCH_TIME_FIFO != 0);"
    STATUSBAR_HAVE_NETDEV_XSK_LAUNCH_TIME)
  cmake_pop_check_state()
  if(STATUSBAR_HAVE_NETDEV_XSK_FEATURES)
    target_compile_definitions(statusbar-net PRIVATE HAVE_NETDEV_XSK_FEATURES=1)
  endif()
  if(STATUSBAR_HAVE_NETDEV_XSK_LAUNCH_TIME)
    target_compile_definitions(statusbar-net
                               PRIVATE HAVE_NETDEV_XSK_LAUNCH_TIME=1)
  endif()

  find_package(PkgConfig)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBBPF libbpf)
    pkg_check_modules(LIBXDP libxdp)
  endif()
  if(LIBBPF_FOUND AND LIBXDP_FOUND)
    # The BPF object needs the target's multiarch <asm/types.h>: a cross
    # toolchain names it in CMAKE_LIBRARY_ARCHITECTURE (and maybe a sysroot).
    if(CMAKE_CROSSCOMPILING AND CMAKE_LIBRARY_ARCHITECTURE)
      set(MULTIARCH_INCLUDE
          "-I${CMAKE_SYSROOT}/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
    else()
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
    endif()

    find_program(BPF_CLANG clang HINTS ${LLVM_PATH}/bin)
    if(NOT BPF_CLANG)
      message(WARNING "clang not found - cannot compile XDP BPF program")
    endif()

    set(XDP_BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/xdp_filter.bpf.c")
    set(XDP_BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/xdp_filter.bpf.o")
    set(XDP_BPF_HASH "${CMAKE_CURRENT_BINARY_DIR}/xdp_filter_bpf_hash.h")

    # The object's hash goes into a header the embedding TU includes, so a
    # compiler cache (which does not hash #embed'ded files) recompiles it when
    # the object changes.
    add_custom_command(
      OUTPUT ${XDP_BPF_OBJ} ${XDP_BPF_HASH}
      COMMAND ${BPF_CLANG} -target bpf -O2 -g -I${LIBBPF_INCLUDE_DIRS}
              ${MULTIARCH_INCLUDE} -c ${XDP_BPF_SRC} -o ${XDP_BPF_OBJ}
      COMMAND ${CMAKE_COMMAND} -DOBJ=${XDP_BPF_OBJ} -DOUT=${XDP_BPF_HASH} -P
              ${CMAKE_CURRENT_SOURCE_DIR}/xdp_filter_bpf_hash.cmake
      DEPENDS ${XDP_BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/net_tcam_bpf_abi.h
              ${CMAKE_CURRENT_SOURCE_DIR}/xdp_filter_bpf_hash.cmake
      COMMENT "Compiling XDP BPF program"
      VERBATIM)

    add_custom_target(xdp_bpf_obj DEPENDS ${XDP_BPF_OBJ} ${XDP_BPF_HASH})
    add_dependencies(statusbar-net xdp_bpf_obj)

    target_sources(statusbar-net
                   PRIVATE ${CMAKE_CURRENT_LIST_DIR}/xdp_filter_bpf_embed.cpp)
    set_source_files_properties(
      ${CMAKE_CURRENT_LIST_DIR}/xdp_filter_bpf_embed.cpp
      PROPERTIES OBJECT_DEPENDS "${XDP_BPF_OBJ};${XDP_BPF_HASH}")

    # HAVE_XDP must be visible to consumers so the gated parts of
    # net_linux_xdp.hpp compile in their TUs too.
    target_compile_definitions(statusbar-net PUBLIC HAVE_XDP=1)
    # AF_XDP launch time needs xsk_umem__create_opts with tx_metadata_len
    # (libxdp >= 1.5), compiled as net_linux_xdp.cpp uses it. Public: the header
    # uses it.
    include(CheckCXXSourceCompiles)
    include(CMakePushCheckState)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${LIBXDP_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS})
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    check_cxx_source_compiles(
      "#include <xdp/xsk.h>
      auto make(void* area, xsk_ring_prod* fill, xsk_ring_cons* comp) -> xsk_umem* {
        xsk_umem_opts opts{.sz = sizeof(xsk_umem_opts), .size = 4096, .fill_size = 1,
          .comp_size = 1, .frame_size = 4096, .frame_headroom = 24, .flags = 4,
          .tx_metadata_len = 24};
        return xsk_umem__create_opts(area, fill, comp, &opts);
      }"
      STATUSBAR_HAVE_XSK_UMEM_OPTS_TX_METADATA)
    cmake_pop_check_state()
    if(STATUSBAR_HAVE_XSK_UMEM_OPTS_TX_METADATA)
      target_compile_definitions(statusbar-net PUBLIC HAVE_XSK_TX_METADATA=1)
    endif()
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
