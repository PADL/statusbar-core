include(${PROJECT_SOURCE_DIR}/cmake/module.cmake)

# Package INTERFACE library, include path and the global accumulation properties
# (statusbar_package_module_init in cmake/module.cmake).
statusbar_package_module_init()

# Module subdirectories — dependency order.
add_subdirectory(status)
add_subdirectory(safe_arith)
add_subdirectory(checksum)
add_subdirectory(secure_random)
add_subdirectory(fmt)
add_subdirectory(buffer)
add_subdirectory(ieee)
add_subdirectory(test)
add_subdirectory(stats)
add_subdirectory(benchmark)
add_subdirectory(tsn)
add_subdirectory(args)
add_subdirectory(config)
add_subdirectory(toml)
add_subdirectory(container)
add_subdirectory(pcap)
add_subdirectory(ip)
if(STATUSBAR_ENABLE_BPF)
  add_subdirectory(bpf)
endif()
add_subdirectory(colbin)
add_subdirectory(csv)
add_subdirectory(itc)
add_subdirectory(logging)
add_subdirectory(mem)
add_subdirectory(net)
add_subdirectory(http)
add_subdirectory(realtime)
add_subdirectory(sm)
add_subdirectory(tui)

# Populate the package INTERFACE library — skipped under an outer aggregate
# build, where the outer project populates a single shared `statusbar` covering
# every aggregated package.
if(NOT STATUSBAR_AGGREGATE_BUILD)
  target_link_libraries(
    statusbar
    INTERFACE statusbar-status
              statusbar-safe_arith
              statusbar-secure_random
              statusbar-fmt
              statusbar-buffer
              statusbar-ieee
              statusbar-test
              statusbar-stats
              statusbar-benchmark
              statusbar-tsn
              statusbar-args
              statusbar-config
              statusbar-toml
              statusbar-container
              statusbar-pcap
              statusbar-ip
              statusbar-colbin
              statusbar-csv
              statusbar-itc
              statusbar-mem
              statusbar-net
              statusbar-http
              statusbar-realtime
              statusbar-sm
              statusbar-tui)
  if(STATUSBAR_ENABLE_BPF)
    target_link_libraries(statusbar INTERFACE statusbar-bpf)
  endif()
endif()

# Standalone per-package test binary (statusbar_package_test_binary in
# cmake/module.cmake); the outer aggregate build builds one combined
# statusbar_test from every aggregated package instead.
statusbar_package_test_binary()
