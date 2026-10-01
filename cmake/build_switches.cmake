# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Whole-build switches: each one injects a global compile flag or definition, so
# it must be declared exactly once at the widest directory scope of a build —
# the umbrella's top level for an aggregate build, a package's own top level
# standalone. module.cmake includes this file under the same COMMAND guard as
# the sanitizer/coverage/fuzzing options, which is what gives every package (and
# any dependent that reaches module.cmake through find_package( statusbar-core))
# the same three knobs from one definition. Per-package dependency opt-outs
# (STATUSBAR_ENABLE_BPF, STATUSBAR_ENABLE_ALSA, ...) stay with their package:
# they toggle one package's dependencies, not the build.

# Build every library and tool without C++ exceptions. The codebase routes all
# error paths through statusbar::throw_or_abort (which logs + std::terminate()s
# instead of throwing when exceptions are off), so this compiles cleanly. The
# statusbar_test binary is excluded: its EXPECT_* assertions and a handful of
# throw-verification tests rely on exceptions and always run with them on — the
# aggregate and the standalone per-package test binary are both skipped when
# this is ON.
option(ENABLE_NO_EXCEPTIONS
       "Build libraries and tools with -fno-exceptions (test binary excluded)"
       OFF)
if(ENABLE_NO_EXCEPTIONS)
  add_compile_options(-fno-exceptions)
endif()

# Hardened build: make STATUSBAR_ASSERT() emit a real runtime check that traps
# on a violated precondition, even in release. Defense in depth for production
# deployments that prefer fail-closed over the default release behaviour
# ([[assume]], i.e. undefined behaviour on a violated precondition). OFF by
# default; STATUSBAR_HARDENED is otherwise undefined.
option(
  ENABLE_HARDENING
  "Make STATUSBAR_ASSERT trap on violation in all builds (defense in depth)"
  OFF)
if(ENABLE_HARDENING)
  add_compile_definitions(STATUSBAR_HARDENED)
endif()

# PACKET_QDISC_BYPASS lowers stream-TX latency but makes egress INVISIBLE to
# local AF_PACKET capture on the sending host (it skips dev_queue_xmit_nit). ON
# by default. Turn OFF to build a "full local visibility" node (e.g. a Pi used
# as an on-box ATDECC controller/monitor): all TX then goes through the normal
# qdisc path so tcpdump/monitor/controller on the same host observe our own
# stream + control egress, and RawnetContext sockets are opened promiscuous.
option(
  ENABLE_PACKET_QDISC_BYPASS
  "Use PACKET_QDISC_BYPASS for opted-in TX sockets (OFF = all TX visible to local capture + promiscuous RX)"
  ON)
if(NOT ENABLE_PACKET_QDISC_BYPASS)
  add_compile_definitions(STATUSBAR_NO_QDISC_BYPASS)
endif()
