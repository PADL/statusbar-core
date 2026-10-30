# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Write OUT, a header naming OBJ's SHA-256, for xdp_filter_bpf_embed.cpp to include: a
# compiler cache cannot see an #embed'ded file change, but it sees the header change.
file(SHA256 "${OBJ}" hash)
set(header "#pragma once\n#define XDP_FILTER_BPF_SHA256 \"${hash}\"\n")
set(current "")
if(EXISTS "${OUT}")
  file(READ "${OUT}" current)
endif()
if(NOT current STREQUAL header)
  file(WRITE "${OUT}" "${header}")
endif()
