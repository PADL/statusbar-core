# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Write OUT, a header naming OBJ's SHA-256, for xdp_filter_bpf_embed.cpp: a
# compiler cache misses an #embed'ded file's change but sees the header's.
# Written every time, as an OUTPUT of the step that rebuilds OBJ.
file(SHA256 "${OBJ}" hash)
file(WRITE "${OUT}" "#pragma once\n#define XDP_FILTER_BPF_SHA256 \"${hash}\"\n")
