# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
#
# Write OUT, a header defining xdp_filter_bpf_o_sha256 as OBJ's SHA-256, for
# xdp_filter_bpf_embed.cpp: a compiler cache misses an #embed'ded file's change
# but sees the header's.
# Written every time, as an OUTPUT of the step that rebuilds OBJ.
file(SHA256 "${OBJ}" hash)
file(WRITE "${OUT}"
     "#pragma once\nextern char const xdp_filter_bpf_o_sha256[] = \"${hash}\";\n")
