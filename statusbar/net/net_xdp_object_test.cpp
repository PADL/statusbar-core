// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// The embedded XDP object names no build tree. XdpProgram::identity() hashes
// the whole object, debug info included, to decide whether a pinned program
// on the interface is this build's to adopt; a path to the tree it was built
// in would make every tree a different identity and every upgrade a detach
// and a re-attach. The strings in the object may name the source file and
// system headers by their fixed names and nothing under a home, a build or a
// temporary directory.

#include "statusbar/test/test.hpp"

#if defined(__linux__) && defined(HAVE_XDP)

#    include <algorithm>
#    include <cctype>
#    include <cstdint>
#    include <span>
#    include <string>
#    include <string_view>
#    include <vector>

extern unsigned char const xdp_filter_bpf_o[];
extern unsigned int const xdp_filter_bpf_o_len;

namespace {

/// Every run of four or more printable bytes in @p bytes, as strings(1) lists them.
[[nodiscard]] auto printable_runs(std::span<unsigned char const> const bytes) -> std::vector<std::string>
{
    std::vector<std::string> runs;
    std::string current;
    for (unsigned char const c : bytes) {
        if (std::isprint(c) != 0) {
            current.push_back(static_cast<char>(c));
            continue;
        }
        if (current.size() >= 4) {
            runs.push_back(current);
        }
        current.clear();
    }
    return runs;
}

/// Whether @p run names a directory of the tree it was built in: any absolute
/// path that is not a system header's. "/usr" covers the sysroot's headers
/// (/usr/include, the multiarch directory, /usr/local), which are the same on
/// every tree of one distribution.
[[nodiscard]] auto names_a_build_tree(std::string_view const run) -> bool
{
    return run.starts_with("/") && !run.starts_with("/usr");
}

}  // namespace

TEST(xdp_object, the_embedded_program_names_no_build_tree)
{
    if (xdp_filter_bpf_o_len == 0) {
        SKIP("no embedded XDP program in this build");
    }
    auto const runs = printable_runs(std::span<unsigned char const>{xdp_filter_bpf_o, xdp_filter_bpf_o_len});
    // The debug info is there (BTF needs it), and names the source by its mapped name.
    EXPECT_TRUE(std::ranges::any_of(runs, [](std::string const& run) { return run.ends_with("xdp_filter.bpf.c"); }));
    std::string offenders;
    for (auto const& run : runs) {
        if (names_a_build_tree(run)) {
            offenders += run + " ";
        }
    }
    EXPECT_EQ(offenders, std::string{});  // each one a directory of the tree it was built in
}

#endif  // __linux__ && HAVE_XDP

TEST_MAIN(statusbar_net, net_xdp_object_test)
