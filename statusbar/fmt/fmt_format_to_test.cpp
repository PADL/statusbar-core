// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// std::format_to into a back_insert_iterator, a literal after a full 256-code-unit buffer: libc++ 20
// to 22 write it past their stack buffer (llvm-project issue 154670), which ASan reports, unless
// toolchain-clang.cmake's overlay is in use.

#include "statusbar/test/test.hpp"

#include <format>
#include <iterator>
#include <string>
#include <vector>

TEST(statusbar_fmt, format_to_after_a_full_buffer_keeps_writing)
{
    std::vector<char> out;
    std::format_to(std::back_inserter(out), "{}a", std::string(256, 'x'));
    EXPECT_EQ(out.size(), size_t{257});
    EXPECT_EQ(out.back(), 'a');
}

TEST_MAIN(statusbar_fmt, fmt_format_to_test)
