// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#pragma once

/// Where a functional test finds a data file it keeps beside its source.
///
/// A functional test runs in two places. On the machine that built it the
/// source tree is there and the file lies beside the test. On a target there
/// is no source tree: the development package carries the test binary
/// (<package>-functional-test) and the files its module names as
/// FUNCTIONAL_TEST_DATA, installed under one directory. The binary has that
/// directory compiled in; the environment variable
/// STATUSBAR_FUNCTIONAL_TEST_DATA_DIR names another, for a package unpacked
/// somewhere it was not built for.

#include <cstdlib>
#include <filesystem>
#include <string_view>

namespace statusbar::test {

/// The directory the installed data files are under: the environment's, else
/// the one compiled into a functional test binary, else none.
[[nodiscard]] inline auto functional_test_data_dir() -> std::filesystem::path
{
    if (char const* const told = std::getenv("STATUSBAR_FUNCTIONAL_TEST_DATA_DIR"); told != nullptr && *told != '\0') {
        return told;
    }
#if defined(STATUSBAR_FUNCTIONAL_TEST_DATA_DIR)
    return STATUSBAR_FUNCTIONAL_TEST_DATA_DIR;
#else
    return {};
#endif
}

/// The path of the data file @p relative to the directory of @p source_file
/// (pass __FILE__): beside the source when the source tree is there, else in
/// the installed data directory under the module's directory name.
[[nodiscard]] inline auto functional_test_data(char const* source_file, std::string_view relative) -> std::filesystem::path
{
    std::filesystem::path const source_dir = std::filesystem::path{source_file}.parent_path();
    std::filesystem::path const beside_source = source_dir / relative;
    if (std::filesystem::exists(beside_source)) {
        return beside_source;
    }
    return functional_test_data_dir() / source_dir.filename() / relative;
}

}  // namespace statusbar::test
