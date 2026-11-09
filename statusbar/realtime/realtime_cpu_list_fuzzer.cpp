// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// libFuzzer harness for parse_cpu_list(), the sysfs CPU list parser behind CpuSysfs::thread_siblings().
/// It may refuse any input; it may not crash, overflow or list a CPU out of its range.

#include "statusbar/realtime/realtime_cpu_idle.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libFuzzer's bytes read as text
    auto const text = std::string_view{reinterpret_cast<char const*>(data), size};
    if (auto const cpus = statusbar::realtime::parse_cpu_list(text)) {
        for (int const cpu : *cpus) {
            if (cpu < 0 || cpu > 8191) {
                std::abort();
            }
        }
    }
    return 0;
}
