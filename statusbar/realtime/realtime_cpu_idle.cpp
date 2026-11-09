// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/realtime/realtime_cpu_idle.hpp"

#include "statusbar/realtime/realtime_base.hpp"
#include "statusbar/status/status.hpp"

#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace statusbar::realtime {

namespace {

/// The largest CPU number a list may name: the kernel's NR_CPUS limit (CONFIG_NR_CPUS) less one.
constexpr int MAX_CPU = 8191;

[[nodiscard]] auto errno_error() noexcept -> std::error_code
{
    return std::error_code{errno, std::generic_category()};
}

/// `text` as a whole unsigned number no larger than `max`; none for anything else.
template <typename T>
[[nodiscard]] auto parse_number(std::string_view const text, T const max) noexcept -> std::optional<T>
{
    T value{};
    auto const [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    bool const whole = error == std::errc{} && end == text.data() + text.size() && !text.starts_with('-');
    return whole && value <= max ? std::optional<T>{value} : std::nullopt;
}

/// Appends `item`, "N" or "N-M", to `cpus`.
[[nodiscard]] auto add_cpu_range(std::string_view const item, std::vector<int>& cpus) -> Status
{
    auto const dash = item.find('-');
    auto const first = parse_number(item.substr(0, dash), MAX_CPU);
    auto const last = dash == std::string_view::npos ? first : parse_number(item.substr(dash + 1), MAX_CPU);
    if (!first || !last || *last < *first) {
        return failure(std::errc::invalid_argument);
    }
    cpus.append_range(std::views::iota(*first, *last + 1));
    return success();
}

/// `text` without the newline sysfs ends an attribute with.
[[nodiscard]] auto without_newline(std::string_view text) noexcept -> std::string_view
{
    while (text.ends_with('\n')) {
        text.remove_suffix(1);
    }
    return text;
}

/// The attribute at `path`, without its newline; the open or read's error.
[[nodiscard]] auto read_attribute(std::string const& path) -> StatusValue<std::string>
{
    std::string text;
    if (!detail::read_all(path.c_str(), text)) {
        return failure(errno_error());
    }
    return std::string{without_newline(text)};
}

/// Writes `text` to the attribute at `path`; the open or write's error.
[[nodiscard]] auto write_attribute(std::string const& path, std::string_view const text) -> Status
{
    return detail::write_text(path.c_str(), text) ? success() : failure(errno_error());
}

/// A state's exit latency from its `latency` file; invalid_argument when missing or malformed.
[[nodiscard]] auto read_latency(std::string const& directory) -> StatusValue<uint32_t>
{
    auto const text = read_attribute(directory + "/latency");
    if (!text) {
        return text.error() == std::errc::no_such_file_or_directory ? failure(std::errc::invalid_argument) : forward_failure(text);
    }
    auto const latency_us = parse_number(*text, UINT32_MAX);
    return latency_us ? StatusValue<uint32_t>{*latency_us} : failure(std::errc::invalid_argument);
}

/// The state in `directory`, `cpuN/cpuidle/stateK`; no_such_file_or_directory only when it has no `name`.
[[nodiscard]] auto read_idle_state(std::string const& directory) -> StatusValue<CpuIdleState>
{
    auto name = read_attribute(directory + "/name");
    auto const latency_us = name ? read_latency(directory) : StatusValue<uint32_t>{failure(name.error())};
    if (!latency_us) {
        return forward_failure(latency_us);
    }
    return CpuIdleState{.name = std::move(*name), .latency_us = *latency_us};
}

}  // namespace

auto parse_cpu_list(std::string_view const text) -> StatusValue<std::vector<int>>
{
    if (text.empty()) {
        return failure(std::errc::invalid_argument);  // split() would yield no item
    }
    std::vector<int> cpus;
    for (auto const item : std::views::split(text, ',')) {
        if (auto const added = add_cpu_range(std::string_view{item}, cpus); !added) {
            return forward_failure(added);
        }
    }
    return cpus;
}

CpuSysfs::CpuSysfs(std::string root)
    : root_{std::move(root)}
{}

auto CpuSysfs::thread_siblings(int const cpu) const -> StatusValue<std::vector<int>>
{
    auto const list = read_attribute(cpu_path(cpu, "topology/thread_siblings_list"));
    return list ? parse_cpu_list(*list) : forward_failure(list);
}

auto CpuSysfs::idle_states(int const cpu) const -> StatusValue<std::vector<CpuIdleState>>
{
    std::vector<CpuIdleState> states;
    for (;;) {
        auto state = read_idle_state(cpu_path(cpu, std::format("cpuidle/state{}", states.size())));
        if (!state) {
            bool const ended = state.error() == std::errc::no_such_file_or_directory && !states.empty();
            return ended ? StatusValue<std::vector<CpuIdleState>>{std::move(states)} : forward_failure(state);
        }
        states.push_back(std::move(*state));
    }
}

auto CpuSysfs::set_resume_latency_limit(int const cpu, uint32_t const limit_us) const -> Status
{
    auto const text = limit_us == 0 ? std::string{"n/a"} : std::to_string(limit_us);
    return write_attribute(cpu_path(cpu, "power/pm_qos_resume_latency_us"), text);
}

auto CpuSysfs::cpu_path(int const cpu, std::string_view const file) const -> std::string
{
    return std::format("{}/cpu{}/{}", root_, cpu, file);
}

}  // namespace statusbar::realtime
