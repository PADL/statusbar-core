// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/config/config.hpp"
#include "statusbar/realtime/realtime.hpp"
#include "statusbar/status/status.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <functional>
#include <print>
#include <system_error>
#include <thread>

using namespace statusbar;

namespace {

struct Config
{
    realtime::TimerConfig timer;
    realtime::TraceConfig trace;
    bool quiet{false};
    bool verbose{true};
    bool dump_stats_on_exit{true};
};

auto build_arg_specs(Config& config) -> args::ArgumentSpecs
{
    args::ArgumentSpecs specs;

    // Merge timer specs with "timer." prefix
    specs.merge(realtime::build_timer_arg_specs(config.timer), "timer.");

    // Merge trace specs with "trace." prefix
    specs.merge(realtime::build_trace_arg_specs(config.trace), "trace.");

    specs.add<bool>(
        "quiet", "Suppress per-wake output, only show summary on exit", config.quiet, [&](auto v) { config.quiet = v; });
    specs.add<bool>("verbose", "Enable verbose output during setup", config.verbose, [&](auto v) { config.verbose = v; });
    specs.add<bool>("dump_stats_on_exit", "Dump timer statistics on exit", config.dump_stats_on_exit, [&](auto v) {
        config.dump_stats_on_exit = v;
    });
    return specs;
}

auto parse_config(int argc, char** argv) -> StatusValue<Config>
{
    Config config;
    auto specs = build_arg_specs(config);

    // Parse CLI arguments, handle --completion, --help, --config-load, --config-save, apply bindings
    auto cli_result = config::parse_cli_args(argc, argv, specs);
    if (!cli_result) {
        return failure(cli_result.error());
    }

    // Validate timer config
    if (!realtime::validate_timer_config(config.timer, "timer.")) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }

    return config;
}

/// Everything before the timer exists: the config, the signal handlers
/// and the system's realtime preparation.
auto prepare(int argc, char** argv) -> Config
{
    // Ensure stdout is line-buffered so output appears promptly in terminals
    setvbuf(stdout, NULL, _IOLBF, 0);

    Config config = config::parse_config_or_exit(parse_config, argc, argv);
    realtime::setup_shutdown_signal_handlers();

    // Check realtime capabilities and prepare system
    (void)realtime::print_realtime_diagnostics_and_prepare(config.verbose);

    // Use timer CPU for trace CPU
    config.trace.cpu = config.timer.cpu;
    return config;
}

/// Wait for the shutdown signal, then report as the config asks.
auto wait_and_report(Config const& config, realtime::TimerBase const& timer) -> void
{
    while (!realtime::is_shutdown_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (config.verbose) {
        std::print("\n\nShutting down...\n");
    }
    if (config.dump_stats_on_exit) {
        std::print("\n");
        realtime::print_timer_stats(timer);
    }
}

/// Run a timer until shutdown. Given no adapter, it is scheduled on the
/// default clock, CLOCK_MONOTONIC_RAW.
auto run_timer(Config const& config, realtime::TripwireMonitor& tripwire_monitor) -> void
{
    auto tripwire_monitor_start = realtime::TripwireMonitorStart{tripwire_monitor, &realtime::shutdown_token()};
    realtime::Timer<> timer(config.timer, [&tripwire_monitor, &config](auto const& event, auto const& stats) {
        // Observe tripwire (will trigger if error exceeds threshold)
        realtime::observe_and_handle_tripwire(tripwire_monitor, event);
        if (!config.quiet) {
            event.print(stats);
        }
    });
    if (config.verbose) {
        realtime::print_timer_config(config.timer);
        std::print("\n");
    }
    timer.start(&realtime::shutdown_token());
    wait_and_report(config, timer);
}

}  // namespace

auto main(int argc, char** argv) -> int
{
    Config const config = prepare(argc, argv);

    // Create TripwireMonitor (combines TraceController + Tripwire + monitor thread)
    realtime::TripwireMonitor tripwire_monitor(config.trace);
    run_timer(config, tripwire_monitor);
    return EXIT_SUCCESS;
}
