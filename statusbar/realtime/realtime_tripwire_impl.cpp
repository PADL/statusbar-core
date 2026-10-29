// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Implementation of large non-template functions extracted from realtime_tripwire.hpp

#include "statusbar/realtime/realtime_tripwire.hpp"
#include "statusbar/status/catch_or_status.hpp"

namespace statusbar::realtime {

auto build_trace_arg_specs(TraceConfig& config) -> statusbar::args::ArgumentSpecs
{
    statusbar::args::ArgumentSpecs specs;
    specs.add<std::string>(
        "tracer", "Tracer for wake latency trips (wakeup_rt, preemptirqsoff)", config.tracer, [&](auto v) -> void {
            config.tracer = std::move(v);
        });
    specs.add<std::string>(
        "duration_tracer", "Tracer for duration trips (function_graph, function)", config.duration_tracer, [&](auto v) -> void {
            config.duration_tracer = std::move(v);
        });
    specs.add<int>("cpu", "CPU to trace", config.cpu, [&](auto v) -> void { config.cpu = v; });
    specs.add<int>("buffer_kb", "Trace buffer size in KB", config.buffer_kb, [&](auto v) -> void { config.buffer_kb = v; });
    specs.add<std::string>(
        "out_dir", "Directory for trace output files", config.out_dir, [&](auto v) -> void { config.out_dir = std::move(v); });
    specs.add<std::string>("tr_root", "Tracefs root path", config.tr_root, [&](auto v) -> void { config.tr_root = std::move(v); });
    specs.add<int64_t>(
        "tripwire_threshold_ns",
        "Tripwire threshold for wake latency in nanoseconds",
        config.tripwire_threshold_ns,
        [&](auto v) -> void { config.tripwire_threshold_ns = v; });
    specs.add<int64_t>(
        "tripwire_duration_threshold_ns",
        "Tripwire threshold for callback duration in nanoseconds (0=disabled)",
        config.tripwire_duration_threshold_ns,
        [&](auto v) -> void { config.tripwire_duration_threshold_ns = v; });
    specs.add<bool>(
        "enable_tracing",
        "Enable ftrace tracing (false=zero-overhead tripwire only, no trace capture)",
        config.enable_tracing,
        [&](auto v) -> void { config.enable_tracing = v; });
    return specs;
}

auto monitor_tripwire(
    TraceController& controller,
    Tripwire& tripwire,
    statusbar::itc::StopToken* shutdown_token,
    std::atomic<bool>* running_flag,
    int poll_interval_us) -> std::thread
{
    return std::thread([&controller, &tripwire, shutdown_token, running_flag, poll_interval_us]() -> void {
        // `run_guarded`'s label names the thread in our own diagnostics; this
        // names it for top -H, perf and a core dump, which is where a missed
        // deadline is usually being investigated from.
        set_current_thread_name("rt-tripwire");
        // Exception barrier: a thread entry must never let an exception escape
        // (that calls std::terminate and aborts the process). The body is
        // effectively no-throw today, but run_guarded keeps it that way if a
        // future change introduces a throwing call.
        run_guarded("rt tripwire monitor", [&]() -> void {
            // Poll event_ready() (the triple buffer's can_consume) rather
            // than has_fired(): can_consume only flips true after the
            // producer's publish() completes, so the consumed event is
            // always whole — no torn read between the latch and payload.
            while (!tripwire.event_ready()) {
                // Local running flag allows direct stop() without global shutdown
                if (running_flag != nullptr && !running_flag->load(std::memory_order_acquire)) {
                    break;
                }
                // Stop token signals shutdown
                if (shutdown_token != nullptr && shutdown_token->stop_requested()) {
                    break;
                }
                ::usleep(static_cast<useconds_t>(poll_interval_us));
            }

            if (!tripwire.event_ready()) {
                return;  // Clean shutdown without the tripwire firing
            }

            TripwireEvent const ev = tripwire.consume_event();

            char buf[256];
            if (ev.fired_on_duration) {
                std::snprintf(
                    buf,
                    sizeof(buf),
                    "rt_duration_exceeded tick=%" PRIu64 " duration_ns=%" PRId64 " duration_us=%.3f",
                    ev.tick,
                    ev.duration_ns,
                    static_cast<double>(ev.duration_ns) / 1000.0);
            } else {
                std::snprintf(
                    buf,
                    sizeof(buf),
                    "rt_late tick=%" PRIu64 " late_ns=%" PRId64 " late_us=%.3f now_ns=%" PRId64 " sched_ns=%" PRId64,
                    ev.tick,
                    ev.late_ns,
                    static_cast<double>(ev.late_ns) / 1000.0,
                    ev.now_ns,
                    ev.sched_ns);
            }

            controller.capture(buf);
        });
    });
}

auto TraceController::start() -> bool
{
    // If tracing is disabled, explicitly disable any existing ftrace tracer
    // to ensure zero overhead, then mark as started
    if (!cfg_.enable_tracing) {
        auto p = [&](std::string const& leaf) -> std::string { return cfg_.tr_root + "/" + leaf; };
        std::string const tracing_on = p("tracing_on");
        std::string const cur_tracer = p("current_tracer");

        // Disable tracing and set tracer to nop (no-op) for zero overhead
        (void)detail::write_text(tracing_on.c_str(), "0\n");
        (void)detail::write_text(cur_tracer.c_str(), "nop\n");

        started_ = true;
        tracing_enabled_ = false;
        return true;
    }

    tracing_enabled_ = true;
    auto p = [&](std::string const& leaf) -> std::string { return cfg_.tr_root + "/" + leaf; };

    std::string const tracing_on = p("tracing_on");
    std::string const trace = p("trace");
    std::string const snapshot = p("snapshot");
    std::string const snap_clear = p("snapshot_clear");
    std::string const cur_tracer = p("current_tracer");
    std::string const cpumask = p("tracing_cpumask");
    std::string const buf_kb = p("buffer_size_kb");

    // cpu mask: bit cpu -> hex
    // CPU3 => 0x8. Clamp to [0, 31] so we never invoke UB by shifting
    // past the width of `unsigned`. CPUs >= 32 require comma-separated
    // bitmask groups in /sys/.../tracing_cpumask, which this code path
    // doesn't generate — better to refuse than to emit a malformed mask.
    int const cpu_bit = (cfg_.cpu < 0 || cfg_.cpu > 31) ? 0 : cfg_.cpu;
    unsigned const mask = 1U << static_cast<unsigned>(cpu_bit);
    char mask_hex[64];
    std::snprintf(mask_hex, sizeof(mask_hex), "%x\n", mask);

    // Always use the wake latency tracer (wakeup_rt) during operation.
    // The duration_tracer (function_graph) has too much overhead for realtime use.
    // If duration threshold trips, we capture what we can from the wake latency tracer.
    std::string const& active_tracer = cfg_.tracer;

    bool ok = true;
    ok &= detail::write_text(tracing_on.c_str(), "0\n");
    ok &= detail::write_text(cpumask.c_str(), mask_hex);
    ok &= detail::write_text(buf_kb.c_str(), (std::to_string(cfg_.buffer_kb) + "\n"));
    ok &= detail::write_text(cur_tracer.c_str(), (active_tracer + "\n"));

    // Enable function tracing within latency tracers for more detail
    std::string const trace_options = p("trace_options");
    (void)detail::write_text(trace_options.c_str(), "funcgraph-tail\n");  // Show function graph tails
    (void)detail::write_text(trace_options.c_str(), "funcgraph-proc\n");  // Show process names
    (void)detail::write_text(trace_options.c_str(), "latency-format\n");  // Use latency format

    // clear trace buffer
    ok &= detail::write_text(trace.c_str(), "\n");

    // Reset max latency counter (critical for wakeup_rt tracer)
    // Without this, the tracer only updates when it sees a NEW max latency
    std::string const max_latency = p("tracing_max_latency");
    (void)detail::write_text(max_latency.c_str(), "0\n");

    // clear snapshot if supported
    if (detail::file_exists(snap_clear.c_str())) {
        (void)detail::write_text(snap_clear.c_str(), "1\n");
    }

    // baseline proc snapshots
    detail::save_file("/proc/interrupts", cfg_.out_dir + "/rt_interrupts_baseline.txt");
    detail::save_file("/proc/softirqs", cfg_.out_dir + "/rt_softirqs_baseline.txt");

    ok &= detail::write_text(tracing_on.c_str(), "1\n");
    snapshot_supported_ = detail::file_exists(snapshot.c_str());
    started_ = ok;

    // Log diagnostic information to help debug trace capture issues
    if (auto* f = std::fopen((cfg_.out_dir + "/rt_trace_setup.log").c_str(), "w"); f) {
        std::println(f, "TraceController setup:");
        std::println(f, "  active_tracer: {} (always use wake tracer for low overhead)", active_tracer);
        std::println(f, "  duration_threshold_ns: {}", cfg_.tripwire_duration_threshold_ns);
        std::println(f, "  cpu: {} (mask: {:#x})", cfg_.cpu, mask);
        std::println(f, "  buffer_kb: {}", cfg_.buffer_kb);
        std::println(f, "  tracefs: {}", cfg_.tr_root);
        std::println(f, "  snapshot_supported: {}", snapshot_supported_ ? "yes" : "no");
        std::println(f, "  configuration: {}", ok ? "SUCCESS" : "FAILED");
        std::println(f, "");

        // Read back current tracer to verify
        std::string current_tracer;
        if (detail::read_all(cur_tracer.c_str(), current_tracer)) {
            std::print(f, "Current tracer: {}", current_tracer);
        } else {
            std::println(f, "ERROR: Cannot read current_tracer (permission denied?)");
        }

        std::fclose(f);
    }

    return ok;
}

auto TraceController::capture(std::string const& reason) const -> CaptureResult
{
    CaptureResult result;

    // If tracing is disabled, just log the reason
    if (!tracing_enabled_) {
        if (auto* f = std::fopen((cfg_.out_dir + "/rt_late.log").c_str(), "a"); f) {
            std::println(f, "{} (tracing disabled - no trace captured)", reason);
            std::fclose(f);
        }
        result.tracing_disabled = true;
        return result;
    }

    auto p = [&](std::string const& leaf) -> std::string { return cfg_.tr_root + "/" + leaf; };

    std::string const marker = p("trace_marker");
    std::string const tracing_on = p("tracing_on");
    std::string const snapshot = p("snapshot");
    std::string const trace = p("trace");

    // Write marker so you can find the event in the trace
    (void)detail::write_text(marker.c_str(), reason + "\n");

    // Stop tracing to freeze buffers
    (void)detail::write_text(tracing_on.c_str(), "0\n");

    // Trigger snapshot if supported; otherwise dump current trace buffer
    if (snapshot_supported_ && detail::file_exists(snapshot.c_str())) {
        // Many kernels snapshot on write "1"
        (void)detail::write_text(snapshot.c_str(), "1\n");

        // Try to save snapshot - check if it worked
        std::string snapshot_data;
        if (detail::read_all(snapshot.c_str(), snapshot_data) && !snapshot_data.empty()) {
            std::string const output_path = cfg_.out_dir + "/rt_snapshot.txt";
            int const fd = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                (void)detail::write_all(fd, snapshot_data);
                ::close(fd);
                result.success = true;
                result.output_file = output_path;
            }
        }
    }

    if (!result.success) {
        // Fallback to trace buffer
        std::string trace_data;
        if (detail::read_all(trace.c_str(), trace_data) && !trace_data.empty()) {
            std::string const output_path = cfg_.out_dir + "/rt_trace.txt";
            int const fd = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0) {
                (void)detail::write_all(fd, trace_data);
                ::close(fd);
                result.success = true;
                result.output_file = output_path;
            }
        }
    }

    // dump proc state at event
    detail::save_file("/proc/interrupts", cfg_.out_dir + "/rt_interrupts_at_event.txt");
    detail::save_file("/proc/softirqs", cfg_.out_dir + "/rt_softirqs_at_event.txt");

    // Log capture results
    if (auto* f = std::fopen((cfg_.out_dir + "/rt_late.log").c_str(), "a"); f) {
        std::println(f, "{}", reason);
        if (result.success) {
            std::println(f, "  -> Trace captured successfully: {}", result.output_file);
        } else {
            std::println(f, "  -> WARNING: Failed to capture trace (check permissions and tracer status)");
        }
        std::fclose(f);
    }

    return result;
}

}  // namespace statusbar::realtime
