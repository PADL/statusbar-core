// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// statusbar-logging-example — the intended shape of real-time-safe logging.
//
// Two producer threads (a simulated 1 kHz "media" loop and a "control" loop),
// each with its OWN LogChannel (the SPSC contract), both drained by ONE
// consumer: the LogCollector loop writing to stderr. The media thread logs
// from its timing-critical loop — a suppressed level costs one relaxed atomic
// load, an emitted message costs a <=64-byte pack plus a wait-free ring
// publish, and all formatting/I/O happens on the collector thread.
//
// Also demonstrated: runtime verbosity (the media channel starts at Status,
// gets flipped to Debug mid-run), string-literal parameters via lit(), a
// library function that logs through a `Logger&` it was handed, and the
// drop-counting overflow policy under a deliberate burst.

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/logging/logging.hpp"
#include "statusbar/logging/logging_collector.hpp"
#include "statusbar/logging/logging_sink.hpp"

#include <chrono>
#include <thread>

using namespace statusbar;
using namespace statusbar::logging;

namespace {

// A library function does not know (or care) where its channel lives — it is
// handed a Logger& by its caller.
void library_connect(Logger& log, int const stream, bool const encrypted)
{
    log.status("stream {} connected encryption={}", stream, encrypted ? lit("on") : lit("off"));
    if (!encrypted) {
        log.warning("stream {} is running in the clear", stream);
    }
}

void media_thread(Logger log, itc::StopToken& stop)
{
    int wake = 0;
    while (!stop.stop_requested()) {
        // ... produce one packet's worth of audio here ...
        ++wake;
        if (log.enabled(LogLevel::Debug)) {
            // enabled() guards argument computation, not just the emit.
            log.debug("wake {} err={}ns", wake, (wake % 7) * 25);
        }
        if (wake % 250 == 0) {
            log.status("media alive: {} wakes", wake);
        }
        if (wake == 400) {
            log.error("simulated xrun at wake {}", wake);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
}

}  // namespace

auto main() -> int
{
    LogChannel<256> media_channel{lit("media")};
    LogChannel<16> control_channel{lit("control"), LogLevel::Debug};

    LogCollector<4> collector;
    (void)collector.add(media_channel);
    (void)collector.add(control_channel);

    StderrSink sink;
    itc::StopToken stop;
    std::thread consumer{[&] { collector.run(stop, sink, std::chrono::milliseconds{5}); }};
    std::thread media{[&] { media_thread(media_channel.logger(), stop); }};

    auto control = control_channel.logger();
    control.status("example starting: verbosity media={} control={}", 3, 4);
    library_connect(control, 0, true);
    library_connect(control, 1, false);

    // Runtime verbosity: let the media channel's debug lines through briefly.
    std::this_thread::sleep_for(std::chrono::milliseconds{300});
    control.status("raising media verbosity to Debug for 50ms");
    media_channel.set_verbosity(LogLevel::Debug);
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    media_channel.set_verbosity(LogLevel::Status);
    control.status("media verbosity back to Status");

    // Overflow policy: a burst beyond the control ring's capacity drops (the
    // collector reports the count) instead of ever blocking the producer.
    for (int i = 0; i < 100; ++i) {
        control.debug("burst {}", i);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    control.status("example done");
    stop.request_stop();
    media.join();
    consumer.join();
    return 0;
}
