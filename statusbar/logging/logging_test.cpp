// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the deferred-formatting SPSC logging: entry encode/decode
// round-trips, verbosity gating, overflow accounting, sequence numbering,
// the collector's multi-channel drain, sinks, and a producer/consumer
// threading smoke test. The "no transient strings" rule is compile-time
// (consteval StrLit / static_asserts in detail::stored), so it has no
// runtime negative test — a violation does not compile.

#include "statusbar/logging/logging.hpp"

#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/logging/logging_collector.hpp"
#include "statusbar/logging/logging_sink.hpp"
#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using namespace statusbar;
using namespace statusbar::logging;

namespace {

/// Captures rendered lines for assertions.
class CaptureSink final : public LogSink
{
  public:
    void write(LogLevel const level, std::string_view const line) override
    {
        levels.push_back(level);
        lines.emplace_back(line);
    }
    void flush() override { ++flushes; }

    std::vector<LogLevel> levels;
    std::vector<std::string> lines;
    int flushes{0};
};

/// Drain one entry and render just the message text.
auto drain_message(LogChannelBase& channel) -> std::string
{
    auto const entry = channel.drain_one();
    EXPECT_TRUE(entry.has_value());
    return entry ? entry->message() : std::string{};
}

}  // namespace

TEST(logging, formats_arithmetic_and_literal_args)
{
    LogChannel<8> channel{lit("test")};
    auto log = channel.logger();

    log.status("plain message");
    log.status("i={} u={} f={:.3f} b={} c={}", -42, 7U, 2.625, true, 'x');
    log.status("mode={} rate={}", lit("fast"), uint64_t{96000});

    EXPECT_EQ(drain_message(channel), "plain message");
    EXPECT_EQ(drain_message(channel), "i=-42 u=7 f=2.625 b=true c=x");
    EXPECT_EQ(drain_message(channel), "mode=fast rate=96000");

    // static_str: the explicit escape hatch for name-table lookups (runtime-
    // selected pointers to string literals).
    static constexpr char const* names[] = {"Idle", "Ready"};
    int const state = 1;
    log.status("state={}", static_str(names[state]));  // NOLINT
    EXPECT_EQ(drain_message(channel), "state=Ready");
    EXPECT_FALSE(channel.drain_one().has_value());
}

TEST(logging, entry_is_self_contained_after_publish)
{
    // The rendered output must not depend on producer-side storage: the
    // format string and lit() parameters are static, everything else is
    // copied by value into the entry.
    LogChannel<8> channel{lit("test")};
    auto log = channel.logger();

    {
        int transient = 1234;  // goes out of scope before rendering
        log.status("v={}", transient);
        transient = 0;
    }
    auto const entry = channel.drain_one();
    EXPECT_TRUE(entry.has_value());
    EXPECT_EQ(entry->message(), "v=1234");
    // The format pointer refers to static storage (trampoline + literal).
    EXPECT_TRUE(entry->fmt_data != nullptr);
    EXPECT_TRUE(entry->format != nullptr);
}

TEST(logging, verbosity_gates_levels)
{
    LogChannel<16> channel{lit("test"), LogLevel::Warning};
    auto log = channel.logger();

    log.error("e");
    log.warning("w");
    log.status("s");  // suppressed at Warning verbosity
    log.debug("d");   // suppressed

    EXPECT_EQ(drain_message(channel), "e");
    EXPECT_EQ(drain_message(channel), "w");
    EXPECT_FALSE(channel.drain_one().has_value());

    EXPECT_TRUE(channel.enabled(LogLevel::Warning));
    EXPECT_FALSE(channel.enabled(LogLevel::Status));

    channel.set_verbosity(LogLevel::None);
    log.error("suppressed entirely");
    EXPECT_FALSE(channel.drain_one().has_value());
    EXPECT_FALSE(channel.enabled(LogLevel::Error));

    channel.set_verbosity(LogLevel::Debug);
    log.debug("now visible");
    EXPECT_EQ(drain_message(channel), "now visible");

    // Suppressed messages consume no sequence numbers and count no drops.
    EXPECT_EQ(channel.take_dropped(), 0U);
}

TEST(logging, overflow_drops_and_counts)
{
    // Capacity 4 ring holds 3 entries (one slot is the full/empty sentinel).
    LogChannel<4> channel{lit("test")};
    auto log = channel.logger();

    for (int i = 0; i < 10; ++i) {
        log.status("m{}", i);
    }
    // Oldest entries survive, in order; the rest were dropped, not blocked on.
    EXPECT_EQ(drain_message(channel), "m0");
    EXPECT_EQ(drain_message(channel), "m1");
    EXPECT_EQ(drain_message(channel), "m2");
    EXPECT_FALSE(channel.drain_one().has_value());
    EXPECT_EQ(channel.take_dropped(), 7U);
    EXPECT_EQ(channel.take_dropped(), 0U);  // counter resets on read
}

TEST(logging, sequence_and_timestamp_are_stamped)
{
    LogChannel<8> channel{lit("test")};
    channel.set_clock([]() noexcept -> uint64_t { return 42'000'000'000ULL; });
    auto log = channel.logger();

    log.status("a");
    log.status("b");
    auto const a = channel.drain_one();
    auto const b = channel.drain_one();
    EXPECT_TRUE(a.has_value() && b.has_value());
    EXPECT_EQ(a->seq, 0U);
    EXPECT_EQ(b->seq, 1U);
    EXPECT_EQ(a->timestamp_ns, 42'000'000'000ULL);
    EXPECT_EQ(a->level, LogLevel::Status);
}

TEST(logging, collector_drains_multiple_channels_and_reports_drops)
{
    LogChannel<8> media{lit("media")};
    LogChannel<4> control{lit("control"), LogLevel::Debug};
    LogCollector<4> collector;
    EXPECT_TRUE(collector.add(media));
    EXPECT_TRUE(collector.add(control));
    EXPECT_EQ(collector.channel_count(), 2U);

    auto media_log = media.logger();
    auto control_log = control.logger();
    media_log.status("wake ok");
    media_log.error("xrun {}", 3);
    control_log.debug("srp {}", lit("Ready"));
    for (int i = 0; i < 10; ++i) {
        control_log.status("flood {}", i);  // capacity-4 ring: most drop
    }

    CaptureSink sink;
    auto const lines = collector.poll(sink);
    // media: 2 lines; control: 3 ring entries (srp + 2 floods) + 1 drop line.
    EXPECT_EQ(lines, 6U);
    EXPECT_TRUE(sink.lines[0].find("[media] wake ok") != std::string::npos);
    EXPECT_TRUE(sink.lines[0].find(" S ") != std::string::npos);
    EXPECT_TRUE(sink.lines[1].find("[media] xrun 3") != std::string::npos);
    EXPECT_TRUE(sink.lines[2].find("[control] srp Ready") != std::string::npos);
    EXPECT_TRUE(sink.lines.back().find("[control] log ring overflow: 8 message(s) dropped") != std::string::npos);
    EXPECT_TRUE(sink.flushes >= 1);

    // Idle poll writes nothing and doesn't flush again.
    auto const flushes_before = sink.flushes;
    EXPECT_EQ(collector.poll(sink), 0U);
    EXPECT_EQ(sink.flushes, flushes_before);
}

TEST(logging, render_line_layout)
{
    LogChannel<8> channel{lit("tone")};
    channel.set_clock([]() noexcept -> uint64_t { return 1'500'000ULL; });  // 0.001500 s
    auto log = channel.logger();
    log.warning("late by {}ns", 250);
    auto const entry = channel.drain_one();
    EXPECT_TRUE(entry.has_value());
    EXPECT_EQ(render_line(channel.name(), *entry), "0.001500 W [tone] late by 250ns\n");
}

TEST(logging, file_sink_writes_lines)
{
    char path[] = "/tmp/statusbar_logging_test_XXXXXX";
    int const fd = mkstemp(path);
    EXPECT_TRUE(fd >= 0);
    close(fd);

    {
        FileSink sink{path};
        EXPECT_TRUE(sink.is_open());
        sink.write(LogLevel::Status, "hello sink\n");
        sink.flush();
    }
    std::FILE* f = std::fopen(path, "re");
    EXPECT_TRUE(f != nullptr);
    char buf[64] = {};
    (void)std::fgets(buf, sizeof(buf), f);
    (void)std::fclose(f);
    (void)std::remove(path);
    EXPECT_EQ(std::string{buf}, "hello sink\n");
}

TEST(logging, spsc_threaded_smoke)
{
    // One producer thread hammering, the collector loop consuming — every
    // message is either delivered (in order) or counted as dropped.
    constexpr int TOTAL = 20'000;
    LogChannel<64> channel{lit("smoke")};
    LogCollector<1> collector;
    EXPECT_TRUE(collector.add(channel));

    class CountingSink final : public LogSink
    {
      public:
        void write(LogLevel /*level*/, std::string_view const line) override
        {
            // Drop-report lines carry the count the collector consumed from
            // the channel's counter; fold them in so the total balances.
            auto const pos = line.find("overflow: ");
            if (pos == std::string_view::npos) {
                ++delivered;
                return;
            }
            dropped += std::atoi(line.data() + pos + 10);  // NOLINT(cert-err34-c)
        }
        int delivered{0};
        int dropped{0};
    };
    CountingSink sink;

    itc::StopToken stop;
    std::thread consumer{[&] { collector.run(stop, sink, std::chrono::milliseconds{1}); }};

    std::thread producer{[&] {
        auto log = channel.logger();
        for (int i = 0; i < TOTAL; ++i) {
            log.status("n={}", i);
        }
    }};
    producer.join();
    stop.request_stop();
    consumer.join();

    auto const residual = static_cast<int>(channel.take_dropped());
    EXPECT_EQ(sink.delivered + sink.dropped + residual, TOTAL);
    EXPECT_TRUE(sink.delivered > 0);
}

TEST_MAIN(statusbar_logging, logging_test)
