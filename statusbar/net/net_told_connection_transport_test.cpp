// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ToldConnectionTransport: the in-memory transport an engine's unit tests
// stand it on. These tests pin down that it behaves as the socket pool does
// where an engine can see the difference: readiness is level-triggered and
// obeys read interest, a short write arms write interest, EOF and reset read
// differently, and a close is told to the handler.

#include "statusbar/net/net_told_connection_transport.hpp"

#include "statusbar/net/net_error.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace statusbar;
using namespace statusbar::net;

namespace {

/// A handler that records what it is told and reads nothing by itself.
struct Recorder : TcpConnectionHandler
{
    std::vector<std::string> events;
    int rejected{0};

    void on_accept(size_t slot, SocketAddress const&, int64_t now_ns) override { note("accept", slot, now_ns); }
    void on_readable(size_t slot, int64_t now_ns) override { note("readable", slot, now_ns); }
    void on_writable(size_t slot, int64_t now_ns) override { note("writable", slot, now_ns); }
    void on_closed(size_t slot, int64_t now_ns) override { note("closed", slot, now_ns); }
    void on_rejected(SocketAddress const&, int64_t) override { ++rejected; }

    void note(char const* what, size_t slot, int64_t now_ns)
    {
        events.push_back(std::string{what} + " " + std::to_string(slot) + " @" + std::to_string(now_ns));
    }
};

auto read_text(ToldConnectionTransport& wire, size_t slot, size_t at_most = 64) -> std::string
{
    std::vector<uint8_t> buf(at_most);
    auto const n = wire.read(slot, buf);
    return n ? std::string{buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n)} : std::string{"<error>"};
}

auto bytes_of(std::string_view text) -> std::span<uint8_t const>
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<uint8_t const*>(text.data()), text.size()};
}

}  // namespace

TEST(told_transport, a_peer_lands_in_the_lowest_free_slot_and_a_full_house_turns_it_away)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 2}};
    EXPECT_EQ(wire.capacity(), size_t{2});

    EXPECT_EQ(wire.connect(10).value_or(99), size_t{0});
    EXPECT_EQ(wire.connect(11).value_or(99), size_t{1});
    EXPECT_FALSE(wire.connect(12).has_value());
    EXPECT_EQ(handler.rejected, 1);
    EXPECT_EQ(wire.active_count(), size_t{2});
    EXPECT_TRUE(handler.events == (std::vector<std::string>{"accept 0 @10", "accept 1 @11"}));

    // A closed slot is the next one handed out, and it is a new connection.
    uint64_t const first = wire.generation(0);
    wire.close(0);
    EXPECT_FALSE(wire.is_open(0));
    EXPECT_EQ(wire.connect(20).value_or(99), size_t{0});
    EXPECT_EQ(wire.generation(0), first + 1);
}

TEST(told_transport, what_a_peer_sends_is_readable_until_it_is_read)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 1}};
    size_t const slot = wire.connect(1).value_or(0);

    // Nothing sent: nothing raised, and a read would block.
    EXPECT_EQ(wire.poll(2), size_t{0});
    std::array<uint8_t, 8> buf{};
    auto const empty = wire.read(slot, buf);
    EXPECT_FALSE(empty.has_value());
    EXPECT_TRUE(empty.error() == make_error_code(NetError::would_block));

    EXPECT_TRUE(wire.peer_sends(slot, "hello world"));
    EXPECT_EQ(wire.unread(slot), size_t{11});
    // Level-triggered: raised on every poll while bytes are left unread.
    EXPECT_EQ(wire.poll(3), size_t{1});
    EXPECT_EQ(wire.poll(4), size_t{1});
    EXPECT_TRUE(read_text(wire, slot, 5) == "hello");
    EXPECT_EQ(wire.poll(5), size_t{1});
    EXPECT_TRUE(read_text(wire, slot) == " world");
    EXPECT_EQ(wire.poll(6), size_t{0});
    EXPECT_TRUE(handler.events.back() == "readable 0 @5");
}

TEST(told_transport, read_interest_off_leaves_the_bytes_where_they_are)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 1}};
    size_t const slot = wire.connect(1).value_or(0);
    EXPECT_TRUE(wire.read_interest(slot));

    wire.set_read_interest(slot, false);
    EXPECT_TRUE(wire.peer_sends(slot, "waiting"));
    EXPECT_EQ(wire.poll(2), size_t{0});
    EXPECT_EQ(wire.unread(slot), size_t{7});

    // On again, the pending bytes raise on_readable at the next poll.
    wire.set_read_interest(slot, true);
    EXPECT_EQ(wire.poll(3), size_t{1});
    EXPECT_TRUE(read_text(wire, slot) == "waiting");
}

TEST(told_transport, a_shutdown_reads_as_end_of_file_after_the_bytes_and_a_reset_as_an_error)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 2}};
    size_t const tidy = wire.connect(1).value_or(0);
    size_t const rude = wire.connect(1).value_or(0);

    EXPECT_TRUE(wire.peer_sends(tidy, "bye"));
    wire.peer_shuts_down(tidy);
    EXPECT_EQ(wire.poll(2), size_t{1});
    EXPECT_TRUE(read_text(wire, tidy) == "bye");
    // The end of file is itself readable, and reads as zero bytes.
    EXPECT_EQ(wire.poll(3), size_t{1});
    std::array<uint8_t, 8> buf{};
    EXPECT_EQ(wire.read(tidy, buf).value_or(99), size_t{0});

    EXPECT_TRUE(wire.peer_sends(rude, "lost"));
    wire.peer_resets(rude);
    EXPECT_EQ(wire.poll(4), size_t{2});
    auto const failed = wire.read(rude, buf);
    EXPECT_FALSE(failed.has_value());
    EXPECT_TRUE(failed.error() == make_error_code(NetError::receive_failed));
}

TEST(told_transport, a_short_write_arms_write_interest_until_the_peer_takes_more)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 1}};
    size_t const slot = wire.connect(1).value_or(0);

    // A whole write: nothing armed.
    EXPECT_EQ(wire.write(slot, bytes_of("abc")).value_or(99), size_t{3});
    EXPECT_FALSE(wire.write_interest(slot));

    // The peer stops reading after four more bytes.
    wire.set_write_window(slot, 4);
    EXPECT_EQ(wire.write(slot, bytes_of("defghij")).value_or(99), size_t{4});
    EXPECT_TRUE(wire.write_interest(slot));
    // Nothing more fits: no on_writable, however often the reactor turns.
    EXPECT_EQ(wire.poll(2), size_t{0});
    EXPECT_EQ(wire.write(slot, bytes_of("hij")).value_or(99), size_t{0});

    // The peer reads again: on_writable, and the rest goes out.
    wire.set_write_window(slot, ToldConnectionTransport::UNLIMITED);
    EXPECT_EQ(wire.poll(3), size_t{1});
    EXPECT_TRUE(handler.events.back() == "writable 0 @3");
    EXPECT_EQ(wire.write(slot, bytes_of("hij")).value_or(99), size_t{3});
    EXPECT_FALSE(wire.write_interest(slot));
    EXPECT_EQ(wire.poll(4), size_t{0});

    auto const written = wire.written(slot);
    EXPECT_TRUE((std::string{written.begin(), written.end()}) == "abcdefghij");
    wire.take_written(slot);
    EXPECT_TRUE(wire.written(slot).empty());
}

TEST(told_transport, a_close_is_told_at_the_last_time_the_transport_was_told)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 1}};
    size_t const slot = wire.connect(1).value_or(0);
    EXPECT_EQ(wire.write(slot, bytes_of("last words")).value_or(99), size_t{10});
    (void)wire.poll(41);

    wire.close(slot);
    EXPECT_TRUE(handler.events.back() == "closed 0 @41");
    EXPECT_FALSE(wire.is_open(slot));
    EXPECT_EQ(wire.active_count(), size_t{0});
    // Closing twice tells nobody twice, and a closed slot does nothing.
    size_t const told = handler.events.size();
    wire.close(slot);
    EXPECT_EQ(handler.events.size(), told);
    std::array<uint8_t, 8> buf{};
    EXPECT_TRUE(wire.read(slot, buf).error() == make_error_code(NetError::invalid_handle));
    EXPECT_FALSE(wire.peer_sends(slot, "anyone?"));
    // What was written before the close is still the peer's to read.
    EXPECT_EQ(wire.written(slot).size(), size_t{10});
}

TEST(told_transport, more_than_the_buffer_holds_is_refused_whole)
{
    Recorder handler;
    ToldConnectionTransport wire{handler, {.connections = 1, .inbound_bytes = 8, .outbound_bytes = 8}};
    size_t const slot = wire.connect(1).value_or(0);

    EXPECT_FALSE(wire.peer_sends(slot, "nine byte"));
    EXPECT_EQ(wire.unread(slot), size_t{0});
    EXPECT_TRUE(wire.peer_sends(slot, "eight by"));

    // The engine's side fills, and the rest is a short write.
    EXPECT_EQ(wire.write(slot, bytes_of("0123456789")).value_or(99), size_t{8});
    EXPECT_TRUE(wire.write_interest(slot));
}

TEST_MAIN(statusbar_net, net_told_connection_transport_test)
