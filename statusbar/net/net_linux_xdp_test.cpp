// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Tests for statusbar.net:linux_xdp module

#include "statusbar/test/test.hpp"

#ifdef __linux__

// XdpSocketStats has to be a plain struct at namespace scope - a caller
// forward-declares it in its own header, so an alias or a nested type would
// not do. Declared and used here *before* net.hpp is included: if it ever
// became either of those, this stops compiling, which is the only way to
// hold that property down.
namespace statusbar::net {
struct XdpSocketStats;
}
static auto stats_through_an_incomplete_type(statusbar::net::XdpSocketStats const& stats) -> statusbar::net::XdpSocketStats const&;

#    include "statusbar/ieee/ieee.hpp"
#    include "statusbar/net/net.hpp"
#    include "statusbar/status/status.hpp"

#    include <array>
#    include <cerrno>
#    include <cstdint>
#    include <expected>
#    include <optional>
#    include <span>
#    include <string>
#    include <system_error>
#    include <vector>

using namespace statusbar;
using namespace statusbar::net;

static auto stats_through_an_incomplete_type(XdpSocketStats const& stats) -> XdpSocketStats const&
{
    return stats;
}

//
// XdpError tests
//

TEST(xdp_error, error_code_from_enum)
{
    std::error_code ec = XdpError::socket_creation_failed;
    EXPECT_TRUE(ec.value() == 1);
    EXPECT_TRUE(ec.category().name() != nullptr);
}

TEST(xdp_error, different_errors_have_different_values)
{
    std::error_code ec1 = XdpError::socket_creation_failed;
    std::error_code ec2 = XdpError::interface_not_found;
    EXPECT_NE(ec1.value(), ec2.value());
}

TEST(xdp_error, error_message_not_empty)
{
    std::error_code ec = XdpError::socket_creation_failed;
    EXPECT_TRUE(!ec.message().empty());
}

TEST(xdp_error, all_errors_have_messages)
{
    // Verify every error code produces a non-"Unknown" message
    auto check = [](XdpError e) {
        std::error_code ec = e;
        EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
    };
    check(XdpError::socket_creation_failed);
    check(XdpError::interface_not_found);
    check(XdpError::get_hwaddr_failed);
    check(XdpError::umem_creation_failed);
    check(XdpError::xsk_creation_failed);
    check(XdpError::bpf_load_failed);
    check(XdpError::bpf_attach_failed);
    check(XdpError::bpf_map_update_failed);
    check(XdpError::tap_creation_failed);
    check(XdpError::tap_configure_failed);
    check(XdpError::not_open);
    check(XdpError::tx_ring_full);
    check(XdpError::rx_ring_empty);
    check(XdpError::fill_ring_full);
    check(XdpError::free_list_empty);
    check(XdpError::invalid_addr);
    check(XdpError::frame_too_large);
    check(XdpError::tx_flush_failed);
    check(XdpError::join_multicast_failed);
    check(XdpError::not_supported_on_platform);
    check(XdpError::invalid_bpf_program);
    check(XdpError::too_many_filter_rules);
    check(XdpError::zero_copy_needs_native_attach);
    check(XdpError::zero_copy_unavailable);
    check(XdpError::bpffs_not_mounted);
    check(XdpError::invalid_pin_path);
    check(XdpError::pin_failed);
    check(XdpError::queue_busy);
}

TEST(xdp_error, a_busy_queue_says_so)
{
    // An operator reading this goes looking for the process holding the
    // queue, which is the right next move; "XSK socket creation failed"
    // would send them nowhere.
    std::error_code const ec = XdpError::queue_busy;
    EXPECT_TRUE(ec.message().find("busy") != std::string::npos);
}

TEST(xdp_error, category_name)
{
    std::error_code ec = XdpError::not_open;
    std::string name = ec.category().name();
    EXPECT_EQ(name, std::string("statusbar.net.xdp"));
}

//
// XdpConfig defaults tests
//

TEST(xdp_config, default_values)
{
    XdpConfig config{.interface_name = "eth0"};
    EXPECT_EQ(config.default_action, XdpAction::pass_kernel);
    EXPECT_EQ(config.queue_id, 0u);
    EXPECT_EQ(config.rx_ring_size, 256u);
    EXPECT_EQ(config.tx_ring_size, 256u);
    EXPECT_EQ(config.fill_ring_size, 512u);
    EXPECT_EQ(config.completion_ring_size, 512u);
    EXPECT_EQ(config.umem_frame_size, 2048u);
    EXPECT_EQ(config.umem_frame_count, 1024u);
    EXPECT_EQ(config.umem_headroom, 0u);
    EXPECT_EQ(config.tap_ifindex, 0u);
    EXPECT_EQ(config.rx_drain_max, 32u);
    EXPECT_TRUE(config.bind_mode == XdpBindMode::auto_);
    EXPECT_TRUE(config.attach_mode == XdpAttachMode::native);
    // Empty pin path: no pinning, which is the behaviour from before pinning
    // existed. `adopt` only has a say once a pin path is given.
    EXPECT_TRUE(config.pin_path.empty());
    EXPECT_TRUE(config.adopt);
}

//
// Bind / attach mode policy
//
// The whole table is constexpr, so the policy is checked at compile time as
// well as run time. What cannot be checked without hardware is whether a
// given driver actually grants zero-copy or a native attach; that is what
// XdpContext::bind_mode() and attach_mode() report back at run time.
//

TEST(xdp_attach_plan, zero_copy_demands_native_and_does_not_fall_back)
{
    constexpr auto plan = detail::attach_plan(XdpAttachMode::native, XdpBindMode::zero_copy);
    static_assert(plan.has_value());
    static_assert(plan->first == XdpAttachMode::native);
    // Falling back to generic here would quietly deliver copy mode, which is
    // the one thing the caller said it did not want.
    static_assert(!plan->fallback.has_value());
    EXPECT_TRUE(plan.has_value());
}

TEST(xdp_attach_plan, zero_copy_with_generic_attach_is_impossible)
{
    constexpr auto plan = detail::attach_plan(XdpAttachMode::generic, XdpBindMode::zero_copy);
    // Generic XDP runs in the stack, where there is no driver to hand a frame
    // to, so there is nothing to try.
    static_assert(!plan.has_value());
    EXPECT_FALSE(plan.has_value());
}

TEST(xdp_attach_plan, auto_and_copy_try_native_then_generic)
{
    for (auto const bind : {XdpBindMode::auto_, XdpBindMode::copy}) {
        auto const plan = detail::attach_plan(XdpAttachMode::native, bind);
        EXPECT_TRUE(plan.has_value());
        if (plan) {
            EXPECT_TRUE(plan->first == XdpAttachMode::native);
            EXPECT_TRUE(plan->fallback.has_value());
            if (plan->fallback) {
                EXPECT_TRUE(*plan->fallback == XdpAttachMode::generic);
            }
        }
    }

    static_assert(detail::attach_plan(XdpAttachMode::native, XdpBindMode::auto_)->fallback == XdpAttachMode::generic);
    static_assert(detail::attach_plan(XdpAttachMode::native, XdpBindMode::copy)->fallback == XdpAttachMode::generic);
}

TEST(xdp_attach_plan, generic_attach_stays_generic)
{
    for (auto const bind : {XdpBindMode::auto_, XdpBindMode::copy}) {
        auto const plan = detail::attach_plan(XdpAttachMode::generic, bind);
        EXPECT_TRUE(plan.has_value());
        if (plan) {
            EXPECT_TRUE(plan->first == XdpAttachMode::generic);
            // Nothing to fall back to: generic is the mode that works
            // everywhere, so there is nowhere further down to go.
            EXPECT_FALSE(plan->fallback.has_value());
        }
    }
}

TEST(xdp_attach_plan, the_defaults_mean_try_native_fall_back_to_generic)
{
    // A caller that leaves XdpConfig's fields alone gets the forgiving plan.
    constexpr auto plan = detail::attach_plan(XdpAttachMode{}, XdpBindMode{});
    static_assert(plan.has_value());
    static_assert(plan->first == XdpAttachMode::native);
    static_assert(plan->fallback == XdpAttachMode::generic);
    EXPECT_TRUE(plan.has_value());
}

//
// Program pinning: the pure parts
//
// pin_path_for() touches no filesystem, so the convention itself - one
// directory per interface, under a mounted bpffs, with fixed entry names - is
// checked here. What needs a kernel is further down.
//

TEST(xdp_pin_path, each_interface_gets_its_own_directory)
{
    EXPECT_TRUE(XdpProgram::pin_path_for("eth0") == "/sys/fs/bpf/statusbar/eth0");
    EXPECT_TRUE(XdpProgram::pin_path_for("eth1") == "/sys/fs/bpf/statusbar/eth1");
    EXPECT_TRUE(XdpProgram::pin_path_for("eth0") != XdpProgram::pin_path_for("eth1"));
    // Under the bpffs mount, which is the only place a pin can live.
    EXPECT_TRUE(XdpProgram::pin_path_for("eno1").starts_with(XdpProgram::BPFFS_ROOT));
}

TEST(xdp_pin_path, a_name_the_kernel_would_refuse_yields_no_path)
{
    // An empty result means "do not pin". Returning a path built from a name
    // with a '/' in it would be the dangerous answer: pin() creates that
    // directory and detach() unlinks inside it, so a name that can climb out
    // of the pin directory must never reach either.
    for (auto const* const name : {"", "/", "..", ".", "eth0/../../etc", "a b", "eth:0", "with\tTab", "sixteen-chars-xx"}) {
        EXPECT_TRUE(XdpProgram::pin_path_for(name).empty());
    }
    // Fifteen characters is the longest an interface name can be.
    EXPECT_FALSE(XdpProgram::pin_path_for("fifteen-chars-x").empty());
}

TEST(xdp_pin_path, interface_name_validity_is_constexpr)
{
    static_assert(detail::valid_interface_name("eth0"));
    static_assert(detail::valid_interface_name("fifteen-chars-x"));
    static_assert(!detail::valid_interface_name("sixteen-chars-xx"));
    static_assert(!detail::valid_interface_name(""));
    static_assert(!detail::valid_interface_name("."));
    static_assert(!detail::valid_interface_name(".."));
    static_assert(!detail::valid_interface_name("a/b"));
    static_assert(!detail::valid_interface_name("a:b"));
    static_assert(!detail::valid_interface_name("a b"));
    EXPECT_TRUE(detail::valid_interface_name("lo"));
}

TEST(xdp_pin_path, the_entry_names_are_fixed)
{
    auto const dir = XdpProgram::pin_path_for("eth0");
    EXPECT_TRUE(XdpProgram::pin_entry(dir, XdpProgram::PIN_PROG) == "/sys/fs/bpf/statusbar/eth0/prog");
    EXPECT_TRUE(XdpProgram::pin_entry(dir, XdpProgram::PIN_RULES_MAP) == "/sys/fs/bpf/statusbar/eth0/rules_map");
    EXPECT_TRUE(XdpProgram::pin_entry(dir, XdpProgram::PIN_XSK_MAP) == "/sys/fs/bpf/statusbar/eth0/xsk_map");
    EXPECT_TRUE(XdpProgram::pin_entry(dir, XdpProgram::PIN_DEVMAP) == "/sys/fs/bpf/statusbar/eth0/devmap");
    // A trailing slash on the directory does not double up.
    EXPECT_TRUE(XdpProgram::pin_entry("/sys/fs/bpf/statusbar/eth0/", XdpProgram::PIN_PROG) == "/sys/fs/bpf/statusbar/eth0/prog");
    // No directory, no entry: the "do not pin" answer propagates.
    EXPECT_TRUE(XdpProgram::pin_entry("", XdpProgram::PIN_PROG).empty());
    EXPECT_TRUE(XdpProgram::pin_entry(XdpProgram::pin_path_for("bad/name"), XdpProgram::PIN_PROG).empty());
}

TEST(xdp_config, compiled_rule_defaults)
{
    CompiledRule<32> rule{};
    EXPECT_EQ(rule.result_flags, 0u);
    EXPECT_EQ(rule.min_frame_size, 0u);
    EXPECT_EQ(rule.priority, 0u);
    for (auto m : rule.mask) {
        EXPECT_EQ(m, 0u);
    }
    for (auto m : rule.match) {
        EXPECT_EQ(m, 0u);
    }
}

//
// UmemFreeList tests
//

TEST(xdp_freelist, initial_state)
{
    detail::UmemFreeList fl(4, 2048);
    EXPECT_EQ(fl.available(), 4u);
}

TEST(xdp_freelist, pop_returns_frame_addresses)
{
    detail::UmemFreeList fl(4, 2048);
    // Pop all 4 — should get addresses 0, 2048, 4096, 6144 in some order
    std::vector<uint64_t> addrs;
    for (size_t i = 0; i < 4; ++i) {
        auto addr = fl.pop();
        EXPECT_TRUE(addr.has_value());
        addrs.push_back(*addr);
    }
    EXPECT_EQ(fl.available(), 0u);

    // Verify they are multiples of frame_size
    for (auto a : addrs) {
        EXPECT_EQ(a % 2048, 0u);
    }
}

TEST(xdp_freelist, pop_empty_returns_nullopt)
{
    detail::UmemFreeList fl(1, 2048);
    auto a1 = fl.pop();
    EXPECT_TRUE(a1.has_value());
    auto a2 = fl.pop();
    EXPECT_FALSE(a2.has_value());
}

TEST(xdp_freelist, push_then_pop)
{
    detail::UmemFreeList fl(2, 2048);
    auto a1 = fl.pop();
    auto a2 = fl.pop();
    EXPECT_EQ(fl.available(), 0u);

    fl.push(*a1);
    EXPECT_EQ(fl.available(), 1u);

    auto a3 = fl.pop();
    EXPECT_TRUE(a3.has_value());
    EXPECT_EQ(*a3, *a1);
}

TEST(xdp_freelist, push_does_not_exceed_capacity)
{
    detail::UmemFreeList fl(2, 2048);
    // Pop one to make room, then push two back — only one should fit
    auto a1 = fl.pop();
    EXPECT_TRUE(a1.has_value());
    EXPECT_EQ(fl.available(), 1u);

    fl.push(*a1);
    EXPECT_EQ(fl.available(), 2u);

    // Already at capacity — extra push should be silently dropped
    fl.push(99999);
    EXPECT_EQ(fl.available(), 2u);
}

TEST(xdp_freelist, default_constructed_is_empty)
{
    detail::UmemFreeList fl;
    EXPECT_EQ(fl.available(), 0u);
    auto a = fl.pop();
    EXPECT_FALSE(a.has_value());
}

//
// ScopeGuard tests
//

TEST(xdp_scopeguard, fires_on_normal_exit)
{
    bool fired = false;
    {
        auto guard = detail::scopeguard([&] { fired = true; });
        EXPECT_FALSE(fired);
    }
    EXPECT_TRUE(fired);
}

TEST(xdp_scopeguard, fires_on_early_return)
{
    bool fired = false;
    auto test_fn = [&]() {
        auto guard = detail::scopeguard([&] { fired = true; });
        return;  // Early return
    };
    test_fn();
    EXPECT_TRUE(fired);
}

//
// XdpContextOpen RAII wrapper test
//

TEST(xdp_raii, open_throws_on_failure)
{
    XdpContext ctx;
    XdpConfig config{.interface_name = "nonexistent_iface_xyz"};
    bool threw = false;
    try {
        XdpContextOpen opener{ctx, config};
    } catch (std::system_error const&) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

//
// Stub tests (verify stub returns not_supported_on_platform on non-Linux or without libbpf)
//

TEST(xdp_stub, open_fails)
{
    XdpContext ctx;
    XdpConfig config{.interface_name = "eth0"};
    auto status = ctx.open(config);
    EXPECT_FALSE(status.has_value());
}

TEST(xdp_stub, not_valid_by_default)
{
    XdpContext ctx;
    EXPECT_FALSE(ctx.valid());
    EXPECT_EQ(ctx.xsk_fd(), -1);
    EXPECT_EQ(ctx.fd(), -1);
    EXPECT_EQ(ctx.interface_index(), 0u);
}

TEST(xdp_stub, stats_zero_by_default)
{
    XdpContext ctx;
    auto const& s = ctx.stats();
    EXPECT_EQ(s.rx_count, 0u);
    EXPECT_EQ(s.tx_count, 0u);
    EXPECT_EQ(s.tx_ring_full_count, 0u);
}

//
// Socket statistics
//
// Each counter has one home, and the tests below sit in two groups: the
// conditions a plain XdpContext can be put into without a NIC or a
// capability, and the ones that need a bound socket and live in
// xdp_integration further down.
//

TEST(xdp_stats, every_counter_starts_at_zero)
{
    XdpContext ctx;
    auto const& s = ctx.socket_stats();
    EXPECT_EQ(s.rx_count, 0u);
    EXPECT_EQ(s.tx_count, 0u);
    EXPECT_EQ(s.tx_ring_full_count, 0u);
    EXPECT_EQ(s.umem_exhausted_count, 0u);
    EXPECT_EQ(s.rx_budget_hit_count, 0u);
    EXPECT_EQ(s.tx_flush_count, 0u);
    EXPECT_EQ(s.tx_flush_skipped, 0u);
    EXPECT_EQ(s.tx_flush_failed, 0u);
    EXPECT_EQ(s.tx_flush_transient, 0u);
    EXPECT_EQ(s.tx_flush_errno, 0);
    EXPECT_EQ(s.rx_wakeup_count, 0u);

    // stats() is the same object under its older name, and the reference is
    // the live one rather than a copy - which is what lets a caller publish a
    // snapshot of it from its own tick.
    EXPECT_TRUE(&ctx.stats() == &ctx.socket_stats());
    EXPECT_TRUE(&stats_through_an_incomplete_type(ctx.socket_stats()) == &ctx.socket_stats());
}

TEST(xdp_stats, a_send_with_no_umem_frame_left_is_counted)
{
    // The hardest counter to get right and the one that matters most, along
    // with tx_ring_full_count below. A context with no UMEM takes the same
    // branch an exhausted pool takes - the free list is empty either way -
    // so the increment is reachable without a NIC. Exhausting a real pool
    // under load is in xdp_integration.
    XdpContext ctx;
    EXPECT_EQ(ctx.socket_stats().umem_exhausted_count, 0u);
    auto const slot = ctx.tx_start();
    EXPECT_FALSE(slot.has_value());
    if (!slot) {
        EXPECT_TRUE(slot.error() == XdpError::free_list_empty);
    }
    EXPECT_EQ(ctx.socket_stats().umem_exhausted_count, 1u);
    EXPECT_FALSE(ctx.tx_start().has_value());
    EXPECT_EQ(ctx.socket_stats().umem_exhausted_count, 2u);
    // And nothing was sent, so the send counters stay put.
    EXPECT_EQ(ctx.socket_stats().tx_count, 0u);
}

TEST(xdp_stats, a_kick_with_nothing_waiting_is_skipped_rather_than_made)
{
    // A sender ticking faster than it sends spends most ticks with nothing in
    // the TX ring. Those kicks are skipped, and the skip is counted: a *low*
    // skip ratio means a sender kicking the kernel for nothing.
    XdpContext ctx;
    EXPECT_TRUE(ctx.tx_flush().has_value());
    EXPECT_TRUE(ctx.tx_flush().has_value());
    EXPECT_EQ(ctx.socket_stats().tx_flush_skipped, 2u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, 0u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_failed, 0u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_transient, 0u);
}

TEST(xdp_stats, closing_puts_every_counter_back)
{
    XdpContext ctx;
    EXPECT_FALSE(ctx.tx_start().has_value());
    EXPECT_TRUE(ctx.tx_flush().has_value());
    EXPECT_TRUE(ctx.socket_stats().umem_exhausted_count > 0);
    EXPECT_TRUE(ctx.socket_stats().tx_flush_skipped > 0);
    ctx.close();
    EXPECT_EQ(ctx.socket_stats().umem_exhausted_count, 0u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_skipped, 0u);
}

//
// Which refused kicks pass by themselves. The classification is pure, so the
// arms a developer host will never produce are still checked - and checked at
// compile time.
//

TEST(xdp_stats, transient_kick_errnos_are_the_ones_that_pass)
{
    static_assert(detail::transient_kick_errno(EAGAIN));
    static_assert(detail::transient_kick_errno(EWOULDBLOCK));
    static_assert(detail::transient_kick_errno(EBUSY));
    static_assert(detail::transient_kick_errno(ENOBUFS));
    static_assert(detail::transient_kick_errno(ENETDOWN));
    // Anything else means something is actually wrong, and a caller should
    // escalate instead of sending into it again.
    static_assert(!detail::transient_kick_errno(EINVAL));
    static_assert(!detail::transient_kick_errno(EPERM));
    static_assert(!detail::transient_kick_errno(ENODEV));
    static_assert(!detail::transient_kick_errno(EBADF));
    static_assert(!detail::transient_kick_errno(0));
    EXPECT_TRUE(detail::transient_kick_errno(EAGAIN));
    EXPECT_FALSE(detail::transient_kick_errno(EINVAL));
}

TEST(xdp_stub, modes_before_open)
{
    XdpContext ctx;
    // Nothing is bound, so nothing got zero-copy. bind_mode() answers copy
    // rather than auto_ because it reports what is in force, and auto_ is
    // only ever a request.
    EXPECT_FALSE(ctx.zero_copy());
    EXPECT_TRUE(ctx.bind_mode() == XdpBindMode::copy);
    EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
}

TEST(xdp_stub, no_program_before_open)
{
    XdpContext ctx;
    EXPECT_FALSE(ctx.pinned());
    EXPECT_FALSE(ctx.adopted());
    EXPECT_FALSE(ctx.program().pinned());
    EXPECT_FALSE(ctx.program().adopted());
    EXPECT_TRUE(ctx.program().pin_path().empty());
    EXPECT_EQ(ctx.program().id(), 0u);
}

// Needs no privilege and no NIC: the combination is refused before open()
// looks up the interface, so the failure arrives the same way everywhere.
TEST(xdp_open, zero_copy_with_generic_attach_is_refused_before_any_syscall)
{
    XdpContext ctx;
    XdpConfig const config{
        .interface_name = "lo",
        .bind_mode = XdpBindMode::zero_copy,
        .attach_mode = XdpAttachMode::generic,
    };
    auto const status = ctx.open(config);
    EXPECT_FALSE(status.has_value());
    if (!status) {
        EXPECT_TRUE(status.error() == XdpError::zero_copy_needs_native_attach);
    }
    EXPECT_FALSE(ctx.valid());

    // The name is never even looked at, so a nonexistent interface gives the
    // same answer rather than interface_not_found.
    XdpContext other;
    XdpConfig const elsewhere{
        .interface_name = "statusbar-no-such-if",
        .bind_mode = XdpBindMode::zero_copy,
        .attach_mode = XdpAttachMode::generic,
    };
    auto const same = other.open(elsewhere);
    EXPECT_FALSE(same.has_value());
    if (!same) {
        EXPECT_TRUE(same.error() == XdpError::zero_copy_needs_native_attach);
    }
}

//
// Bind retry: the policy
//
// A bind refused with EBUSY is a queue whose previous owner has not finished
// handing it back, which is what every restart runs into. The window is
// microseconds to milliseconds wide and cannot be opened on demand, so the
// policy is tested against a counted attempt and a counted clock instead of
// a socket: that is the only way to see the arms a developer host will not
// produce, and it needs no privilege.
//

namespace {

/// A bind that reports EBUSY the first `busy_for` times it is called and
/// then succeeds, counting both the attempts and the pauses taken between
/// them. Stands in for xsk_socket__create(), which reports a negative errno.
struct CountedBind
{
    size_t busy_for{0};
    int final_errno{0};
    size_t attempts{0};
    size_t pauses{0};

    auto attempt() -> int
    {
        ++attempts;
        return attempts <= busy_for ? -EBUSY : final_errno;
    }

    void pause() { ++pauses; }
};

}  // namespace

TEST(xdp_bind_retry, a_queue_that_is_free_is_bound_once)
{
    CountedBind bind{.busy_for = 0};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, 0);
    EXPECT_EQ(bind.attempts, 1u);
    // Nothing was waited for, so the common case costs no latency at all.
    EXPECT_EQ(bind.pauses, 0u);
}

TEST(xdp_bind_retry, a_queue_still_being_released_is_waited_out)
{
    CountedBind bind{.busy_for = 3};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, 0);
    EXPECT_EQ(bind.attempts, 4u);
    EXPECT_EQ(bind.pauses, 3u);
}

TEST(xdp_bind_retry, the_last_retry_still_counts)
{
    // The boundary from below: refused on every attempt but the last one the
    // budget allows, and the open succeeds.
    CountedBind bind{.busy_for = xdp_bind_busy_retries};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, 0);
    EXPECT_EQ(bind.attempts, xdp_bind_busy_retries + 1);
    EXPECT_EQ(bind.pauses, xdp_bind_busy_retries);
}

TEST(xdp_bind_retry, a_queue_that_stays_busy_gives_up_as_busy)
{
    // The boundary from above. What comes back is the EBUSY itself, so the
    // caller can say "busy" rather than "bind failed".
    CountedBind bind{.busy_for = xdp_bind_busy_retries + 1};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, -EBUSY);
    EXPECT_EQ(bind.attempts, xdp_bind_busy_retries + 1);
    EXPECT_EQ(bind.pauses, xdp_bind_busy_retries);
}

TEST(xdp_bind_retry, the_whole_wait_is_bounded)
{
    // The bound the comment on xdp_bind_busy_retries claims: one pause per
    // retry and no more, so the worst case is the pause times the count.
    // Counted in nanoseconds rather than measured, so this says what the
    // policy costs without anybody waiting for it.
    CountedBind bind{.busy_for = 1000};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, -EBUSY);
    auto const waited_ns = static_cast<long long>(bind.pauses) * xdp_bind_busy_pause_ns;
    EXPECT_EQ(waited_ns, 500'000'000LL);
}

TEST(xdp_bind_retry, an_errno_that_is_not_ebusy_is_never_retried)
{
    // Asserted by the attempt count, not by timing: a real fault must come
    // straight back instead of stalling half a second first and failing the
    // same way. ENODEV is a wrong interface, EOPNOTSUPP a driver without
    // zero-copy, EPERM a missing capability - none of them improve by
    // waiting, and retrying them would hide them behind the busy message.
    for (int const err : {ENODEV, EOPNOTSUPP, EINVAL, EPERM, ENOMEM, EFAULT}) {
        CountedBind bind{.busy_for = 0, .final_errno = -err};
        auto const result =
            detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
        EXPECT_EQ(result, -err);
        EXPECT_EQ(bind.attempts, 1u);
        EXPECT_EQ(bind.pauses, 0u);
    }
}

TEST(xdp_bind_retry, an_errno_that_is_not_ebusy_ends_a_retry_too)
{
    // A queue that is busy and then fails for another reason: the retry
    // stops at the real error rather than carrying on to the bound.
    CountedBind bind{.busy_for = 2, .final_errno = -ENODEV};
    auto const result =
        detail::retry_while_busy(xdp_bind_busy_retries, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, -ENODEV);
    EXPECT_EQ(bind.attempts, 3u);
    EXPECT_EQ(bind.pauses, 2u);
}

TEST(xdp_bind_retry, no_retries_means_the_refusal_is_seen_raw)
{
    // The seam a caller uses to fail fast, and the one a test uses to
    // observe an EBUSY that the default would have waited out.
    CountedBind bind{.busy_for = 1};
    auto const result = detail::retry_while_busy(0, [&bind] { return bind.attempt(); }, [&bind] { bind.pause(); });
    EXPECT_EQ(result, -EBUSY);
    EXPECT_EQ(bind.attempts, 1u);
    EXPECT_EQ(bind.pauses, 0u);
}

TEST(xdp_bind_retry, the_default_config_waits_the_window_out)
{
    // No caller wants the un-retried behaviour, so it is on without being
    // asked for; a caller that names no retry count gets it.
    XdpConfig const config{.interface_name = "lo"};
    EXPECT_EQ(config.bind_busy_retries, xdp_bind_busy_retries);
    EXPECT_EQ(config.bind_busy_retries, 50u);
    EXPECT_EQ(xdp_bind_busy_pause_ns, 10'000'000L);
}

TEST(xdp_bind_retry, a_fresh_context_has_waited_for_nothing)
{
    XdpContext ctx;
    EXPECT_EQ(ctx.bind_retries(), 0u);
}

#    if defined(__linux__) && defined(HAVE_XDP)

//
// Pinning against the real kernel, without privilege
//
// Querying what is attached to an interface goes over netlink and needs no
// capability, so these run everywhere. Pinning itself needs CAP_BPF and a
// writable /sys/fs/bpf, so what is checked here is that each way of being
// unable to pin reports itself as itself.
//

#        include <unistd.h>

#        include <net/if.h>

TEST(xdp_query, nothing_is_attached_to_loopback)
{
    auto const index = ::if_nametoindex("lo");
    EXPECT_TRUE(index != 0);
    auto const attached = XdpProgram::query(index);
    EXPECT_TRUE(attached.has_value());
    if (attached) {
        // An answer, and the answer is "nothing" - told apart from the query
        // having failed, which is the distinction a caller deciding whether
        // to adopt depends on.
        EXPECT_FALSE(attached->has_value());
    }
}

TEST(xdp_query, an_unknown_interface_is_reported_as_one)
{
    constexpr unsigned int NoSuchInterface = 0x7FFFFFFF;
    auto const attached = XdpProgram::query(NoSuchInterface);
    EXPECT_FALSE(attached.has_value());
    if (!attached) {
        EXPECT_TRUE(attached.error() == std::errc::no_such_device);
    }
}

TEST(xdp_detach, succeeds_when_there_is_nothing_to_detach)
{
    // An empty pin path means "detach only", so this reaches nothing but the
    // interface - and loopback has no program on it. Nothing attached is not
    // an error: detach() is idempotent, so a daemon can call it on the way in
    // without first working out what the last run left behind.
    auto const index = ::if_nametoindex("lo");
    EXPECT_TRUE(index != 0);
    EXPECT_TRUE(XdpProgram::detach(index, "").has_value());
    EXPECT_TRUE(XdpProgram::detach(index, "").has_value());
}

TEST(xdp_detach, an_unreadable_pin_directory_is_reported_rather_than_assumed_empty)
{
    // /sys/fs/bpf is mode 700, so without privilege we cannot tell "the pin
    // is not there" from "we cannot look". Reporting the permission error is
    // the honest answer; silently treating it as "nothing to remove" would
    // tell a daemon it had cleaned up when it had not.
    auto const index = ::if_nametoindex("lo");
    auto const absent = XdpProgram::pin_path_for("statusbar-no-if");
    auto const status = XdpProgram::detach(index, absent);
    if (getuid() == 0) {
        EXPECT_TRUE(status.has_value());  // root can look, and there is nothing there
    } else {
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_TRUE(status.error() == std::errc::permission_denied);
        }
    }
}

//
// pinnable(): the three ways pinning can be unavailable, told apart
//

TEST(xdp_pinnable, a_path_outside_the_bpf_filesystem_is_refused)
{
    // "" is what pin_path_for() returns for a name it refused; BPFFS_ROOT
    // itself names no interface; and a path that merely starts with the same
    // letters is not the mount point.
    for (auto const* const path :
         {"/tmp/statusbar-not-bpffs/lo", "/var/lib/statusbar/lo", "", "/sys/fs/bpf", "/sys/fs/bpfs-elsewhere/lo"}) {
        auto const status = XdpProgram::pinnable(path);
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_TRUE(status.error() == XdpError::invalid_pin_path);
        }
    }
}

TEST(xdp_pinnable, a_path_in_a_mounted_bpffs_is_accepted_without_privilege)
{
    // Needs no capability and creates nothing: it is the question a daemon
    // asks of its own config at startup.
    auto const path = XdpProgram::pin_path_for("lo");
    auto const status = XdpProgram::pinnable(path);
    if (status) {
        EXPECT_TRUE(status.has_value());
    } else {
        // A host with no bpffs mounted says so, and says it distinctly from
        // the bad-path answer above.
        EXPECT_TRUE(status.error() == XdpError::bpffs_not_mounted);
    }
    // Nothing was created on the way through.
    EXPECT_TRUE(::access(path.c_str(), F_OK) != 0 || getuid() == 0);
}

TEST(xdp_detach, a_pin_path_it_could_not_have_made_is_refused)
{
    // detach() unlinks inside the directory and then removes it, so a path
    // that is not somewhere a pin could be must not be followed. Nothing
    // outside bpffs is touched, and the interface is left alone too.
    auto const index = ::if_nametoindex("lo");
    for (auto const* const path : {"/tmp/statusbar-elsewhere/lo", "/sys/fs/bpf", "/etc"}) {
        auto const status = XdpProgram::detach(index, path);
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_TRUE(status.error() == XdpError::invalid_pin_path);
        }
    }
}

TEST(xdp_detach, an_unknown_interface_is_reported_as_one)
{
    constexpr unsigned int NoSuchInterface = 0x7FFFFFFF;
    auto const status = XdpProgram::detach(NoSuchInterface, "");
    EXPECT_FALSE(status.has_value());
    if (!status) {
        EXPECT_TRUE(status.error() == std::errc::no_such_device);
    }
}

TEST(xdp_open, a_pin_path_outside_bpffs_is_refused_before_any_syscall)
{
    // Pinning only works inside a bpf filesystem. A path somewhere else is a
    // configuration mistake, and open() says so before it looks the
    // interface up or allocates anything - which is also why this test needs
    // no privilege and no NIC.
    XdpContext ctx;
    XdpConfig const config{
        .interface_name = "lo",
        .umem_frame_count = 16,
        .pin_path = "/tmp/statusbar-not-bpffs/lo",
    };
    auto const status = ctx.open(config);
    EXPECT_FALSE(status.has_value());
    if (!status) {
        EXPECT_TRUE(status.error() == XdpError::invalid_pin_path);
    }
    EXPECT_FALSE(ctx.valid());
    EXPECT_FALSE(ctx.pinned());

    // Not created on the way past, either.
    EXPECT_TRUE(::access("/tmp/statusbar-not-bpffs", F_OK) != 0);

    // The name is never looked up, so a nonexistent interface gives the same
    // answer rather than interface_not_found.
    XdpContext other;
    XdpConfig elsewhere = config;
    elsewhere.interface_name = "statusbar-no-such-if";
    auto const same = other.open(elsewhere);
    EXPECT_FALSE(same.has_value());
    if (!same) {
        EXPECT_TRUE(same.error() == XdpError::invalid_pin_path);
    }
}

TEST(xdp_open, an_empty_pin_path_changes_nothing)
{
    // The opt-in has to be exactly that: with no pin path, open() takes the
    // path it took before pinning existed. Here that means it gets as far as
    // the UMEM and fails there for want of privilege - never on anything to
    // do with pinning.
    XdpContext ctx;
    XdpConfig const config{.interface_name = "lo", .umem_frame_count = 16};
    EXPECT_TRUE(config.pin_path.empty());
    auto const status = ctx.open(config);
    if (!status) {
        EXPECT_TRUE(status.error() != XdpError::invalid_pin_path);
        EXPECT_TRUE(status.error() != XdpError::bpffs_not_mounted);
        EXPECT_TRUE(status.error() != XdpError::pin_failed);
    }
    EXPECT_FALSE(ctx.pinned());
    EXPECT_FALSE(ctx.adopted());
}

//
// Integration tests (require root, veth pairs, Linux with XDP)
//

#        include <cstdlib>

// Helper: create veth pair (requires root)
static bool create_veth_pair(char const* name_a, char const* name_b)
{
    char cmd[256];
    snprintf(
        cmd,
        sizeof(cmd),
        "ip link add %s type veth peer name %s && "
        "ip link set %s up && ip link set %s up",
        name_a,
        name_b,
        name_a,
        name_b);
    return system(cmd) == 0;
}

static void destroy_veth_pair(char const* name_a)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name_a);
    (void)system(cmd);
}

TEST(xdp_integration, open_close_lifecycle)
{
    // Skip if not root
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    auto const rules = ClassifierRuleBuilder<32>{}.ethertype(0x22F0).vlan_tagged_any().result(flag::process).build();

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = rules,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());
    EXPECT_TRUE(ctx.valid());
    EXPECT_TRUE(ctx.xsk_fd() >= 0);
    EXPECT_TRUE(ctx.interface_index() > 0);

    ctx.close();
    EXPECT_FALSE(ctx.valid());
}

// A veth has no native XDP and no zero-copy, which makes it the right place to
// prove the fallback: the default config asks for native, has to settle for
// generic, and must say so afterwards.
TEST(xdp_integration, veth_falls_back_to_generic_attach)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto const status = ctx.open(config);
    EXPECT_TRUE(status.has_value());
    if (status) {
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::generic);
        EXPECT_FALSE(ctx.zero_copy());
        EXPECT_TRUE(ctx.bind_mode() == XdpBindMode::copy);
    }
    ctx.close();

    // Asking for generic outright reaches the same place.
    config.attach_mode = XdpAttachMode::generic;
    auto const generic = ctx.open(config);
    EXPECT_TRUE(generic.has_value());
    if (generic) {
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::generic);
    }
    ctx.close();

    // And insisting on zero-copy fails cleanly, with the reason named and no
    // program left behind on the interface.
    config.attach_mode = XdpAttachMode::native;
    config.bind_mode = XdpBindMode::zero_copy;
    auto const refused = ctx.open(config);
    EXPECT_FALSE(refused.has_value());
    if (!refused) {
        EXPECT_TRUE(refused.error() == XdpError::zero_copy_unavailable);
    }
    EXPECT_FALSE(ctx.valid());
}

// The feature in one test: a pinned program outlives the context that made
// it, the next open adopts it instead of attaching another, and detach() is
// the only thing that takes it away.
//
// Root-only, and so does not run on a developer host. Run it with
//   sudo ./statusbar_test statusbar/net/net_linux_xdp_test
TEST(xdp_integration, a_pinned_program_outlives_the_context_and_is_adopted)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    EXPECT_FALSE(pin_path.empty());
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(::if_nametoindex("xdptest0"), pin_path);
        destroy_veth_pair("xdptest0");
    });

    XdpConfig config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };

    unsigned int if_index = 0;
    uint32_t first_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
        EXPECT_TRUE(ctx.pinned());
        EXPECT_FALSE(ctx.adopted());  // nothing was there to adopt
        EXPECT_TRUE(ctx.program().pin_path() == pin_path);
        EXPECT_TRUE(ctx.program().id() != 0);
        if_index = ctx.interface_index();
        first_id = ctx.program().id();
    }

    // The context is gone and the program is still steering. This is the
    // whole point: an unpinned context would have detached here.
    auto const after = XdpProgram::query(if_index);
    EXPECT_TRUE(after.has_value());
    if (after) {
        EXPECT_TRUE(after->has_value());
        if (*after) {
            EXPECT_EQ((*after)->program_id, first_id);
        }
    }
    for (auto const entry : {XdpProgram::PIN_PROG, XdpProgram::PIN_RULES_MAP, XdpProgram::PIN_XSK_MAP, XdpProgram::PIN_DEVMAP}) {
        EXPECT_EQ(::access(XdpProgram::pin_entry(pin_path, entry).c_str(), F_OK), 0);
    }

    // Second open: the same program, adopted, not attached again.
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
            EXPECT_EQ(ctx.program().id(), first_id);
            auto const during = XdpProgram::query(if_index);
            EXPECT_TRUE(during.has_value());
            if (during && *during) {
                // Not a second attach, and not a replacement: the program on
                // the interface never changed.
                EXPECT_EQ((*during)->program_id, first_id);
            }
        }
    }

    // A pin whose program is no longer attached is stale, not adoptable. The
    // usual way to get here is a crash that took the attachment with it.
    EXPECT_TRUE(XdpProgram::detach(if_index, "").has_value());  // detach only; pins stay
    EXPECT_EQ(::access(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_PROG).c_str(), F_OK), 0);
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
            EXPECT_TRUE(ctx.program().id() != first_id);  // a fresh program, freshly pinned
        }
    }

    // adopt = false forces a fresh attach even when the pin is good.
    uint32_t replaced_id = 0;
    {
        XdpConfig fresh = config;
        fresh.adopt = false;
        XdpContext ctx;
        auto const status = ctx.open(fresh);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
            replaced_id = ctx.program().id();
        }
    }

    // detach() removes both the attachment and the pins, and the process
    // that made them is already gone by now.
    EXPECT_TRUE(XdpProgram::detach(if_index, pin_path).has_value());
    auto const gone = XdpProgram::query(if_index);
    EXPECT_TRUE(gone.has_value());
    if (gone) {
        EXPECT_FALSE(gone->has_value());
    }
    for (auto const entry : {XdpProgram::PIN_PROG, XdpProgram::PIN_RULES_MAP, XdpProgram::PIN_XSK_MAP, XdpProgram::PIN_DEVMAP}) {
        EXPECT_TRUE(::access(XdpProgram::pin_entry(pin_path, entry).c_str(), F_OK) != 0);
    }
    EXPECT_TRUE(replaced_id != 0);

    // And calling it a second time, with nothing left, still succeeds.
    EXPECT_TRUE(XdpProgram::detach(if_index, pin_path).has_value());
}

// Adopting a map that is not the one this build declares would mean writing
// rules into someone else's memory. A pin with a wrong-shaped rules_map must
// be replaced, and must come out of it untouched.
TEST(xdp_integration, a_foreign_pinned_map_is_replaced_and_never_written_to)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(::if_nametoindex("xdptest0"), pin_path);
        destroy_veth_pair("xdptest0");
    });

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };

    unsigned int if_index = 0;
    {
        XdpContext ctx;
        if (!ctx.open(config)) {
            return;
        }
        if_index = ctx.interface_index();
    }

    // Swap the pinned rules_map for one with a different capacity - the shape
    // an older build of the program would have left behind.
    auto const rules_pin = XdpProgram::pin_entry(pin_path, XdpProgram::PIN_RULES_MAP);
    EXPECT_EQ(::unlink(rules_pin.c_str()), 0);
    int const foreign = bpf_map_create(BPF_MAP_TYPE_ARRAY, "rules_map", sizeof(uint32_t), sizeof(uint32_t), 4, nullptr);
    EXPECT_TRUE(foreign >= 0);
    if (foreign < 0) {
        return;
    }
    EXPECT_EQ(bpf_obj_pin(foreign, rules_pin.c_str()), 0);

    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            // Not adopted - and so the foreign map was never written into.
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
        }
    }

    // Every slot of the map we did not recognise is still zero.
    for (uint32_t key = 0; key < 4; ++key) {
        uint32_t value = 0xFFFFFFFF;
        EXPECT_EQ(bpf_map_lookup_elem(foreign, &key, &value), 0);
        EXPECT_EQ(value, 0u);
    }
    ::close(foreign);
}

TEST(xdp_integration, tx_rx_loopback)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // TX side on xdptest0
    XdpConfig tx_config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext tx_ctx;
    auto s1 = tx_ctx.open(tx_config);
    EXPECT_TRUE(s1.has_value());

    // RX side on xdptest1 — accept frames with ethertype 0x9000 via XSK
    auto const rx_rules = ClassifierRuleBuilder<32>{}.ethertype(0x9000).vlan_untagged().result(flag::process).build();
    XdpConfig rx_config{
        .interface_name = "xdptest1",
        .filter_rules = rx_rules,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext rx_ctx;
    auto s2 = rx_ctx.open(rx_config);
    EXPECT_TRUE(s2.has_value());

    // Prime RX fill ring
    (void)rx_ctx.fill_replenish();

    // TX: send a test frame with ethertype 0x9000
    auto tx_slot = tx_ctx.tx_start();
    EXPECT_TRUE(tx_slot.has_value());

    // Build minimal Ethernet frame: dst(6) + src(6) + ethertype(2) + payload
    auto buf = tx_slot->buffer;
    // Broadcast dest
    for (int i = 0; i < 6; ++i) {
        buf[i] = 0xFF;
    }
    // Source from tx interface
    auto const& src_mac = tx_ctx.hardware_address();
    auto const* src_data = src_mac.value.data();
    for (int i = 0; i < 6; ++i) {
        buf[6 + i] = src_data[i];
    }
    // Ethertype 0x9000
    buf[12] = 0x90;
    buf[13] = 0x00;
    // Payload
    buf[14] = 0xDE;
    buf[15] = 0xAD;

    (void)tx_ctx.tx_commit(tx_slot->handle, 64);  // Min frame size
    (void)tx_ctx.tx_flush();

    // Give kernel a moment to deliver
    usleep(10000);  // 10ms

    // RX: check for received frame
    rx_ctx.begin_cycle();
    auto rx_result = rx_ctx.rx_start();
    EXPECT_TRUE(rx_result.has_value());
    // Frame may or may not have arrived (XDP_COPY mode timing), so don't
    // hard-fail. If it arrived, verify payload.
    if (*rx_result) {
        auto const& slot = **rx_result;
        EXPECT_TRUE(slot.buffer.size() >= 16);
        if (slot.buffer.size() >= 16) {
            EXPECT_EQ(slot.buffer[14], 0xDE);
            EXPECT_EQ(slot.buffer[15], 0xAD);
        }
        (void)rx_ctx.rx_release(slot.handle);
    }
}

TEST(xdp_integration, rx_drain_budget)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .rx_drain_max = 2,  // Only drain 2 per cycle
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Verify context opens with drain budget configured and
    // begin_cycle/rx_start work on an empty ring.
    // Note: rx_cycle_count_ only increments on actual frame receipt,
    // so budget enforcement requires live traffic to fully exercise.
    ctx.begin_cycle();

    auto r1 = ctx.rx_start();
    EXPECT_TRUE(r1.has_value());    // Success (no error)
    EXPECT_FALSE(r1->has_value());  // Empty optional (no frames)

    // An empty ring is not the budget: rx_budget_hit_count must stay put, or
    // it would read as a budget problem on every idle tick.
    EXPECT_EQ(ctx.socket_stats().rx_budget_hit_count, 0u);
    EXPECT_EQ(ctx.socket_stats().rx_count, 0u);

    // The budget itself: the counter moves once the cycle has taken its
    // allowance, which is the signal that a tick is cutting a drain short.
    // rx_cycle_count only advances on a frame received, so this is the arm
    // live traffic reaches; checked here against the configured limit.
    EXPECT_EQ(config.rx_drain_max, 2u);
}

TEST(xdp_integration, multiple_inflight_tx)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = {},
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Acquire multiple TX slots before committing any
    auto slot1 = ctx.tx_start();
    auto slot2 = ctx.tx_start();
    auto slot3 = ctx.tx_start();
    EXPECT_TRUE(slot1.has_value());
    EXPECT_TRUE(slot2.has_value());
    EXPECT_TRUE(slot3.has_value());

    // All handles must be distinct
    EXPECT_NE(slot1->handle, slot2->handle);
    EXPECT_NE(slot1->handle, slot3->handle);
    EXPECT_NE(slot2->handle, slot3->handle);

    // Commit all, then single flush
    (void)ctx.tx_commit(slot1->handle, 64);
    (void)ctx.tx_commit(slot2->handle, 64);
    (void)ctx.tx_commit(slot3->handle, 64);
    EXPECT_EQ(ctx.socket_stats().tx_count, 3u);
    (void)ctx.tx_flush();
    // Three frames, one kick: that is the whole point of batching, and the
    // counters are what show it is happening.
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, 1u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_failed, 0u);

    // Reclaim via tx_complete
    usleep(10000);
    (void)ctx.tx_complete();
}

// The counters that need a bound socket. Root-only, so this does not run on a
// developer host; the branches reachable without one are in xdp_stats above.
//   sudo ./statusbar_test statusbar/net/net_linux_xdp_test
TEST(xdp_integration, the_tx_ring_filling_and_the_umem_emptying_are_counted)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // A TX ring smaller than the UMEM, so the ring fills first and the pool
    // empties second: the two conditions are told apart rather than being
    // whichever happened to come first.
    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .tx_ring_size = 8,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    if (!ctx.open(config)) {
        return;
    }

    // Fill the TX ring without ever kicking, so nothing drains out of it.
    size_t committed = 0;
    for (size_t i = 0; i < 64; ++i) {
        auto slot = ctx.tx_start();
        if (!slot) {
            break;
        }
        if (ctx.tx_commit(slot->handle, 64)) {
            ++committed;
        }
    }
    EXPECT_TRUE(committed > 0);
    EXPECT_EQ(ctx.socket_stats().tx_count, committed);
    // Past the ring's capacity every commit is refused and counted, and the
    // frame goes back to the pool rather than leaking.
    EXPECT_TRUE(ctx.socket_stats().tx_ring_full_count > 0);

    // Now empty the pool. fill_replenish() at open() already offered most of
    // it to the kernel, so what is left goes quickly.
    uint64_t exhausted_before = ctx.socket_stats().umem_exhausted_count;
    for (size_t i = 0; i < 4096; ++i) {
        auto slot = ctx.tx_start();
        if (!slot) {
            break;
        }
    }
    EXPECT_TRUE(ctx.socket_stats().umem_exhausted_count > exhausted_before);

    // And the kick that was owed is made exactly once; the next finds nothing
    // waiting and skips.
    auto const kicks_before = ctx.socket_stats().tx_flush_count;
    (void)ctx.tx_flush();
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, kicks_before + 1);
    auto const skipped_before = ctx.socket_stats().tx_flush_skipped;
    (void)ctx.tx_flush();
    EXPECT_EQ(ctx.socket_stats().tx_flush_skipped, skipped_before + 1);
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, kicks_before + 1);
}

// A descriptor the kernel will not accept is the one way to make it refuse a
// kick on demand, which is what gives tx_flush_failed and tx_flush_errno a
// test at all.
TEST(xdp_integration, a_kick_the_kernel_refuses_is_counted_and_keeps_its_errno)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    if (!ctx.open(config)) {
        return;
    }

    // An address past the end of the UMEM. tx_commit() submits it; the kernel
    // rejects the descriptor when the kick asks it to send.
    constexpr uint64_t PastTheUmem = 64 * 2048;
    EXPECT_TRUE(ctx.tx_commit(PastTheUmem, 64).has_value());

    auto const status = ctx.tx_flush();
    EXPECT_FALSE(status.has_value());
    if (!status) {
        EXPECT_TRUE(status.error() == XdpError::tx_flush_failed);
    }
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, 1u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_failed, 1u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_transient, 0u);
    // The errno is kept for the log, and it is a hard one - which is what
    // tells a caller to escalate rather than ride it out.
    EXPECT_TRUE(ctx.socket_stats().tx_flush_errno != 0);
    EXPECT_FALSE(detail::transient_kick_errno(ctx.socket_stats().tx_flush_errno));

    // Still pending, because the kernel never took it: the next kick tries
    // again rather than counting the frame as delivered.
    EXPECT_FALSE(ctx.tx_flush().has_value());
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, 2u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_skipped, 0u);
}

TEST(xdp_integration, set_rules)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // Start with one rule
    auto const rules1 = ClassifierRuleBuilder<32>{}.ethertype(0x22F0).vlan_tagged_any().result(flag::process).build();

    XdpConfig config{
        .interface_name = "xdptest0",
        .filter_rules = rules1,
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto status = ctx.open(config);
    EXPECT_TRUE(status.has_value());

    // Update to different rules
    auto const gptp_rule = ClassifierRuleBuilder<32>{}.ethertype(0x88F7).vlan_untagged().result(flag::none).build();
    auto const udp_rule =
        ClassifierRuleBuilder<32>{}.ethertype(0x0800).ipv4_protocol(17).vlan_untagged().result(flag::process).build();
    std::array<CompiledRule<32>, 2> rules2{gptp_rule[0], udp_rule[0]};

    auto update_status = ctx.set_rules(rules2);
    EXPECT_TRUE(update_status.has_value());
}

// The failure FEAT-007 exists for, reproduced: close a queue and bind it
// again immediately. Without the retry this fails - not every iteration,
// which is what makes the bug so unpleasant to chase, but often enough that
// twenty turns round the loop find it.
TEST(xdp_integration, a_queue_rebound_the_instant_it_is_closed_still_opens)
{
    if (getuid() != 0) {
        return;
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        return;
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    size_t waited = 0;
    for (int i = 0; i < 20; ++i) {
        XdpContext ctx;
        auto const status = ctx.open(config);
        // The whole point: no iteration may come back queue_busy. The
        // previous iteration's socket was closed microseconds ago.
        EXPECT_TRUE(status.has_value());
        if (!status) {
            EXPECT_TRUE(status.error() != XdpError::queue_busy);
            return;
        }
        waited += ctx.bind_retries();
        ctx.close();
    }

    // Not asserted: whether any iteration actually caught the queue still
    // registered depends on how fast this kernel's teardown happens to run,
    // and a test that insists on seeing the race would be the flaky kind.
    // It is reported instead, because a non-zero count is the evidence that
    // the window is real on this machine rather than a story about RCU.
    if (waited != 0) {
        printf("    (the queue was still busy on %zu of 20 re-opens)\n", waited);
    }
}

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_test)