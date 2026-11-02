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

#    include <poll.h>
#    include <unistd.h>

#    include <array>
#    include <cerrno>
#    include <cstddef>
#    include <cstdint>
#    include <expected>
#    include <fstream>
#    include <limits>
#    include <optional>
#    include <span>
#    include <string>
#    include <system_error>
#    include <vector>

#    include <linux/if_packet.h>
#    include <net/if.h>

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
    check(XdpError::foreign_program);
    check(XdpError::pin_not_adoptable);
    check(XdpError::program_unidentifiable);
    check(XdpError::stats_read_failed);
}

TEST(xdp_error, a_busy_queue_says_so)
{
    // An operator reading this goes looking for the process holding the
    // queue, which is the right next move; "XSK socket creation failed"
    // would send them nowhere.
    std::error_code const ec = XdpError::queue_busy;
    EXPECT_TRUE(ec.message().find("busy") != std::string::npos);
}

TEST(xdp_error, the_two_ways_a_pin_is_not_adopted_read_differently)
{
    // One of these says "left alone", the other says "replaced", and an
    // operator has to be able to tell which happened from the message.
    std::error_code const foreign = XdpError::foreign_program;
    std::error_code const stale = XdpError::pin_not_adoptable;
    EXPECT_TRUE(foreign.message() != stale.message());
    EXPECT_TRUE(foreign.message().find("not ours") != std::string::npos);
    EXPECT_TRUE(foreign.message().find("left alone") != std::string::npos);
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

// A UMEM frame must leave room for a whole Ethernet frame *after* the kernel's
// XDP headroom and after igb/igc round the RX buffer down to a 1 KiB unit.
// 2048 leaves 1792, which rounds to 1 KiB, and a 1522-octet frame then arrives
// truncated to its first buffer - silently, counted as received, with the
// payload cut. 4096 leaves 3840, which rounds to 3 KiB.
TEST(xdp_config, the_default_umem_frame_holds_a_whole_frame_after_the_kernels_headroom)
{
    constexpr size_t XDP_HEADROOM = 256;     // XDP_PACKET_HEADROOM
    constexpr size_t RX_BUFFER_UNIT = 1024;  // igb/igc allocate in 1 KiB units
    constexpr size_t LARGEST_FRAME = 1522;   // 1500-octet MTU, VLAN tagged, FCS
    XdpConfig const config{.interface_name = "eth0"};
    size_t const usable = config.umem_frame_size - config.umem_headroom - XDP_HEADROOM;
    EXPECT_TRUE(usable / RX_BUFFER_UNIT * RX_BUFFER_UNIT >= LARGEST_FRAME);
}

// The kernel's own rules for a UMEM's geometry (net/xdp/xdp_umem.c,
// xdp_umem_reg), checked here rather than discovered as a bare EINVAL that
// open() would report as "UMEM creation failed".
//
// The page size is a parameter because it is not the same everywhere: x86 has
// 4 KiB pages, this host and the Pi 5 have 16 KiB. A frame size above 4096
// therefore works on one and is refused on the other, which is exactly the
// kind of difference that should not need hardware to find.
TEST(xdp_umem_geometry, the_kernels_rules_for_a_frame_size_are_checked_up_front)
{
    constexpr size_t PAGE_4K = 4096;
    constexpr size_t PAGE_16K = 16384;
    // The usual pair, valid everywhere.
    EXPECT_TRUE(detail::umem_geometry_is_valid(2048, 0, PAGE_4K));
    EXPECT_TRUE(detail::umem_geometry_is_valid(4096, 0, PAGE_4K));
    // Below the kernel's minimum chunk.
    EXPECT_FALSE(detail::umem_geometry_is_valid(1024, 0, PAGE_4K));
    // Not a power of two: refused in aligned-chunk mode, which is the only
    // mode this module uses.
    EXPECT_FALSE(detail::umem_geometry_is_valid(3000, 0, PAGE_4K));
    // Larger than a page. Legal on a 16 KiB-page host, not on a 4 KiB one.
    EXPECT_FALSE(detail::umem_geometry_is_valid(8192, 0, PAGE_4K));
    EXPECT_TRUE(detail::umem_geometry_is_valid(8192, 0, PAGE_16K));
}

// The headroom has to leave the kernel its own 256 octets and something for a
// frame; a caller that asks for all of it gets a refusal, not a UMEM whose
// frames hold nothing.
TEST(xdp_umem_geometry, a_headroom_that_crowds_out_the_frame_is_refused)
{
    constexpr size_t PAGE_4K = 4096;
    constexpr size_t XDP_HEADROOM = 256;
    EXPECT_TRUE(detail::umem_geometry_is_valid(4096, 4096 - XDP_HEADROOM - 1, PAGE_4K));
    EXPECT_FALSE(detail::umem_geometry_is_valid(4096, 4096 - XDP_HEADROOM, PAGE_4K));
    EXPECT_FALSE(detail::umem_geometry_is_valid(2048, 2048, PAGE_4K));
}

// The default geometry is one the kernel takes, on either page size.
TEST(xdp_umem_geometry, the_default_geometry_is_valid_on_every_page_size)
{
    XdpConfig const config{.interface_name = "eth0"};
    EXPECT_TRUE(detail::umem_geometry_is_valid(config.umem_frame_size, config.umem_headroom, 4096));
    EXPECT_TRUE(detail::umem_geometry_is_valid(config.umem_frame_size, config.umem_headroom, 16384));
}

TEST(xdp_config, default_values)
{
    XdpConfig config{.interface_name = "eth0"};
    EXPECT_EQ(config.default_action, XdpAction::pass_kernel);
    EXPECT_EQ(config.queue_id, 0u);
    EXPECT_EQ(config.rx_ring_size, 256u);
    EXPECT_EQ(config.tx_ring_size, 256u);
    EXPECT_EQ(config.fill_ring_size, 512u);
    EXPECT_EQ(config.completion_ring_size, 512u);
    EXPECT_EQ(config.umem_frame_size, 4096u);
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

#    if defined(HAVE_XDP)
TEST(xdp_bind_flags, auto_binds_copy_under_a_generic_program)
{
    // The kernel's own choice, which is zero-copy where the driver has it,
    // is taken only under a native program; a generic attach - the plan's
    // fall-back, or an adopted generic pin - cannot drive a zero-copy queue.
    static_assert(detail::bind_flags_for(XdpBindMode::auto_, XdpAttachMode::generic) == XDP_COPY);
    static_assert(detail::bind_flags_for(XdpBindMode::auto_, XdpAttachMode::native) == 0);
    EXPECT_EQ(detail::bind_flags_for(XdpBindMode::auto_, XdpAttachMode::generic), XDP_COPY);
    EXPECT_EQ(detail::bind_flags_for(XdpBindMode::auto_, XdpAttachMode::native), 0);
}

TEST(xdp_bind_flags, only_auto_needs_the_attach_before_the_bind)
{
    // Under auto_ the flags follow the attach, so the attach goes first.
    // Under an explicit mode they do not, and the bind goes first so that a
    // refused zero-copy bind - the one a caller retries in copy mode - costs
    // no attach and detach round trip on the interface.
    static_assert(detail::attach_precedes_bind(XdpBindMode::auto_));
    static_assert(!detail::attach_precedes_bind(XdpBindMode::zero_copy));
    static_assert(!detail::attach_precedes_bind(XdpBindMode::copy));
    EXPECT_TRUE(detail::attach_precedes_bind(XdpBindMode::auto_));
    EXPECT_FALSE(detail::attach_precedes_bind(XdpBindMode::zero_copy));
    EXPECT_FALSE(detail::attach_precedes_bind(XdpBindMode::copy));
}

TEST(xdp_bind_flags, an_explicit_bind_mode_is_kept_whatever_the_attach)
{
    for (auto const attached : {XdpAttachMode::native, XdpAttachMode::generic}) {
        EXPECT_EQ(detail::bind_flags_for(XdpBindMode::copy, attached), XDP_COPY);
    }
    // zero_copy under generic never reaches a bind: attach_plan() refused it.
    EXPECT_EQ(detail::bind_flags_for(XdpBindMode::zero_copy, XdpAttachMode::native), XDP_ZEROCOPY);
}
#    endif

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

TEST(xdp_program, a_program_not_yet_opened_is_neither_pinned_adopted_nor_swapped)
{
    XdpProgram const program{};
    EXPECT_FALSE(program.pinned());
    EXPECT_FALSE(program.adopted());
    EXPECT_FALSE(program.swapped());
    EXPECT_EQ(program.id(), 0U);
    EXPECT_TRUE(program.pin_path().empty());
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

TEST(xdp_config, a_rule_for_any_frame_size_does_not_end_the_bpf_table)
{
    CompiledRule<32> rule{};
    rule.result_flags = flag::process;
    EXPECT_EQ(detail::tcam_slot(rule).min_frame_size, std::uint16_t{TCAM_WINDOW_BYTES});
    EXPECT_EQ(detail::tcam_slot(rule).result_flags, rule.result_flags);
    rule.min_frame_size = 60;
    EXPECT_EQ(detail::tcam_slot(rule).min_frame_size, std::uint16_t{60});
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
// fill_reserve_count tests
//
// xsk_ring_prod__reserve is all-or-nothing, so the replenish path must ask for
// no more than the ring reports free. Asking for every free UMEM frame
// reserves nothing whenever the UMEM is the larger of the two, which stalls
// receive silently.
//

TEST(xdp_fill_reserve, ring_is_the_limit)
{
    // The stalling case before the fix: 64 frames free, room for 8.
    EXPECT_EQ(detail::fill_reserve_count(64, 8), 8u);
}

TEST(xdp_fill_reserve, umem_is_the_limit)
{
    EXPECT_EQ(detail::fill_reserve_count(8, 64), 8u);
}

TEST(xdp_fill_reserve, equal_takes_all)
{
    EXPECT_EQ(detail::fill_reserve_count(32, 32), 32u);
}

TEST(xdp_fill_reserve, no_frames_free)
{
    EXPECT_EQ(detail::fill_reserve_count(0, 64), 0u);
}

TEST(xdp_fill_reserve, no_ring_space)
{
    EXPECT_EQ(detail::fill_reserve_count(64, 0), 0u);
}

TEST(xdp_fill_reserve, both_zero)
{
    EXPECT_EQ(detail::fill_reserve_count(0, 0), 0u);
}

TEST(xdp_fill_reserve, available_above_uint32_clamps_to_ring)
{
    // available is a size_t frame count; the reserve argument is a uint32_t.
    // The ring free count bounds the result, so the narrowing cast is only
    // ever applied to a value the ring already admitted.
    constexpr size_t huge = static_cast<size_t>(std::numeric_limits<uint32_t>::max()) + 1;
    EXPECT_EQ(detail::fill_reserve_count(huge, 16), 16u);
}

TEST(xdp_fill_reserve, is_constexpr)
{
    static_assert(detail::fill_reserve_count(64, 8) == 8u);
    static_assert(detail::fill_reserve_count(8, 64) == 8u);
    static_assert(detail::fill_reserve_count(0, 0) == 0u);
}

//
// Transmit reserve: RX and TX share one UMEM free list, and the fill ring
// will take every frame in it unless something holds some back.
//

TEST(xdp_tx_reserve, the_reserve_is_what_the_fill_ring_does_not_get)
{
    EXPECT_EQ(detail::fillable_frames(1024, 256), size_t{768});
    EXPECT_EQ(detail::fillable_frames(64, 32), size_t{32});
    // No reserve is the old behaviour, and is right for a receive-only
    // context: receive may have the lot.
    EXPECT_EQ(detail::fillable_frames(64, 0), size_t{64});
}

TEST(xdp_tx_reserve, a_reserve_as_big_as_what_is_free_leaves_the_ring_nothing)
{
    // Not an error: the frames are out with transmit, and the next cycle
    // fills whatever completion has handed back.
    EXPECT_EQ(detail::fillable_frames(32, 32), size_t{0});
    EXPECT_EQ(detail::fillable_frames(10, 32), size_t{0});
    EXPECT_EQ(detail::fillable_frames(0, 32), size_t{0});
}

TEST(xdp_tx_reserve, the_reserve_is_capped_at_half_the_umem)
{
    // The shipped default against the shipped UMEM: taken as asked.
    EXPECT_EQ(detail::effective_tx_reserve(xdp_default_tx_frame_reserve, 1024), size_t{256});
    // ...and against a UMEM smaller than the default reserve, capped - which
    // is the case that would otherwise starve receive instead of transmit.
    EXPECT_EQ(detail::effective_tx_reserve(xdp_default_tx_frame_reserve, 64), size_t{32});
    EXPECT_EQ(detail::effective_tx_reserve(xdp_default_tx_frame_reserve, 8), size_t{4});
    EXPECT_EQ(detail::effective_tx_reserve(1024, 1024), size_t{512});
    EXPECT_EQ(detail::effective_tx_reserve(0, 1024), size_t{0});
}

TEST(xdp_tx_reserve, neither_side_is_starved_at_any_umem_size)
{
    // The bug this reserve exists for: with a 64-frame UMEM and a 512-entry
    // fill ring, the first fill_replenish() took all 64 frames and tx_start()
    // never saw another one. Checked across sizes rather than at the one that
    // happened to fail.
    for (size_t frames = 2; frames <= 4096; frames *= 2) {
        auto const reserve = detail::effective_tx_reserve(xdp_default_tx_frame_reserve, frames);
        auto const fillable = detail::fillable_frames(frames, reserve);
        EXPECT_TRUE(reserve > 0);   // transmit can always get a frame
        EXPECT_TRUE(fillable > 0);  // and receive is never shut out for it
        EXPECT_TRUE(reserve + fillable == frames);
    }
}

TEST(xdp_tx_reserve, is_constexpr)
{
    static_assert(detail::fillable_frames(64, 32) == 32);
    static_assert(detail::fillable_frames(32, 64) == 0);
    static_assert(detail::effective_tx_reserve(256, 64) == 32);
    static_assert(detail::effective_tx_reserve(256, 1024) == 256);
    // The default config, resolved at compile time: a context opened with it
    // can both send and receive.
    static_assert(detail::effective_tx_reserve(xdp_default_tx_frame_reserve, 1024) > 0);
    static_assert(detail::fillable_frames(1024, detail::effective_tx_reserve(xdp_default_tx_frame_reserve, 1024)) > 0);
}

TEST(xdp_tx_reserve, a_fresh_context_reserves_nothing_until_it_is_open)
{
    XdpContext ctx;
    EXPECT_EQ(ctx.tx_frame_reserve(), size_t{0});
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
    // An interface no host has. With real XDP support and root this test
    // used to open "eth0" for real - attaching a program to the node's
    // production link and taking it off again - and then fail because the
    // open succeeded. The stub refuses any name; the real path refuses
    // this one before it touches anything.
    XdpContext ctx;
    XdpConfig config{.interface_name = "statusbar-nosuch0"};
    auto status = ctx.open(config);
    EXPECT_FALSE(status.has_value());
#    if !(defined(__linux__) && defined(HAVE_XDP))
    if (!status) {
        EXPECT_EQ(status.error(), XdpError::not_supported_on_platform);
    }
#    endif
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

TEST(xdp_closed, the_ring_paths_answer_not_open_rather_than_touch_rings_that_are_not_there)
{
    // A context that is not open has no rings, and libxdp's ring helpers
    // read through the ring's producer and consumer pointers, null until
    // open(). The other backends answer not_open on every path; these four
    // used to go straight to the rings.
    auto const says_not_open = [](auto const& answer) {
        EXPECT_FALSE(answer.has_value());
        if (!answer) {
            EXPECT_TRUE(answer.error() == XdpError::not_open);
        }
    };
    XdpContext ctx;
    says_not_open(ctx.rx_start());
    says_not_open(ctx.rx_start(RxTimePoint{RxClock::duration{5}}));
    says_not_open(ctx.tx_commit(0, 64));
    says_not_open(ctx.tx_complete());
    says_not_open(ctx.end_cycle());

    // The same after a close as before an open.
    ctx.close();
    says_not_open(ctx.rx_start());
    says_not_open(ctx.end_cycle());

    // And nothing was counted as sent, received or refused by a full ring.
    EXPECT_EQ(ctx.socket_stats().rx_count, 0u);
    EXPECT_EQ(ctx.socket_stats().tx_count, 0u);
    EXPECT_EQ(ctx.socket_stats().tx_ring_full_count, 0u);
    EXPECT_EQ(ctx.socket_stats().rx_budget_hit_count, 0u);
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
}

// Whose program is on the interface decides whether open() may replace it,
// and the kernel only answers that question for CAP_SYS_ADMIN. A daemon
// running under a service file's CAP_BPF and CAP_NET_ADMIN is told EPERM
// about its own program, and before this was refused as foreign_program
// forever: its own pinned program, after a redeploy, was somebody else's.
TEST(xdp_ownership, a_program_the_kernel_will_not_name_is_ours_only_when_we_pinned_it)
{
    using detail::AttachedProgramOwner;
    using detail::attachment_is_ours;
    EXPECT_TRUE(attachment_is_ours(AttachedProgramOwner::ours, 7, 0).value_or(false));
    EXPECT_FALSE(attachment_is_ours(AttachedProgramOwner::foreign, 7, 7).value_or(true));
    EXPECT_TRUE(attachment_is_ours(AttachedProgramOwner::unknown, 7, 7).value_or(false));
}

TEST(xdp_ownership, a_program_the_kernel_will_not_name_and_the_pin_does_not_vouch_for_is_reported_not_guessed)
{
    using detail::AttachedProgramOwner;
    using detail::attachment_is_ours;
    auto const unpinned = attachment_is_ours(AttachedProgramOwner::unknown, 7, 0);
    EXPECT_FALSE(unpinned.has_value());
    if (!unpinned) {
        EXPECT_EQ(unpinned.error(), XdpError::program_unidentifiable);
    }
    // A pin that holds a different program vouches for nothing on the
    // interface: ours to unpin, not ours to detach.
    auto const other = attachment_is_ours(AttachedProgramOwner::unknown, 7, 8);
    EXPECT_FALSE(other.has_value());
}

TEST(xdp_ownership, the_unidentifiable_message_names_the_privilege_and_says_the_program_stays)
{
    std::error_code const ec = XdpError::program_unidentifiable;
    EXPECT_TRUE(ec.message().find("CAP_SYS_ADMIN") != std::string::npos);
    EXPECT_TRUE(ec.message().find("left alone") != std::string::npos);
    EXPECT_TRUE(ec.message() != std::error_code{XdpError::foreign_program}.message());
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
// The kernel's own counters
//
// XdpSocketStats above counts what we did. These are what the kernel threw
// away after we handed it over, and nothing in this process can see them any
// other way.
//

// counters_reported is the whole guard against reading a counter the kernel
// never filled. The kernel answers XDP_STATISTICS with either 24 bytes (the
// three counters it has always had) or 48 (all six, added in 5.9), and says
// which in the option length it returns; the fields we zeroed and it did not
// write would otherwise read as a confident zero.
TEST(xdp_kernel_stats, counters_reported_gates_the_later_fields)
{
    XdpKernelStats const old_kernel{.counters_reported = 3};
    EXPECT_FALSE(old_kernel.has_rx_ring_full());
    EXPECT_FALSE(old_kernel.has_ring_empty_counters());

    // The one in between matters too: a kernel could answer with the four and
    // not the ring-empty pair, and the two predicates have to disagree.
    XdpKernelStats const four{.counters_reported = 4};
    EXPECT_TRUE(four.has_rx_ring_full());
    EXPECT_FALSE(four.has_ring_empty_counters());

    XdpKernelStats const current{.counters_reported = 6};
    EXPECT_TRUE(current.has_rx_ring_full());
    EXPECT_TRUE(current.has_ring_empty_counters());
}

TEST(xdp_kernel_stats, default_constructed_claims_nothing)
{
    XdpKernelStats const stats;
    EXPECT_EQ(stats.counters_reported, 0u);
    EXPECT_FALSE(stats.has_rx_ring_full());
    EXPECT_FALSE(stats.has_ring_empty_counters());
    EXPECT_EQ(stats.tx_invalid_descs, 0u);
}

// "No data" must not be readable as "no drops": a context with no socket has
// to fail rather than hand back six zeroes.
TEST(xdp_kernel_stats, unopened_context_fails_rather_than_reading_zero)
{
    XdpContext ctx;
    auto const stats = ctx.kernel_stats();
    EXPECT_FALSE(stats.has_value());
    // Which error it is matters: not_open says there is no socket to ask,
    // where stats_read_failed would mean we asked and the kernel refused.
    // Without this the guard could be deleted and the EBADF from
    // getsockopt(-1) would look like the same failure.
#    if defined(__linux__) && defined(HAVE_XDP)
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::not_open));
#    else
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::not_supported_on_platform));
#    endif
}

//
// Program identity: the pure parts
//
// What makes a pinned program adoptable is that it is the program this
// build would have attached. Structure cannot answer that - a recompiled
// filter declares exactly the same maps - so the answer is written into the
// pin directory and read back. The fingerprint and the identity it goes
// into need no kernel, so they are checked here.
//

TEST(xdp_identity, the_fingerprint_is_fnv1a)
{
    // Against the published vectors, so the function is the hash it says it
    // is rather than merely some hash. constexpr, so a build that got this
    // wrong does not compile. Spelled as byte arrays because a string
    // literal can only be reinterpret_cast to bytes at run time.
    constexpr std::array<unsigned char, 0> nothing{};
    constexpr std::array<unsigned char, 1> letter_a{'a'};
    constexpr std::array<unsigned char, 6> foobar{'f', 'o', 'o', 'b', 'a', 'r'};
    static_assert(detail::fnv1a64(nothing) == 0xcbf2'9ce4'8422'2325ULL);
    static_assert(detail::fnv1a64(letter_a) == 0xaf63'dc4c'8601'ec8cULL);
    static_assert(detail::fnv1a64(foobar) == 0x8594'4171'f739'67e8ULL);
    constexpr std::array<unsigned char, 9> name{'s', 't', 'a', 't', 'u', 's', 'b', 'a', 'r'};
    EXPECT_EQ(detail::fnv1a64(name), 0x8745'ebff'7c18'9690ULL);
}

TEST(xdp_identity, one_byte_is_enough_to_tell_two_programs_apart)
{
    // The property the whole scheme rests on: a filter that was recompiled
    // must not fingerprint the same as the one before it. A single flipped
    // byte standing in for a code change.
    std::array<unsigned char, 64> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<unsigned char>(i);
    }
    auto const before = detail::fnv1a64(bytes);
    for (size_t i = 0; i < bytes.size(); ++i) {
        auto flipped = bytes;
        flipped[i] = static_cast<unsigned char>(flipped[i] ^ 0x01U);
        EXPECT_TRUE(detail::fnv1a64(flipped) != before);
    }
    // And length matters, so a truncated object is not the whole one.
    EXPECT_TRUE(detail::fnv1a64(std::span{bytes}.first(63)) != before);
}

TEST(xdp_identity, this_build_knows_what_it_is)
{
    auto const self = XdpProgram::identity();
    EXPECT_EQ(self.magic, xdp_pin_magic);
    // The embedded object is real, so its fingerprint is not the empty one.
    EXPECT_TRUE(self.program_hash != 0);
    EXPECT_TRUE(self.program_hash != 0xcbf2'9ce4'8422'2325ULL);
    EXPECT_EQ(self.window_bytes, static_cast<uint32_t>(TCAM_WINDOW_BYTES));
    EXPECT_EQ(self.max_rules, static_cast<uint32_t>(TCAM_MAX_RULES));
}

TEST(xdp_identity, the_answer_does_not_move_within_a_build)
{
    // A restart has to compute the same fingerprint the previous run pinned,
    // or nothing is ever adopted.
    auto const first = XdpProgram::identity();
    auto const second = XdpProgram::identity();
    EXPECT_EQ(first.program_hash, second.program_hash);
    EXPECT_EQ(first.magic, second.magic);
}

TEST(xdp_identity, the_magic_spells_something_on_purpose)
{
    // Readable in a hex dump of the pinned map, which is the point of
    // choosing bytes over a random constant.
    std::array<char, 8> text{};
    for (size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<char>((xdp_pin_magic >> (56U - (8U * i))) & 0xFFU);
    }
    EXPECT_EQ(std::string(text.data(), text.size()), std::string("STATUSBR"));
}

TEST(xdp_identity, the_pinned_layout_is_fixed)
{
    // An older build reads this struct out of bpffs, so its layout is an
    // ABI between releases and not an implementation detail.
    static_assert(std::is_trivially_copyable_v<XdpPinIdentity>);
    static_assert(sizeof(XdpPinIdentity) == 24);
    static_assert(offsetof(XdpPinIdentity, magic) == 0);
    static_assert(offsetof(XdpPinIdentity, program_hash) == 8);
    static_assert(offsetof(XdpPinIdentity, window_bytes) == 16);
    static_assert(offsetof(XdpPinIdentity, max_rules) == 20);
    // Default-constructed must not look like ours, since that is what a
    // failed read leaves behind.
    XdpPinIdentity const empty{};
    EXPECT_TRUE(empty.magic != xdp_pin_magic);
}

TEST(xdp_identity, the_entry_name_is_fixed_like_the_others)
{
    auto const dir = XdpProgram::pin_path_for("eth0");
    EXPECT_TRUE(XdpProgram::pin_entry(dir, XdpProgram::PIN_IDENTITY) == "/sys/fs/bpf/statusbar/eth0/identity");
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

TEST(xdp_pinnable, a_path_that_climbs_out_of_bpffs_is_refused)
{
    // Starts with the mount point, then leaves it. prepare_pin_dir() and
    // detach() create, unlink and rmdir at the path they are given, so
    // this one has to be refused on shape alone, before any statfs.
    for (auto const* const path :
         {"/sys/fs/bpf/../../tmp/x",
          "/sys/fs/bpf/statusbar/..",
          "/sys/fs/bpf/statusbar/./lo",
          "/sys/fs/bpf//lo",
          "/sys/fs/bpf/statusbar/lo/"}) {
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

TEST(xdp_owner, a_path_that_could_not_hold_a_pin_is_refused)
{
    // Same gate as pinnable(), and for the same reason: this call opens
    // things by path, so the path has to be one of ours first.
    for (auto const* const path : {"/tmp/statusbar-elsewhere/lo", "/sys/fs/bpf", "/etc", ""}) {
        auto const owner = XdpProgram::owner(path);
        EXPECT_FALSE(owner.has_value());
        if (!owner) {
            EXPECT_TRUE(owner.error() == XdpError::invalid_pin_path);
        }
    }
}

TEST(xdp_owner, an_empty_pin_directory_is_claimed_by_nobody)
{
    // Nothing of ours has ever been pinned for this made-up interface, so
    // there is no identity to find and the directory is ours to use.
    //
    // Unprivileged, /sys/fs/bpf cannot be opened at all, and then the call
    // reports that errno rather than answering "nobody" - which is the
    // distinction that matters, since "I cannot tell" must never be acted
    // on as "unclaimed".
    auto const path = XdpProgram::pin_path_for("statusbar-none");
    EXPECT_FALSE(path.empty());
    auto const owner = XdpProgram::owner(path);
    if (getuid() == 0) {
        EXPECT_TRUE(owner.has_value());
        if (owner) {
            EXPECT_TRUE(*owner == XdpPinOwner::none);
        }
    } else if (!owner) {
        // Whatever stopped us, it is not a verdict about the directory.
        EXPECT_TRUE(owner.error() != XdpError::foreign_program);
        EXPECT_TRUE(owner.error() != XdpError::invalid_pin_path);
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

//
// kernel_stats_from - the mapping, with no socket at all
//

TEST(xdp_kernel_stats, every_counter_lands_in_its_own_field)
{
    // Distinct values, so a crossed pair cannot pass.
    struct xdp_statistics raw{};
    raw.rx_dropped = 11;
    raw.rx_invalid_descs = 22;
    raw.tx_invalid_descs = 33;
    raw.rx_ring_full = 44;
    raw.rx_fill_ring_empty_descs = 55;
    raw.tx_ring_empty_descs = 66;

    auto const stats = detail::kernel_stats_from(raw, sizeof(raw));
    EXPECT_EQ(stats.rx_dropped, 11u);
    EXPECT_EQ(stats.rx_invalid_descs, 22u);
    EXPECT_EQ(stats.tx_invalid_descs, 33u);
    EXPECT_EQ(stats.rx_ring_full, 44u);
    EXPECT_EQ(stats.rx_fill_ring_empty_descs, 55u);
    EXPECT_EQ(stats.tx_ring_empty_descs, 66u);
    EXPECT_EQ(stats.counters_reported, 6u);
}

TEST(xdp_kernel_stats, the_reported_length_decides_how_many_counters_are_claimed)
{
    struct xdp_statistics const raw{};

    // The three the kernel has always had.
    EXPECT_EQ(detail::kernel_stats_from(raw, 3 * sizeof(uint64_t)).counters_reported, 3u);
    // All six, since 5.9.
    EXPECT_EQ(detail::kernel_stats_from(raw, sizeof(raw)).counters_reported, 6u);
    // A kernel newer than this header: clamped to the fields we have, never
    // claiming counters we could not have copied.
    EXPECT_EQ(detail::kernel_stats_from(raw, 9 * sizeof(uint64_t)).counters_reported, 6u);
    EXPECT_EQ(detail::kernel_stats_from(raw, 0).counters_reported, 0u);
}

TEST(xdp_kernel_stats, reading_a_closed_descriptor_fails)
{
    auto const stats = detail::read_xdp_kernel_stats(-1);
    EXPECT_FALSE(stats.has_value());
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::stats_read_failed));
}

//
// Integration tests (require root, veth pairs, Linux with XDP)
//

#        include <cstdlib>

//
// The kernel's counters against a real AF_XDP socket, with no privilege
//
// A plain uid owns CAP_NET_RAW and CAP_NET_ADMIN over a network namespace it
// creates together with a user namespace, and that is all a transmit-only
// AF_XDP socket needs: binding one attaches no BPF program. Loading a program
// would want CAP_BPF, which a user namespace does NOT grant - the load fails
// with EPERM inside the namespace exactly as it does outside - so these tests
// cannot drive XdpContext, whose open() loads the filter. They build the
// socket with libxdp instead and read it through the same code the member
// calls, which is why that code takes a descriptor.
//
// The socket binds to the namespace's own loopback, which is the one device
// every network namespace already has: no veth to create, and so no `ip`
// binary to depend on - in a build container with no iproute2 the veth
// version of this skipped instead of running. Loopback must be brought UP
// first, with an ioctl rather than a shell: a down device makes the kick fail
// ENETDOWN before the kernel ever looks at the descriptor, and the counter
// these tests are about stays at zero.
//
// unshare(CLONE_NEWUSER) needs a single-threaded process; a child of fork() is
// one however many threads the test binary has.

#        include <sched.h>

#        include <cstring>
#        include <memory>

#        include <sys/wait.h>

//
// Multicast memberships
//

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

// The busy-poll bookkeeping and the stalled-ring detector are plain state
// with no socket behind them, so they are checked on every platform.
#include "statusbar/net/net_linux_xdp.hpp"

#include <cstdint>
#include <type_traits>

// Off, armed by set(true), polling once a kick got through, off again by
// set(false); a kick on an idle queue arms nothing.
TEST(xdp_napi_busy_poll, armed_by_set_polling_after_a_kick)
{
    statusbar::net::detail::NapiBusyPoll poll;
    EXPECT_FALSE(poll.on());
    EXPECT_FALSE(poll.polling());
    poll.kicked();
    EXPECT_FALSE(poll.on());
    poll.set(true);
    EXPECT_TRUE(poll.on());
    EXPECT_FALSE(poll.polling());
    poll.kicked();
    EXPECT_TRUE(poll.on());
    EXPECT_TRUE(poll.polling());
    poll.set(false);
    EXPECT_FALSE(poll.on());
    EXPECT_FALSE(poll.polling());
}

// Turning busy poll on again re-arms: the thread sleeps until the next kick.
TEST(xdp_napi_busy_poll, set_again_rearms_and_swap_exchanges_states)
{
    statusbar::net::detail::NapiBusyPoll a;
    statusbar::net::detail::NapiBusyPoll b;
    a.set(true);
    a.kicked();
    a.set(true);
    EXPECT_FALSE(a.polling());
    a.kicked();
    a.swap(b);
    EXPECT_FALSE(a.on());
    EXPECT_TRUE(b.polling());
}

// A stall is descriptors pending across two flushes with the kernel's
// progress unchanged between them. The first flush with frames pending is
// never a stall: there is nothing yet to compare against.
TEST(xdp_tx_progress, pending_with_no_progress_since_the_last_flush_is_a_stall)
{
    using statusbar::net::detail::TxRingState;
    statusbar::net::detail::TxProgress progress;
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 4, .progress = 10}));
    EXPECT_TRUE(progress.stalled(TxRingState{.pending = 4, .progress = 10}));
    EXPECT_TRUE(progress.stalled(TxRingState{.pending = 6, .progress = 10}));
}

// Progress of any kind - consumption, or completion of a full ring - clears
// the stall, and so does an empty ring on either side.
TEST(xdp_tx_progress, progress_or_an_empty_ring_is_not_a_stall)
{
    using statusbar::net::detail::TxRingState;
    statusbar::net::detail::TxProgress progress;
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 4, .progress = 10}));
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 4, .progress = 11}));
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 0, .progress = 11}));
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 3, .progress = 11}));
    EXPECT_TRUE(progress.stalled(TxRingState{.pending = 3, .progress = 11}));
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 0, .progress = 11}));
    EXPECT_FALSE(progress.stalled(TxRingState{.pending = 0, .progress = 11}));
}

// The stalled-kick counter starts at zero with the rest.
TEST(xdp_socket_stats, the_stalled_kick_counter_is_part_of_the_stats)
{
    statusbar::net::XdpSocketStats const stats{};
    EXPECT_EQ(stats.tx_flush_stalled, std::uint64_t{0});
    static_assert(std::is_trivially_copyable_v<statusbar::net::XdpSocketStats>);
}

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_test)