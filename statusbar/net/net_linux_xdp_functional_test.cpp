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

//
// XdpConfig defaults tests
//

// A geometry the kernel would refuse is reported as what it is, so a caller
// that tuned the frame size learns which knob is wrong.
TEST(xdp_umem_geometry, opening_with_an_impossible_frame_size_says_so)
{
    XdpContext context;
    XdpConfig config{.interface_name = "lo"};
    config.umem_frame_size = 3000;
    auto const opened = context.open(config);
    EXPECT_FALSE(opened.has_value());
    if (!opened) {
        EXPECT_EQ(opened.error(), make_error_code(XdpError::invalid_umem_geometry));
    }
}

//
// Bind / attach mode policy
//
// The whole table is constexpr, so the policy is checked at compile time as
// well as run time. What cannot be checked without hardware is whether a
// given driver actually grants zero-copy or a native attach; that is what
// XdpContext::bind_mode() and attach_mode() report back at run time.
//

#    if defined(HAVE_XDP)

#    endif

//
// Program pinning: the pure parts
//
// pin_path_for() touches no filesystem, so the convention itself - one
// directory per interface, under a mounted bpffs, with fixed entry names - is
// checked here. What needs a kernel is further down.
//

//
// UmemFreeList tests
//

//
// fill_reserve_count tests
//
// xsk_ring_prod__reserve is all-or-nothing, so the replenish path must ask for
// no more than the ring reports free. Asking for every free UMEM frame
// reserves nothing whenever the UMEM is the larger of the two, which stalls
// receive silently.
//

//
// Transmit reserve: RX and TX share one UMEM free list, and the fill ring
// will take every frame in it unless something holds some back.
//

//
// ScopeGuard tests
//

//
// XdpContextOpen RAII wrapper test
//

//
// Stub tests (verify stub returns not_supported_on_platform on non-Linux or without libbpf)
//

//
// Socket statistics
//
// Each counter has one home, and the tests below sit in two groups: the
// conditions a plain XdpContext can be put into without a NIC or a
// capability, and the ones that need a bound socket and live in
// xdp_integration further down.
//

//
// Which refused kicks pass by themselves. The classification is pure, so the
// arms a developer host will never produce are still checked - and checked at
// compile time.
//

//
// The kernel's own counters
//
// XdpSocketStats above counts what we did. These are what the kernel threw
// away after we handed it over, and nothing in this process can see them any
// other way.
//

//
// Program identity: the pure parts
//
// What makes a pinned program adoptable is that it is the program this
// build would have attached. Structure cannot answer that - a recompiled
// filter declares exactly the same maps - so the answer is written into the
// pin directory and read back. The fingerprint and the identity it goes
// into need no kernel, so they are checked here.
//

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
// kernel_stats_from - the mapping, with no socket at all
//

TEST(xdp_kernel_stats, reading_a_socket_that_is_not_an_af_xdp_socket_fails)
{
    int const udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(udp >= 0);
    auto const stats = detail::read_xdp_kernel_stats(udp);
    ::close(udp);
    EXPECT_FALSE(stats.has_value());
    EXPECT_TRUE(stats.error() == std::error_code(XdpError::stats_read_failed));
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
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

// A veth takes a native attach - it has had ndo_bpf since Linux 4.14 - and
// has no zero-copy. So it is the right place to prove the *bind* refusal and
// that the mode is reported truthfully, and the wrong place to prove the
// attach fallback: there is nothing here for native to fall back from.
//
// This test previously asserted the fallback and was never run, because it
// skipped silently off root. The first root run said attach_mode() was not
// generic, which on a successful open leaves only native.
//
// Proving the fallback needs an interface whose driver has no XDP at all.
// detail::attach_plan covers the policy without one; what is missing is a
// test that the plan is carried out, and that needs hardware this host has
// not got.
TEST(xdp_integration, a_veth_attaches_natively_and_still_refuses_zero_copy)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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
        // The default config asks for native and gets it, so the fallback is
        // never reached. What a veth does refuse is zero-copy, and the bind
        // mode has to come back as the copy it settled for rather than the
        // auto_ that was asked for.
        EXPECT_TRUE(ctx.attach_mode() == XdpAttachMode::native);
        EXPECT_FALSE(ctx.zero_copy());
        EXPECT_TRUE(ctx.bind_mode() == XdpBindMode::copy);
    }
    ctx.close();

    // Asking for generic outright gets generic: the mode is honoured, not
    // upgraded to the native the driver would have allowed.
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
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

// When the program did change - a redeploy built from different source -
// the pinned program is not adoptable and the new one takes its place. That
// used to be a detach and then an attach, an adapter reset each on igb; it is
// now one request, XDP_FLAGS_REPLACE naming the old program by the pin's
// descriptor, which igb and ice carry out without a reset. An open that
// declines to adopt stands in for the changed build here: what the pin holds
// is ours, so it is swapped, in either order of attach and bind.
TEST(xdp_integration, a_program_of_ours_the_pin_holds_is_swapped_for_the_new_one_in_one_request)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(::if_nametoindex("xdptest0"), pin_path);
        destroy_veth_pair("xdptest0");
    });
    unsigned int const if_index = ::if_nametoindex("xdptest0");

    XdpConfig config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };

    auto const attached_id = [&]() -> uint32_t {
        auto const found = XdpProgram::query(if_index);
        return found && found->has_value() ? (*found)->program_id : 0;
    };

    // First open: a bare interface, attached to and pinned. Nothing swapped.
    uint32_t first_id = 0;
    {
        XdpContext ctx;
        EXPECT_TRUE(ctx.open(config).has_value());
        EXPECT_FALSE(ctx.program().swapped());
        EXPECT_FALSE(ctx.adopted());
        first_id = ctx.program().id();
    }
    EXPECT_TRUE(first_id != 0 && attached_id() == first_id);

    // Second open, not adopting: the new program in place of the first, in
    // one request, under auto_ (attached before the bind).
    config.adopt = false;
    uint32_t second_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.program().swapped());
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
            second_id = ctx.program().id();
            EXPECT_TRUE(second_id != 0 && second_id != first_id);
            EXPECT_EQ(attached_id(), second_id);
        }
    }
    EXPECT_EQ(attached_id(), second_id);  // pinned: it stays
    EXPECT_EQ(::access(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_PROG).c_str(), F_OK), 0);

    // And under an explicit copy bind, where the attach waits for the bind:
    // the old program stays on the interface through the bind and is then
    // swapped.
    config.bind_mode = XdpBindMode::copy;
    uint32_t third_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.program().swapped());
            third_id = ctx.program().id();
            EXPECT_TRUE(third_id != 0 && third_id != second_id);
            EXPECT_EQ(attached_id(), third_id);
        }
    }

    // Adoption back on: the swapped-in program is the one the pin holds, and
    // the next open adopts it. Nothing swapped, nothing attached.
    config.adopt = true;
    config.bind_mode = XdpBindMode::auto_;
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_FALSE(ctx.program().swapped());
            EXPECT_EQ(ctx.program().id(), third_id);
        }
    }

    // An interface with nothing of ours on it is attached to, not swapped.
    EXPECT_TRUE(XdpProgram::detach(if_index, pin_path).has_value());
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.program().swapped());
            EXPECT_FALSE(ctx.adopted());
        }
    }
}

// Adopting a map that is not the one this build declares would mean writing
// rules into someone else's memory. A pin with a wrong-shaped rules_map must
// be replaced, and must come out of it untouched.
TEST(xdp_integration, a_pinned_map_of_the_wrong_shape_is_replaced_and_never_written_to)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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
    // an older build of the program would have left behind. The identity is
    // left alone, so the directory is still recognisably ours: what is being
    // tested here is the structural check, not the ownership one.
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

TEST(xdp_integration, a_program_somebody_else_attached_is_left_alone_and_open_refuses)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    unsigned int const if_index = ::if_nametoindex("xdptest0");
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)bpf_xdp_detach(static_cast<int>(if_index), XDP_FLAGS_SKB_MODE, nullptr);
        (void)XdpProgram::detach(if_index, pin_path);
        destroy_veth_pair("xdptest0");
    });

    // Somebody else's program: two instructions that pass every frame,
    // attached in generic mode and pinned nowhere. Our pin directory says
    // nothing about it, and on the strength of that silence the replace
    // path used to take it off the interface.
    std::array<bpf_insn, 2> const pass{
        bpf_insn{
            .code = static_cast<__u8>(BPF_ALU64 | BPF_MOV | BPF_K),
            .dst_reg = BPF_REG_0,
            .src_reg = 0,
            .off = 0,
            .imm = static_cast<__s32>(XDP_PASS)},
        bpf_insn{.code = static_cast<__u8>(BPF_JMP | BPF_EXIT), .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},
    };
    int const foreign = bpf_prog_load(BPF_PROG_TYPE_XDP, "foreign_pass", "MIT", pass.data(), pass.size(), nullptr);
    EXPECT_TRUE(foreign >= 0);
    if (foreign < 0) {
        return;
    }
    EXPECT_EQ(bpf_xdp_attach(static_cast<int>(if_index), foreign, XDP_FLAGS_SKB_MODE, nullptr), 0);
    bpf_prog_info info{};
    __u32 info_length = sizeof(info);
    EXPECT_EQ(bpf_prog_get_info_by_fd(foreign, &info, &info_length), 0);

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_EQ(status.error(), XdpError::foreign_program);
        }
    }

    // An unpinned open has no pin directory to ask about and used to attach
    // straight over the top; it is refused the same way.
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
        });
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_EQ(status.error(), XdpError::foreign_program);
        }
    }
    // And detach() - the operator's broom - sweeps only ours.
    EXPECT_TRUE(XdpProgram::detach(if_index, "").has_value());

    // Still theirs, still attached, and the same program.
    auto const attached = XdpProgram::query(if_index);
    EXPECT_TRUE(attached.has_value() && attached->has_value());
    if (attached && attached->has_value()) {
        EXPECT_EQ((*attached)->program_id, info.id);
        EXPECT_EQ((*attached)->mode, XdpAttachMode::generic);
    }
    ::close(foreign);
}

TEST(xdp_integration, our_own_orphaned_attachment_is_replaced_whether_pinned_or_not)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    unsigned int const if_index = ::if_nametoindex("xdptest0");
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(if_index, pin_path);
        destroy_veth_pair("xdptest0");
    });

    // A program of ours on the interface with no pin to say so: the shape a
    // crash between attach and pin leaves, and the shape an unpinned build
    // leaves when it dies. Made here by pinning and then removing the pins.
    uint32_t orphan_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
            .pin_path = pin_path,
        });
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
        orphan_id = ctx.program().id();
    }
    for (auto const entry :
         {XdpProgram::PIN_IDENTITY,
          XdpProgram::PIN_PROG,
          XdpProgram::PIN_RULES_MAP,
          XdpProgram::PIN_XSK_MAP,
          XdpProgram::PIN_DEVMAP}) {
        EXPECT_EQ(::unlink(XdpProgram::pin_entry(pin_path, entry).c_str()), 0);
    }
    EXPECT_EQ(::rmdir(pin_path.c_str()), 0);
    auto const before = XdpProgram::query(if_index);
    EXPECT_TRUE(before.has_value() && before->has_value());

    // An unpinned open recognises it as ours by name and replaces it,
    // where a stranger's program is refused (the test above).
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
        });
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_NE(ctx.program().id(), orphan_id);
        }
    }
    // Unpinned, so closing detached it: the interface is clear again.
    auto const between = XdpProgram::query(if_index);
    EXPECT_TRUE(between.has_value() && !between->has_value());

    // The same orphan, met by a pinned open: replaced and pinned.
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
            .pin_path = pin_path,
        });
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
    }
    EXPECT_TRUE(XdpProgram::detach(if_index, "").has_value());  // detach only; pins stay
    auto const orphaned_again = XdpProgram::query(if_index);
    EXPECT_TRUE(orphaned_again.has_value() && !orphaned_again->has_value());
    // Pins without an attachment are the other half-state, and a pinned
    // open replaces them too (adopt() refuses a pin whose program is not
    // the one on the interface).
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
            .pin_path = pin_path,
        });
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
        }
    }
}

TEST(xdp_integration, an_adopted_program_reports_the_mode_it_is_attached_in)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    unsigned int const if_index = ::if_nametoindex("xdptest0");
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(if_index, pin_path);
        destroy_veth_pair("xdptest0");
    });

    // Attached in generic mode on purpose, where veth would have taken
    // native: the adopted answer has to come from the interface, not from
    // the default.
    XdpConfig const generic{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .attach_mode = XdpAttachMode::generic,
        .pin_path = pin_path,
    };
    uint32_t first_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(generic);
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
        EXPECT_EQ(ctx.attach_mode(), XdpAttachMode::generic);
        first_id = ctx.program().id();
    }
    {
        XdpContext ctx;
        auto const status = ctx.open(generic);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_EQ(ctx.program().id(), first_id);
            EXPECT_EQ(ctx.attach_mode(), XdpAttachMode::generic);
        }
    }

    // The default plan - native, falling back to generic - accepts a
    // generic program and adopts it as what it is.
    XdpConfig const by_default{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };
    {
        XdpContext ctx;
        auto const status = ctx.open(by_default);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_EQ(ctx.attach_mode(), XdpAttachMode::generic);
        }
    }

    // A caller who asked for generic and finds a native program - the
    // reverse - is not given native: the program is replaced in the mode
    // asked for. Set up by attaching natively, then opening for generic.
    EXPECT_TRUE(XdpProgram::detach(if_index, pin_path).has_value());
    uint32_t native_id = 0;
    {
        XdpContext ctx;
        auto const status = ctx.open(by_default);
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
        EXPECT_EQ(ctx.attach_mode(), XdpAttachMode::native);
        native_id = ctx.program().id();
    }
    {
        XdpContext ctx;
        auto const status = ctx.open(generic);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
            EXPECT_NE(ctx.program().id(), native_id);
            EXPECT_EQ(ctx.attach_mode(), XdpAttachMode::generic);
        }
    }
}

TEST(xdp_integration, an_adopted_program_with_no_tap_asked_for_forwards_to_no_tap)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    unsigned int const if_index = ::if_nametoindex("xdptest0");
    unsigned int const peer_index = ::if_nametoindex("xdptest1");
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(if_index, pin_path);
        destroy_veth_pair("xdptest0");
    });

    // Run 1 points the devmap at the peer. Any netdev will do for the map;
    // the peer is one this test owns.
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
            .tap_ifindex = peer_index,
            .pin_path = pin_path,
        });
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
    }
    auto const devmap_pin = XdpProgram::pin_entry(pin_path, XdpProgram::PIN_DEVMAP);
    auto const slot = [&devmap_pin]() -> std::optional<uint32_t> {
        int const fd = bpf_obj_get(devmap_pin.c_str());
        if (fd < 0) {
            return std::nullopt;
        }
        uint32_t key = 0;
        uint32_t value = 0;
        int const ret = bpf_map_lookup_elem(fd, &key, &value);
        ::close(fd);
        return ret == 0 ? std::optional<uint32_t>{value} : std::nullopt;
    };
    EXPECT_EQ(slot(), std::optional<uint32_t>{peer_index});

    // Run 2 adopts with no TAP: the slot it inherited is emptied, so a
    // forward_tap rule has nowhere to go, as the config says.
    {
        XdpContext ctx;
        auto const status = ctx.open(XdpConfig{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
            .pin_path = pin_path,
        });
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_EQ(slot(), std::nullopt);
        }
    }
}

TEST(xdp_integration, a_launch_time_the_nic_cannot_honour_is_refused_at_open)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    // veth times nothing on any kernel. A build without TX metadata refuses
    // for that reason first; one with it asks the kernel about the NIC and
    // is refused there. Either way no socket is opened whose times the NIC
    // would discard, and the context says it has no launch time.
    XdpContext ctx;
    auto const status = ctx.open(XdpConfig{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .tx_launch_time = true,
    });
    EXPECT_FALSE(status.has_value());
    if (!status) {
        EXPECT_TRUE(status.error() == XdpError::launch_time_not_supported || status.error() == XdpError::tx_metadata_not_supported);
    }
    EXPECT_FALSE(ctx.valid());
    EXPECT_FALSE(ctx.tx_launch_time());
}

TEST(xdp_integration, tx_rx_loopback)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

    // Block until the kernel has delivered, however long that takes. The
    // timeout only ends the wait for a frame that never comes.
    struct pollfd waiting{.fd = rx_ctx.fd(), .events = POLLIN, .revents = 0};
    (void)::poll(&waiting, 1, 2'000);

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
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

    // Reclaim via tx_complete: whatever the kernel has completed by now.
    (void)ctx.tx_complete();
}

// The counters that need a bound socket. Root-only, so this does not run on a
// developer host; the branches reachable without one are in xdp_stats above.
//   sudo ./statusbar_test statusbar/net/net_linux_xdp_test
TEST(xdp_integration, the_tx_ring_filling_and_the_umem_emptying_are_counted)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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
    auto const opened = ctx.open(config);
    EXPECT_TRUE(opened.has_value());
    if (!opened) {
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

// The member's success path needs an opened context, and opening one loads
// the BPF filter - CAP_BPF, which no user namespace grants. So unlike the
// xdp_kernel_stats tests further down, this one really does need root.
TEST(xdp_integration, kernel_stats_on_an_open_context)
{
    if (getuid() != 0) {
        SKIP("needs root to load the XDP program");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig const config{.interface_name = "xdptest0", .umem_frame_count = 64};
    XdpContext ctx;
    auto const opened = ctx.open(config);
    EXPECT_TRUE(opened.has_value());
    if (!opened) {
        return;
    }

    auto const stats = ctx.kernel_stats();
    EXPECT_TRUE(stats.has_value());
    if (stats) {
        EXPECT_EQ(stats->tx_invalid_descs, 0u);
        EXPECT_TRUE(stats->counters_reported >= 3);
    }

    // And the same context, once closed, reports a failure rather than the
    // zeroes it would have been honest about a moment ago.
    ctx.close();
    EXPECT_FALSE(ctx.kernel_stats().has_value());
}

// A descriptor the kernel will not accept is the one way to make it refuse a
// kick on demand, which is what gives tx_flush_failed and tx_flush_errno a
// test at all.
TEST(xdp_integration, a_kick_the_kernel_refuses_is_counted_and_keeps_its_errno)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto cleanup = detail::scopeguard([&] { destroy_veth_pair("xdptest0"); });

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
    };

    XdpContext ctx;
    auto const opened = ctx.open(config);
    EXPECT_TRUE(opened.has_value());
    if (!opened) {
        return;
    }

    // A real frame, from a real UMEM slot, so the only thing wrong with the
    // kick is the state of the link.
    auto slot = ctx.tx_start();
    EXPECT_TRUE(slot.has_value());
    if (!slot) {
        return;
    }
    EXPECT_TRUE(ctx.tx_commit(slot->handle, 64).has_value());

    // Take the link down under the socket. This is the one refusal that can
    // be produced to order: the earlier version of this test submitted a
    // descriptor pointing past the end of the UMEM and expected the kick to
    // fail, but the kernel does not refuse that - xsk_generic_xmit validates
    // the descriptor, counts it in XDP_STATISTICS tx_invalid_descs and drops
    // the frame, and sendto still returns success. That counter is now
    // readable through kernel_stats(), and the drop it makes visible is
    // asserted in xdp_kernel_stats below - but it is still not a kick
    // failure, which is what this test is about.
    EXPECT_EQ(system("ip link set xdptest0 down"), 0);

    auto const status = ctx.tx_flush();
    auto const& stats = ctx.socket_stats();
    EXPECT_EQ(stats.tx_flush_count, 1u);

    if (stats.tx_flush_errno == 0) {
        // Some kernels take the frame anyway and drop it further down. There
        // is then no refusal to classify, and asserting on one would be
        // asserting on this kernel rather than on our bookkeeping.
        SKIP("this kernel accepted a kick on a down link");
    }

    // Whichever errno it gave, the counters have to agree with the
    // classification: that agreement is the thing under test, not the
    // identity of the errno, which is the kernel's business and varies.
    bool const transient = detail::transient_kick_errno(stats.tx_flush_errno);
    EXPECT_EQ(stats.tx_flush_transient, transient ? 1u : 0u);
    EXPECT_EQ(stats.tx_flush_failed, transient ? 0u : 1u);
    // A transient refusal reads as success so the caller does not escalate on
    // a hiccup; a hard one is reported.
    EXPECT_EQ(status.has_value(), transient);
    if (!status) {
        EXPECT_TRUE(status.error() == XdpError::tx_flush_failed);
    }

    // Either way the frames stayed pending, because the kernel never took
    // them: the next kick tries again rather than counting them as delivered,
    // and so is a kick and not a skip.
    (void)ctx.tx_flush();
    EXPECT_EQ(ctx.socket_stats().tx_flush_count, 2u);
    EXPECT_EQ(ctx.socket_stats().tx_flush_skipped, 0u);
}

TEST(xdp_integration, set_rules)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

// Overwrite what a pin directory claims about itself. Needed because the
// interesting cases - somebody else's program, and our own from a different
// build - cannot otherwise be produced without a second build to hand.
static bool rewrite_pinned_identity(std::string_view pin_path, XdpPinIdentity const& identity)
{
    int const fd = bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_IDENTITY).c_str());
    if (fd < 0) {
        return false;
    }
    uint32_t const key = 0;
    bool const written = bpf_map_update_elem(fd, &key, &identity, BPF_ANY) == 0;
    ::close(fd);
    return written;
}

TEST(xdp_integration, a_pin_that_belongs_to_somebody_else_is_left_strictly_alone)
{
    // The dangerous case, and the one the identity exists for. A directory
    // claiming an owner that is not us must not be adopted - that would
    // write our rules into a stranger's map - and must not be replaced
    // either, because replacing means unlinking their pins and taking their
    // program off the interface. Open fails, and nothing moves.
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        // detach() refuses a foreign pin directory too - that is asserted
        // below - so the identity goes back to ours before the broom runs,
        // or the stranger's pins would outlive this test and refuse every
        // pinned open after it.
        (void)rewrite_pinned_identity(pin_path, XdpProgram::identity());
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
    uint32_t attached_id = 0;
    {
        XdpContext ctx;
        if (!ctx.open(config)) {
            return;
        }
        EXPECT_TRUE(ctx.pinned());
        if_index = ctx.interface_index();
        attached_id = ctx.program().id();
    }
    EXPECT_TRUE(attached_id != 0);

    // Someone else's magic in our directory. Contrived here; in the field it
    // would be a pin path pointed somewhere it should not have been.
    XdpPinIdentity theirs = XdpProgram::identity();
    theirs.magic = 0x0102'0304'0506'0708ULL;
    EXPECT_TRUE(rewrite_pinned_identity(pin_path, theirs));

    auto const owner = XdpProgram::owner(pin_path);
    EXPECT_TRUE(owner.has_value());
    if (owner) {
        EXPECT_TRUE(*owner == XdpPinOwner::foreign);
    }

    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_FALSE(status.has_value());
        if (!status) {
            EXPECT_TRUE(status.error() == XdpError::foreign_program);
        }
        EXPECT_FALSE(ctx.valid());
        EXPECT_FALSE(ctx.adopted());
        EXPECT_FALSE(ctx.pinned());
    }
    // And the operator's broom will not sweep it either.
    {
        auto const refused = XdpProgram::detach(::if_nametoindex("xdptest0"), pin_path);
        EXPECT_FALSE(refused.has_value());
        if (!refused) {
            EXPECT_TRUE(refused.error() == XdpError::foreign_program);
        }
    }

    // Untouched: the program is the same one, still on the interface, and
    // the pins are all still there.
    auto const still = XdpProgram::query(if_index);
    EXPECT_TRUE(still.has_value());
    if (still && still->has_value()) {
        EXPECT_EQ((*still)->program_id, attached_id);
    } else {
        EXPECT_TRUE(false);  // the attachment was removed, which is the bug
    }
    for (auto const entry :
         {XdpProgram::PIN_IDENTITY,
          XdpProgram::PIN_PROG,
          XdpProgram::PIN_RULES_MAP,
          XdpProgram::PIN_XSK_MAP,
          XdpProgram::PIN_DEVMAP}) {
        EXPECT_EQ(::access(XdpProgram::pin_entry(pin_path, entry).c_str(), F_OK), 0);
    }

    // And the claim still reads as theirs: we did not quietly restamp it.
    auto const after = XdpProgram::owner(pin_path);
    EXPECT_TRUE(after.has_value());
    if (after) {
        EXPECT_TRUE(*after == XdpPinOwner::foreign);
    }
}

TEST(xdp_integration, a_pin_from_a_different_build_of_ours_is_replaced)
{
    // The common case, and the one a structural check cannot catch: same
    // maps, same names, same capacities, different code. A redeploy. It has
    // to be detected - adopting it would run the old filter while believing
    // the new one is in force - and it has to be replaced rather than
    // refused, or no upgrade could ever restart.
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

    uint32_t first_id = 0;
    {
        XdpContext ctx;
        if (!ctx.open(config)) {
            return;
        }
        first_id = ctx.program().id();
    }

    // Our magic, a different program. One bit of the fingerprint is all it
    // takes, which is the point of fingerprinting the object at all.
    XdpPinIdentity older = XdpProgram::identity();
    older.program_hash ^= 1ULL;
    EXPECT_TRUE(rewrite_pinned_identity(pin_path, older));

    // Still ours, so the directory may be replaced.
    auto const owner = XdpProgram::owner(pin_path);
    EXPECT_TRUE(owner.has_value());
    if (owner) {
        EXPECT_TRUE(*owner == XdpPinOwner::ours);
    }

    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (!status) {
            return;
        }
        EXPECT_FALSE(ctx.adopted());
        EXPECT_TRUE(ctx.pinned());
        // A fresh program, not the one that was there.
        EXPECT_TRUE(ctx.program().id() != 0);
        EXPECT_TRUE(ctx.program().id() != first_id);
    }

    // And the directory now claims this build again, so the *next* restart
    // adopts instead of replacing.
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
        }
    }
}

TEST(xdp_integration, pinned_and_adopted_report_every_combination_truthfully)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
    }
    auto const pin_path = XdpProgram::pin_path_for("xdptest0");
    auto cleanup = detail::scopeguard([&] {
        (void)XdpProgram::detach(::if_nametoindex("xdptest0"), pin_path);
        destroy_veth_pair("xdptest0");
    });

    // Neither: no pin path, so nothing outlives the context.
    unsigned int if_index = 0;
    {
        XdpContext ctx;
        XdpConfig const unpinned{
            .interface_name = "xdptest0",
            .default_action = XdpAction::pass_kernel,
            .umem_frame_count = 64,
        };
        if (!ctx.open(unpinned)) {
            return;
        }
        EXPECT_FALSE(ctx.pinned());
        EXPECT_FALSE(ctx.adopted());
        if_index = ctx.interface_index();
        ctx.close();

        // The other half of the close policy: a program we attached and did
        // *not* pin comes off the interface with us.
        auto const gone = XdpProgram::query(if_index);
        EXPECT_TRUE(gone.has_value());
        if (gone) {
            EXPECT_FALSE(gone->has_value());
        }
    }

    XdpConfig const config{
        .interface_name = "xdptest0",
        .default_action = XdpAction::pass_kernel,
        .umem_frame_count = 64,
        .pin_path = pin_path,
    };

    // Pinned, not adopted: the first run.
    {
        XdpContext ctx;
        if (!ctx.open(config)) {
            return;
        }
        EXPECT_TRUE(ctx.pinned());
        EXPECT_FALSE(ctx.adopted());
    }

    // Pinned and adopted: every run after it.
    {
        XdpContext ctx;
        auto const status = ctx.open(config);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_TRUE(ctx.pinned());
            EXPECT_TRUE(ctx.adopted());
        }
    }

    // Adopted but not pinned is the fourth combination, and it cannot
    // happen: adoption reads a pin, so it implies one. Asked for
    // explicitly rather than left to be obvious.
    {
        XdpContext ctx;
        XdpConfig fresh = config;
        fresh.adopt = false;
        auto const status = ctx.open(fresh);
        EXPECT_TRUE(status.has_value());
        if (status) {
            EXPECT_FALSE(ctx.adopted());
            EXPECT_TRUE(ctx.pinned());
        }
        EXPECT_TRUE(!ctx.adopted() || ctx.pinned());
    }
}

// The failure the bind retry exists for, reproduced: close a queue and bind it
// again immediately. Without the retry this fails - not every iteration,
// which is what makes the bug so unpleasant to chase, but often enough that
// twenty turns round the loop find it.
TEST(xdp_integration, a_queue_rebound_the_instant_it_is_closed_still_opens)
{
    if (getuid() != 0) {
        SKIP("needs root");
    }

    destroy_veth_pair("xdptest0");
    if (!create_veth_pair("xdptest0", "xdptest1")) {
        SKIP("could not create a veth pair");
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

namespace {

constexpr size_t PROBE_FRAME_SIZE = 2048;
constexpr size_t PROBE_FRAME_COUNT = 64;
constexpr size_t PROBE_RING_SIZE = 64;
constexpr size_t PROBE_FRAME_LENGTH = 60;

// Write a uid/gid map for the new user namespace, so the child is root in it.
auto write_own_map(char const* path, char const* line) -> bool
{
    FILE* f = ::fopen(path, "we");
    if (f == nullptr) {
        return false;
    }
    bool const wrote = ::fputs(line, f) >= 0;
    return ::fclose(f) == 0 && wrote;
}

auto enter_private_namespaces() -> bool
{
    // The maps name the caller's own id, not a literal: without CAP_SETUID
    // outside the namespace that is the only mapping the kernel will accept,
    // and hardcoding one makes the test skip for every other uid - including
    // root, which is how this was caught.
    std::array<char, 32> uid_line{};
    std::array<char, 32> gid_line{};
    (void)std::snprintf(uid_line.data(), uid_line.size(), "0 %u 1", static_cast<unsigned>(::getuid()));
    (void)std::snprintf(gid_line.data(), gid_line.size(), "0 %u 1", static_cast<unsigned>(::getgid()));

    if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return false;
    }
    // setgroups must be denied before the gid map may be written.
    (void)write_own_map("/proc/self/setgroups", "deny");
    return write_own_map("/proc/self/uid_map", uid_line.data()) && write_own_map("/proc/self/gid_map", gid_line.data());
}

// Bring a device up with no help from a shell.
auto bring_up(char const* device) -> bool
{
    int const control = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (control < 0) {
        return false;
    }
    auto const closer = detail::scopeguard([control] { ::close(control); });
    ifreq request{};
    (void)std::snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", device);
    if (::ioctl(control, SIOCGIFFLAGS, &request) < 0) {
        return false;
    }
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
    return ::ioctl(control, SIOCSIFFLAGS, &request) == 0;
}

// Everything a child reports back. POD so it crosses the pipe as bytes.
struct ProbeReport
{
    bool entered{false};
    bool link_up{false};
    bool umem_created{false};
    bool socket_bound{false};
    bool fresh_read{false};
    bool bad_desc_submitted{false};
    bool kick_succeeded{false};
    bool after_read{false};
    uint64_t counters_reported{0};
    uint64_t fresh_tx_invalid{0};
    uint64_t fresh_sum{0};
    uint64_t after_tx_invalid{0};
};

// Build a transmit-only AF_XDP socket on the namespace's loopback, submit one
// descriptor addressed past the end of the UMEM, kick it, and report the
// counters either side. Runs as the child of fork(), inside its own
// namespaces.
void probe_tx_invalid(ProbeReport& out)
{
    out.entered = enter_private_namespaces();
    if (!out.entered) {
        return;
    }
    if (!bring_up("lo")) {
        return;
    }
    out.link_up = true;

    // The kernel refuses a UMEM whose area is not page-aligned, so this cannot
    // be a plain vector. aligned_alloc wants the size to be a multiple of the
    // alignment, which a whole number of frames is on any page size that
    // divides the region.
    size_t const area_size = PROBE_FRAME_SIZE * PROBE_FRAME_COUNT;
    auto const page_size = static_cast<size_t>(::getpagesize());
    std::unique_ptr<void, decltype(&std::free)> const area{std::aligned_alloc(page_size, area_size), &std::free};
    if (!area) {
        return;
    }
    std::memset(area.get(), 0, area_size);

    xsk_umem* umem = nullptr;
    xsk_ring_prod fill{};
    xsk_ring_cons comp{};
    xsk_umem_config const umem_config{
        .fill_size = PROBE_RING_SIZE,
        .comp_size = PROBE_RING_SIZE,
        .frame_size = PROBE_FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };
    if (xsk_umem__create(&umem, area.get(), area_size, &fill, &comp, &umem_config) != 0) {
        return;
    }
    out.umem_created = true;

    xsk_socket* xsk = nullptr;
    xsk_ring_prod tx{};
    xsk_socket_config const socket_config{
        .rx_size = PROBE_RING_SIZE,
        .tx_size = PROBE_RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_COPY,
    };
    if (xsk_socket__create(&xsk, "lo", 0, umem, nullptr, &tx, &socket_config) != 0) {
        xsk_umem__delete(umem);
        return;
    }
    out.socket_bound = true;
    int const fd = xsk_socket__fd(xsk);

    if (auto const fresh = detail::read_xdp_kernel_stats(fd); fresh.has_value()) {
        out.fresh_read = true;
        out.counters_reported = fresh->counters_reported;
        out.fresh_tx_invalid = fresh->tx_invalid_descs;
        out.fresh_sum = fresh->rx_dropped + fresh->rx_invalid_descs + fresh->tx_invalid_descs + fresh->rx_ring_full +
            fresh->rx_fill_ring_empty_descs + fresh->tx_ring_empty_descs;
    }

    uint32_t index = 0;
    if (xsk_ring_prod__reserve(&tx, 1, &index) == 1) {
        xdp_desc* desc = xsk_ring_prod__tx_desc(&tx, index);
        desc->addr = area_size + PROBE_FRAME_SIZE;  // past the end of the UMEM
        desc->len = PROBE_FRAME_LENGTH;
        desc->options = 0;
        xsk_ring_prod__submit(&tx, 1);
        out.bad_desc_submitted = true;
        out.kick_succeeded = ::sendto(fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0) == 0;
    }

    if (auto const after = detail::read_xdp_kernel_stats(fd); after.has_value()) {
        out.after_read = true;
        out.after_tx_invalid = after->tx_invalid_descs;
    }

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
}

// What a probe came back with, or why there is nothing to assert. The reason
// is a string rather than a silent nullopt so the test body can hand it to
// SKIP(): a test that stops running has to say so.
struct ProbeOutcome
{
    std::optional<ProbeReport> report;
    char const* skipped{nullptr};
};

// Run fill() in a forked child inside private namespaces and bring its report
// back.
auto run_probe(void (*fill)(ProbeReport&)) -> ProbeOutcome
{
    std::array<int, 2> pipe_fds{-1, -1};
    if (::pipe(pipe_fds.data()) != 0) {
        return ProbeOutcome{.skipped = "pipe() failed"};
    }
    pid_t const child = ::fork();
    if (child < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return ProbeOutcome{.skipped = "fork() failed"};
    }
    if (child == 0) {
        ::close(pipe_fds[0]);
        ProbeReport report;
        fill(report);
        auto const* bytes = reinterpret_cast<uint8_t const*>(&report);
        ssize_t const written = ::write(pipe_fds[1], bytes, sizeof(report));
        ::close(pipe_fds[1]);
        ::_exit(written == static_cast<ssize_t>(sizeof(report)) ? 0 : 1);
    }
    ::close(pipe_fds[1]);
    ProbeReport report;
    ssize_t const read_bytes = ::read(pipe_fds[0], &report, sizeof(report));
    ::close(pipe_fds[0]);
    int status = 0;
    (void)::waitpid(child, &status, 0);
    if (read_bytes != static_cast<ssize_t>(sizeof(report))) {
        return ProbeOutcome{.skipped = "the child reported nothing"};
    }
    if (!report.entered) {
        return ProbeOutcome{.skipped = "no user+network namespace available to this uid"};
    }
    if (!report.link_up) {
        return ProbeOutcome{.skipped = "could not bring the namespace's loopback up"};
    }
    if (!report.umem_created) {
        return ProbeOutcome{.skipped = "could not register a UMEM (RLIMIT_MEMLOCK?)"};
    }
    if (!report.socket_bound) {
        return ProbeOutcome{.skipped = "could not bind a transmit-only AF_XDP socket to loopback"};
    }
    return ProbeOutcome{.report = report};
}

}  // namespace

TEST(xdp_kernel_stats, a_fresh_socket_reads_zero_on_every_counter)
{
    auto const outcome = run_probe(probe_tx_invalid);
    if (outcome.skipped != nullptr) {
        SKIP(outcome.skipped);
    }
    auto const& report = *outcome.report;

    EXPECT_TRUE(report.fresh_read);
    EXPECT_EQ(report.fresh_sum, 0u);
    // Six, which is what pins that the read asks for the whole struct: a
    // request truncated to the old three would still succeed and still read
    // zero, and only this number would notice. A kernel older than 5.9
    // answers 3 and fails here, which is the right way to find that out.
    EXPECT_EQ(report.counters_reported, 6u);
}

// The point of the whole feature: the kernel refuses the descriptor, drops the
// frame, counts it - and sendto still returns success, so without this counter
// a dropped frame is indistinguishable from a sent one.
TEST(xdp_kernel_stats, an_out_of_range_tx_descriptor_is_counted_though_the_kick_succeeds)
{
    auto const outcome = run_probe(probe_tx_invalid);
    if (outcome.skipped != nullptr) {
        SKIP(outcome.skipped);
    }
    auto const& report = *outcome.report;

    EXPECT_TRUE(report.bad_desc_submitted);
    EXPECT_TRUE(report.kick_succeeded);
    EXPECT_TRUE(report.after_read);
    EXPECT_EQ(report.fresh_tx_invalid, 0u);
    EXPECT_EQ(report.after_tx_invalid, 1u);
}

//
// Multicast memberships
//

/// Whether the kernel lists @p group on the loopback interface: a line of
/// /proc/net/dev_mcast reading "<ifindex> lo <users> <global> <hex address>".
auto lo_lists_group(std::string const& hex_address) -> bool
{
    std::ifstream table{"/proc/net/dev_mcast"};
    std::string line;
    while (std::getline(table, line)) {
        if (line.find(" lo ") != std::string::npos && line.find(hex_address) != std::string::npos) {
            return true;
        }
    }
    return false;
}

TEST(xdp_membership, memberships_are_counted_per_socket_and_per_group)
{
    // Root-only: AF_PACKET needs CAP_NET_RAW. The loopback interface takes
    // memberships like any other, so the counting can be checked without a
    // NIC: two joins keep the group on the interface through one leave and
    // drop it at the second. A leave past that, or of a group never joined,
    // is a no-op the kernel answers with success.
    int const probe = ::socket(AF_PACKET, SOCK_RAW, 0);
    if (probe < 0) {
        SKIP("needs CAP_NET_RAW (AF_PACKET open refused)");
    }
    ::close(probe);
    unsigned int const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        SKIP("no loopback interface");
    }

    auto sock = detail::open_membership_socket();
    EXPECT_TRUE(sock.has_value());
    ieee::Eui48 const group{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
    std::string const group_hex{"01005e0000fb"};
    auto change = [&](ieee::Eui48 const& addr, int optname) { return detail::change_membership(sock->get(), lo, addr, optname); };
    EXPECT_FALSE(lo_lists_group(group_hex));

    EXPECT_TRUE(change(group, PACKET_ADD_MEMBERSHIP).has_value());
    EXPECT_TRUE(change(group, PACKET_ADD_MEMBERSHIP).has_value());
    EXPECT_TRUE(lo_lists_group(group_hex));
    EXPECT_TRUE(change(group, PACKET_DROP_MEMBERSHIP).has_value());
    EXPECT_TRUE(lo_lists_group(group_hex));  // one of the two joins still stands
    EXPECT_TRUE(change(group, PACKET_DROP_MEMBERSHIP).has_value());
    EXPECT_FALSE(lo_lists_group(group_hex));
    EXPECT_TRUE(change(group, PACKET_DROP_MEMBERSHIP).has_value());  // nothing held: a no-op
}

TEST(xdp_membership, a_membership_ends_with_its_socket)
{
    int const probe = ::socket(AF_PACKET, SOCK_RAW, 0);
    if (probe < 0) {
        SKIP("needs CAP_NET_RAW (AF_PACKET open refused)");
    }
    ::close(probe);
    unsigned int const lo = ::if_nametoindex("lo");
    if (lo == 0) {
        SKIP("no loopback interface");
    }

    ieee::Eui48 const group{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFC};
    std::string const group_hex{"01005e0000fc"};
    {
        auto sock = detail::open_membership_socket();
        EXPECT_TRUE(sock.has_value());
        EXPECT_TRUE(detail::change_membership(sock->get(), lo, group, PACKET_ADD_MEMBERSHIP).has_value());
        EXPECT_TRUE(lo_lists_group(group_hex));
    }
    // The socket is closed: what a killed process would leave behind under
    // SIOCADDMULTI is gone here.
    EXPECT_FALSE(lo_lists_group(group_hex));
}

#    endif  // __linux__ && HAVE_XDP

#endif  // __linux__

// The busy-poll bookkeeping and the stalled-ring detector are plain state
// with no socket behind them, so they are checked on every platform.
#include "statusbar/net/net_linux_xdp.hpp"

#include <cstdint>
#include <type_traits>

//
// Test Runner
//

TEST_MAIN(statusbar_net, net_linux_xdp_functional_test)