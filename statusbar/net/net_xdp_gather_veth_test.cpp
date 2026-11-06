// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Transmit-only copy-mode AF_XDP sockets on two veth pairs sharing one UMEM (XDP_SHARED_UMEM, XDP_USE_SG): a frame
/// gathered from another share's payload leaves whole and the payload's frame goes home; a share reopens, on the
/// anchor's queue or another, while the other stays bound. Needs root (a user namespace's will do); skips without it.

#include "statusbar/net/net_linux_xdp.hpp"
#include "statusbar/net/net_socket.hpp"
#include "statusbar/net/net_xdp_shared_umem.hpp"
#include "statusbar/test/test.hpp"

#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>

using namespace statusbar;
using namespace statusbar::net;

#if defined(__linux__) && defined(HAVE_XDP)

namespace {

constexpr uint16_t ETHERTYPE = 0x88B5;  ///< IEEE 802 local experimental
constexpr size_t PER_SHARE = 256;
constexpr size_t PAYLOAD = 600;

/// A veth pair, both ends up; removed on destruction.
class VethPair
{
  public:
    VethPair(std::string near, std::string const& far)
        : near_{std::move(near)}
    {
        (void)std::system(std::format("ip link del {} 2>/dev/null", near_).c_str());
        ok_ = std::system(
                  std::format("ip link add {0} type veth peer name {1} && ip link set {0} up && ip link set {1} up", near_, far)
                      .c_str()) == 0;
    }
    ~VethPair() { (void)std::system(std::format("ip link del {} 2>/dev/null", near_).c_str()); }
    VethPair(VethPair const&) = delete;
    auto operator=(VethPair const&) -> VethPair& = delete;
    VethPair(VethPair&&) = delete;
    auto operator=(VethPair&&) -> VethPair& = delete;
    [[nodiscard]] auto ok() const noexcept -> bool { return ok_; }

  private:
    std::string near_;
    bool ok_{false};
};

/// Frames of ETHERTYPE arriving on an interface (AF_PACKET).
class Capture
{
  public:
    explicit Capture(std::string const& interface)
        : fd_{::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETHERTYPE))}
    {
        sockaddr_ll address{};
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETHERTYPE);
        address.sll_ifindex = static_cast<int>(::if_nametoindex(interface.c_str()));
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the sockets API takes a sockaddr
        ok_ = fd_.valid() && ::bind(fd_.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address)) == 0;
    }
    [[nodiscard]] auto ok() const noexcept -> bool { return ok_; }
    /// The next frame within a second, or nothing.
    [[nodiscard]] auto next() const -> std::vector<uint8_t>
    {
        std::array<uint8_t, 2048> buffer{};
        for (int i = 0; i < 100; ++i) {
            auto const n = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
            if (n > 0) {
                return {buffer.begin(), buffer.begin() + n};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return {};
    }

  private:
    FileDescriptor fd_;
    bool ok_{false};
};

auto config_on(std::string_view const interface, XdpSharedUmem& umem, size_t const share) -> XdpConfig
{
    return XdpConfig{
        .interface_name = interface,
        .rx_ring_size = 64,
        .tx_ring_size = 64,
        .fill_ring_size = 64,
        .completion_ring_size = 64,
        .tx_launch_time = false,
        .bind_mode = XdpBindMode::copy,
        .attach_mode = XdpAttachMode::generic,
        .bind_busy_retries = 20,  // a closed socket's queue is given back a moment later
        .tx_frame_reserve = 0,
        .shared_umem = &umem,
        .umem_share = share,
        .tx_scatter_gather = true,
        .tx_only = true,
    };
}

/// Complete what `context` sent, for up to a second, until `done`.
template <typename Done>
void complete_until(XdpContext& context, Done const& done)
{
    for (int i = 0; i < 100 && !done(); ++i) {
        (void)context.tx_flush();
        (void)context.tx_complete();
        (void)context.fill_replenish();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

/// One frame from `sender`'s own header and a payload in a frame of `owner`'s share, as a held received frame
/// would be: it leaves `capture` whole, and the payload's frame goes home once the owner and the completion are
/// done with it.
void round_trip(XdpContext& owner, XdpContext& sender, Capture const& capture, XdpSharedUmem& umem)
{
    auto held = owner.tx_start();
    EXPECT_TRUE(held.has_value());
    size_t const owner_free = owner.free_frames();
    auto const payload = held->buffer.subspan(100, PAYLOAD);
    for (size_t i = 0; i < PAYLOAD; ++i) {
        payload[i] = static_cast<uint8_t>(i * 7);
    }
    auto header = sender.tx_start();
    EXPECT_TRUE(header.has_value());
    std::array<uint8_t, 14> const ethernet{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0, 0, 0, 0, 1, 0x88, 0xB5};
    std::memcpy(header->buffer.data(), ethernet.data(), ethernet.size());
    std::array<std::span<uint8_t const>, 1> const rest{payload};
    EXPECT_TRUE(sender.tx_commit_gather(header->handle, ethernet.size(), rest).has_value());
    EXPECT_TRUE(umem.ledger().lent(held->handle));
    (void)sender.tx_flush();

    auto const frame = capture.next();
    EXPECT_EQ(frame.size(), ethernet.size() + PAYLOAD);
    EXPECT_TRUE(
        frame.size() == ethernet.size() + PAYLOAD && std::memcmp(frame.data(), ethernet.data(), ethernet.size()) == 0 &&
        std::memcmp(frame.data() + ethernet.size(), payload.data(), PAYLOAD) == 0);

    // The owner is done first; the completion on the sender's share sends the frame home through the queue.
    EXPECT_TRUE(owner.rx_release(held->handle).has_value());
    EXPECT_EQ(owner.free_frames(), owner_free);
    complete_until(sender, [&] { return !umem.ledger().lent(held->handle); });
    (void)owner.fill_replenish();
    EXPECT_EQ(owner.free_frames(), owner_free + 1);
}

/// `context` opened on `interface` as share `share` of `umem`: whether it opened.
auto opened(XdpContext& context, std::string_view const interface, XdpSharedUmem& umem, size_t const share) -> bool
{
    auto const status = context.open(config_on(interface, umem, share));
    if (!status) {
        std::fprintf(stderr, "open %s share %zu: %s\n", std::string{interface}.c_str(), share, status.error().message().c_str());
    }
    EXPECT_TRUE(status.has_value());
    return status.has_value();
}

}  // namespace

TEST(xdp_gather_veth, a_frame_gathered_from_another_shares_payload_leaves_whole_and_its_frame_goes_home)
{
    if (::geteuid() != 0) {
        SKIP("needs root (veth pairs, AF_XDP)");
    }
    VethPair const a{"xgthra0", "xgthra1"};
    VethPair const b{"xgthrb0", "xgthrb1"};
    auto umem = XdpSharedUmem::create(PER_SHARE, 2);
    EXPECT_TRUE(a.ok() && b.ok() && umem.has_value());
    if (!a.ok() || !b.ok() || !umem) {
        return;
    }
    XdpContext owner;
    XdpContext sender;
    if (!opened(owner, "xgthra0", **umem, 0) || !opened(sender, "xgthrb0", **umem, 1)) {
        return;
    }
    EXPECT_TRUE(sender.tx_segments() > 2);
    Capture const capture{"xgthrb1"};
    EXPECT_TRUE(capture.ok());
    round_trip(owner, sender, capture, **umem);

    // A frame given back before the gather is refused: nothing sent, the sender's own frame freed.
    auto released = owner.tx_start();
    EXPECT_TRUE(released.has_value());
    EXPECT_TRUE(owner.rx_release(released->handle).has_value());
    auto header = sender.tx_start();
    EXPECT_TRUE(header.has_value());
    size_t const sender_free = sender.free_frames();
    std::array<std::span<uint8_t const>, 1> const rest{released->buffer.subspan(100, PAYLOAD)};
    auto const refused = sender.tx_commit_gather(header->handle, 14, rest);
    EXPECT_TRUE(!refused && refused.error() == XdpError::frame_not_held);
    EXPECT_EQ(sender.free_frames(), sender_free + 1);
    // A launch time with no frame of the sender's to carry it is refused too.
    auto held = owner.tx_start();
    EXPECT_TRUE(held.has_value());
    std::array<std::span<uint8_t const>, 1> const alone{held->buffer.subspan(100, PAYLOAD)};
    auto const untimed = sender.tx_commit_gather(std::nullopt, 0, alone, 1);
    EXPECT_TRUE(!untimed && untimed.error() == XdpError::tx_gather_not_supported);
    EXPECT_FALSE(umem.value()->ledger().lent(held->handle));
}

// The first socket on a shared UMEM anchors it; one that fails to open gives the registration up, and so does the
// last to close, so the next socket anchors afresh; while another is bound it stays.
TEST(xdp_gather_veth, the_registration_follows_its_sockets)
{
    if (::geteuid() != 0) {
        SKIP("needs root (veth pairs, AF_XDP)");
    }
    VethPair const a{"xgthrc0", "xgthrc1"};
    VethPair const b{"xgthrd0", "xgthrd1"};
    auto umem = XdpSharedUmem::create(PER_SHARE, 2);
    EXPECT_TRUE(a.ok() && b.ok() && umem.has_value());
    if (!a.ok() || !b.ok() || !umem) {
        return;
    }
    XdpContext failed;
    EXPECT_FALSE(failed.open(config_on("xgthr-none", **umem, 0)).has_value());  // no such interface: before registering
    auto bad = config_on("xgthrc0", **umem, 0);
    bad.queue_id = 99;  // registered, then the anchor's bind refused
    EXPECT_FALSE(failed.open(bad).has_value());
    EXPECT_TRUE(umem.value()->registered() == nullptr);
    XdpContext first;
    XdpContext second;
    EXPECT_TRUE(first.open(config_on("xgthrc0", **umem, 0)).has_value());
    EXPECT_TRUE(second.open(config_on("xgthrd0", **umem, 1)).has_value());
    first.close();
    EXPECT_TRUE(umem.value()->registered() != nullptr);  // the second still binds it
    second.close();
    EXPECT_TRUE(umem.value()->registered() == nullptr);                     // the last took it with it
    EXPECT_TRUE(second.open(config_on("xgthrd0", **umem, 1)).has_value());  // anchored afresh, on its own queue
    EXPECT_TRUE(umem.value()->registered() != nullptr);
    EXPECT_EQ(second.free_frames(), PER_SHARE);
    second.close();
}

// Either share reopens while the other stays bound: on the anchor's queue the socket joins the queue's pool (the
// anchor keeps it), elsewhere it makes its own; a frame sent whole before the close comes back to the share.
TEST(xdp_gather_veth, a_share_reopens_while_the_other_is_bound)
{
    if (::geteuid() != 0) {
        SKIP("needs root (veth pairs, AF_XDP)");
    }
    VethPair const a{"xgthre0", "xgthre1"};
    VethPair const b{"xgthrf0", "xgthrf1"};
    auto umem = XdpSharedUmem::create(PER_SHARE, 2);
    EXPECT_TRUE(a.ok() && b.ok() && umem.has_value());
    if (!a.ok() || !b.ok() || !umem) {
        return;
    }
    XdpContext owner;
    XdpContext sender;
    if (!opened(owner, "xgthre0", **umem, 0) || !opened(sender, "xgthrf0", **umem, 1)) {
        return;
    }
    Capture const capture{"xgthrf1"};
    EXPECT_TRUE(capture.ok());
    // The anchor's queue: the owner sends a frame whole and closes at once; the reopened socket reaps its completion.
    auto whole = owner.tx_start();
    EXPECT_TRUE(whole.has_value());
    std::memset(whole->buffer.data(), 0xFF, 14);
    EXPECT_TRUE(owner.tx_commit(whole->handle, 60).has_value());
    owner.close();
    EXPECT_TRUE(umem.value()->registered() != nullptr);
    if (!opened(owner, "xgthre0", **umem, 0)) {
        return;
    }
    complete_until(owner, [&] { return owner.free_frames() == PER_SHARE; });
    EXPECT_EQ(owner.free_frames(), PER_SHARE);
    round_trip(owner, sender, capture, **umem);
    // The other queue: its pool goes with the socket, and the share is whole again.
    sender.close();
    if (!opened(sender, "xgthrf0", **umem, 1)) {
        return;
    }
    EXPECT_EQ(sender.free_frames(), PER_SHARE);
    round_trip(owner, sender, capture, **umem);
}

#endif  // __linux__ && HAVE_XDP

TEST_MAIN(statusbar_net, net_xdp_gather_veth_test)
