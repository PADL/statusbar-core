// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rawnet.hpp"

#include "statusbar/net/net_posix_util.hpp"

#if defined(__linux__)
#    include <arpa/inet.h>
#    include <linux/filter.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <sys/socket.h>
#elif defined(__APPLE__)
#    include <fcntl.h>
#    include <ifaddrs.h>

#    include <net/bpf.h>
#    include <net/if_dl.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#endif

namespace statusbar::net {

auto RawnetContext::operator=(RawnetContext&& other) noexcept -> RawnetContext&
{
    if (this != &other) {
        close();
        fd_ = other.fd_;
        ethertype_ = other.ethertype_;
        interface_index_ = other.interface_index_;
        my_mac_ = other.my_mac_;
        default_dest_mac_ = other.default_dest_mac_;
        tx_tap_ = std::move(other.tx_tap_);
#if defined(__APPLE__)
        bpf_buffer_size_ = other.bpf_buffer_size_;
#endif
        other.fd_ = -1;
        other.interface_index_ = -1;
        other.tx_tap_ = {};
    }
    return *this;
}

//
// Linux Implementation
//

#if defined(__linux__)

[[nodiscard]] auto RawnetContext::open(
    std::string_view interface_name, uint16_t ethertype, Eui48 const* multicast_mac, bool qdisc_bypass) noexcept -> Status
{
    // Create with ETH_P_ALL (not htons(ethertype)) so the socket sits in the
    // kernel's ptype_all list and therefore receives BOTH wire frames AND
    // locally-transmitted (PACKET_OUTGOING) frames via the egress tap. The egress
    // tap (dev_queue_xmit_nit) only feeds ETH_P_ALL sockets, never protocol-bound
    // ones — so a protocol-bound socket cannot hear another process's TX on the
    // same host, and an L2 switch will not reflect a frame back to its source
    // port (802.1Q). ETH_P_ALL is what makes same-host RX work (e.g. an on-box
    // ATDECC controller hearing a co-located entity). A cBPF filter below narrows
    // delivery back down to `ethertype` in the kernel so we don't drown in
    // unrelated traffic. TX is unaffected (sendto carries its own sll_protocol).
    int const sock_fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        return failure(NetError::socket_creation_failed);
    }

    // Attach a classic-BPF program: accept only frames whose ethertype is
    // `ethertype`, whether untagged (ethertype at L2 offset 12) or carrying one
    // 802.1Q tag (0x8100 at 12, inner ethertype at 16).
    {
        sock_filter code[] = {
            {BPF_LD | BPF_H | BPF_ABS, 0, 0, 12},            // 0: A = ethertype @12
            {BPF_JMP | BPF_JEQ | BPF_K, 4, 0, ethertype},    // 1: A==type -> accept (6)
            {BPF_JMP | BPF_JEQ | BPF_K, 0, 2, ETH_P_8021Q},  // 2: A==0x8100 -> inner (3) else drop (5)
            {BPF_LD | BPF_H | BPF_ABS, 0, 0, 16},            // 3: A = inner ethertype @16
            {BPF_JMP | BPF_JEQ | BPF_K, 1, 0, ethertype},    // 4: inner==type -> accept (6) else drop (5)
            {BPF_RET | BPF_K, 0, 0, 0},                      // 5: drop
            {BPF_RET | BPF_K, 0, 0, 0xFFFFFFFFU},            // 6: accept
        };
        sock_fprog const prog{.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0])), .filter = code};
        (void)::setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));  // non-fatal
    }

    // Get interface index
    struct ifreq ifr{};
    if (interface_name.size() >= sizeof(ifr.ifr_name)) {
        ::close(sock_fd);
        return failure(NetError::invalid_address);
    }
    span_copy(ifname_bytes(ifr).first(interface_name.size()), make_const_span(interface_name));

    if (::ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sock_fd);
        return failure(NetError::invalid_address);
    }
    interface_index_ = ifr.ifr_ifindex;

    // Get MAC address
    if (::ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        ::close(sock_fd);
        return failure(NetError::socket_creation_failed);
    }
    for (int i = 0; i < 6; ++i) {
        my_mac_.value[i] = static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
    }

    // Optionally bypass the qdisc for lower TX latency (packets go directly to
    // the driver via packet_direct_xmit). OPT-IN and OFF by default.
    //
    // IMPORTANT: PACKET_QDISC_BYPASS does NOT drop frames — frames still reach
    // the wire normally (verified Pi 5 -> Pi 5 over a switch). What it DOES do
    // is skip dev_queue_xmit_nit, the egress tap that feeds AF_PACKET capture.
    // So a frame sent with bypass is INVISIBLE to tcpdump/AF_PACKET on the
    // *sending* host (it is still seen by remote hosts). We default it OFF so
    // local `tcpdump` can observe our own egress — that visibility is worth far
    // more than the marginal latency win for control-plane traffic
    // (ADP/MVRP/MSRP), and its absence caused a long misdiagnosis. Enable it
    // only for latency-critical TX where local capture visibility is not needed.
#    if defined(STATUSBAR_NO_QDISC_BYPASS)
    // Compile-time "local capture visibility" build (ENABLE_PACKET_QDISC_BYPASS=OFF):
    // never bypass the qdisc, so all TX goes through dev_queue_xmit_nit and is
    // visible to AF_PACKET capture / on-box ATDECC tools on the sending host.
    // Also open the socket promiscuous so it receives every frame of its
    // ethertype regardless of multicast-group membership.
    (void)qdisc_bypass;
    {
        struct packet_mreq promisc{};
        promisc.mr_ifindex = interface_index_;
        promisc.mr_type = PACKET_MR_PROMISC;
        (void)::setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &promisc, sizeof(promisc));
    }
#    else
    if (qdisc_bypass) {
        int const bypass = 1;
        if (::setsockopt(sock_fd, SOL_PACKET, PACKET_QDISC_BYPASS, &bypass, sizeof(bypass)) < 0) {
            // Non-fatal: older kernels may not support this option.
        }
    }
#    endif

    fd_ = sock_fd;
    ethertype_ = ethertype;

    // Set default destination MAC if provided
    if (multicast_mac != nullptr) {
        default_dest_mac_ = *multicast_mac;
        if (auto status = join_multicast(*multicast_mac); !status) {
            close();
            return status;
        }
    }

    // Set non-blocking
    if (auto status = set_nonblocking(fd_); !status) {
        close();
        return status;
    }

    return success();
}

void RawnetContext::close() noexcept
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    interface_index_ = -1;
}

[[nodiscard]] auto RawnetContext::send(std::span<uint8_t const> full_frame) const noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Set up sockaddr_ll
    struct sockaddr_ll socket_address{};
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ethertype_);
    socket_address.sll_ifindex = interface_index_;
    socket_address.sll_hatype = 1;  // ARPHRD_ETHER
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = ETH_ALEN;
    span_copy(std::span{socket_address.sll_addr}.first(ETH_ALEN), make_const_span(my_mac_.value));

    // Send
    ssize_t sent_len = 0;
    do {
        sent_len = ::sendto(fd_, full_frame.data(), full_frame.size(), 0, sockaddr_cast(socket_address), sizeof(socket_address));
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    return success(static_cast<ssize_t>(sent_len - ETHERNET_HEADER_SIZE));
}

[[nodiscard]] auto RawnetContext::send(Eui48 const* dest_mac, std::span<uint8_t const> payload) noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Build Ethernet frame
    std::array<uint8_t, MAX_ETHERNET_FRAME_SIZE> buffer{};
    std::span<uint8_t> const buffer_span{buffer};

    // Set up sockaddr_ll
    struct sockaddr_ll socket_address{};
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ethertype_);
    socket_address.sll_ifindex = interface_index_;
    socket_address.sll_hatype = 1;  // ARPHRD_ETHER
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = ETH_ALEN;
    span_copy(std::span{socket_address.sll_addr}.first(ETH_ALEN), make_const_span(my_mac_.value));

    // Destination MAC
    Eui48 const& dest = (dest_mac != nullptr) ? *dest_mac : default_dest_mac_;
    span_copy(buffer_span.subspan(0, 6), dest.value);

    // Source MAC
    span_copy(buffer_span.subspan(6, 6), my_mac_.value);

    // EtherType (network byte order)
    buffer[12] = static_cast<uint8_t>(ethertype_ >> 8);
    buffer[13] = static_cast<uint8_t>(ethertype_ & 0xFF);

    // Copy payload
    size_t const payload_len = std::min(payload.size(), MAX_ETHERNET_FRAME_SIZE - ETHERNET_HEADER_SIZE);
    span_copy(buffer_span.subspan(ETHERNET_HEADER_SIZE, payload_len), payload.subspan(0, payload_len));

    // Send
    ssize_t sent_len = 0;
    do {
        sent_len = ::sendto(
            fd_, buffer.data(), payload_len + ETHERNET_HEADER_SIZE, 0, sockaddr_cast(socket_address), sizeof(socket_address));
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    return success(static_cast<ssize_t>(sent_len - ETHERNET_HEADER_SIZE));
}

[[nodiscard]] auto RawnetContext::send_vlan(
    Eui48 const* dest_mac, std::span<uint8_t const> payload, uint16_t vlan_id, uint8_t pcp) noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    static constexpr uint16_t TPID_8021Q = 0x8100;
    static constexpr size_t TAGGED_HEADER_SIZE = ETHERNET_HEADER_SIZE + 4;  // + TPID(2) + TCI(2)

    std::array<uint8_t, MAX_ETHERNET_FRAME_SIZE_VLAN> buffer{};
    std::span<uint8_t> const buffer_span{buffer};

    struct sockaddr_ll socket_address{};
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ethertype_);
    socket_address.sll_ifindex = interface_index_;
    socket_address.sll_hatype = 1;  // ARPHRD_ETHER
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = ETH_ALEN;
    span_copy(std::span{socket_address.sll_addr}.first(ETH_ALEN), make_const_span(my_mac_.value));

    Eui48 const& dest = (dest_mac != nullptr) ? *dest_mac : default_dest_mac_;
    span_copy(buffer_span.subspan(0, 6), dest.value);
    span_copy(buffer_span.subspan(6, 6), my_mac_.value);

    // 802.1Q tag: TPID 0x8100, then TCI = PCP(3) | DEI(1) | VID(12).
    uint16_t const tci = static_cast<uint16_t>((static_cast<uint16_t>(pcp & 0x07) << 13) | (vlan_id & 0x0FFF));
    buffer[12] = static_cast<uint8_t>(TPID_8021Q >> 8);
    buffer[13] = static_cast<uint8_t>(TPID_8021Q & 0xFF);
    buffer[14] = static_cast<uint8_t>(tci >> 8);
    buffer[15] = static_cast<uint8_t>(tci & 0xFF);

    // Inner ethertype follows the tag.
    buffer[16] = static_cast<uint8_t>(ethertype_ >> 8);
    buffer[17] = static_cast<uint8_t>(ethertype_ & 0xFF);

    size_t const payload_len = std::min(payload.size(), MAX_ETHERNET_FRAME_SIZE_VLAN - TAGGED_HEADER_SIZE);
    span_copy(buffer_span.subspan(TAGGED_HEADER_SIZE, payload_len), payload.subspan(0, payload_len));

    ssize_t sent_len = 0;
    do {
        sent_len = ::sendto(
            fd_, buffer.data(), payload_len + TAGGED_HEADER_SIZE, 0, sockaddr_cast(socket_address), sizeof(socket_address));
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    // Egress tap: hand the exact on-wire frame (full L2, VLAN tag included) to an
    // observer. The only way to see a PACKET_QDISC_BYPASS stream's own egress.
    if (tx_tap_) {
        tx_tap_(std::span<uint8_t const>{buffer.data(), payload_len + TAGGED_HEADER_SIZE});
    }

    return success(static_cast<ssize_t>(sent_len - static_cast<ssize_t>(TAGGED_HEADER_SIZE)));
}

[[nodiscard]] auto RawnetContext::recv(Eui48* src_mac, Eui48* dest_mac, std::span<uint8_t> payload_buf) noexcept
    -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    std::array<uint8_t, MAX_ETHERNET_FRAME_SIZE> buffer{};
    ssize_t buf_len = 0;

    do {
        buf_len = ::recv(fd_, buffer.data(), buffer.size(), 0);
    } while (buf_len < 0 && errno == EINTR);

    if (buf_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::receive_failed);
    }

    if (buf_len < static_cast<ssize_t>(ETHERNET_HEADER_SIZE)) {
        return failure(NetError::receive_failed);
    }

    // Extract MACs
    std::span<uint8_t const> const buf_span{buffer};
    if (dest_mac != nullptr) {
        span_copy(dest_mac->value, buf_span.subspan(0, 6));
    }
    if (src_mac != nullptr) {
        span_copy(src_mac->value, buf_span.subspan(6, 6));
    }

    // L2 header length: 14, or 18 if the frame carries a single 802.1Q VLAN tag
    // (0x8100 at offset 12). The ETH_P_ALL socket can deliver tagged frames when
    // RX VLAN offload is off; strip the tag so the returned payload always starts
    // at the upper-layer header. (Untagged frames are unaffected.)
    size_t l2_header_len = ETHERNET_HEADER_SIZE;
    if (buf_len >= 18) {
        uint16_t const outer_ethertype = (static_cast<uint16_t>(buffer[12]) << 8) | buffer[13];
        if (outer_ethertype == 0x8100U) {
            l2_header_len = 18;
        }
    }

    // Copy payload
    ssize_t payload_len = static_cast<ssize_t>(buf_len - static_cast<ssize_t>(l2_header_len));
    if (static_cast<size_t>(payload_len) > payload_buf.size()) {
        payload_len = static_cast<ssize_t>(payload_buf.size());
    }
    span_copy(
        payload_buf.subspan(0, static_cast<size_t>(payload_len)),
        buf_span.subspan(l2_header_len, static_cast<size_t>(payload_len)));

    return success(payload_len);
}

[[nodiscard]] auto RawnetContext::join_multicast(Eui48 const& multicast_mac) const noexcept -> Status
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Bind to interface. CRITICAL: bind with sll_protocol = ETH_P_ALL, NOT
    // htons(ethertype_). Binding to a specific protocol re-registers the socket
    // under that protocol's hash and removes it from the kernel's ptype_all list
    // — which is exactly the list the egress tap (dev_queue_xmit_nit) feeds. A
    // protocol-bound socket therefore stops hearing locally-transmitted
    // (PACKET_OUTGOING) frames, breaking same-host RX (an on-box controller
    // hearing a co-located entity). The socket was opened on ETH_P_ALL precisely
    // to stay in ptype_all; keep it there. The cBPF filter attached in open()
    // already narrows delivery to `ethertype_`, so binding to ETH_P_ALL does not
    // widen what we actually receive — it only preserves same-host delivery.
    struct sockaddr_ll saddr{};
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = interface_index_;
    saddr.sll_pkttype = PACKET_MULTICAST;
    saddr.sll_protocol = htons(ETH_P_ALL);

    if (::bind(fd_, sockaddr_cast(saddr), sizeof(saddr)) < 0) {
        return failure(NetError::bind_failed);
    }

    // Add multicast membership
    struct packet_mreq mreq{};
    mreq.mr_ifindex = interface_index_;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    span_copy(std::span{mreq.mr_address}.first(6), make_const_span(multicast_mac.value));

    if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return failure(NetError::socket_creation_failed);
    }

    return success();
}

[[nodiscard]] auto RawnetContext::leave_multicast(Eui48 const& multicast_mac) const noexcept -> Status
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Symmetric to join_multicast: drop the NIC multicast filter entry. No
    // re-bind needed — leaving membership does not touch the socket's protocol
    // binding.
    struct packet_mreq mreq{};
    mreq.mr_ifindex = interface_index_;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    span_copy(std::span{mreq.mr_address}.first(6), make_const_span(multicast_mac.value));

    if (::setsockopt(fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return failure(NetError::socket_creation_failed);
    }

    return success();
}

#endif  // __linux__

//
// macOS Implementation
//

#if defined(__APPLE__)

[[nodiscard]] auto RawnetContext::open(
    std::string_view interface_name, uint16_t ethertype, Eui48 const* multicast_mac, bool qdisc_bypass) noexcept -> Status
{
    (void)qdisc_bypass;  // qdisc bypass is a Linux AF_PACKET concept; no-op on macOS BPF
    // Find and open an available BPF device
    int bpf_fd = -1;
    char dev_path[32];
    for (int i = 0; i < 255; ++i) {
        snprintf(dev_path, sizeof(dev_path), "/dev/bpf%d", i);
        bpf_fd = ::open(dev_path, O_RDWR);
        if (bpf_fd >= 0) {
            break;
        }
        if (errno != EBUSY) {
            continue;  // Try next device
        }
    }

    if (bpf_fd < 0) {
        return failure(NetError::socket_creation_failed);
    }

    // Set buffer size
    u_int buf_len = sizeof(bpf_read_buffer_);
    if (::ioctl(bpf_fd, BIOCSBLEN, &buf_len) < 0) {
        ::close(bpf_fd);
        return failure(NetError::socket_creation_failed);
    }
    bpf_buffer_size_ = buf_len;

    // Bind to interface
    struct ifreq ifr{};
    if (interface_name.size() >= sizeof(ifr.ifr_name)) {
        ::close(bpf_fd);
        return failure(NetError::invalid_address);
    }
    span_copy(ifname_bytes(ifr).first(interface_name.size()), make_const_span(interface_name));

    if (::ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        ::close(bpf_fd);
        return failure(NetError::invalid_address);
    }

    // Get interface index using if_nametoindex. ifname_buf is a char array
    // for if_nametoindex; make_span(arr) views it as the underlying bytes.
    std::array<char, IFNAMSIZ> ifname_buf{};
    span_copy(make_span(ifname_buf).first(interface_name.size()), make_const_span(interface_name));
    interface_index_ = static_cast<int>(if_nametoindex(ifname_buf.data()));

    // Get MAC address from interface
    struct ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs const* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_LINK) {
                continue;
            }
            if (std::strncmp(ifa->ifa_name, ifname_buf.data(), IFNAMSIZ) != 0) {
                continue;
            }
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — macOS sockaddr_dl overlay
            auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen == 6) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — LLADDR returns char*
                span_copy(my_mac_.value, std::span<uint8_t const>(reinterpret_cast<uint8_t const*>(LLADDR(sdl)), 6));
                break;
            }
        }
        ::freeifaddrs(ifaddr);
    }

    // Enable immediate mode (don't wait for buffer to fill)
    u_int immediate = 1;
    if (::ioctl(bpf_fd, BIOCIMMEDIATE, &immediate) < 0) {
        ::close(bpf_fd);
        return failure(NetError::socket_creation_failed);
    }

    // Enable header complete mode (we provide the full Ethernet header)
    u_int hdrcmplt = 1;
    if (::ioctl(bpf_fd, BIOCSHDRCMPLT, &hdrcmplt) < 0) {
        ::close(bpf_fd);
        return failure(NetError::socket_creation_failed);
    }

    // Enable "see sent" mode (we'll see our own transmissions)
    u_int seesent = 0;                        // Don't see our own packets
    ::ioctl(bpf_fd, BIOCSSEESENT, &seesent);  // Ignore error, not critical

    // Enable promiscuous mode so multicast control traffic (ATDECC/ACMP/ADP to
    // 91:e0:f0:01:00:00, MSRP/MVRP groups) is reliably delivered to BPF. Without
    // it, reception depends on the NIC's hardware multicast filter, which is not
    // guaranteed to carry these groups — observed as intermittent discovery on a
    // Thunderbolt AVB dongle. Not critical (some virtual ifaces reject it), so
    // the error is ignored. This is a controller/sniffer endpoint, so seeing
    // extra traffic is harmless (the ethertype BPF filter still applies).
    ::ioctl(bpf_fd, BIOCPROMISC, nullptr);

    // Set up BPF filter for ethertype
    struct bpf_insn filter[] = {
        // Load ethertype (offset 12)
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        // Compare with our ethertype
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ethertype, 0, 1),
        // Accept: return max packet size
        BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        // Reject: return 0
        BPF_STMT(BPF_RET + BPF_K, 0),
    };

    struct bpf_program prog{};
    prog.bf_len = sizeof(filter) / sizeof(filter[0]);
    prog.bf_insns = filter;

    if (::ioctl(bpf_fd, BIOCSETF, &prog) < 0) {
        ::close(bpf_fd);
        return failure(NetError::socket_creation_failed);
    }

    fd_ = bpf_fd;
    ethertype_ = ethertype;

    // Set default destination MAC if provided
    if (multicast_mac != nullptr) {
        default_dest_mac_ = *multicast_mac;
    }

    // Set non-blocking
    if (auto status = set_nonblocking(fd_); !status) {
        close();
        return status;
    }

    return success();
}

void RawnetContext::close() noexcept
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    interface_index_ = -1;
    bpf_read_offset_ = 0;
    bpf_read_length_ = 0;
}

[[nodiscard]] auto RawnetContext::send(std::span<uint8_t const> full_frame) const noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Send via BPF write
    ssize_t sent_len = 0;
    do {
        sent_len = ::write(fd_, full_frame.data(), full_frame.size());
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    return success(static_cast<ssize_t>(sent_len - ETHERNET_HEADER_SIZE));
}

[[nodiscard]] auto RawnetContext::send(Eui48 const* dest_mac, std::span<uint8_t const> payload) noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    // Build Ethernet frame
    std::array<uint8_t, MAX_ETHERNET_FRAME_SIZE> buffer{};
    std::span<uint8_t> const buf_span{buffer};

    // Destination MAC
    Eui48 const& dest = (dest_mac != nullptr) ? *dest_mac : default_dest_mac_;
    span_copy(buf_span.subspan(0, 6), dest.value);

    // Source MAC
    span_copy(buf_span.subspan(6, 6), my_mac_.value);

    // EtherType (network byte order)
    buffer[12] = static_cast<uint8_t>(ethertype_ >> 8);
    buffer[13] = static_cast<uint8_t>(ethertype_ & 0xFF);

    // Copy payload
    size_t const payload_len = std::min(payload.size(), MAX_ETHERNET_FRAME_SIZE - ETHERNET_HEADER_SIZE);
    span_copy(buf_span.subspan(ETHERNET_HEADER_SIZE, payload_len), payload.subspan(0, payload_len));

    // Send via BPF write
    ssize_t sent_len = 0;
    do {
        sent_len = ::write(fd_, buffer.data(), payload_len + ETHERNET_HEADER_SIZE);
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    return success(static_cast<ssize_t>(sent_len - ETHERNET_HEADER_SIZE));
}

[[nodiscard]] auto RawnetContext::send_vlan(
    Eui48 const* dest_mac, std::span<uint8_t const> payload, uint16_t vlan_id, uint8_t pcp) noexcept -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    static constexpr uint16_t TPID_8021Q = 0x8100;
    static constexpr size_t TAGGED_HEADER_SIZE = ETHERNET_HEADER_SIZE + 4;

    std::array<uint8_t, MAX_ETHERNET_FRAME_SIZE_VLAN> buffer{};
    std::span<uint8_t> const buf_span{buffer};

    Eui48 const& dest = (dest_mac != nullptr) ? *dest_mac : default_dest_mac_;
    span_copy(buf_span.subspan(0, 6), dest.value);
    span_copy(buf_span.subspan(6, 6), my_mac_.value);

    uint16_t const tci = static_cast<uint16_t>((static_cast<uint16_t>(pcp & 0x07) << 13) | (vlan_id & 0x0FFF));
    buffer[12] = static_cast<uint8_t>(TPID_8021Q >> 8);
    buffer[13] = static_cast<uint8_t>(TPID_8021Q & 0xFF);
    buffer[14] = static_cast<uint8_t>(tci >> 8);
    buffer[15] = static_cast<uint8_t>(tci & 0xFF);
    buffer[16] = static_cast<uint8_t>(ethertype_ >> 8);
    buffer[17] = static_cast<uint8_t>(ethertype_ & 0xFF);

    size_t const payload_len = std::min(payload.size(), MAX_ETHERNET_FRAME_SIZE_VLAN - TAGGED_HEADER_SIZE);
    span_copy(buf_span.subspan(TAGGED_HEADER_SIZE, payload_len), payload.subspan(0, payload_len));

    ssize_t sent_len = 0;
    do {
        sent_len = ::write(fd_, buffer.data(), payload_len + TAGGED_HEADER_SIZE);
    } while (sent_len < 0 && errno == EINTR);

    if (sent_len < 0) {
        if (would_block()) {
            return failure(NetError::would_block);
        }
        return failure(NetError::send_failed);
    }

    // Egress tap: hand the exact on-wire frame (full L2, VLAN tag included) to an
    // observer. The only way to see a PACKET_QDISC_BYPASS stream's own egress.
    if (tx_tap_) {
        tx_tap_(std::span<uint8_t const>{buffer.data(), payload_len + TAGGED_HEADER_SIZE});
    }

    return success(static_cast<ssize_t>(sent_len - static_cast<ssize_t>(TAGGED_HEADER_SIZE)));
}

[[nodiscard]] auto RawnetContext::recv(Eui48* src_mac, Eui48* dest_mac, std::span<uint8_t> payload_buf) noexcept
    -> StatusValue<ssize_t>
{
    if (fd_ < 0) {
        return failure(NetError::not_connected);
    }

    for (;;) {
        // Check if we have buffered data from a previous read
        while (bpf_read_offset_ < bpf_read_length_) {
            // Verify the BPF header itself fits in the remaining buffer before
            // reinterpret_casting and dereferencing it.
            if (bpf_read_length_ - bpf_read_offset_ < sizeof(struct bpf_hdr)) {
                break;
            }
            // Parse BPF header
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — macOS BPF packet walker
            auto* bh = reinterpret_cast<struct bpf_hdr*>(bpf_read_buffer_.data() + bpf_read_offset_);

            // Verify the header-declared frame fits in the remaining buffer.
            size_t const total = static_cast<size_t>(bh->bh_hdrlen) + static_cast<size_t>(bh->bh_caplen);
            if (total > bpf_read_length_ - bpf_read_offset_) {
                break;
            }

            uint8_t const* frame = bpf_read_buffer_.data() + bpf_read_offset_ + bh->bh_hdrlen;
            uint32_t const caplen = bh->bh_caplen;

            // Advance to next packet (BPF_WORDALIGN). Guard against the
            // corrupt-header zero-advance case to avoid an infinite loop.
            size_t const advance = BPF_WORDALIGN(total);
            if (advance == 0) {
                break;
            }
            bpf_read_offset_ += advance;

            // Check minimum size
            if (caplen < ETHERNET_HEADER_SIZE) {
                continue;
            }

            // Extract MACs
            std::span<uint8_t const> const frame_span{frame, caplen};
            if (dest_mac != nullptr) {
                span_copy(dest_mac->value, frame_span.subspan(0, 6));
            }
            if (src_mac != nullptr) {
                span_copy(src_mac->value, frame_span.subspan(6, 6));
            }

            // Copy payload
            size_t payload_len = caplen - ETHERNET_HEADER_SIZE;
            if (payload_len > payload_buf.size()) {
                payload_len = payload_buf.size();
            }
            span_copy(payload_buf.subspan(0, payload_len), frame_span.subspan(ETHERNET_HEADER_SIZE, payload_len));

            return success(static_cast<ssize_t>(payload_len));
        }

        // Need to read more from BPF
        ssize_t n = 0;
        do {
            n = ::read(fd_, bpf_read_buffer_.data(), bpf_read_buffer_.size());
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            if (would_block()) {
                return failure(NetError::would_block);
            }
            return failure(NetError::receive_failed);
        }

        if (n == 0) {
            return failure(NetError::would_block);
        }

        bpf_read_offset_ = 0;
        bpf_read_length_ = static_cast<size_t>(n);
    }
}

[[nodiscard]] auto RawnetContext::join_multicast(Eui48 const& /*multicast_mac*/) const noexcept -> Status
{
    // On macOS, BPF in promiscuous mode or with appropriate filter sees multicast
    // No explicit join needed for receive; the filter handles ethertype matching
    // For proper multicast, we'd need to use SIOCADDMULTI on the interface
    return success();
}

[[nodiscard]] auto RawnetContext::leave_multicast(Eui48 const& /*multicast_mac*/) const noexcept -> Status
{
    // Symmetric to the macOS join_multicast no-op: nothing was added, so there is
    // nothing to drop (BPF receive does not use explicit multicast membership).
    return success();
}

#endif  // __APPLE__

auto RawnetContext::set_priority(int const priority) noexcept -> Status
{
    if (fd_ < 0) {
        return failure(std::make_error_code(std::errc::bad_file_descriptor));
    }
#if defined(__linux__)
    if (::setsockopt(fd_, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0) {
        return failure(std::error_code{errno, std::system_category()});
    }
#else
    (void)priority;  // no per-socket TX queue steering on BPF
#endif
    return success();
}

}  // namespace statusbar::net
