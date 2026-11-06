// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_linux_mmap.hpp"

#include "statusbar/net/net_posix_util.hpp"
#include "statusbar/net/net_socket.hpp"

namespace statusbar::net {

auto MmapErrorCategory::message(int ev) const -> std::string
{
    switch (static_cast<MmapError>(ev)) {
        case MmapError::socket_creation_failed:
            return "Socket creation failed";
        case MmapError::interface_not_found:
            return "Network interface not found";
        case MmapError::bind_failed:
            return "Bind failed";
        case MmapError::set_nonblocking_failed:
            return "Failed to set non-blocking mode";
        case MmapError::set_priority_failed:
            return "Failed to set socket priority";
        case MmapError::get_hwaddr_failed:
            return "Failed to get hardware address";
        case MmapError::set_packet_version_failed:
            return "Failed to set TPACKET version";
        case MmapError::join_multicast_failed:
            return "Failed to join multicast group";
        case MmapError::allocate_ring_failed:
            return "Failed to allocate ring buffer";
        case MmapError::mmap_failed:
            return "Memory mapping failed";
        case MmapError::not_open:
            return "Context not open";
        case MmapError::tx_ring_full:
            return "TX ring buffer full";
        case MmapError::rx_ring_empty:
            return "RX ring buffer empty";
        case MmapError::invalid_index:
            return "Invalid slot index";
        case MmapError::not_supported_on_platform:
            return "PACKET_MMAP not supported on this platform";
        case MmapError::frame_too_long:
            return "Frame longer than the interface takes";
        default:
            return "Unknown MMAP error";
    }
}

auto mmap_error_category() noexcept -> std::error_category const&
{
    static MmapErrorCategory const instance;
    return instance;
}

auto make_error_code(MmapError e) noexcept -> std::error_code
{
    return {static_cast<int>(e), mmap_error_category()};
}

}  // namespace statusbar::net

#if defined(__linux__)

#    include <atomic>

namespace statusbar::net {

namespace {

// tp_status is one side of a handshake over memory shared with the kernel.
// The kernel fills a slot, then publishes the status behind a write barrier,
// and reads the status we publish before it touches the slot again. Our side
// of the handshake has to carry the same ordering: a plain load may be
// reordered after the reads of the frame it guards, and a plain store before
// the writes it is meant to publish - the compiler does both, and arm64
// reorders stores as well. Acquire on the way in, release on the way out.

[[nodiscard]] auto load_status(tpacket2_hdr* hdr) noexcept -> uint32_t
{
    return std::atomic_ref<__u32>{hdr->tp_status}.load(std::memory_order_acquire);
}

void store_status(tpacket2_hdr* hdr, uint32_t const status) noexcept
{
    std::atomic_ref<__u32>{hdr->tp_status}.store(status, std::memory_order_release);
}

}  // namespace

void MmapContext::swap(MmapContext& other) noexcept
{
    std::swap(fd_, other.fd_);
    std::swap(hardware_address_, other.hardware_address_);
    std::swap(if_index_, other.if_index_);
    std::swap(ethertype_, other.ethertype_);
    std::swap(ring_memory_, other.ring_memory_);
    std::swap(ring_memory_size_, other.ring_memory_size_);
    std::swap(tx_ring_, other.tx_ring_);
    std::swap(tx_req_, other.tx_req_);
    std::swap(tx_index_, other.tx_index_);
    std::swap(tx_slot_in_use_, other.tx_slot_in_use_);
    std::swap(max_tx_frame_length_, other.max_tx_frame_length_);
    std::swap(rx_ring_, other.rx_ring_);
    std::swap(rx_req_, other.rx_req_);
    std::swap(rx_index_, other.rx_index_);
}

auto MmapContext::open(MmapConfig const& config) -> Status
{  // NOLINT(statusbar-block-statements): one socket opened and set up option by option, in order
    // Close any existing context
    close();

    ethertype_ = config.ethertype;

    // Create AF_PACKET socket with SOCK_RAW
    fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(config.ethertype != 0 ? config.ethertype : ETH_P_ALL));
    if (fd_ < 0) {
        return failure(MmapError::socket_creation_failed);
    }

    // Get interface index
    struct ifreq ifr{};
    auto const name_len = config.interface_name.size() < IFNAMSIZ ? config.interface_name.size() : IFNAMSIZ - 1;
    span_copy(ifname_bytes(ifr).first(name_len), make_const_span(config.interface_name).first(name_len));
    ifr.ifr_name[name_len] = '\0';

    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        close();
        return failure(MmapError::interface_not_found);
    }
    if_index_ = static_cast<unsigned int>(ifr.ifr_ifindex);

    // Get hardware address
    if (::ioctl(fd_, SIOCGIFHWADDR, &ifr) < 0) {
        close();
        return failure(MmapError::get_hwaddr_failed);
    }
    span_copy(hardware_address_.value, hwaddr_bytes(ifr));

    // The MTU bounds what tx_commit() takes (see mmap_max_tx_frame_length).
    // A device that will not say keeps the slot's own limit.
    max_tx_frame_length_ =
        ::ioctl(fd_, SIOCGIFMTU, &ifr) == 0 ? mmap_max_tx_frame_length(static_cast<size_t>(ifr.ifr_mtu)) : MMAP_MAX_FRAME_LENGTH;

    // Set non-blocking mode
    int const flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        close();
        return failure(MmapError::set_nonblocking_failed);
    }

    // Set socket priority if requested
    if (config.priority > 0) {
        if (auto const set = set_priority(fd_, static_cast<int>(config.priority)); !set) {
            close();
            return failure(MmapError::set_priority_failed);
        }
    }

    // Set TPACKET_V2
    int version = TPACKET_V2;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        close();
        return failure(MmapError::set_packet_version_failed);
    }

    // Bypass qdisc for lower TX latency (packets go directly to driver)
    int const bypass = 1;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_QDISC_BYPASS, &bypass, sizeof(bypass)) < 0) {
        // Non-fatal: older kernels may not support this option
    }

    // Calculate ring buffer parameters using runtime page size
    size_t const block_size = get_mmap_block_size();
    size_t const frames_per_block = get_frames_per_block();
    size_t const rx_blocks = (config.rx_queue_size + frames_per_block - 1) / frames_per_block;
    size_t const tx_blocks = (config.tx_queue_size + frames_per_block - 1) / frames_per_block;

    // Setup RX ring
    rx_req_.tp_block_size = static_cast<unsigned int>(block_size);
    rx_req_.tp_block_nr = static_cast<unsigned int>(rx_blocks);
    rx_req_.tp_frame_size = MMAP_FRAME_SIZE;
    rx_req_.tp_frame_nr = static_cast<unsigned int>(rx_blocks * frames_per_block);

    if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &rx_req_, sizeof(rx_req_)) < 0) {
        close();
        return failure(MmapError::allocate_ring_failed);
    }

    // Setup TX ring
    tx_req_.tp_block_size = static_cast<unsigned int>(block_size);
    tx_req_.tp_block_nr = static_cast<unsigned int>(tx_blocks);
    tx_req_.tp_frame_size = MMAP_FRAME_SIZE;
    tx_req_.tp_frame_nr = static_cast<unsigned int>(tx_blocks * frames_per_block);

    if (::setsockopt(fd_, SOL_PACKET, PACKET_TX_RING, &tx_req_, sizeof(tx_req_)) < 0) {
        close();
        return failure(MmapError::allocate_ring_failed);
    }

    // Memory map both rings
    ring_memory_size_ = (rx_req_.tp_block_size * rx_req_.tp_block_nr) + (tx_req_.tp_block_size * tx_req_.tp_block_nr);
    ring_memory_ = ::mmap(nullptr, ring_memory_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (ring_memory_ == MAP_FAILED) {
        ring_memory_ = nullptr;
        close();
        return failure(MmapError::mmap_failed);
    }

    // Prevent copy-on-write issues on fork
    (void)::madvise(ring_memory_, ring_memory_size_, MADV_DONTFORK);

    // Hint to kernel to prefault pages
    (void)::madvise(ring_memory_, ring_memory_size_, MADV_WILLNEED);

    // Prefault all ring buffer pages by touching each page
    // This ensures pages are resident before realtime operation begins
    {
        uint8_t volatile* p = static_cast<uint8_t volatile*>(ring_memory_);
        for (size_t i = 0; i < ring_memory_size_; i += 4096) {
            (void)p[i];  // Read to fault in page
        }
    }

    // Set ring pointers (RX ring is first, TX ring follows)
    rx_ring_ = ring_memory_;
    tx_ring_ = static_cast<uint8_t*>(ring_memory_) + (static_cast<size_t>(rx_req_.tp_block_size) * rx_req_.tp_block_nr);

    // Bind to the interface
    struct sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(config.ethertype != 0 ? config.ethertype : ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(if_index_);

    if (::bind(fd_, sockaddr_cast(addr), sizeof(addr)) < 0) {
        close();
        return failure(MmapError::bind_failed);
    }

    return success();
}

auto MmapContext::close() noexcept -> void
{
    if (ring_memory_ != nullptr) {
        ::munmap(ring_memory_, ring_memory_size_);
        ring_memory_ = nullptr;
        ring_memory_size_ = 0;
        rx_ring_ = nullptr;
        tx_ring_ = nullptr;
    }

    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }

    hardware_address_ = {};
    if_index_ = 0;
    ethertype_ = 0;
    tx_req_ = {};
    rx_req_ = {};
    tx_index_ = 0;
    rx_index_ = 0;
    tx_slot_in_use_ = UINT64_MAX;
    max_tx_frame_length_ = MMAP_MAX_FRAME_LENGTH;
}

auto MmapContext::tx_start(int64_t launch_time_ns) -> StatusValue<EthernetTxSlot>
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    // Get header at current TX index
    auto* hdr = tx_header_at(tx_index_);

    // Check if slot is available (TP_STATUS_AVAILABLE == 0 for TX ring). The
    // acquire keeps our writes into the slot after the kernel's reads of it.
    if (load_status(hdr) != TP_STATUS_AVAILABLE) {
        return failure(MmapError::tx_ring_full);
    }

    // Store index for commit/cancel
    size_t const slot_index = tx_index_;
    tx_slot_in_use_ = static_cast<uint64_t>(slot_index);

    // Advance TX index (wrap around)
    tx_index_ = (tx_index_ + 1) % tx_req_.tp_frame_nr;

    // Set launch time if specified
    if (launch_time_ns > 0) {
        hdr->tp_sec = static_cast<uint32_t>(launch_time_ns / 1'000'000'000);
        hdr->tp_nsec = static_cast<uint32_t>(launch_time_ns % 1'000'000'000);
    } else {
        hdr->tp_sec = 0;
        hdr->tp_nsec = 0;
    }

    // Return slot with buffer pointing to payload area
    return success(EthernetTxSlot{
        .handle = static_cast<uint64_t>(slot_index),
        .buffer = std::span<uint8_t>(tx_payload(hdr), max_tx_frame_length_),
    });
}

auto MmapContext::tx_commit(uint64_t handle, size_t frame_length) -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    auto const index = static_cast<size_t>(handle);

    if (index >= tx_req_.tp_frame_nr) {
        return failure(MmapError::invalid_index);
    }

    if (frame_length > max_tx_frame_length_) {
        // Refused here rather than by the kernel, which would wedge the ring
        // (see mmap_max_tx_frame_length). The slot goes back the way
        // tx_cancel() gives one back: no hole, nothing after it held up.
        (void)tx_cancel(handle);
        return failure(MmapError::frame_too_long);
    }

    auto* hdr = tx_header_at(index);

    // Enforce minimum frame size
    size_t const actual_length = (frame_length < MMAP_MIN_FRAME_LENGTH) ? MMAP_MIN_FRAME_LENGTH : frame_length;

    // Set frame length
    hdr->tp_len = static_cast<unsigned int>(actual_length);
    hdr->tp_snaplen = static_cast<unsigned int>(actual_length);

    // Mark for transmission - kernel will pick this up. The release publishes
    // the frame and the lengths above before the status that says to send.
    store_status(hdr, TP_STATUS_SEND_REQUEST);

    tx_slot_in_use_ = UINT64_MAX;

    return success();
}

auto MmapContext::tx_cancel(uint64_t handle) -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    auto const index = static_cast<size_t>(handle);

    // Only the slot tx_start() handed out last can be given back: any other
    // index is a frame already committed, or no slot of the caller's at all.
    if (index >= tx_req_.tp_frame_nr || handle != tx_slot_in_use_) {
        return failure(MmapError::invalid_index);
    }

    auto* hdr = tx_header_at(index);

    // Return slot to available state, and make it the next one handed out.
    // The kernel sends the ring in order and stops at the first slot that is
    // not a send request, so a slot left available behind the index is a
    // hole: every frame committed after it waits until the index has gone
    // round the whole ring and filled it.
    store_status(hdr, TP_STATUS_AVAILABLE);
    tx_index_ = index;
    tx_slot_in_use_ = UINT64_MAX;

    return success();
}

auto MmapContext::tx_flush() -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    // sendto with interface address kicks the kernel to transmit pending frames
    struct sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ethertype_ != 0 ? ethertype_ : ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(if_index_);
    addr.sll_halen = ETH_ALEN;

    if (::sendto(fd_, nullptr, 0, 0, sockaddr_cast(addr), sizeof(addr)) < 0) {
        // EAGAIN/EWOULDBLOCK is OK (means nothing to send)
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return failure(std::error_code(errno, std::system_category()));
        }
    }

    return success();
}

auto MmapContext::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    return rx_start(rx_clock_now());
}

auto MmapContext::rx_start(RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    auto* hdr = rx_header_at(rx_index_);

    // Check if frame is available from kernel. The acquire keeps the reads of
    // the header fields and the frame after the status that says they are
    // there.
    if ((load_status(hdr) & TP_STATUS_USER) == 0) {
        // No frame ready
        return success(std::optional<EthernetRxSlot>{});
    }

    // The slot is stamped @p now, the RX clock. The kernel's own stamp in
    // tp_sec/tp_nsec is CLOCK_REALTIME, which is not the clock a stamp is
    // compared on (RxClock, MONOTONIC_RAW), and moving it onto that clock
    // would take a REALTIME read on this path. So it is not handed on.

    // tp_snaplen is what the kernel copied into the slot; tp_len is the
    // frame's length on the wire, which is longer when the frame did not fit
    // and the kernel truncated it. A span of tp_len would run off the end of
    // the slot into the next one, or past the mapping on the last.
    return success(std::optional<EthernetRxSlot>{EthernetRxSlot{
        .handle = static_cast<uint64_t>(rx_index_),
        .buffer = std::span<uint8_t const>(rx_payload(hdr), hdr->tp_snaplen),
        .timestamp_ns = rx_timestamp_ns(now),
    }});
}

auto MmapContext::rx_release(uint64_t handle) -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    auto const index = static_cast<size_t>(handle);

    if (index >= rx_req_.tp_frame_nr) {
        return failure(MmapError::invalid_index);
    }

    auto* hdr = rx_header_at(index);

    // Return slot to kernel. The release keeps the caller's reads of the
    // frame before the status that lets the kernel refill the slot.
    store_status(hdr, TP_STATUS_KERNEL);

    // Advance RX index (wrap around)
    rx_index_ = (rx_index_ + 1) % rx_req_.tp_frame_nr;

    return success();
}

auto MmapContext::join_multicast(ieee::Eui48 const& addr) -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    struct packet_mreq mreq{};
    mreq.mr_ifindex = static_cast<int>(if_index_);
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    span_copy(std::span{mreq.mr_address}.first(6), make_const_span(addr.value));

    if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return failure(MmapError::join_multicast_failed);
    }

    return success();
}

auto MmapContext::leave_multicast(ieee::Eui48 const& addr) -> Status
{
    if (!valid()) {
        return failure(MmapError::not_open);
    }

    struct packet_mreq mreq{};
    mreq.mr_ifindex = static_cast<int>(if_index_);
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    span_copy(std::span{mreq.mr_address}.first(6), make_const_span(addr.value));

    if (::setsockopt(fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return failure(MmapError::join_multicast_failed);
    }

    return success();
}

}  // namespace statusbar::net

#endif  // __linux__
