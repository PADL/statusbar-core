// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_linux_xdp.hpp"

#include "statusbar/net/net_posix_util.hpp"

#if defined(__linux__) && defined(HAVE_XDP)
#    include <linux/magic.h>
#    include <sys/stat.h>
#    include <sys/vfs.h>
#endif

#include <utility>

namespace statusbar::net {

auto XdpErrorCategory::message(int ev) const -> std::string
{
    switch (static_cast<XdpError>(ev)) {
        case XdpError::socket_creation_failed:
            return "Socket creation failed";
        case XdpError::interface_not_found:
            return "Network interface not found";
        case XdpError::get_hwaddr_failed:
            return "Failed to get hardware address";
        case XdpError::umem_creation_failed:
            return "UMEM creation failed";
        case XdpError::xsk_creation_failed:
            return "XSK socket creation failed";
        case XdpError::bpf_load_failed:
            return "BPF program load failed";
        case XdpError::bpf_attach_failed:
            return "BPF program attach failed";
        case XdpError::bpf_map_update_failed:
            return "BPF map update failed";
        case XdpError::tap_creation_failed:
            return "TAP device creation failed";
        case XdpError::tap_configure_failed:
            return "TAP device configuration failed";
        case XdpError::not_open:
            return "Context not open";
        case XdpError::tx_ring_full:
            return "TX ring buffer full";
        case XdpError::rx_ring_empty:
            return "RX ring buffer empty";
        case XdpError::fill_ring_full:
            return "Fill ring full";
        case XdpError::free_list_empty:
            return "UMEM free list empty";
        case XdpError::invalid_addr:
            return "Invalid UMEM frame address";
        case XdpError::frame_too_large:
            return "Frame exceeds maximum size";
        case XdpError::tx_flush_failed:
            return "TX flush sendto failed";
        case XdpError::join_multicast_failed:
            return "Failed to join multicast group";
        case XdpError::not_supported_on_platform:
            return "AF_XDP not supported on this platform";
        case XdpError::invalid_bpf_program:
            return "Embedded BPF program is empty or invalid";
        case XdpError::too_many_filter_rules:
            return "Filter rule count exceeds TCAM_MAX_RULES";
        case XdpError::zero_copy_needs_native_attach:
            return "Zero-copy bind cannot be combined with generic XDP attach";
        case XdpError::zero_copy_unavailable:
            return "Driver does not support zero-copy AF_XDP on this queue";
        case XdpError::bpffs_not_mounted:
            return "No bpf filesystem mounted at /sys/fs/bpf, so nothing can be pinned";
        case XdpError::invalid_pin_path:
            return "Pin path is not under /sys/fs/bpf";
        case XdpError::pin_failed:
            return "Pinning the XDP program or one of its maps failed";
        default:
            return "Unknown XDP error";
    }
}

// ──────────────────────────────────────────────
// XdpProgram
// ──────────────────────────────────────────────

auto XdpProgram::pin_path_for(std::string_view const interface_name) -> std::string
{
    // An empty result means "do not pin", so a name that could not be an
    // interface - or that could escape the pin directory - lands on the safe
    // answer rather than on a path we would then create and unlink in.
    if (!detail::valid_interface_name(interface_name)) {
        return {};
    }
    std::string path{BPFFS_ROOT};
    path += '/';
    path += PIN_NAMESPACE;
    path += '/';
    path += interface_name;
    return path;
}

auto XdpProgram::pin_entry(std::string_view const pin_path, std::string_view const entry) -> std::string
{
    if (pin_path.empty() || entry.empty()) {
        return {};
    }
    std::string path{pin_path};
    if (!path.ends_with('/')) {
        path += '/';
    }
    path += entry;
    return path;
}

auto XdpProgram::pinnable([[maybe_unused]] std::string_view const pin_path) -> Status
{
    // The shape first, which is pure: a pin has to live inside the bpf
    // filesystem and name something below its root.
    if (!pin_path.starts_with(BPFFS_ROOT) || pin_path.size() <= BPFFS_ROOT.size() || pin_path[BPFFS_ROOT.size()] != '/') {
        return failure(XdpError::invalid_pin_path);
    }
#if defined(__linux__) && defined(HAVE_XDP)
    std::string const root{BPFFS_ROOT};
    struct statfs fs{};
    if (::statfs(root.c_str(), &fs) != 0) {
        return failure(XdpError::bpffs_not_mounted);
    }
    // An ordinary directory at /sys/fs/bpf is the shape of a host where the
    // mount is simply missing, and it is told apart from a bad path because
    // the two want different fixes.
    if (static_cast<unsigned long>(fs.f_type) != static_cast<unsigned long>(BPF_FS_MAGIC)) {
        return failure(XdpError::bpffs_not_mounted);
    }
    return success();
#else
    return failure(XdpError::not_supported_on_platform);
#endif
}

auto XdpProgram::query([[maybe_unused]] unsigned int const if_index) -> StatusValue<std::optional<XdpAttachedProgram>>
{
#if defined(__linux__) && defined(HAVE_XDP)
    struct bpf_xdp_query_opts opts{};
    opts.sz = sizeof(opts);
    if (int const ret = bpf_xdp_query(static_cast<int>(if_index), 0, &opts); ret != 0) {
        return failure(std::error_code{-ret, std::generic_category()});
    }
    if (opts.attach_mode == XDP_ATTACHED_NONE) {
        return std::optional<XdpAttachedProgram>{};
    }
    // XDP_ATTACHED_MULTI leaves prog_id zero: programs are attached in more
    // than one mode and the kernel will not pick one for us. Reported as it
    // stands, with the zero id, which is what stops adopt() from matching.
    return std::optional<XdpAttachedProgram>{XdpAttachedProgram{
        .program_id = opts.prog_id,
        .mode = opts.attach_mode == XDP_ATTACHED_SKB ? XdpAttachMode::generic : XdpAttachMode::native,
    }};
#else
    return failure(XdpError::not_supported_on_platform);
#endif
}

auto XdpProgram::detach([[maybe_unused]] unsigned int const if_index, [[maybe_unused]] std::string_view const pin_path) -> Status
{
#if defined(__linux__) && defined(HAVE_XDP)
    // This call unlinks files and removes a directory, so the path has to be
    // one a pin could be at before any of that happens. Without the check a
    // caller that built a path by hand could have us deleting somewhere else
    // entirely. An empty path asks for no unlinking at all and is fine.
    if (!pin_path.empty()) {
        if (auto status = pinnable(pin_path); !status) {
            return status;
        }
    }

    Status result = success();
    auto const keep_first_error = [&result](Status status) noexcept {
        if (!status && result) {
            result = status;
        }
    };

    // The pins first: they are what an outside tool sees, and removing them
    // while the program is still attached is the harmless order of the two.
    for (auto const entry : {PIN_PROG, PIN_RULES_MAP, PIN_XSK_MAP, PIN_DEVMAP}) {
        auto const path = pin_entry(pin_path, entry);
        if (path.empty()) {
            continue;
        }
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            keep_first_error(failure(std::error_code{errno, std::generic_category()}));
        }
    }
    if (!pin_path.empty()) {
        // Best effort. A directory someone else put something in is theirs to
        // clean up, and leaving it is not a failure of this call.
        (void)::rmdir(std::string{pin_path}.c_str());
    }

    // Then the attachment, in the mode it is actually in: flags of 0 mean
    // "native" to the kernel on any driver with ndo_bpf, so a generic attach
    // would survive a detach that did not say so.
    struct bpf_xdp_query_opts opts{};
    opts.sz = sizeof(opts);
    if (int const ret = bpf_xdp_query(static_cast<int>(if_index), 0, &opts); ret != 0) {
        keep_first_error(failure(std::error_code{-ret, std::generic_category()}));
        return result;
    }
    for (auto const& [id, mode] :
         {std::pair{opts.drv_prog_id, XdpAttachMode::native}, std::pair{opts.skb_prog_id, XdpAttachMode::generic}}) {
        if (id == 0) {
            continue;
        }
        if (int const ret = bpf_xdp_detach(static_cast<int>(if_index), detail::BpfAttachment::attach_flags(mode), nullptr);
            ret != 0) {
            keep_first_error(failure(std::error_code{-ret, std::generic_category()}));
        }
    }
    return result;
#else
    return failure(XdpError::not_supported_on_platform);
#endif
}

#if defined(__linux__) && defined(HAVE_XDP)

auto detail::UmemRegion::allocate(
    size_t frame_count, size_t frame_size, size_t headroom, size_t fill_ring_size, size_t comp_ring_size, RingSet& rings)
    -> StatusValue<struct xsk_umem*>
{
    close();

    frame_size_ = frame_size;
    headroom_ = headroom;

    size_t const total_size = frame_count * frame_size;
    area_ = static_cast<uint8_t*>(
        ::mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0));
    if (area_ == MAP_FAILED) {
        area_ = nullptr;
        frame_size_ = 0;
        headroom_ = 0;
        return failure(XdpError::umem_creation_failed);
    }
    area_size_ = total_size;

    (void)::madvise(area_, total_size, MADV_DONTFORK);
    {
        size_t const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
        uint8_t volatile* p = area_;
        for (size_t i = 0; i < total_size; i += page_size) {
            (void)p[i];
        }
    }

    struct xsk_umem_config umem_cfg{};
    umem_cfg.fill_size = static_cast<__u32>(fill_ring_size);
    umem_cfg.comp_size = static_cast<__u32>(comp_ring_size);
    umem_cfg.frame_size = static_cast<__u32>(frame_size);
    umem_cfg.frame_headroom = static_cast<__u32>(headroom);
    umem_cfg.flags = 0;

    int const ret = xsk_umem__create(&umem_, area_, total_size, &rings.fill, &rings.comp, &umem_cfg);
    if (ret != 0) {
        close();
        return failure(XdpError::umem_creation_failed);
    }

    free_list_ = UmemFreeList(frame_count, frame_size);

    return umem_;
}

void detail::UmemRegion::close() noexcept
{
    if (umem_ != nullptr) {
        (void)xsk_umem__delete(umem_);
        umem_ = nullptr;
    }
    if (area_ != nullptr) {
        ::munmap(area_, area_size_);
        area_ = nullptr;
        area_size_ = 0;
    }
    frame_size_ = 0;
    headroom_ = 0;
    free_list_ = {};
}

namespace {

/// The kernel's id for whatever the descriptor refers to, 0 if it will not
/// say. Used to tell "the program we pinned" from "a program".
/// @param prog_fd A BPF program descriptor
[[nodiscard]] auto program_info_id(int const prog_fd) noexcept -> uint32_t
{
    struct bpf_prog_info info{};
    uint32_t length = sizeof(info);
    if (bpf_prog_get_info_by_fd(prog_fd, &info, &length) != 0) {
        return 0;
    }
    return info.id;
}

/// Whether a map is the shape the BPF program declares, which is how an
/// adopted map is told from one that merely has the right name. Adopting a
/// foreign map means writing rules into someone else's memory, so every
/// dimension the kernel will report is checked.
/// @param map_fd The map to inspect
/// @param type The expected BPF map type
/// @param key_size Expected key size in bytes
/// @param value_size Expected value size in bytes
/// @param max_entries Expected capacity
[[nodiscard]] auto map_matches(
    int const map_fd,
    enum bpf_map_type const type,
    uint32_t const key_size,
    uint32_t const value_size,
    uint32_t const max_entries) noexcept -> bool
{
    struct bpf_map_info info{};
    uint32_t length = sizeof(info);
    if (bpf_map_get_info_by_fd(map_fd, &info, &length) != 0) {
        return false;
    }
    return info.type == static_cast<uint32_t>(type) && info.key_size == key_size && info.value_size == value_size &&
        info.max_entries == max_entries;
}

/// A descriptor that closes itself, for the handles bpf_obj_get() returns
/// while the adoption checks decide whether to keep them.
class OwnedFd
{
  public:
    OwnedFd() = default;

    /// @param fd A descriptor to take ownership of, or a negative value
    explicit OwnedFd(int const fd) noexcept
        : fd_{fd}
    {}

    ~OwnedFd() noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    OwnedFd(OwnedFd&& other) noexcept
        : fd_{other.fd_}
    {
        other.fd_ = -1;
    }

    auto operator=(OwnedFd&&) -> OwnedFd& = delete;
    OwnedFd(OwnedFd const&) = delete;
    auto operator=(OwnedFd const&) -> OwnedFd& = delete;

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }
    [[nodiscard]] auto valid() const noexcept -> bool { return fd_ >= 0; }

    /// Hand the descriptor to a longer-lived owner.
    [[nodiscard]] auto release() noexcept -> int
    {
        int const fd = fd_;
        fd_ = -1;
        return fd;
    }

  private:
    int fd_{-1};
};

/// Create the pin directory, and every directory between it and the bpffs
/// mount. XdpProgram::pinnable() has already settled that the path is one a
/// pin can live at, so what is left here is permissions and ENOSPC.
/// @param pin_path The pin directory, which must be under BPFFS_ROOT
[[nodiscard]] auto prepare_pin_dir(std::string_view const pin_path) -> Status
{
    // Re-asked rather than assumed: this function creates directories, and it
    // must not be possible to reach it with a path open() did not vet.
    if (auto status = XdpProgram::pinnable(pin_path); !status) {
        return status;
    }
    std::string const root{XdpProgram::BPFFS_ROOT};

    // Each component below the mount, so BPFFS_ROOT/statusbar/<interface>
    // comes into being in one call rather than needing the caller to have
    // made the namespace directory first.
    constexpr mode_t PinDirMode = 0700;
    for (size_t slash = pin_path.find('/', root.size() + 1); slash != std::string_view::npos;
         slash = pin_path.find('/', slash + 1)) {
        std::string const parent{pin_path.substr(0, slash)};
        if (::mkdir(parent.c_str(), PinDirMode) != 0 && errno != EEXIST) {
            return failure(std::error_code{errno, std::generic_category()});
        }
    }
    std::string const leaf{pin_path};
    if (::mkdir(leaf.c_str(), PinDirMode) != 0 && errno != EEXIST) {
        return failure(std::error_code{errno, std::generic_category()});
    }
    return success();
}

}  // namespace

auto detail::BpfState::load(std::span<CompiledRule<32> const> rules, XdpAction default_action) -> Status
{
    close();
    default_action_ = default_action;

    if (xdp_filter_bpf_o_len == 0) {
        return failure(XdpError::invalid_bpf_program);
    }

    BpfObject obj;
    if (auto status = obj.open_and_load(xdp_filter_bpf_o, xdp_filter_bpf_o_len); !status) {
        return status;
    }

    struct bpf_map* rules_map = bpf_object__find_map_by_name(obj.get(), "rules_map");
    struct bpf_map* xsk_map = bpf_object__find_map_by_name(obj.get(), "xsk_map");
    struct bpf_map* devmap = bpf_object__find_map_by_name(obj.get(), "devmap");

    auto are_xdp_maps_valid = [](bpf_map* rm, bpf_map* xsk, bpf_map* dev) -> bool {
        return rm != nullptr && xsk != nullptr && dev != nullptr;
    };
    if (!are_xdp_maps_valid(rules_map, xsk_map, devmap)) {
        return failure(XdpError::bpf_load_failed);
    }

    rules_map_fd_ = bpf_map__fd(rules_map);
    xsk_map_fd_ = bpf_map__fd(xsk_map);
    devmap_fd_ = bpf_map__fd(devmap);

    // The loaded BPF object starts with all rule slots zero-initialized
    // (array map default), so any pre-existing stale entries from the
    // previous loader run are already cleared. install_tcam_rules() fills
    // slots 0..rules.size()-1 and re-zeroes the tail to keep that
    // guarantee on subsequent set_rules() calls.
    if (auto status = install_tcam_rules(rules); !status) {
        return status;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj.get(), "xdp_filter_prog");
    if (prog == nullptr) {
        return failure(XdpError::bpf_load_failed);
    }
    prog_fd_ = bpf_program__fd(prog);
    program_id_ = program_info_id(prog_fd_);

    obj_ = std::move(obj);
    return success();
}

auto detail::BpfState::adopt(
    std::string_view const pin_path,
    unsigned int const if_index,
    std::span<CompiledRule<32> const> const rules,
    XdpAction const default_action) -> Status
{
    close();

    // Every pinned entry has to be there. A directory with some of them is a
    // half-written or half-removed pin, not something to run on.
    OwnedFd prog{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_PROG).c_str())};
    OwnedFd rules_map{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_RULES_MAP).c_str())};
    OwnedFd xsk_map{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_XSK_MAP).c_str())};
    OwnedFd devmap{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_DEVMAP).c_str())};
    if (!prog.valid() || !rules_map.valid() || !xsk_map.valid() || !devmap.valid()) {
        return failure(XdpError::bpf_load_failed);
    }

    // The maps must have the layout this build's program declares. Without
    // this check an older build's pin - same names, different rule slot size
    // or capacity - would be adopted and then written to, which is the one
    // outcome worth being careful about here.
    constexpr uint32_t KeySize = sizeof(uint32_t);
    constexpr uint32_t FdSize = sizeof(uint32_t);
    if (!map_matches(rules_map.get(), BPF_MAP_TYPE_ARRAY, KeySize, sizeof(struct tcam_rule), TCAM_MAX_RULES)) {
        return failure(XdpError::bpf_load_failed);
    }
    if (!map_matches(xsk_map.get(), BPF_MAP_TYPE_XSKMAP, KeySize, FdSize, TCAM_XSK_MAP_ENTRIES)) {
        return failure(XdpError::bpf_load_failed);
    }
    if (!map_matches(devmap.get(), BPF_MAP_TYPE_DEVMAP, KeySize, FdSize, TCAM_DEVMAP_ENTRIES)) {
        return failure(XdpError::bpf_load_failed);
    }

    // And the pinned program must be the program on the interface. A pin
    // whose program is loaded but not attached is stale - the usual shape of
    // a crash that took the attachment with it - and attaching it again is
    // the fresh path's job, not this one's.
    uint32_t const id = program_info_id(prog.get());
    if (id == 0) {
        return failure(XdpError::bpf_load_failed);
    }
    auto const attached = XdpProgram::query(if_index);
    if (!attached) {
        return failure(attached.error());
    }
    if (!attached->has_value() || (*attached)->program_id != id) {
        return failure(XdpError::bpf_attach_failed);
    }

    prog_fd_ = prog.release();
    rules_map_fd_ = rules_map.release();
    xsk_map_fd_ = xsk_map.release();
    devmap_fd_ = devmap.release();
    owns_fds_ = true;
    program_id_ = id;
    default_action_ = default_action;
    adopted_ = true;

    if (auto status = install_tcam_rules(rules); !status) {
        close();
        return status;
    }
    return success();
}

auto detail::BpfState::pin(std::string_view const pin_path) -> Status
{
    if (auto status = prepare_pin_dir(pin_path); !status) {
        return status;
    }

    struct Entry
    {
        std::string_view name;
        int fd;
    };
    for (auto const& entry : std::array<Entry, 4>{
             Entry{.name = XdpProgram::PIN_PROG, .fd = prog_fd_},
             Entry{.name = XdpProgram::PIN_RULES_MAP, .fd = rules_map_fd_},
             Entry{.name = XdpProgram::PIN_XSK_MAP, .fd = xsk_map_fd_},
             Entry{.name = XdpProgram::PIN_DEVMAP, .fd = devmap_fd_},
         }) {
        if (entry.fd < 0) {
            return failure(XdpError::not_open);
        }
        if (bpf_obj_pin(entry.fd, XdpProgram::pin_entry(pin_path, entry.name).c_str()) != 0) {
            return failure(XdpError::pin_failed);
        }
    }

    // Pinned, so the attachment is now outliving us deliberately: close()
    // must stop taking the program off the interface.
    attachment_.disown();
    return success();
}

namespace {

/// Derive the catch-all rule the BPF program needs when the user wants a
/// non-pass default. The mask is all-zero, so the rule matches every
/// frame, but `min_frame_size` is set to the full TCAM window so the
/// slot also passes the "active rule" gate in the BPF loop.
[[nodiscard]] auto catch_all_rule_for(XdpAction action) -> std::optional<CompiledRule<32>>
{
    CompiledRule<32> rule{};
    rule.min_frame_size = static_cast<std::uint16_t>(TCAM_WINDOW_BYTES);
    rule.priority = 255;  // Ordered last; irrelevant for the BPF engine but documents intent.
    switch (action) {
        case XdpAction::redirect_xsk:
            rule.result_flags = flag::process;
            return rule;
        case XdpAction::redirect_tap:
            rule.result_flags = flag::forward_tap;
            return rule;
        case XdpAction::pass_kernel:
            return std::nullopt;  // Falls through to XDP_PASS naturally.
    }
    return std::nullopt;
}

}  // namespace

auto detail::BpfState::install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status
{
    auto catch_all = catch_all_rule_for(default_action_);
    std::size_t const extra = catch_all.has_value() ? 1U : 0U;
    if (rules.size() + extra > TCAM_MAX_RULES) {
        return failure(XdpError::too_many_filter_rules);
    }

    auto write_slot = [this](std::uint32_t index, CompiledRule<32> const& rule) -> Status {
        if (bpf_map_update_elem(rules_map_fd_, &index, &rule, BPF_ANY) != 0) {
            return failure(XdpError::bpf_map_update_failed);
        }
        return success();
    };

    std::uint32_t slot = 0;
    for (auto const& rule : rules) {
        if (auto s = write_slot(slot, rule); !s) {
            return s;
        }
        ++slot;
    }
    if (catch_all.has_value()) {
        if (auto s = write_slot(slot, *catch_all); !s) {
            return s;
        }
        ++slot;
    }

    CompiledRule<32> const empty{};
    for (std::uint32_t i = slot; i < TCAM_MAX_RULES; ++i) {
        if (auto s = write_slot(i, empty); !s) {
            return s;
        }
    }

    return success();
}

auto XdpContext::open(XdpConfig const& config) -> Status
{
    close();

    // Step 0: Settle the bind/attach policy before touching anything. A
    // zero-copy request with generic attach cannot be honoured, and the
    // caller should hear that as a configuration mistake rather than as a
    // half-built socket.
    auto const plan = detail::attach_plan(config.attach_mode, config.bind_mode);
    if (!plan.has_value()) {
        return failure(XdpError::zero_copy_needs_native_attach);
    }

    // And a pin path that cannot be pinned to is the same kind of mistake:
    // worth one statfs here rather than a surprise after the UMEM has been
    // mapped and the program loaded.
    bool const pinning = !config.pin_path.empty();
    if (pinning) {
        if (auto status = XdpProgram::pinnable(config.pin_path); !status) {
            return status;
        }
    }

    // Step 1: Look up interface index and MAC address
    int sock_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return failure(XdpError::socket_creation_failed);
    }
    auto close_sock = detail::scopeguard([&]() noexcept { ::close(sock_fd); });

    struct ifreq ifr{};
    auto const name_len = config.interface_name.size() < IFNAMSIZ ? config.interface_name.size() : IFNAMSIZ - 1;
    span_copy(ifname_bytes(ifr).first(name_len), make_const_span(config.interface_name).first(name_len));
    ifr.ifr_name[name_len] = '\0';

    if (::ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        return failure(XdpError::interface_not_found);
    }
    interface_.index = static_cast<unsigned int>(ifr.ifr_ifindex);

    if (::ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        close();
        return failure(XdpError::get_hwaddr_failed);
    }
    span_copy(interface_.hardware_address.value, hwaddr_bytes(ifr));

    // Step 1b: Make the pin directory, now the interface is known to exist
    // and before anything has been allocated. What can go wrong here is
    // permissions, and a daemon started without CAP_BPF should hear about it
    // before it maps a UMEM.
    if (pinning) {
        if (auto status = prepare_pin_dir(config.pin_path); !status) {
            close();
            return status;
        }
    }

    // Step 2: Allocate UMEM
    auto umem_result = umem_.allocate(
        config.umem_frame_count,
        config.umem_frame_size,
        config.umem_headroom,
        config.fill_ring_size,
        config.completion_ring_size,
        rings_);
    if (!umem_result) {
        close();
        return failure(umem_result.error());
    }

    // Step 3: The program. With a pin path it may already be on the
    // interface from a previous run, in which case adopting it is the point
    // of the whole exercise: no detach, no re-attach, no gap.
    if (pinning && config.adopt) {
        // Best effort by design. A pin that is stale, foreign or from an
        // older build is not an error - it only means there is nothing here
        // to adopt, and the fresh path below takes over.
        (void)bpf_.adopt(config.pin_path, interface_.index, config.filter_rules, config.default_action);
    }
    if (!bpf_.adopted()) {
        if (pinning) {
            // Whatever is attached is not adoptable, and its pins would
            // collide with the ones we are about to make, so both go. We
            // never write into a map we did not recognise; we replace it.
            (void)XdpProgram::detach(interface_.index, config.pin_path);
        }
        if (auto status = bpf_.load(config.filter_rules, config.default_action); !status) {
            close();
            return status;
        }
    }

    // Step 4: Create XSK socket
    struct xsk_socket_config xsk_cfg{};
    xsk_cfg.rx_size = static_cast<__u32>(config.rx_ring_size);
    xsk_cfg.tx_size = static_cast<__u32>(config.tx_ring_size);
    xsk_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = 0;
    xsk_cfg.bind_flags = detail::bind_flags(config.bind_mode);

    std::string const ifname_str(config.interface_name);
    int const ret = xsk_socket__create(&xsk_, ifname_str.c_str(), config.queue_id, *umem_result, &rings_.rx, &rings_.tx, &xsk_cfg);
    if (ret != 0) {
        bool const refused_zero_copy = config.bind_mode == XdpBindMode::zero_copy && (-ret == EOPNOTSUPP || -ret == EINVAL);
        close();
        // Told apart from every other reason the socket would not open: a
        // driver without zero-copy is a fact about the hardware, and the
        // caller may well want to open again in copy mode.
        return failure(refused_zero_copy ? XdpError::zero_copy_unavailable : XdpError::xsk_creation_failed);
    }
    zero_copy_ = detail::socket_has_zero_copy(xsk_socket__fd(xsk_));

    // Step 5: Attach BPF + register socket. An adopted program is already
    // attached and stays as it is; only the xsk_map entry is ours to replace,
    // since the socket the last process put there died with it.
    if (bpf_.adopted()) {
        if (auto status = bpf_.register_xsk(config.queue_id, xsk_socket__fd(xsk_)); !status) {
            close();
            return status;
        }
    } else {
        if (auto status = bpf_.attach(interface_.index, config.queue_id, xsk_socket__fd(xsk_), *plan); !status) {
            close();
            return status;
        }
        // Step 5b: Pin what we just attached, so the next start can adopt it.
        // From here close() leaves the program on the interface.
        if (pinning) {
            if (auto status = bpf_.pin(config.pin_path); !status) {
                close();
                return status;
            }
        }
    }

    program_.pin_path_ = pinning ? std::string{config.pin_path} : std::string{};
    program_.id_ = bpf_.program_id();
    program_.pinned_ = pinning;
    program_.adopted_ = bpf_.adopted();

    // Step 6: Register TAP device if requested
    if (config.tap_ifindex != 0) {
        if (auto status = bpf_.register_tap(config.tap_ifindex); !status) {
            close();
            return status;
        }
    }

    // Step 7: Store budget config + initial fill
    budget_.rx_drain_max = config.rx_drain_max;
    budget_.completion_drain_max = config.completion_drain_max;
    budget_.rx_clock_id = config.rx_clock_id;

    auto fill_status = fill_replenish();
    if (!fill_status) {
        close();
        return fill_status;
    }

    return success();
}

void XdpContext::close() noexcept
{
    if (xsk_ != nullptr) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }

    bpf_.close();
    umem_.close();

    zero_copy_ = false;
    tx_pending_ = false;
    interface_ = {};
    rings_ = {};
    budget_ = {};
    stats_ = {};
    // The pins themselves are deliberately left where they are: a pinned
    // program outliving the process is the feature. XdpProgram::detach() is
    // what removes them.
    program_ = {};
}

auto XdpContext::tx_commit(uint64_t handle, size_t frame_length) -> Status
{
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&rings_.tx, 1, &idx) == 0) {
        // The TX ring is full. Return the caller's UMEM frame to the free
        // list so we do not leak it — without this, every tx_ring_full
        // event consumed one UMEM frame permanently until umem_exhausted
        // saturated.
        umem_.free_frame(handle);
        ++stats_.tx_ring_full_count;
        return failure(XdpError::tx_ring_full);
    }
    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&rings_.tx, idx);
    desc->addr = handle + umem_.headroom();
    desc->len = static_cast<uint32_t>(frame_length);
    xsk_ring_prod__submit(&rings_.tx, 1);
    ++stats_.tx_count;
    // The kernel does not know about it until tx_flush() kicks, and that is
    // what makes the kick needed rather than skippable.
    tx_pending_ = true;
    return success();
}

auto XdpContext::tx_complete() -> Status
{
    uint32_t idx = 0;
    auto completed = xsk_ring_cons__peek(&rings_.comp, static_cast<uint32_t>(budget_.completion_drain_max), &idx);
    for (uint32_t i = 0; i < completed; ++i) {
        auto addr = *xsk_ring_cons__comp_addr(&rings_.comp, idx + i);
        umem_.free_frame(addr);
    }
    if (completed > 0) {
        xsk_ring_cons__release(&rings_.comp, completed);
    }
    return success();
}

auto XdpContext::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (budget_.rx_drain_max > 0 && budget_.rx_cycle_count >= budget_.rx_drain_max) {
        ++stats_.rx_budget_hit_count;
        return std::optional<EthernetRxSlot>{};
    }

    uint32_t idx = 0;
    if (xsk_ring_cons__peek(&rings_.rx, 1, &idx) == 0) {
        return std::optional<EthernetRxSlot>{};
    }

    auto const* desc = xsk_ring_cons__rx_desc(&rings_.rx, idx);

    struct timespec ts{};
    (void)::clock_gettime(budget_.rx_clock_id, &ts);
    int64_t const timestamp_ns = (static_cast<int64_t>(ts.tv_sec) * 1'000'000'000) + ts.tv_nsec;

    EthernetRxSlot slot{
        .handle = desc->addr,
        .buffer = umem_.readable_span(desc->addr, desc->len),
        .timestamp_ns = timestamp_ns,
    };

    // Release ring slot — UMEM frame remains valid until rx_release(handle)
    xsk_ring_cons__release(&rings_.rx, 1);
    ++budget_.rx_cycle_count;
    ++stats_.rx_count;

    return std::optional<EthernetRxSlot>{slot};
}

auto XdpContext::fill_replenish() -> Status
{
    auto available = umem_.available_frames();
    if (available == 0) {
        return success();
    }

    uint32_t idx = 0;
    auto reserved = xsk_ring_prod__reserve(&rings_.fill, static_cast<uint32_t>(available), &idx);
    uint32_t filled = 0;
    for (uint32_t i = 0; i < reserved; ++i) {
        auto addr = umem_.alloc_frame();
        if (!addr) {
            break;
        }
        *xsk_ring_prod__fill_addr(&rings_.fill, idx + i) = *addr;
        ++filled;
    }
    if (filled > 0) {
        xsk_ring_prod__submit(&rings_.fill, filled);
    }

    // The counterpart of the TX kick: a driver that asked to be woken for the
    // fill ring is waiting on a recvfrom before it will pick the new frames
    // up. The flag is only ever set on a socket bound with
    // XDP_USE_NEED_WAKEUP, which we do not ask for yet, so today this costs
    // nothing and the counter stays at zero - but the wakeup is here and
    // correct for when the bind flag is added.
    if (xsk_ring_prod__needs_wakeup(&rings_.fill) != 0) {
        (void)::recvfrom(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
        ++stats_.rx_wakeup_count;
    }
    return success();
}

auto XdpContext::join_multicast(ieee::Eui48 const& addr) -> Status
{
    if (xsk_ == nullptr) {
        return failure(XdpError::not_open);
    }

    struct ifreq ifr{};
    if (::if_indextoname(interface_.index, ifr.ifr_name) == nullptr) {
        return failure(XdpError::interface_not_found);
    }
    span_copy(hwaddr_bytes(ifr), make_const_span(addr.value));
    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;

    int sock_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return failure(XdpError::socket_creation_failed);
    }
    auto close_sock = detail::scopeguard([&]() noexcept { ::close(sock_fd); });

    if (::ioctl(sock_fd, SIOCADDMULTI, &ifr) < 0) {
        return failure(XdpError::join_multicast_failed);
    }

    return success();
}

#endif  // __linux__ && HAVE_XDP

}  // namespace statusbar::net
