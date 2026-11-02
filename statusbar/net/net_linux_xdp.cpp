// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_linux_xdp.hpp"

#include "statusbar/net/net_netdev_features.hpp"
#include "statusbar/net/net_posix_util.hpp"
#include "statusbar/net/net_socket.hpp"

#if defined(__linux__) && defined(HAVE_XDP)
#    include <linux/if_packet.h>
#    include <linux/magic.h>
#    include <sys/stat.h>
#    include <sys/vfs.h>
#endif

#include <algorithm>
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
        case XdpError::queue_busy:
            return "Queue still busy after retrying the bind: another process is holding it";
        case XdpError::foreign_program:
            return "An XDP program that is not ours is pinned at this path; it has been left alone";
        case XdpError::pin_not_adoptable:
            return "The pinned XDP program is not the one this build attaches, so it cannot be adopted";
        case XdpError::program_unidentifiable:
            return "The XDP program on the interface could not be identified: reading a program by its id needs "
                   "CAP_SYS_ADMIN, and it has been left alone";
        case XdpError::stats_read_failed:
            return "Reading the kernel's socket statistics failed";
        case XdpError::tx_metadata_not_supported:
            return "This build or kernel cannot put TX metadata on an AF_XDP frame";
        case XdpError::launch_time_not_supported:
            return "The kernel or this NIC does not time AF_XDP frames: Linux 6.15 and a driver with the feature are needed";
        case XdpError::invalid_umem_geometry:
            return "The UMEM frame size or headroom is not one the kernel will register";
        default:
            return "Unknown XDP error";
    }
}

// ──────────────────────────────────────────────
// XdpProgram
// ──────────────────────────────────────────────

#if defined(__linux__) && defined(HAVE_XDP)
namespace {

/// The name the embedded program is loaded under. The kernel records it,
/// and it is how one of ours that has no pin to speak for it - left by a
/// crash between attach and pin, or by an unpinned build that died - is
/// told from somebody else's program on the same interface.
constexpr char const* XDP_PROGRAM_NAME = "xdp_filter_prog";

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

/// The shape of the identity map: one XdpPinIdentity at key 0.
constexpr uint32_t IdentityKeySize = sizeof(uint32_t);
constexpr uint32_t IdentityValueSize = sizeof(XdpPinIdentity);
constexpr uint32_t IdentityEntries = 1;

/// Read the identity out of the pin directory at `pin_path`.
///
/// Three outcomes, and they are three on purpose. An error means the
/// question could not be asked - no permission to open the pin, most
/// likely - and must not be read as an answer: "I cannot tell who owns
/// this" is not "nobody owns this". An empty result means there is nothing
/// there, or nothing readable there, which does say the directory is
/// unclaimed. A value is what the directory claims about itself.
///
/// Readable means exactly the map we would have written:
/// bpf_map_lookup_elem() fills value_size bytes whatever the caller's
/// buffer is, so a map of some other width cannot be read into an
/// XdpPinIdentity at all, let alone trusted.
/// @param pin_path The pin directory to look in
[[nodiscard]] auto read_pin_identity(std::string_view const pin_path) -> StatusValue<std::optional<XdpPinIdentity>>
{
    OwnedFd const map{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_IDENTITY).c_str())};
    if (!map.valid()) {
        if (errno == ENOENT) {
            return std::optional<XdpPinIdentity>{};
        }
        return failure(std::error_code{errno, std::generic_category()});
    }
    if (!map_matches(map.get(), BPF_MAP_TYPE_ARRAY, IdentityKeySize, IdentityValueSize, IdentityEntries)) {
        return std::optional<XdpPinIdentity>{};
    }
    uint32_t const key = 0;
    XdpPinIdentity stored{};
    if (bpf_map_lookup_elem(map.get(), &key, &stored) != 0) {
        return std::optional<XdpPinIdentity>{};
    }
    return std::optional<XdpPinIdentity>{stored};
}

/// Create the identity map, write this build's identity into it and pin it
/// at `pin_path`. The descriptor is closed on the way out: the pin is what
/// keeps the map alive, and nothing reads it again until a later run adopts.
/// @param pin_path The pin directory, already created
[[nodiscard]] auto write_pin_identity(std::string_view const pin_path) -> Status
{
    OwnedFd const map{
        bpf_map_create(BPF_MAP_TYPE_ARRAY, "statusbar_id", IdentityKeySize, IdentityValueSize, IdentityEntries, nullptr)};
    if (!map.valid()) {
        return failure(XdpError::pin_failed);
    }
    uint32_t const key = 0;
    XdpPinIdentity const self = XdpProgram::identity();
    if (bpf_map_update_elem(map.get(), &key, &self, BPF_ANY) != 0) {
        return failure(XdpError::pin_failed);
    }
    if (bpf_obj_pin(map.get(), XdpProgram::pin_entry(pin_path, XdpProgram::PIN_IDENTITY).c_str()) != 0) {
        return failure(XdpError::pin_failed);
    }
    return success();
}

/// Whether the program behind this descriptor is one of ours, by the name
/// the kernel recorded for it. Any build of ours answers yes, which is the
/// point: an orphan left by an older build is ours to clear away, not a
/// stranger's to be refused forever.
[[nodiscard]] auto is_ours_by_name(int const prog_fd) noexcept -> bool
{
    struct bpf_prog_info info{};
    uint32_t length = sizeof(info);
    if (bpf_prog_get_info_by_fd(prog_fd, &info, &length) != 0) {
        return false;
    }
    return std::string_view{static_cast<char const*>(info.name)} == XDP_PROGRAM_NAME;
}

/// What the kernel says of the attached program with this id. Opening a
/// program by its id is a CAP_SYS_ADMIN privilege: a daemon with CAP_BPF and
/// CAP_NET_ADMIN alone gets EPERM for its own program as for anybody's, and
/// that is `unknown`, not `foreign` - the caller has the pin to ask next.
/// @param id A program id from XdpProgram::query(); 0 (programs in both
///           modes at once) is nobody's, since the kernel will not name one
[[nodiscard]] auto attached_program_owner(uint32_t const id) noexcept -> detail::AttachedProgramOwner
{
    using detail::AttachedProgramOwner;
    if (id == 0) {
        return AttachedProgramOwner::foreign;
    }
    OwnedFd const prog{bpf_prog_get_fd_by_id(id)};
    if (!prog.valid()) {
        return errno == EPERM ? AttachedProgramOwner::unknown : AttachedProgramOwner::foreign;
    }
    return is_ours_by_name(prog.get()) ? AttachedProgramOwner::ours : AttachedProgramOwner::foreign;
}

/// The id of the program pinned in `pin_path`, 0 for no pin, no path, or a
/// pin that will not open. Whose directory it is was the caller's question,
/// asked first through XdpProgram::owner(), so a program pinned here is
/// ours. Opening a pin and reading the id of a descriptor one holds need
/// no privilege beyond the bpffs permissions.
[[nodiscard]] auto pinned_program_id(std::string_view const pin_path) -> uint32_t
{
    if (pin_path.empty()) {
        return 0;
    }
    OwnedFd const prog{bpf_obj_get(XdpProgram::pin_entry(pin_path, XdpProgram::PIN_PROG).c_str())};
    return prog.valid() ? program_info_id(prog.get()) : 0;
}

/// Whether the attached program `id` is ours to take off the interface: by
/// name where the kernel gives it, else by being the program we pinned.
/// @param pinned_id The id of the program in our pin directory, 0 for none
[[nodiscard]] auto attachment_is_ours(uint32_t const id, uint32_t const pinned_id) noexcept -> StatusValue<bool>
{
    return detail::attachment_is_ours(attached_program_owner(id), id, pinned_id);
}

}  // namespace
#endif  // __linux__ && HAVE_XDP

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

namespace {

/// Whether every path component below the bpffs root is a name a directory
/// there could have: not empty, not "." or "..", none of the separators.
/// A path that passes the prefix test and then climbs out with ".." would
/// otherwise be created, unlinked in and removed wherever it lands.
[[nodiscard]] auto pin_components_valid(std::string_view below_root) noexcept -> bool
{
    for (std::string_view rest = below_root;;) {
        auto const slash = rest.find('/');
        if (!statusbar::net::detail::valid_interface_name(rest.substr(0, slash))) {
            return false;
        }
        if (slash == std::string_view::npos) {
            return true;
        }
        rest.remove_prefix(slash + 1);
    }
}

}  // namespace

auto XdpProgram::pinnable([[maybe_unused]] std::string_view const pin_path) -> Status
{
    // The shape first, which is pure: a pin has to live inside the bpf
    // filesystem and name something below its root, by components that
    // stay below it.
    if (!pin_path.starts_with(BPFFS_ROOT) || pin_path.size() <= BPFFS_ROOT.size() || pin_path[BPFFS_ROOT.size()] != '/' ||
        !pin_components_valid(pin_path.substr(BPFFS_ROOT.size() + 1))) {
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

auto XdpProgram::identity() -> XdpPinIdentity
{
#if defined(__linux__) && defined(HAVE_XDP)
    return XdpPinIdentity{
        .magic = xdp_pin_magic,
        .program_hash = detail::fnv1a64(std::span<unsigned char const>{xdp_filter_bpf_o, xdp_filter_bpf_o_len}),
        .window_bytes = static_cast<uint32_t>(TCAM_WINDOW_BYTES),
        .max_rules = static_cast<uint32_t>(TCAM_MAX_RULES),
    };
#else
    // No embedded program, so nothing to be the identity of. The zero magic
    // never matches, which is the safe way for this to be wrong.
    return XdpPinIdentity{};
#endif
}

auto XdpProgram::owner([[maybe_unused]] std::string_view const pin_path) -> StatusValue<XdpPinOwner>
{
#if defined(__linux__) && defined(HAVE_XDP)
    if (auto status = pinnable(pin_path); !status) {
        return failure(status.error());
    }
    auto const stored = read_pin_identity(pin_path);
    if (!stored) {
        return failure(stored.error());
    }
    if (!stored->has_value()) {
        // Absent, or there in a shape we cannot read. Both say the same
        // thing: nothing here claims to be anybody's, so the directory is
        // ours to replace. Calling an unreadable entry foreign would
        // hard-fail a downgrade to a build whose identity was a different
        // size - a real thing to do, and not a dangerous one.
        return XdpPinOwner::none;
    }
    return (*stored)->magic == xdp_pin_magic ? XdpPinOwner::ours : XdpPinOwner::foreign;
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

#if defined(__linux__) && defined(HAVE_XDP)
namespace {

/// The pins first: they are what an outside tool sees, and removing them
/// while the program is still attached is the harmless order of the two.
/// @param keep_first_error Where the first failure, if any, is kept
template <typename Keep>
auto unpin(std::string_view const pin_path, Keep const& keep_first_error) -> void
{
    for (auto const entry :
         {XdpProgram::PIN_IDENTITY,
          XdpProgram::PIN_PROG,
          XdpProgram::PIN_RULES_MAP,
          XdpProgram::PIN_XSK_MAP,
          XdpProgram::PIN_DEVMAP}) {
        auto const path = XdpProgram::pin_entry(pin_path, entry);
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
}

/// Then the attachment, in the mode it is actually in: flags of 0 mean
/// "native" to the kernel on any driver with ndo_bpf, so a generic attach
/// would survive a detach that did not say so. Only a program of ours, by
/// name or by being the one we pinned: one somebody else attached stays,
/// and that is a success here - there was nothing of ours to remove. One
/// the kernel will not name and the pin does not vouch for is reported,
/// not guessed at.
/// @param pinned_id The id of the program our pin directory held, read
///                  before the pins went, 0 for none
/// @param keep_first_error Where the first failure, if any, is kept
template <typename Keep>
auto detach_ours(unsigned int const if_index, uint32_t const pinned_id, Keep const& keep_first_error) -> void
{
    struct bpf_xdp_query_opts opts{};
    opts.sz = sizeof(opts);
    if (int const ret = bpf_xdp_query(static_cast<int>(if_index), 0, &opts); ret != 0) {
        keep_first_error(failure(std::error_code{-ret, std::generic_category()}));
        return;
    }
    for (auto const& [id, mode] :
         {std::pair{opts.drv_prog_id, XdpAttachMode::native}, std::pair{opts.skb_prog_id, XdpAttachMode::generic}}) {
        if (id == 0) {
            continue;
        }
        auto const ours = attachment_is_ours(id, pinned_id);
        if (!ours) {
            keep_first_error(failure(ours.error()));
            continue;
        }
        if (!*ours) {
            continue;
        }
        if (int const ret = bpf_xdp_detach(static_cast<int>(if_index), detail::BpfAttachment::attach_flags(mode), nullptr);
            ret != 0) {
            keep_first_error(failure(std::error_code{-ret, std::generic_category()}));
        }
    }
}

}  // namespace
#endif  // __linux__ && HAVE_XDP

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
        // Somebody else's pins are not ours to unlink, whatever is on the
        // interface. Nobody's - absent, or unreadable to the point of saying
        // nothing - are ours to clear.
        auto const owner = XdpProgram::owner(pin_path);
        if (!owner) {
            return failure(owner.error());
        }
        if (*owner == XdpPinOwner::foreign) {
            return failure(XdpError::foreign_program);
        }
    }

    Status result = success();
    auto const keep_first_error = [&result](Status status) noexcept {
        if (!status && result) {
            result = status;
        }
    };
    // Read before the pins go: it is what vouches for the attachment when
    // the kernel will not name it.
    uint32_t const pinned_id = pinned_program_id(pin_path);
    unpin(pin_path, keep_first_error);
    detach_ours(if_index, pinned_id, keep_first_error);
    return result;
#else
    return failure(XdpError::not_supported_on_platform);
#endif
}

#if defined(__linux__) && defined(HAVE_XDP)

namespace {

// One counter per uint64_t in the kernel's struct. The kernel reports how
// many it filled as a byte count, and refuses an option length shorter than
// its oldest three.
constexpr size_t KERNEL_STAT_COUNT = 6;

static_assert(
    sizeof(struct xdp_statistics) == KERNEL_STAT_COUNT * sizeof(uint64_t),
    "struct xdp_statistics has grown: add the new counters to XdpKernelStats and raise KERNEL_STAT_COUNT");

}  // namespace

auto detail::kernel_stats_from(struct xdp_statistics const& raw, socklen_t reported_length) -> XdpKernelStats
{
    // Clamped: a kernel newer than this header fills more counters than
    // there are fields here, and claiming them would be a lie.
    auto const reported = std::min(static_cast<size_t>(reported_length) / sizeof(uint64_t), KERNEL_STAT_COUNT);
    return XdpKernelStats{
        .rx_dropped = raw.rx_dropped,
        .rx_invalid_descs = raw.rx_invalid_descs,
        .tx_invalid_descs = raw.tx_invalid_descs,
        .rx_ring_full = raw.rx_ring_full,
        .rx_fill_ring_empty_descs = raw.rx_fill_ring_empty_descs,
        .tx_ring_empty_descs = raw.tx_ring_empty_descs,
        .counters_reported = reported,
    };
}

auto detail::read_xdp_kernel_stats(int fd) -> StatusValue<XdpKernelStats>
{
    // Zeroed, so a counter the kernel does not fill is a deterministic zero
    // rather than stack litter. counters_reported is what says which of them
    // the kernel actually wrote.
    //
    // No test can reach this: a kernel since 5.9 fills all six, so there is
    // nothing left unwritten for the garbage to show through. It stays
    // because the one kernel that would expose it is the one we cannot test.
    //
    // Read into room the kernel's struct will not outgrow for a while. Given
    // a buffer shorter than its own struct, the kernel does not truncate: it
    // falls back to the oldest three counters, so a kernel with a seventh
    // counter would have hidden the three this header knows about. The
    // length it reports back is still what says how many it filled.
    std::array<uint64_t, 4 * KERNEL_STAT_COUNT> room{};
    socklen_t length = sizeof(room);
    if (::getsockopt(fd, SOL_XDP, XDP_STATISTICS, room.data(), &length) < 0) {
        return failure(XdpError::stats_read_failed);
    }
    struct xdp_statistics raw{};
    std::memcpy(&raw, room.data(), sizeof(raw));
    return kernel_stats_from(raw, length);
}

namespace {

/// The plain umem create, for a UMEM with no TX metadata.
[[nodiscard]] auto create_plain_umem(
    struct xsk_umem** umem,
    uint8_t* area,
    size_t total_size,
    size_t frame_size,
    size_t headroom,
    size_t fill_ring_size,
    size_t comp_ring_size,
    detail::RingSet& rings) noexcept -> bool
{
    struct xsk_umem_config umem_cfg{
        .fill_size = static_cast<__u32>(fill_ring_size),
        .comp_size = static_cast<__u32>(comp_ring_size),
        .frame_size = static_cast<__u32>(frame_size),
        .frame_headroom = static_cast<__u32>(headroom),
        .flags = 0,
    };
    return xsk_umem__create(umem, area, total_size, &rings.fill, &rings.comp, &umem_cfg) == 0;
}

#    if defined(HAVE_XDP_TX_METADATA)

/// The opts-style create, the only one that can set tx_metadata_len. It
/// returns the umem rather than an int, and sets errno on failure.
[[nodiscard]] auto create_umem_with_metadata(
    struct xsk_umem** umem,
    uint8_t* area,
    size_t total_size,
    size_t frame_size,
    size_t headroom,
    size_t fill_ring_size,
    size_t comp_ring_size,
    size_t tx_metadata_len,
    detail::RingSet& rings) noexcept -> bool
{
    // Designated, and in declaration order: xsk_umem_opts carries its own size
    // in `sz` so libxdp can tell which fields a caller knew about.
    struct xsk_umem_opts opts{
        .sz = sizeof(struct xsk_umem_opts),
        .size = total_size,
        .fill_size = static_cast<__u32>(fill_ring_size),
        .comp_size = static_cast<__u32>(comp_ring_size),
        .frame_size = static_cast<__u32>(frame_size),
        .frame_headroom = static_cast<__u32>(headroom),
        .tx_metadata_len = static_cast<__u32>(tx_metadata_len),
    };
    *umem = xsk_umem__create_opts(area, &rings.fill, &rings.comp, &opts);
    return *umem != nullptr;
}

#    endif  // HAVE_XDP_TX_METADATA

}  // namespace

auto detail::UmemRegion::allocate(
    size_t frame_count,
    size_t frame_size,
    size_t headroom,
    size_t fill_ring_size,
    size_t comp_ring_size,
    RingSet& rings,
    size_t tx_metadata_len) -> StatusValue<struct xsk_umem*>
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

    tx_metadata_len_ = tx_metadata_len;
    if (!create_umem(total_size, frame_size, headroom, fill_ring_size, comp_ring_size, rings)) {
        XdpError const refusal = create_refusal();
        close();
        return failure(refusal);
    }

    free_list_ = UmemFreeList(frame_count, frame_size);

    return umem_;
}

auto detail::UmemRegion::create_umem(
    size_t total_size, size_t frame_size, size_t headroom, size_t fill_ring_size, size_t comp_ring_size, RingSet& rings) noexcept
    -> bool
{
    bool const created = create_umem_as_asked(total_size, frame_size, headroom, fill_ring_size, comp_ring_size, rings);
    // Read here, straight after the libxdp call: allocate() closes on failure,
    // and the munmap in that close would overwrite it.
    create_errno_ = created ? 0 : errno;
    return created;
}

auto detail::UmemRegion::create_umem_as_asked(
    size_t total_size, size_t frame_size, size_t headroom, size_t fill_ring_size, size_t comp_ring_size, RingSet& rings) noexcept
    -> bool
{
#    if defined(HAVE_XDP_TX_METADATA)
    if (tx_metadata_len_ != 0) {
        return create_umem_with_metadata(
            &umem_, area_, total_size, frame_size, headroom, fill_ring_size, comp_ring_size, tx_metadata_len_, rings);
    }
#    endif
    // A caller that asked for metadata on a build without it never gets here:
    // open() refuses before allocating.
    return create_plain_umem(&umem_, area_, total_size, frame_size, headroom, fill_ring_size, comp_ring_size, rings);
}

auto detail::UmemRegion::create_refusal() const noexcept -> XdpError
{
    // xsk_umem__create reports every reason as one EINVAL. The geometry was
    // checked before this, so with metadata asked for, EINVAL (or a kernel
    // saying so in as many words) is the kernel not having TX metadata.
    bool const no_metadata = create_errno_ == EINVAL || create_errno_ == ENOTSUP || create_errno_ == EOPNOTSUPP;
    return tx_metadata_len_ != 0 && no_metadata ? XdpError::tx_metadata_not_supported : XdpError::umem_creation_failed;
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
    tx_metadata_len_ = 0;
    free_list_ = {};
}

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

    struct bpf_program* prog = bpf_object__find_program_by_name(obj.get(), XDP_PROGRAM_NAME);
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
    XdpAction const default_action,
    AttachPlan const& plan) -> Status
{  // NOLINT(statusbar-block-statements) a pin is checked piece by piece, each refusal its own
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

    // The structure being right is not the same as the program being ours.
    // A recompiled xdp_filter.bpf.c declares exactly the same maps, so every
    // check above passes for a pin left by a build with different code in
    // it - and that, a redeploy, is the common case rather than the exotic
    // one. The identity is what settles it.
    auto const read = read_pin_identity(pin_path);
    if (!read) {
        return failure(read.error());
    }
    if (!read->has_value()) {
        return failure(XdpError::pin_not_adoptable);
    }
    XdpPinIdentity const stored = **read;
    if (stored.magic != xdp_pin_magic) {
        // Reached only by calling adopt() directly; open() asks
        // XdpProgram::owner() first and never gets this far. Reported as
        // itself anyway, because a caller must not read this as "ours but
        // stale" and go on to replace it.
        return failure(XdpError::foreign_program);
    }
    XdpPinIdentity const self = XdpProgram::identity();
    if (stored.program_hash != self.program_hash || stored.window_bytes != self.window_bytes ||
        stored.max_rules != self.max_rules) {
        return failure(XdpError::pin_not_adoptable);
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
    // And attached the way this open() would attach it. A generic-mode
    // program is no use to a zero-copy bind, and a native one is not what
    // a caller who asked for generic asked for: either is replaced, which
    // the fresh path does, rather than adopted into a policy it breaks.
    XdpAttachMode const mode = (*attached)->mode;
    if (mode != plan.first && mode != plan.fallback) {
        return failure(XdpError::pin_not_adoptable);
    }
    attachment_.adopt(if_index, mode);

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

    // Last, and deliberately so: the identity is what a later run trusts,
    // and a directory that claims one is a directory whose other pins are
    // all already there. A process that died mid-pin leaves no identity, so
    // the next run replaces the remains rather than adopting half of them.
    if (auto status = write_pin_identity(pin_path); !status) {
        return status;
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

/// Whether open() may take what is on the interface off it: nothing is
/// attached, or what is attached is one of ours - by name, or by being the
/// program pinned in our own directory when the kernel will not give the
/// name. The pin directory being ours - or nobody's - says nothing about the
/// attachment by itself: a program somebody else attached, pinned elsewhere
/// or nowhere, is theirs, and the ownership contract says it may not be
/// detached. Programs in two modes at once report an id of zero, which is
/// nobody's: a guess is not a claim.
/// @param if_index The interface
/// @param pin_path Our pin directory, empty when not pinning
[[nodiscard]] auto attachment_replaceable(unsigned int const if_index, std::string_view const pin_path) -> StatusValue<bool>
{
    auto const attached = XdpProgram::query(if_index);
    if (!attached) {
        return failure(attached.error());
    }
    if (!attached->has_value()) {
        return true;
    }
    return attachment_is_ours((*attached)->program_id, pinned_program_id(pin_path));
}

}  // namespace

auto detail::BpfState::install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status
{
    auto const catch_all = catch_all_rule_for(default_action_);
    if (rules.size() + (catch_all.has_value() ? 1U : 0U) > TCAM_MAX_RULES) {
        return failure(XdpError::too_many_filter_rules);
    }
    // The rules, the catch-all, then every slot after them cleared: the scan stops at the first vacant one.
    auto const written = write_tcam_rules(rules, catch_all);
    return written ? clear_tcam_slots(*written) : forward_failure(written);
}

auto detail::BpfState::write_tcam_rules(std::span<CompiledRule<32> const> rules, std::optional<CompiledRule<32>> const& catch_all)
    -> StatusValue<std::uint32_t>
{
    std::uint32_t slot = 0;
    for (auto const& rule : rules) {
        if (auto s = write_tcam_slot(slot++, detail::tcam_slot(rule)); !s) {
            return forward_failure(s);
        }
    }
    if (auto s = catch_all.has_value() ? write_tcam_slot(slot++, *catch_all) : Status{}; !s) {
        return forward_failure(s);
    }
    return slot;
}

auto detail::BpfState::clear_tcam_slots(std::uint32_t const from) -> Status
{
    CompiledRule<32> const empty{};
    for (std::uint32_t i = from; i < TCAM_MAX_RULES; ++i) {
        if (auto s = write_tcam_slot(i, empty); !s) {
            return s;
        }
    }
    return success();
}

auto detail::BpfState::write_tcam_slot(std::uint32_t index, CompiledRule<32> const& rule) -> Status
{
    if (bpf_map_update_elem(rules_map_fd_, &index, &rule, BPF_ANY) != 0) {
        return failure(XdpError::bpf_map_update_failed);
    }
    return success();
}

auto XdpContext::open(XdpConfig const& config) -> Status
{  // NOLINT(statusbar-block-statements) the setup sequence, one step after another, each undoing the last on failure
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

    // A name no interface can have is refused here - after the pin path,
    // the earlier of the two pure checks - rather than truncated into an
    // ifreq, where a sixteen-character name would have named whichever
    // interface its first fifteen characters do.
    if (!detail::valid_interface_name(config.interface_name)) {
        return failure(XdpError::interface_not_found);
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

    // Step 1b: Whose pin directory is it? Asked before adopting and before
    // replacing, because the two are equally destructive to somebody else's
    // program: one writes our rules into their map, the other unlinks their
    // pins and takes their program off the interface. Neither is ours to do,
    // so the question comes before the choice between them - and before
    // anything is created, so a refusal leaves not even an empty directory
    // behind.
    if (pinning) {
        auto const owner = XdpProgram::owner(config.pin_path);
        if (!owner) {
            close();
            return failure(owner.error());
        }
        if (*owner == XdpPinOwner::foreign) {
            close();
            return failure(XdpError::foreign_program);
        }
    }

    // Step 2: Allocate UMEM.
    //
    // Launch time is refused here rather than ignored: a socket whose times
    // the kernel discards looks exactly like one that works, and the frames
    // go out at the wrong moment with nothing reported.
    size_t tx_metadata_len = 0;
    size_t headroom = config.umem_headroom;
    if (config.tx_launch_time) {
        // Two questions, in order: can this build and kernel carry TX
        // metadata at all (a compile-time fact here; the UMEM registration
        // below asks the kernel), and will this NIC act on a launch time in
        // it. A kernel from 6.8 to 6.14 answers yes to the first and
        // discards the time, which is why the second is asked of the NIC.
        if (!detail::xdp_tx_metadata_built) {
            close();
            return failure(XdpError::tx_metadata_not_supported);
        }
        if (auto const probed = probe_tx_launch_time(interface_.index); !probed) {
            close();
            return failure(probed.error());
        }
        tx_metadata_len = detail::xdp_tx_metadata_len;
        // The kernel puts the metadata below the descriptor address, so the
        // headroom has to hold it.
        headroom = std::max(headroom, tx_metadata_len);
    }
    // Checked here rather than left to the kernel: xsk_umem__create reports
    // every reason as one EINVAL, which open() would pass on as "UMEM
    // creation failed" and tell a caller nothing about which knob is wrong.
    auto const page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    if (!detail::umem_geometry_is_valid(config.umem_frame_size, headroom, page_size)) {
        close();
        return failure(XdpError::invalid_umem_geometry);
    }
    auto umem_result = umem_.allocate(
        config.umem_frame_count,
        config.umem_frame_size,
        headroom,
        config.fill_ring_size,
        config.completion_ring_size,
        rings_,
        tx_metadata_len);
    if (!umem_result) {
        close();
        return failure(umem_result.error());
    }

    // Step 3: The program. With a pin path it may already be on the
    // interface from a previous run, in which case adopting it is the point
    // of the whole exercise: no detach, no re-attach, no gap.
    if (pinning && config.adopt) {
        // Best effort by design. A pin left by an older build of ours, or a
        // half-written one, is not an error - it only means there is nothing
        // here to adopt, and the fresh path below takes over. A pin that is
        // nobody's to touch cannot reach this point.
        (void)bpf_.adopt(config.pin_path, interface_.index, config.filter_rules, config.default_action, *plan);
    }
    if (!bpf_.adopted()) {
        // What the interface holds is asked before anything is put there,
        // pinned or not, because the pin directory does not say: a program
        // somebody else attached, pinned elsewhere or nowhere, is theirs,
        // and detaching it would be the very thing the ownership check in
        // step 1b exists to prevent. One of ours - an older build's, or an
        // orphan left by a crash between attach and pin - is known by its
        // name, and goes, with any pins that would collide with the ones
        // about to be made. We never write into a map we did not recognise;
        // we replace it.
        auto const replaceable = attachment_replaceable(interface_.index, config.pin_path);
        if (!replaceable) {
            close();
            return failure(replaceable.error());
        }
        if (!*replaceable) {
            close();
            return failure(XdpError::foreign_program);
        }
        (void)XdpProgram::detach(interface_.index, config.pin_path);
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
    // XDP_USE_NEED_WAKEUP: the driver tells us, through the ring flags, when
    // it needs a kick to notice a new fill or TX submission, and sleeps
    // otherwise instead of polling the rings. tx_flush() and the fill path
    // both honour the flag.
    xsk_cfg.bind_flags = detail::bind_flags(config.bind_mode) | XDP_USE_NEED_WAKEUP;

    std::string const ifname_str(config.interface_name);
    // A bind refused with EBUSY is a queue the last owner has not finished
    // giving back, which is what a restart finds; it is retried rather than
    // reported. The loop sits around the whole of xsk_socket__create()
    // because that is where the bind is, and libxdp unwinds a failed bind
    // completely - the RX and TX ring mappings go, the UMEM's refcount and
    // its context list come back to where they were, the descriptor it
    // borrowed from the UMEM is left open - so a second attempt starts from
    // the same state as the first and `xsk_` is written only on success.
    size_t pauses = 0;
    int const ret = detail::retry_while_busy(
        config.bind_busy_retries,
        [&] {
            return xsk_socket__create(&xsk_, ifname_str.c_str(), config.queue_id, *umem_result, &rings_.rx, &rings_.tx, &xsk_cfg);
        },
        [&pauses] {
            ++pauses;
            detail::pause_for_busy_bind();
        });
    if (ret != 0) {
        bool const refused_zero_copy = config.bind_mode == XdpBindMode::zero_copy && (-ret == EOPNOTSUPP || -ret == EINVAL);
        close();
        // Told apart from every other reason the socket would not open: a
        // driver without zero-copy is a fact about the hardware, and the
        // caller may well want to open again in copy mode. A queue that is
        // still busy once the retries are spent is told apart too - that
        // one sends an operator looking for the process holding it, which
        // "XSK socket creation failed" would not.
        if (-ret == EBUSY) {
            return failure(XdpError::queue_busy);
        }
        return failure(refused_zero_copy ? XdpError::zero_copy_unavailable : XdpError::xsk_creation_failed);
    }
    bind_retries_ = pauses;
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

    // Step 6: Register TAP device if requested. An adopted program carries
    // the previous process's devmap, so with no TAP asked for its one slot
    // is emptied rather than left pointing wherever it pointed before.
    if (auto status = config.tap_ifindex != 0 ? bpf_.register_tap(config.tap_ifindex)
            : bpf_.adopted()                  ? bpf_.unregister_tap()
                                              : success();
        !status) {
        close();
        return status;
    }

    // Step 7: Store budget config + initial fill
    budget_.rx_drain_max = config.rx_drain_max;
    budget_.completion_drain_max = config.completion_drain_max;
    tx_frame_reserve_ = detail::effective_tx_reserve(config.tx_frame_reserve, config.umem_frame_count);

    auto fill_status = fill_replenish();
    if (!fill_status) {
        close();
        return fill_status;
    }

    return success();
}

void XdpContext::close() noexcept
{  // NOLINT(statusbar-block-statements): every member back to a closed context's, one reset
    if (xsk_ != nullptr) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }

    bpf_.close();
    umem_.close();
    membership_fd_.close();  // and with it every membership this context held

    zero_copy_ = false;
    tx_pending_.store(false, std::memory_order_relaxed);
    napi_busy_poll_.set(false);
    tx_progress_ = {};
    bind_retries_ = 0;
    tx_frame_reserve_ = 0;
    interface_ = {};
    rings_ = {};
    budget_ = {};
    stats_ = {};
    // The pins themselves are deliberately left where they are: a pinned
    // program outliving the process is the feature. XdpProgram::detach() is
    // what removes them.
    program_ = {};
}

#    if defined(HAVE_XDP_TX_METADATA)

namespace {

/// Register the smallest UMEM that carries TX metadata. Nothing is ever sent
/// through it.
[[nodiscard]] auto register_probe_umem(detail::UmemRegion& umem, detail::RingSet& rings) -> Status
{
    constexpr size_t PROBE_FRAMES = 2;
    constexpr size_t PROBE_RING = 8;
    constexpr size_t PROBE_FRAME_SIZE = 2048;
    auto const registered = umem.allocate(
        PROBE_FRAMES, PROBE_FRAME_SIZE, detail::xdp_tx_metadata_len, PROBE_RING, PROBE_RING, rings, detail::xdp_tx_metadata_len);
    return registered ? success() : failure(registered.error());
}

}  // namespace

#    endif  // HAVE_XDP_TX_METADATA

auto probe_tx_metadata() -> Status
{
#    if !defined(HAVE_XDP_TX_METADATA)
    // No kernel UAPI for it, or a libxdp that cannot register the length.
    return failure(XdpError::tx_metadata_not_supported);
#    else
    detail::RingSet rings{};
    detail::UmemRegion umem;
    auto const registered = register_probe_umem(umem, rings);
    if (registered || registered.error() == XdpError::tx_metadata_not_supported) {
        return registered;
    }
    // Some other refusal - EPERM for a caller without CAP_NET_RAW - as the
    // kernel gave it, which allocate() kept from under its own close().
    return failure(std::error_code{umem.create_errno(), std::system_category()});
#    endif
}

// ──────────────────────────────────────────────
// Launch time: what the kernel says this NIC can do
// ──────────────────────────────────────────────

auto probe_tx_launch_time(unsigned int const if_index) -> Status
{
    auto const features = netdev::query_xsk_features(static_cast<int>(if_index));
    if (!features) {
        // A kernel with no netdev family to ask (before 6.6) cannot time a
        // frame either.
        bool const no_family = features.error() == std::errc::no_such_file_or_directory;
        return failure(no_family ? make_error_code(XdpError::launch_time_not_supported) : features.error());
    }
    return features->launch_time() ? success() : failure(XdpError::launch_time_not_supported);
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
    // The frame says for itself whether it carries a launch time. Without the
    // option the kernel never reads the metadata, so a frame that asked for
    // nothing costs nothing.
    desc->options = detail::frame_wants_metadata(umem_.tx_metadata_span(handle)) ? detail::xdp_desc_tx_metadata : 0;
    xsk_ring_prod__submit(&rings_.tx, 1);
    ++stats_.tx_count;
    // The kernel does not know about it until tx_flush() kicks, and that is
    // what makes the kick needed rather than skippable. Release: a kicker
    // that sees the flag sees the submit above.
    tx_pending_.store(true, std::memory_order_release);
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
    return rx_start(rx_clock_now());
}

auto XdpContext::rx_start(RxTimePoint const now) -> StatusValue<std::optional<EthernetRxSlot>>
{
    if (budget_.rx_drain_max > 0 && budget_.rx_cycle_count >= budget_.rx_drain_max) {
        ++stats_.rx_budget_hit_count;
        return std::optional<EthernetRxSlot>{};
    }
    uint32_t idx = 0;
    if (xsk_ring_cons__peek(&rings_.rx, 1, &idx) == 0) {
        return std::optional<EthernetRxSlot>{};
    }
    return std::optional<EthernetRxSlot>{take_rx_desc(idx, now)};
}

auto XdpContext::take_rx_desc(uint32_t const idx, RxTimePoint const now) -> EthernetRxSlot
{
    auto const* desc = xsk_ring_cons__rx_desc(&rings_.rx, idx);
    EthernetRxSlot const slot{
        .handle = desc->addr,
        .buffer = umem_.readable_span(desc->addr, desc->len),
        .timestamp_ns = rx_timestamp_ns(now),
    };
    // Release ring slot — UMEM frame remains valid until rx_release(handle)
    xsk_ring_cons__release(&rings_.rx, 1);
    ++budget_.rx_cycle_count;
    ++stats_.rx_count;
    return slot;
}

auto XdpContext::fill_replenish() -> Status
{
    // What receive may have: everything free except the transmit reserve.
    // Without this the fill ring takes the lot and tx_start() never gets a
    // frame again - see detail::fillable_frames.
    auto const available = detail::fillable_frames(umem_.available_frames(), tx_frame_reserve_);
    if (available == 0) {
        return success();
    }

    // xsk_ring_prod__reserve is all-or-nothing, so never ask for more than the
    // ring has free: a request the ring cannot meet reserves nothing at all.
    auto const want = detail::fill_reserve_count(available, xsk_prod_nb_free(&rings_.fill, static_cast<uint32_t>(available)));
    if (want == 0) {
        return success();
    }

    uint32_t idx = 0;
    auto reserved = xsk_ring_prod__reserve(&rings_.fill, want, &idx);
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
    // up. The socket is bound with XDP_USE_NEED_WAKEUP, so the flag is the
    // driver's to set, and a driver that never sleeps never sets it.
    if (xsk_ring_prod__needs_wakeup(&rings_.fill) != 0) {
        (void)::recvfrom(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
        ++stats_.rx_wakeup_count;
    }
    return success();
}

namespace detail {

auto open_membership_socket() -> StatusValue<FileDescriptor>
{
    // Protocol 0: bound to no EtherType, so the kernel never queues a frame
    // to it. It is a handle for memberships and nothing else.
    int const fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return failure(XdpError::socket_creation_failed);
    }
    return FileDescriptor{fd};
}

/// The PACKET_ADD/DROP_MEMBERSHIP request for multicast @p addr on @p if_index.
auto multicast_request(unsigned int if_index, ieee::Eui48 const& addr) noexcept -> packet_mreq
{
    packet_mreq mreq{};
    mreq.mr_ifindex = static_cast<int>(if_index);
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    span_copy(std::span{mreq.mr_address}.first(6), make_const_span(addr.value));
    return mreq;
}

auto change_membership(int fd, unsigned int if_index, ieee::Eui48 const& addr, int optname) -> Status
{
    auto const mreq = multicast_request(if_index, addr);
    if (::setsockopt(fd, SOL_PACKET, optname, &mreq, sizeof(mreq)) < 0) {
        return failure(XdpError::join_multicast_failed);
    }
    return success();
}

}  // namespace detail

auto XdpContext::join_multicast(ieee::Eui48 const& addr) -> Status
{
    if (xsk_ == nullptr) {
        return failure(XdpError::not_open);
    }
    if (!membership_fd_.valid()) {
        auto sock = detail::open_membership_socket();
        if (!sock) {
            return failure(sock.error());
        }
        membership_fd_ = std::move(*sock);
    }
    return detail::change_membership(membership_fd_.get(), interface_.index, addr, PACKET_ADD_MEMBERSHIP);
}

auto XdpContext::leave_multicast(ieee::Eui48 const& addr) -> Status
{
    if (xsk_ == nullptr) {
        return failure(XdpError::not_open);
    }
    if (!membership_fd_.valid()) {
        return success();  // nothing was ever joined: nothing to drop, as the kernel would say
    }
    return detail::change_membership(membership_fd_.get(), interface_.index, addr, PACKET_DROP_MEMBERSHIP);
}

#endif  // __linux__ && HAVE_XDP

}  // namespace statusbar::net
