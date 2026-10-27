// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_linux_xdp.hpp"

#include "statusbar/net/net_posix_util.hpp"

#if defined(__linux__) && defined(HAVE_XDP)
#    include <algorithm>
#    include <filesystem>
#    include <system_error>
#endif

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
        case XdpError::leave_multicast_failed:
            return "Failed to leave multicast group";
        case XdpError::bpf_query_failed:
            return "Querying the interface's XDP program failed";
        case XdpError::bpf_pin_failed:
            return "Pinning the XDP program or its maps failed";
        case XdpError::bpf_detach_failed:
            return "Detaching the XDP program failed";
        case XdpError::zero_copy_needs_native_attach:
            return "Zero-copy needs the XDP program attached in native (driver) mode";
        default:
            return "Unknown XDP error";
    }
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

/// A program's kernel id and tag (the tag hashes its instructions, map
/// references excluded: the same program loaded twice has the same tag).
struct ProgIdentity
{
    uint32_t id{0};
    std::array<uint8_t, BPF_TAG_SIZE> tag{};
};

[[nodiscard]] auto prog_identity(int prog_fd) -> std::optional<ProgIdentity>
{
    struct bpf_prog_info info{};
    __u32 length = sizeof(info);
    if (bpf_prog_get_info_by_fd(prog_fd, &info, &length) != 0) {
        return std::nullopt;
    }
    ProgIdentity identity{.id = info.id};
    std::memcpy(identity.tag.data(), info.tag, BPF_TAG_SIZE);
    return identity;
}

[[nodiscard]] auto pin_file(std::string_view dir, std::string_view name) -> std::string
{
    std::string path{dir};
    path += '/';
    path += name;
    return path;
}

constexpr std::array<std::string_view, 4> PIN_NAMES = {
    XdpProgram::PIN_PROG, XdpProgram::PIN_RULES_MAP, XdpProgram::PIN_XSK_MAP, XdpProgram::PIN_DEVMAP};

/// Remove the pins under `dir` and the directory itself (ignoring what is not there).
void remove_pins(std::string_view dir) noexcept
{
    if (dir.empty()) {
        return;
    }
    for (auto const name : PIN_NAMES) {
        (void)::unlink(pin_file(dir, name).c_str());
    }
    (void)::rmdir(std::string{dir}.c_str());
}

/// Pin each of `fds` under `dir` (created) by PIN_NAMES; on a failure the pins are removed.
[[nodiscard]] auto pin_objects(std::array<int, 4> const& fds, std::string_view const dir) -> Status
{
    std::error_code error;
    std::filesystem::create_directories(std::string{dir}, error);
    if (error) {
        return failure(XdpError::bpf_pin_failed);
    }
    for (size_t i = 0; i < fds.size(); ++i) {
        if (bpf_obj_pin(fds[i], pin_file(dir, PIN_NAMES[i]).c_str()) != 0) {
            remove_pins(dir);
            return failure(XdpError::bpf_pin_failed);
        }
    }
    return success();
}

/// True when `pinned_fd` is the program attached as `prog_id` and the same
/// build as `built_in_fd` (equal tags).
[[nodiscard]] auto is_attached_build(int const pinned_fd, int const built_in_fd, uint32_t const prog_id) noexcept -> bool
{
    auto const pinned = prog_identity(pinned_fd);
    auto const built_in = prog_identity(built_in_fd);
    return pinned && built_in && pinned->id == prog_id && pinned->tag == built_in->tag;
}

/// A pinned program and its maps, opened from their pins for adoption.
struct PinnedProgram
{
    detail::OwnedFd prog;
    std::array<detail::OwnedFd, 3> maps;  ///< rules_map, xsk_map, devmap
};

/// The program and maps pinned under `pin_path`, when that program is the one
/// attached as `prog_id` and the same build as `built_in_fd`; else nullopt.
[[nodiscard]] auto open_adoptable_pins(std::string_view const pin_path, int const built_in_fd, uint32_t const prog_id)
    -> std::optional<PinnedProgram>
{
    PinnedProgram pins{.prog = detail::OwnedFd{bpf_obj_get(pin_file(pin_path, XdpProgram::PIN_PROG).c_str())}};
    if (pins.prog.get() < 0 || !is_attached_build(pins.prog.get(), built_in_fd, prog_id)) {
        return std::nullopt;  // a stale pin, or another program (an older build's): replaced
    }
    for (size_t i = 0; i < pins.maps.size(); ++i) {
        pins.maps[i] = detail::OwnedFd{bpf_obj_get(pin_file(pin_path, PIN_NAMES[i + 1]).c_str())};
    }
    if (std::ranges::any_of(pins.maps, [](detail::OwnedFd const& fd) { return fd.get() < 0; })) {
        return std::nullopt;
    }
    return pins;
}

/// The fds of the built-in object's maps and program.
struct ProgramFds
{
    int rules_map{-1};
    int xsk_map{-1};
    int devmap{-1};
    int prog{-1};
};

/// The built-in object's map and program fds, or nullopt when one is missing.
[[nodiscard]] auto builtin_fds(struct bpf_object* const obj) noexcept -> std::optional<ProgramFds>
{
    struct bpf_map* rules_map = bpf_object__find_map_by_name(obj, "rules_map");
    struct bpf_map* xsk_map = bpf_object__find_map_by_name(obj, "xsk_map");
    struct bpf_map* devmap = bpf_object__find_map_by_name(obj, "devmap");
    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_filter_prog");
    if (rules_map == nullptr || xsk_map == nullptr || devmap == nullptr || prog == nullptr) {
        return std::nullopt;
    }
    return ProgramFds{
        .rules_map = bpf_map__fd(rules_map),
        .xsk_map = bpf_map__fd(xsk_map),
        .devmap = bpf_map__fd(devmap),
        .prog = bpf_program__fd(prog),
    };
}

/// What to attach in: a native program in place stays native (replaced in
/// place, no adapter reset); a generic one gives way to native.
[[nodiscard]] auto plan_for_attached(std::optional<XdpAttachedProgram> const& attached, XdpProgram::Options const& options) noexcept
    -> detail::AttachPlan
{
    detail::AttachPlan plan{.first = options.attach_mode, .fallback = std::nullopt};
    if (options.attach_mode == XdpAttachMode::native && options.allow_generic_fallback) {
        plan.fallback = XdpAttachMode::generic;
    }
    if (attached && detail::effective_attach_mode(attached->mode, options.attach_mode) == attached->mode) {
        plan = {.first = attached->mode, .fallback = std::nullopt};
    }
    return plan;
}

/// Detach the generic program in place when native is wanted (the two cannot
/// coexist): its fd, to restore it if all fails; else none.
[[nodiscard]] auto displace_generic_for_native(
    unsigned int const if_index, std::optional<XdpAttachedProgram> const& attached, XdpAttachMode const wanted) noexcept
    -> detail::OwnedFd
{
    if (!attached || detail::effective_attach_mode(attached->mode, wanted) == attached->mode) {
        return detail::OwnedFd{};
    }
    detail::OwnedFd displaced{bpf_prog_get_fd_by_id(attached->prog_id)};
    (void)bpf_xdp_detach(static_cast<int>(if_index), XDP_FLAGS_SKB_MODE, nullptr);
    return displaced;
}

/// Whether the bound socket `fd` reads back XDP_OPTIONS_ZEROCOPY (false when
/// XDP_OPTIONS cannot be read).
[[nodiscard]] auto bound_zero_copy(int const fd) noexcept -> bool
{
    struct xdp_options opts{};
    socklen_t opts_len = sizeof(opts);
    return ::getsockopt(fd, SOL_XDP, XDP_OPTIONS, &opts, &opts_len) == 0 && (opts.flags & XDP_OPTIONS_ZEROCOPY) != 0;
}

}  // namespace

auto XdpProgram::query(unsigned int const if_index) -> StatusValue<std::optional<XdpAttachedProgram>>
{
    LIBBPF_OPTS(bpf_xdp_query_opts, opts);
    if (bpf_xdp_query(static_cast<int>(if_index), 0, &opts) != 0) {
        return failure(XdpError::bpf_query_failed);
    }
    switch (opts.attach_mode) {
        case XDP_ATTACHED_DRV:
            return std::optional{XdpAttachedProgram{.prog_id = opts.prog_id, .mode = XdpAttachMode::native}};
        case XDP_ATTACHED_SKB:
            return std::optional{XdpAttachedProgram{.prog_id = opts.prog_id, .mode = XdpAttachMode::generic}};
        case XDP_ATTACHED_MULTI:
            if (opts.drv_prog_id != 0) {
                return std::optional{XdpAttachedProgram{.prog_id = opts.drv_prog_id, .mode = XdpAttachMode::native}};
            }
            if (opts.skb_prog_id != 0) {
                return std::optional{XdpAttachedProgram{.prog_id = opts.skb_prog_id, .mode = XdpAttachMode::generic}};
            }
            break;
        default:
            break;
    }
    return std::optional<XdpAttachedProgram>{};
}

auto XdpProgram::detach(unsigned int const if_index, std::string_view const pin_path) -> Status
{
    Status status = success();
    LIBBPF_OPTS(bpf_xdp_query_opts, opts);
    if (bpf_xdp_query(static_cast<int>(if_index), 0, &opts) != 0) {
        status = failure(XdpError::bpf_query_failed);
    } else {
        if (opts.drv_prog_id != 0 && bpf_xdp_detach(static_cast<int>(if_index), XDP_FLAGS_DRV_MODE, nullptr) != 0) {
            status = failure(XdpError::bpf_detach_failed);
        }
        if (opts.skb_prog_id != 0 && bpf_xdp_detach(static_cast<int>(if_index), XDP_FLAGS_SKB_MODE, nullptr) != 0) {
            status = failure(XdpError::bpf_detach_failed);
        }
    }
    remove_pins(pin_path);
    return status;
}

auto XdpProgram::try_adopt(XdpAttachedProgram const& attached, Options const& options) -> bool
{
    if (detail::effective_attach_mode(attached.mode, options.attach_mode) != attached.mode) {
        return false;  // a generic program, native wanted: replaced
    }
    auto pins = open_adoptable_pins(options.pin_path, state_.prog_fd, attached.prog_id);
    if (!pins) {
        return false;
    }
    adopt(std::move(pins->prog), std::move(pins->maps), attached, options.pin_path);
    return true;
}

void XdpProgram::adopt(
    detail::OwnedFd prog, std::array<detail::OwnedFd, 3> maps, XdpAttachedProgram const& attached, std::string_view const pin_path)
{  // NOLINT(statusbar-block-statements): the adopted state, field by field
    // The freshly loaded copy is not needed.
    state_.obj.reset();
    set_fds(prog.get(), maps[0].get(), maps[1].get(), maps[2].get());
    state_.adopted_prog = std::move(prog);
    state_.adopted_rules_map = std::move(maps[0]);
    state_.adopted_xsk_map = std::move(maps[1]);
    state_.adopted_devmap = std::move(maps[2]);
    state_.prog_id = attached.prog_id;
    state_.mode = attached.mode;
    state_.adopted = true;
    state_.pin_path = std::string{pin_path};
}

void XdpProgram::set_fds(int const prog, int const rules_map, int const xsk_map, int const devmap) noexcept
{
    state_.rules_map_fd = rules_map;
    state_.xsk_map_fd = xsk_map;
    state_.devmap_fd = devmap;
    state_.prog_fd = prog;
}

auto XdpProgram::pin(std::string_view const pin_path) -> Status
{
    remove_pins(pin_path);  // a stale program's pins
    std::array<int, 4> const fds = {state_.prog_fd, state_.rules_map_fd, state_.xsk_map_fd, state_.devmap_fd};
    if (auto status = pin_objects(fds, pin_path); !status) {
        return status;
    }
    state_.pin_path = std::string{pin_path};
    return success();
}

auto XdpProgram::open(unsigned int const if_index, Options const& options) -> Status
{
    close();
    state_.default_action = options.default_action;
    state_.if_index = if_index;
    auto status = adopt_or_attach(if_index, options);
    if (!status) {
        close();
    }
    return status;
}

auto XdpProgram::adopt_or_attach(unsigned int const if_index, Options const& options) -> Status
{
    auto const attached = query(if_index);
    if (!attached) {
        return failure(attached.error());
    }
    if (auto status = load_builtin(); !status) {
        return status;
    }
    if (*attached && options.adopt && !options.pin_path.empty() && try_adopt(**attached, options)) {
        state_.detach_on_close = options.detach_on_close.value_or(false);
        return install_tcam_rules(options.filter_rules);
    }
    // Rules before the attach, so the program filters from its first frame.
    if (auto status = install_tcam_rules(options.filter_rules); !status) {
        return status;
    }
    return attach(if_index, *attached, options);
}

auto XdpProgram::load_builtin() -> Status
{
    // Loaded even when adopting: its tag tells an adoptable pin from an older build's.
    if (xdp_filter_bpf_o_len == 0) {
        return failure(XdpError::invalid_bpf_program);
    }
    if (auto status = state_.obj.open_and_load(xdp_filter_bpf_o, xdp_filter_bpf_o_len); !status) {
        return status;
    }
    auto const fds = builtin_fds(state_.obj.get());
    if (!fds) {
        return failure(XdpError::bpf_load_failed);
    }
    set_fds(fds->prog, fds->rules_map, fds->xsk_map, fds->devmap);
    return success();
}

auto XdpProgram::attach(unsigned int const if_index, std::optional<XdpAttachedProgram> const& attached, Options const& options)
    -> Status
{
    auto const plan = plan_for_attached(attached, options);
    detail::OwnedFd const displaced = displace_generic_for_native(if_index, attached, options.attach_mode);
    if (auto status = attach_by_plan(if_index, plan, displaced.get()); !status) {
        return status;
    }
    // A pin failure (no bpffs) is not fatal: the next open replaces the program in place.
    if (!options.pin_path.empty()) {
        (void)pin(options.pin_path);
    }
    state_.detach_on_close = options.detach_on_close.value_or(state_.mode == XdpAttachMode::generic);
    return success();
}

auto XdpProgram::attach_by_plan(unsigned int const if_index, detail::AttachPlan const& plan, int const displaced) noexcept -> Status
{
    auto attach_in = [&](XdpAttachMode const mode) {
        return bpf_xdp_attach(static_cast<int>(if_index), state_.prog_fd, detail::xdp_attach_flags(mode), nullptr) == 0;
    };
    if (attach_in(plan.first)) {
        state_.mode = plan.first;
    } else if (plan.fallback && attach_in(*plan.fallback)) {
        state_.mode = *plan.fallback;
    } else {
        if (displaced >= 0) {
            (void)bpf_xdp_attach(static_cast<int>(if_index), displaced, XDP_FLAGS_SKB_MODE, nullptr);
        }
        return failure(XdpError::bpf_attach_failed);
    }
    state_.attached = true;
    if (auto const identity = prog_identity(state_.prog_fd)) {
        state_.prog_id = identity->id;
    }
    return success();
}

void XdpProgram::close() noexcept
{
    if (state_.detach_on_close && (state_.attached || state_.adopted) && state_.prog_fd >= 0) {
        // Only if it is still ours: XDP_FLAGS_REPLACE against our program.
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = state_.prog_fd);
        (void)bpf_xdp_detach(static_cast<int>(state_.if_index), detail::xdp_attach_flags(state_.mode), &opts);
        remove_pins(state_.pin_path);
    }
    state_ = State{};
}

auto XdpProgram::register_socket(uint32_t queue_id, int const xsk_fd) -> Status
{
    if (bpf_map_update_elem(state_.xsk_map_fd, &queue_id, &xsk_fd, BPF_ANY) != 0) {
        return failure(XdpError::bpf_map_update_failed);
    }
    return success();
}

auto XdpProgram::register_tap(unsigned int tap_ifindex) -> Status
{
    uint32_t zero_key = 0;
    if (bpf_map_update_elem(state_.devmap_fd, &zero_key, &tap_ifindex, BPF_ANY) != 0) {
        return failure(XdpError::bpf_map_update_failed);
    }
    return success();
}

auto XdpProgram::install_tcam_rules(std::span<CompiledRule<32> const> rules) -> Status
{
    auto catch_all = catch_all_rule_for(state_.default_action);
    std::size_t const extra = catch_all.has_value() ? 1U : 0U;
    if (rules.size() + extra > TCAM_MAX_RULES) {
        return failure(XdpError::too_many_filter_rules);
    }

    auto write_slot = [this](std::uint32_t index, CompiledRule<32> const& rule) -> Status {
        if (bpf_map_update_elem(state_.rules_map_fd, &index, &rule, BPF_ANY) != 0) {
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

auto XdpSocket::open(XdpConfig const& config, XdpAttachMode const attached) -> Status
{
    close();
    auto const bind_flags = detail::xdp_bind_flags(config.bind_mode, attached, config.need_wakeup);
    if (!bind_flags) {
        return failure(bind_flags.error());
    }
    if (auto status = bind_queue(config, *bind_flags); !status) {
        return status;
    }
    record_bind(config, attached);
    return success();
}

auto XdpSocket::bind_queue(XdpConfig const& config, uint16_t const bind_flags) -> Status
{
    struct xsk_socket_config const xsk_cfg{
        .rx_size = static_cast<__u32>(config.rx_ring_size),
        .tx_size = static_cast<__u32>(config.tx_ring_size),
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = bind_flags,
    };
    std::string const ifname_str(config.interface_name);
    // The kernel frees a closed socket's hold on its queue later (an RCU grace
    // period and a work item), so a bind right after a close can see EBUSY.
    for (size_t attempt = 0;; ++attempt) {
        auto const bound = create_once(config, ifname_str, xsk_cfg);
        if (!bound) {
            return failure(bound.error());
        }
        if (*bound) {
            return success();
        }
        if (attempt == BIND_BUSY_RETRIES) {
            return failure(XdpError::xsk_creation_failed);
        }
        struct timespec const pause{.tv_sec = 0, .tv_nsec = BIND_BUSY_PAUSE_NS};
        (void)::nanosleep(&pause, nullptr);
    }
}

auto XdpSocket::create_once(XdpConfig const& config, std::string const& ifname, xsk_socket_config const& xsk_cfg)
    -> StatusValue<bool>
{
    // A failed create leaves its UMEM's rings configured: each attempt starts from a fresh UMEM.
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
    int const ret = xsk_socket__create(&xsk_, ifname.c_str(), config.queue_id, *umem_result, &rings_.rx, &rings_.tx, &xsk_cfg);
    if (ret != 0) {
        xsk_ = nullptr;
        close();
    }
    if (ret != 0 && ret != -EBUSY) {
        return failure(XdpError::xsk_creation_failed);
    }
    return ret == 0;
}

void XdpSocket::record_bind(XdpConfig const& config, XdpAttachMode const attached) noexcept
{
    bind_mode_ = config.bind_mode;
    need_wakeup_ = config.need_wakeup;
    // Zero-copy only under a native program (a generic one never gets the driver's rings).
    zero_copy_ = bound_zero_copy(xsk_socket__fd(xsk_)) && attached == XdpAttachMode::native;
    budget_.rx_drain_max = config.rx_drain_max;
    budget_.completion_drain_max = config.completion_drain_max;
    budget_.rx_clock_id = config.rx_clock_id;
}

void XdpSocket::close() noexcept
{
    if (xsk_ != nullptr) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }
    umem_.close();
    rings_ = {};
    budget_ = {};
    stats_ = {};
    bind_mode_ = XdpBindMode::auto_;
    zero_copy_ = false;
    need_wakeup_ = false;
}

auto XdpSocket::tx_commit(uint64_t handle, size_t frame_length) -> Status
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
    return success();
}

auto XdpSocket::tx_flush() -> Status
{
    if (xsk_ == nullptr) {
        return failure(XdpError::not_open);
    }
    // Descriptors the kernel has not consumed yet (copy mode sends at most a
    // batch per kick, so some may be left from the last one).
    if (*rings_.tx.producer - __atomic_load_n(rings_.tx.consumer, __ATOMIC_ACQUIRE) == 0 ||
        (need_wakeup_ && !xsk_ring_prod__needs_wakeup(&rings_.tx))) {
        ++stats_.tx_flush_skipped;
        return success();
    }
    ++stats_.tx_flush_count;
    auto const ret = ::sendto(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
    if (ret < 0 && detail::is_transient_kick_error(errno)) {
        ++stats_.tx_flush_transient;
    } else if (ret < 0) {
        ++stats_.tx_flush_failed;
        stats_.tx_flush_errno = errno;
        return failure(XdpError::tx_flush_failed);
    }
    return success();
}

auto XdpSocket::tx_complete() -> Status
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

auto XdpSocket::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
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

    int64_t timestamp_ns = 0;
    if (budget_.rx_clock_id >= 0) {
        struct timespec ts{};
        (void)::clock_gettime(budget_.rx_clock_id, &ts);
        timestamp_ns = (static_cast<int64_t>(ts.tv_sec) * 1'000'000'000) + ts.tv_nsec;
    }

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

auto XdpSocket::fill_replenish() -> Status
{
    auto available = umem_.available_frames();
    if (available != 0) {
        auto const count = detail::fill_reserve_count(available, xsk_prod_nb_free(&rings_.fill, static_cast<uint32_t>(available)));
        if (count != 0) {
            uint32_t idx = 0;
            auto reserved = xsk_ring_prod__reserve(&rings_.fill, count, &idx);
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
        }
    }
    // The driver ran out of fill entries and stopped: wake it.
    if (need_wakeup_ && xsk_ != nullptr && xsk_ring_prod__needs_wakeup(&rings_.fill)) {
        ++stats_.rx_wakeup_count;
        (void)::recvfrom(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
    }
    return success();
}

auto XdpContext::open(XdpConfig const& config) -> Status
{
    close();

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

    // Step 2: The program: zero-copy needs it native, with no fallback.
    auto const plan = detail::attach_plan(config.attach_mode, config.bind_mode);
    if (!plan) {
        close();
        return failure(plan.error());
    }
    if (auto status = program_.open(
            interface_.index,
            {
                .filter_rules = config.filter_rules,
                .default_action = config.default_action,
                .attach_mode = plan->first,
                .allow_generic_fallback = plan->fallback.has_value(),
                .pin_path = config.pin_path,
                .adopt = config.adopt,
                .detach_on_close = config.detach_on_close,
            });
        !status) {
        close();
        return status;
    }

    // Step 3: The socket, its bind decided by the mode the program got.
    if (auto status = socket_.open(config, program_.attach_mode()); !status) {
        close();
        return status;
    }

    // Step 4: Register the socket (and the TAP device if requested)
    if (auto status = program_.register_socket(config.queue_id, socket_.fd()); !status) {
        close();
        return status;
    }
    if (config.tap_ifindex != 0) {
        if (auto status = program_.register_tap(config.tap_ifindex); !status) {
            close();
            return status;
        }
    }

    // Step 5: Initial fill
    if (auto fill_status = socket_.fill_replenish(); !fill_status) {
        close();
        return fill_status;
    }

    return success();
}

void XdpContext::close() noexcept
{
    socket_.close();
    program_.close();
    interface_ = {};
}

auto XdpContext::multicast_ioctl(unsigned long const request, ieee::Eui48 const& addr, XdpError const error) -> Status
{
    if (!socket_.valid()) {
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

    if (::ioctl(sock_fd, request, &ifr) < 0) {
        return failure(error);
    }

    return success();
}

auto XdpContext::join_multicast(ieee::Eui48 const& addr) -> Status
{
    return multicast_ioctl(SIOCADDMULTI, addr, XdpError::join_multicast_failed);
}

auto XdpContext::leave_multicast(ieee::Eui48 const& addr) -> Status
{
    return multicast_ioctl(SIOCDELMULTI, addr, XdpError::leave_multicast_failed);
}

#endif  // __linux__ && HAVE_XDP

}  // namespace statusbar::net
