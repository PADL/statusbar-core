// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_any_ethernet_port.hpp"

#include "statusbar/net/net_error.hpp"

namespace statusbar::net {

namespace {

// Every forwarded call has the same shape: closed is not_connected (or the
// closed value), anything else goes to the backend.
template <typename Variant, typename Fn>
auto on_port(Variant& port, Fn&& fn) -> decltype(fn(std::declval<RawnetPort&>()))
{
    using Result = decltype(fn(std::declval<RawnetPort&>()));
    return std::visit(
        [&](auto& backend) -> Result {
            if constexpr (std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                return failure(NetError::not_connected);
            } else {
                return fn(backend);
            }
        },
        port);
}

auto rawnet_config_from(AnyEthernetPortConfig const& config) -> RawnetPortConfig
{
    return RawnetPortConfig{
        .interface_name = config.interface_name,
        .ethertype = config.ethertype,
        .priority = config.priority,
        .rx_clock_id = config.rx_clock_id,
    };
}

auto mmap_config_from(AnyEthernetPortConfig const& config) -> MmapConfig
{
    return MmapConfig{
        .interface_name = config.interface_name,
        .ethertype = config.ethertype,
        .priority = config.priority < 0 ? 0U : static_cast<uint32_t>(config.priority),
        .rx_queue_size = config.ring_size,
        .tx_queue_size = config.ring_size,
        .rx_clock_id = config.rx_clock_id,
    };
}

auto xdp_config_from(AnyEthernetPortConfig const& config) -> XdpConfig
{
    return XdpConfig{
        .interface_name = config.interface_name,
        .filter_rules = config.xdp_filter_rules,
        .queue_id = config.xdp_queue_id,
        .rx_ring_size = config.ring_size,
        .tx_ring_size = config.ring_size,
        .fill_ring_size = config.ring_size * 2,
        .completion_ring_size = config.ring_size * 2,
        .rx_clock_id = config.rx_clock_id,
        .tx_launch_time = config.xdp_tx_launch_time,
        .bind_mode = config.xdp_bind_mode,
        .attach_mode = config.xdp_attach_mode,
        .pin_path = config.xdp_pin_path,
    };
}

}  // namespace

auto AnyEthernetPort::open(EthernetBackend const backend, AnyEthernetPortConfig const& config) -> Status
{
    close();
    auto status = open_backend(backend, config);
    if (!status) {
        close();
    }
    return status;
}

auto AnyEthernetPort::open_backend(EthernetBackend const backend, AnyEthernetPortConfig const& config) -> Status
{
    switch (backend) {
        case EthernetBackend::rawnet:
            return port_.emplace<RawnetPort>().open(rawnet_config_from(config));
        case EthernetBackend::mmap:
            return port_.emplace<MmapContext>().open(mmap_config_from(config));
        case EthernetBackend::xdp:
            return port_.emplace<XdpContext>().open(xdp_config_from(config));
    }
    return failure(NetError::invalid_argument);
}

void AnyEthernetPort::close() noexcept
{
    port_.emplace<std::monostate>();
}

auto AnyEthernetPort::backend() const noexcept -> std::optional<EthernetBackend>
{
    switch (port_.index()) {
        case 1:
            return EthernetBackend::rawnet;
        case 2:
            return EthernetBackend::mmap;
        case 3:
            return EthernetBackend::xdp;
        default:
            return std::nullopt;
    }
}

auto AnyEthernetPort::tx_rx_independent() const noexcept -> bool
{
    return std::holds_alternative<RawnetPort>(port_);
}

auto AnyEthernetPort::describe() const -> std::string
{
    if (auto const* xdp = as<XdpContext>(); xdp != nullptr) {
        std::string out{"xdp ("};
        out += xdp->attach_mode() == XdpAttachMode::native ? "native" : "generic";
        out += xdp->zero_copy() ? ", zero-copy)" : ", copy)";
        return out;
    }
    if (as<MmapContext>() != nullptr) {
        return "mmap (PACKET_MMAP rings)";
    }
    if (as<RawnetPort>() != nullptr) {
        return "rawnet (AF_PACKET, two sockets)";
    }
    return "closed";
}

auto AnyEthernetPort::valid() const noexcept -> bool
{
    return std::visit(
        [](auto const& backend) -> bool {
            if constexpr (std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                return false;
            } else {
                return backend.valid();
            }
        },
        port_);
}

auto AnyEthernetPort::fd() const noexcept -> int
{
    return std::visit(
        [](auto const& backend) -> int {
            if constexpr (std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                return -1;
            } else {
                return backend.fd();
            }
        },
        port_);
}

auto AnyEthernetPort::hardware_address() const noexcept -> ieee::Eui48 const&
{
    static ieee::Eui48 const none{};
    return std::visit(
        [](auto const& backend) -> ieee::Eui48 const& {
            if constexpr (std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                return none;
            } else {
                return backend.hardware_address();
            }
        },
        port_);
}

auto AnyEthernetPort::interface_index() const noexcept -> unsigned int
{
    return std::visit(
        [](auto const& backend) -> unsigned int {
            if constexpr (std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                return 0U;
            } else {
                return backend.interface_index();
            }
        },
        port_);
}

auto AnyEthernetPort::tx_start(int64_t const launch_time_ns) -> StatusValue<EthernetTxSlot>
{
    return on_port(port_, [&](auto& backend) -> StatusValue<EthernetTxSlot> { return backend.tx_start(launch_time_ns); });
}

auto AnyEthernetPort::tx_commit(uint64_t const handle, size_t const frame_length) -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.tx_commit(handle, frame_length); });
}

auto AnyEthernetPort::tx_cancel(uint64_t const handle) -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.tx_cancel(handle); });
}

auto AnyEthernetPort::tx_flush() -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.tx_flush(); });
}

auto AnyEthernetPort::rx_start() -> StatusValue<std::optional<EthernetRxSlot>>
{
    return on_port(port_, [&](auto& backend) -> StatusValue<std::optional<EthernetRxSlot>> { return backend.rx_start(); });
}

auto AnyEthernetPort::rx_release(uint64_t const handle) -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.rx_release(handle); });
}

auto AnyEthernetPort::join_multicast(ieee::Eui48 const& addr) -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.join_multicast(addr); });
}

auto AnyEthernetPort::leave_multicast(ieee::Eui48 const& addr) -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.leave_multicast(addr); });
}

void AnyEthernetPort::begin_cycle() noexcept
{
    std::visit(
        [](auto& backend) {
            if constexpr (!std::is_same_v<std::decay_t<decltype(backend)>, std::monostate>) {
                backend.begin_cycle();
            }
        },
        port_);
}

auto AnyEthernetPort::end_cycle() -> Status
{
    return on_port(port_, [&](auto& backend) -> Status { return backend.end_cycle(); });
}

}  // namespace statusbar::net
