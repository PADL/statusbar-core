#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/sg14/inplace_function.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>

namespace statusbar::bpf {

//
// Constants
//
/// Minimum Ethernet frame header size (destination MAC + source MAC + ethertype).
/// Same value as ieee::protocols::ETHERNET_HEADER_SIZE; redefined here to
/// avoid pulling the IEEE module into the BPF layer.
inline constexpr size_t ETHERNET_HEADER_MIN_SIZE = 14;

/// Default BPF buffer size (16 KB)
inline constexpr size_t bpf_buffer_size = 16384;

/// Maximum BPF device number to try on Darwin
inline constexpr int bpf_max_device_num = 255;

/// Maximum packet size returned by BPF filter
inline constexpr uint32_t bpf_filter_max_packet = 524288;  // 0x80000

//
// Error Handling
//
/// BPF-specific error codes
enum class BpfError
{
    device_not_found = 1,
    device_busy,
    set_buffer_failed,
    set_interface_failed,
    set_immediate_failed,
    set_filter_failed,
    set_promiscuous_failed,
    set_blocking_failed,
    read_failed,
    clock_failed,
    invalid_packet,
    buffer_overflow,
    interface_not_found,
    socket_creation_failed,
    bind_failed,
    invalid_file_descriptor,
    callback_exception,
    get_mtu_failed,
    get_mac_address_failed,
    operation_not_supported
};

/// Error category for BPF errors
class BpfErrorCategory : public std::error_category
{
  public:
    [[nodiscard]] auto name() const noexcept -> char const* override { return "statusbar.bpf"; }

    [[nodiscard]] auto message(int ev) const -> std::string override;
};

/// Get the singleton BPF error category
[[nodiscard]] auto bpf_error_category() noexcept -> std::error_category const&;

/// Make error_code from BpfError
[[nodiscard]] auto make_error_code(BpfError e) noexcept -> std::error_code;

//
// Time Association
//
/// Represents the correlation between BPF timestamp and system monotonic clock.
struct AcquisitionTimeAssociation
{
    int64_t bpf_time_ns;              ///< BPF device timestamp in nanoseconds
    int64_t monotonic_clock_time_ns;  ///< Corresponding CLOCK_MONOTONIC time in nanoseconds
};

//
// Statistics
//
/// Statistics for BPF device operations
struct BpfStatistics
{
    uint64_t packets_received{0};
    uint64_t packets_dropped{0};
    uint64_t read_errors{0};
    uint64_t callback_errors{0};
    uint64_t buffer_overflows{0};
};

//
// Callback Type
//
/// Callback type for packet reception. An inplace_function so the per-packet
/// hot path never touches the heap; captures must fit in 64 bytes.
/// @param frame The received Ethernet frame
/// @param time The acquisition time association
using BpfPacketCallback = statusbar::sg14::inplace_function<void(std::span<uint8_t const>, AcquisitionTimeAssociation const), 64>;

//
// Filter Configuration
//
/// Filter configuration parameters for BPF device
struct FilterParams
{
    /// EtherType to filter (e.g., 0x88f7 for IEEE 802.1AS)
    uint16_t ethertype;

    /// Enable promiscuous mode (receive all packets on network)
    bool promiscuous{false};

    /// Custom buffer size (if not set, uses bpf_buffer_size)
    std::optional<size_t> buffer_size;

    /// Read timeout (if not set, uses blocking reads)
    std::optional<std::chrono::milliseconds> read_timeout;
};

//
// RAII File Descriptor
//
/// Alias to the canonical POSIX-fd RAII wrapper. Implementation lives in
/// `statusbar/buffer/file_descriptor.hpp` so net and bpf share one type.
using FileDescriptor = ::statusbar::FileDescriptor;

}  // namespace statusbar::bpf

// Make BpfError work with std::error_code
template <>
struct std::is_error_code_enum<statusbar::bpf::BpfError> : std::true_type
{};
