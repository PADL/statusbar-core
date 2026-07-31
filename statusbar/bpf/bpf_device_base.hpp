#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/bpf/bpf_base.hpp"
#include "statusbar/ieee/ieee.hpp"
#include "statusbar/status/status.hpp"

#include <array>
#include <string>
#include <system_error>
#include <utility>

namespace statusbar::bpf {

/// Abstract base class for BPF device implementations
///
/// Thread-safety: This class is NOT thread-safe. If multiple threads need
/// to call receive_pdus(), external synchronization is required.
///
/// Resource management: The file descriptor is automatically closed in
/// the destructor. The class is non-copyable and non-movable.
///
/// Error handling: Use is_valid() to check if device initialized successfully.
/// All methods that can fail return Status or StatusValue<T> for error reporting.
class BpfDeviceBase
{
  public:
    /// Construct BPF device with network interface and filter parameters
    /// @param network_device Network interface name (e.g., "en0", "eth0")
    /// @param filter_params Filter configuration
    /// @param file_descriptor Open file descriptor (-1 if initialization failed)
    BpfDeviceBase(std::string network_device, FilterParams filter_params, int file_descriptor);

    virtual ~BpfDeviceBase() noexcept;

    // Delete copy and move operations
    BpfDeviceBase(BpfDeviceBase const&) = delete;
    auto operator=(BpfDeviceBase const&) -> BpfDeviceBase& = delete;
    BpfDeviceBase(BpfDeviceBase&&) = delete;
    auto operator=(BpfDeviceBase&&) -> BpfDeviceBase& = delete;

    //
    // Callback Configuration
    //
    /// Set packet reception callback
    /// @param callback Function to call when packets are received
    auto set_callback(BpfPacketCallback const& callback) { callback_ = callback; }

    /// Get current callback
    [[nodiscard]] auto callback() const -> BpfPacketCallback const& { return callback_; }

    //
    // Device Information
    //
    /// Check if device was initialized successfully
    [[nodiscard]] auto is_valid() const noexcept -> bool { return file_descriptor_ != -1; }

    /// Get raw file descriptor
    [[nodiscard]] auto file_descriptor() const noexcept -> int { return file_descriptor_; }

    /// Get network interface name
    [[nodiscard]] auto network_device() const noexcept -> std::string const& { return network_device_; }

    /// Get configured ethertype filter
    [[nodiscard]] auto ethertype() const noexcept -> uint16_t { return filter_params_.ethertype; }

    /// Get filter configuration
    [[nodiscard]] auto filter_params() const noexcept -> FilterParams const& { return filter_params_; }

    //
    // Statistics
    //
    /// Get statistics for this device
    [[nodiscard]] auto statistics() const noexcept -> BpfStatistics const& { return statistics_; }

    /// Reset statistics counters
    auto reset_statistics() noexcept { statistics_ = BpfStatistics{}; }

    //
    // Packet Reception (Pure Virtual)
    //
    /// Receive and process packets
    /// @return Status indicating success or failure
    [[nodiscard]] virtual auto receive_pdus() -> Status = 0;

    //
    // Interface Information (Virtual)
    //
    /// Get interface MTU (Maximum Transmission Unit)
    /// @return MTU size in bytes, or error
    [[nodiscard]] virtual auto get_mtu() const -> StatusValue<size_t>;

    /// Get interface MAC address
    /// @return The interface's EUI-48 MAC address, or error
    [[nodiscard]] virtual auto get_mac_address() const -> StatusValue<ieee::Eui48>;

    //
    // Configuration (Virtual)
    //
    /// Set blocking mode for read operations
    /// @param blocking true for blocking reads, false for non-blocking
    /// @return Status indicating success or failure
    [[nodiscard]] virtual auto set_blocking(bool blocking) -> Status;

    /// Check if device is in blocking mode
    /// @return true if blocking, false if non-blocking
    [[nodiscard]] virtual auto is_blocking() const -> bool;

  protected:
    // Protected access for derived classes
    auto mutable_statistics() noexcept -> BpfStatistics& { return statistics_; }

  private:
    std::string network_device_;
    FilterParams filter_params_;
    BpfPacketCallback callback_;
    int file_descriptor_;
    BpfStatistics statistics_{};
    bool blocking_{true};
};

}  // namespace statusbar::bpf
