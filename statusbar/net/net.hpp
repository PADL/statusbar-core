#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Network module for statusbar
/// Provides non-blocking async TCP, UDP, and raw Ethernet networking with zero allocations
///
/// This module is a modern C++23 port of the microsupport reactor pattern.
/// It supports single-threaded, event-driven networking using poll().

#include "statusbar/net/net_address.hpp"
#include "statusbar/net/net_bpf_port.hpp"
#include "statusbar/net/net_cbpf_emit.hpp"
#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/net/net_error.hpp"
#include "statusbar/net/net_ethernet_port.hpp"
#include "statusbar/net/net_loopback_port.hpp"
#include "statusbar/net/net_message_reactor.hpp"
#include "statusbar/net/net_notify.hpp"
#include "statusbar/net/net_posix_util.hpp"
#include "statusbar/net/net_raw_ethernet_pollable.hpp"
#include "statusbar/net/net_rawnet.hpp"
#include "statusbar/net/net_rawnet_filter.hpp"
#include "statusbar/net/net_ring_buffer_base.hpp"
#include "statusbar/net/net_ring_queue_base.hpp"
#include "statusbar/net/net_rss.hpp"
#include "statusbar/net/net_server_config.hpp"
#include "statusbar/net/net_socket.hpp"
#include "statusbar/net/net_tap_bridge.hpp"
#include "statusbar/net/net_tcam_classifier.hpp"
#include "statusbar/net/net_test_port.hpp"
#include "statusbar/net/net_traffic_classifier.hpp"
#include "statusbar/net/net_util.hpp"
#include "statusbar/net/net_xdp_avtp_rules.hpp"

#ifdef __linux__
#    include "statusbar/net/net_linux_mmap.hpp"
#    include "statusbar/net/net_linux_xdp.hpp"
#endif

namespace statusbar::net {}
