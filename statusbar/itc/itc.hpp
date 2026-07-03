#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// statusbar::itc — inter-thread communication primitives: small typed
/// synchronization wrappers, the wait-free triple buffer, and the
/// MessagePipe family. Bare atomic ops should only appear inside the
/// implementation of an inter-thread channel; this module is where the
/// named-API wrappers for the common patterns live.

#include "statusbar/itc/itc_atomic_triple_buffer.hpp"
#include "statusbar/itc/itc_atomic_triple_buffer_base.hpp"
#include "statusbar/itc/itc_message_pipe.hpp"
#include "statusbar/itc/itc_published.hpp"
#include "statusbar/itc/itc_rt_callback_slot.hpp"
#include "statusbar/itc/itc_spin_lock.hpp"
#include "statusbar/itc/itc_stop_token.hpp"
#include "statusbar/itc/itc_telemetry_counter.hpp"
