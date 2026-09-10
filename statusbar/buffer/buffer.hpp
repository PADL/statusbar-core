#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Umbrella header for the buffer module.
//
// Threading model: every type in this module is single-threaded. None of
// them synchronizes internally; a MutableBuffer, builder, deserializer or
// compiled serdes object must be confined to one thread or guarded by the
// caller. The protocol free functions are pure over their arguments and may
// be called concurrently on distinct buffers.

#include "statusbar/buffer/buffer_base.hpp"
#include "statusbar/buffer/buffer_deserializer_builder.hpp"
#include "statusbar/buffer/buffer_error.hpp"
#include "statusbar/buffer/buffer_mutable_buffer.hpp"
#include "statusbar/buffer/buffer_protocol.hpp"
#include "statusbar/buffer/buffer_serdes_compiled.hpp"
#include "statusbar/buffer/buffer_serializer_builder.hpp"
#include "statusbar/buffer/buffer_traits.hpp"
#include "statusbar/buffer/file_descriptor.hpp"
#include "statusbar/buffer/span_utils.hpp"
#include "statusbar/buffer/stream_utils.hpp"
