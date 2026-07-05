[← back to module index](README.md)

# itc

Inter-thread communication primitives: small typed synchronization
wrappers, a wait-free triple buffer, the MessagePipe family, and a
cooperative stop signal.

## Overview

`itc` is the home of named-API wrappers for common cross-thread
patterns. Bare `std::atomic` operations should only appear inside
one of these channels; call sites use the wrappers so the
publish/consume contract is documented in the type.

The module covers a deliberately small set of shapes: a latest-wins
scalar (`Published<T>`), a latest-wins struct snapshot
(`AtomicTripleBuffer<T>`), a typed SPSC message channel selectable
as latest-wins / FIFO / timestamped FIFO (`MessagePipe`), a monotone
counter (`TelemetryCounter<T>`), a coherent callback-pair installer
(`RtCallbackSlot<Fn>`), and a cooperative stop signal (`StopToken`)
with a signal-handler-safe variant for SIGINT/SIGTERM. Every channel
is strictly SPSC except `Published<T>` and `TelemetryCounter<T>`,
which are one-writer / many-reader.

## Key types

- `StopToken` — atomic-flag + condition-variable stop signal. `request_stop()` (regular thread), `signal_set()` (signal-handler-safe), `wait_for_stop(timeout)` (blocks).
- `install_stop_signal()` — installs SIGINT/SIGTERM handlers driving a process-static `StopToken`; ignores SIGPIPE; idempotent.
- `Published<T>` — one-writer/many-reader latest-value scalar; release/acquire. Requires `std::atomic<T>::is_always_lock_free`.
- `AtomicTripleBuffer<T>` — wait-free SPSC triple buffer for trivially-copyable `T`. `publish` / `can_consume` / `consume` / `overruns`.
- `MessagePipe<Msg, N, Policy>` — typed SPSC channel. Aliases `LatestPipe<Msg>` (2-slot latest-wins), `QueuedPipe<Msg, N>` (FIFO), `TimedPipe<Msg, N>` (timestamped FIFO). Uniform `can_publish` / `publish` / `try_publish` / `can_consume` / `consume` / `try_consume`; `TimedPipe` adds `can_consume_due` / `try_consume_due` / `peek_activation_time`.
- `RtCallbackSlot<Fn>` — control thread `publish(fn, ctx)` / `clear()`; RT thread `load()` returns the coherent `Callback` pair. Backed by `AtomicTripleBuffer<Callback>`.
- `TelemetryCounter<T>` — `add(n)` (release fetch_add), `load()` (acquire), `reset()` (release store, not concurrent).

## Quick example

```cpp
#include "statusbar/itc/itc.hpp"

#include <cstdint>
#include <thread>

using statusbar::itc::TelemetryCounter;

int main()
{
    TelemetryCounter<uint64_t> counter;
    constexpr uint64_t k_iterations = 100000;
    std::thread producer{[&]() noexcept {
        for (uint64_t i = 0; i < k_iterations; ++i) {
            counter.add();
        }
    }};
    producer.join();
    // Reader sees release/acquire-ordered count.
    return counter.load() == k_iterations ? 0 : 1;
}
```

## Headers

- `statusbar/itc/itc.hpp` — module header pulling in every primitive below; consumers `#include` this.
- `itc_stop_token.hpp` — `StopToken`, `install_stop_signal()`.
- `itc_published.hpp` — `Published<T>`.
- `itc_atomic_triple_buffer.hpp` / `itc_atomic_triple_buffer_base.hpp` — `AtomicTripleBuffer<T>` template plus its non-template state-machine base.
- `itc_message_pipe.hpp` — `MessagePipe` plus `LatestPipe` / `QueuedPipe` / `TimedPipe` aliases.
- `itc_rt_callback_slot.hpp` — `RtCallbackSlot<Fn>`.
- `itc_telemetry_counter.hpp` — `TelemetryCounter<T>`.

## Dependencies

- **Statusbar modules:** none — `itc` is a leaf module.
- **System / external:** standard library only — `<atomic>`, `<chrono>`, `<condition_variable>`, `<mutex>`, `<array>`, `<optional>`, `<type_traits>`, `<cstdint>`, `<cstddef>`, and `<csignal>` (in the `StopToken` implementation).

## Notes & caveats

- **SPSC is strict for `AtomicTripleBuffer`, `RtCallbackSlot`, and every `MessagePipe`.** A second reader races on the front-index swap / dirty-bit clear (triple buffer) or `head_` advancement (FIFO / timestamped). Fan out higher up.
- `Published<T>` and `TelemetryCounter<T>` are the only multi-reader primitives — release/acquire. `Published<T>` is NOT a triple buffer; multi-field structs need `AtomicTripleBuffer<T>`. `TelemetryCounter<T>::reset()` is a release store, not safe against a live reader — start-of-run only.
- `StopToken::request_stop()` does flag-set then *empty* lock-of-`mu_` then `notify_all()`. The empty lock-then-unlock is load-bearing: it serializes against a waiter that has released `mu_` but isn't yet registered on the cv, which would otherwise miss the wake until its next timeout.
- `StopToken::signal_set()` is the only call safe from a POSIX signal handler — it sets just the atomic flag, no cv touch (`notify_all` isn't async-signal-safe). Sleeping waiters won't wake until their next `wait_for_stop` timeout unless a regular thread then calls `request_stop()`.
- `MessagePipe<Msg, 2, Policy::LatestWins>::publish` does `exchange(acq_rel)` on the ready slot then `fetch_add(release)` on a generation counter; consumer's `can_consume` acquire-loads that generation. Stale messages between publishes are silently dropped — that's the contract.
- FIFO and `Timestamped` need `Capacity` a power of two ≥ 2 (static-asserted). `head_`/`tail_` are `alignas(cache_line_bytes)` to avoid producer/consumer false sharing; `cache_line_bytes` is a hard 64 (libc++'s `hardware_destructive_interference_size` is unreliable). `Timestamped` does not reorder — an early activation enqueued after a late one is held back until its predecessor is consumed; producer must enqueue in non-decreasing activation order.
- `AtomicTripleBuffer<T>` needs trivially-copyable + default-constructible `T`. Default ctor is non-dirty; the initial-value ctor marks dirty so the consumer sees exactly one fresh value before any explicit `publish()`. `overruns()` is diagnostic — the publisher never blocks.
