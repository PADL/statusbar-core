#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>

namespace statusbar::itc {

// Cache line size used to separate fields written by different threads,
// avoiding false sharing. 64 bytes is the line size on every architecture
// this project currently targets (x86_64, AArch64 little/big cores at L1).
// Some big.LITTLE designs use 128-byte lines on the big cluster; if that
// becomes relevant, bump this and rebuild — there are no other places that
// embed assumptions about the value.
//
// std::hardware_destructive_interference_size would be the standard answer
// but its libc++ implementation status is uneven (Apple Clang in particular
// does not expose it reliably), so we use a hard constant.
inline constexpr size_t cache_line_bytes = 64;

// MessagePipe — typed, lock-free, single-producer/single-consumer message
// channel between rate domains.
//
// Three policies are supported. Each policy has its own template
// specialization since the storage and operations differ; the policy enum
// exists only to pick the specialization at instantiation time.
//
//   Policy::LatestWins  — Capacity must be 2 (ping/pong). Producer overwrites
//                         the inactive slot; consumer reads the most-recently
//                         committed slot. Stale messages are silently dropped.
//                         Fits the audio-rate coefficient delivery case where
//                         a delayed segment is useless — Tier 1 only needs the
//                         freshest one.
//
//   Policy::Fifo        — Capacity N. Producer enqueues at the tail; consumer
//                         dequeues from the head. Order-preserving. Fits a
//                         "list of pending commands" case.
//
//   Policy::Timestamped — Capacity N FIFO with activation times. Consumer pops
//                         only entries whose activation time has elapsed. Fits
//                         the network-receiving case where a controller can
//                         schedule "fade to -3 dB starting at PTP time T".
//
// API contract (uniform across all policies):
//
//   Producer side:
//     can_publish()      — non-mutating check; returns true when publish()
//                          will succeed. Cheap to call.
//     publish(m)         — commit the message. Precondition: can_publish()
//                          returned true.
//     try_publish(m)     — convenience wrapper returning whether the
//                          publish actually happened.
//
//   Consumer side:
//     can_consume()      — non-mutating check; returns true when consume()
//                          will return a valid value.
//     consume() -> Msg   — pop and return the next message. Precondition:
//                          can_consume() returned true.
//     try_consume()      — returns std::optional<Msg>: engaged with the
//          -> optional     message if one was available, std::nullopt
//                          otherwise. Inner workings are duplicated from
//                          consume() rather than wrapping it, so the empty
//                          path doesn't construct a Msg and the engaged
//                          path returns directly into the optional via
//                          mandatory copy elision.
//
//   For Policy::Timestamped, additionally:
//     can_consume_due(now_ns)         — emptiness + activation-time check.
//     try_consume_due(now_ns)         — std::optional<Msg> version of the
//          -> optional<Msg>             above.

enum class Policy : uint8_t
{
    LatestWins,
    Fifo,
    Timestamped
};

template <typename Msg, size_t Capacity, Policy P>
struct MessagePipe;

// ─────────────────────────────────────────────────────────────────────────────
// LatestWins specialization: 2-slot ping/pong.
//
// Implementation uses a 3-slot triple-buffer to guarantee neither side ever
// reads or writes a slot in use by the other, without retries. The producer
// owns one slot at any time (`producer_slot_`); the consumer owns one slot
// (`consumer_slot_`); the third is the "ready" slot containing the latest
// committed value. Publish and snapshot each atomically swap their owned
// slot index with the ready index.
//
// Lock-free, wait-free for both sides. Producer's commit and consumer's
// snapshot each compile to a single atomic exchange on the index.
// ─────────────────────────────────────────────────────────────────────────────

template <typename Msg>
struct MessagePipe<Msg, 2, Policy::LatestWins>
{
    static_assert(
        std::is_trivially_copyable_v<Msg>,
        "LatestWins requires trivially-copyable Msg for the inner "
        "swap to be safe and zero-cost");

    MessagePipe() noexcept = default;

    MessagePipe(MessagePipe const&) = delete;
    auto operator=(MessagePipe const&) -> MessagePipe& = delete;

    // ── Producer side ────────────────────────────────────────────────────

    // LatestWins always has room — the producer just overwrites the staging
    // slot and atomic-swaps it with the ready slot. Provided as a non-static
    // member for API uniformity with QueuedPipe / TimedPipe whose can_publish
    // depends on instance state.
    [[nodiscard]] auto can_publish() const noexcept -> bool { return true; }

    // Precondition: can_publish() returned true (always true for LatestWins).
    void publish(Msg const& m) noexcept
    {
        size_t const ps = producer_slot_.load(std::memory_order_relaxed);
        slots_[ps] = m;
        // Tag the slot with a monotonically increasing publish sequence. The
        // consumer uses it to reject a stale slot it may grab when a publish
        // races its exchange, so it never delivers an already-superseded value.
        // Written before the release-exchange below, so it's visible whenever
        // the slot's data is.
        uint64_t const seq = next_seq_.load(std::memory_order_relaxed) + 1;
        next_seq_.store(seq, std::memory_order_relaxed);
        slot_seq_[ps].store(seq, std::memory_order_relaxed);
        // Atomically swap producer's owned slot with the ready slot. The
        // returned value (the previous ready slot) becomes our next staging
        // slot to write into.
        producer_slot_.store(ready_idx_.exchange(ps, std::memory_order_acq_rel), std::memory_order_relaxed);
        // Bump the generation last so consumer's acquire pairs with it.
        gen_.fetch_add(1, std::memory_order_release);
    }

    [[nodiscard]] auto try_publish(Msg const& m) noexcept -> bool
    {
        if (!can_publish()) {
            return false;
        }
        publish(m);
        return true;
    }

    // ── Consumer side ────────────────────────────────────────────────────

    // Returns true only if a fresh value has been published since the last
    // successful consume (or since construction). This is the engine's
    // freeze-on-miss enabler: no new segment ⇒ can_consume() false ⇒ caller
    // holds previous state.
    [[nodiscard]] auto can_consume() const noexcept -> bool
    {
        return gen_.load(std::memory_order_acquire) != last_seen_gen_.load(std::memory_order_relaxed);
    }

    // Precondition: can_consume() returned true. Returns the latest
    // committed value and updates the generation watermark so the next
    // can_consume() returns false until another publish happens.
    [[nodiscard]] auto consume() noexcept -> Msg
    {
        size_t const cs = consumer_slot_.load(std::memory_order_relaxed);
        size_t const new_cs = ready_idx_.exchange(cs, std::memory_order_acq_rel);
        last_seen_gen_.store(gen_.load(std::memory_order_acquire), std::memory_order_relaxed);
        consumer_slot_.store(new_cs, std::memory_order_relaxed);
        // If a racing publish left us holding a slot no newer than the last one
        // delivered, freeze on the previous value rather than snapping backwards
        // to a superseded one.
        uint64_t const seq = slot_seq_[new_cs].load(std::memory_order_relaxed);
        if (seq > last_delivered_seq_) {
            last_delivered_seq_ = seq;
            last_msg_ = slots_[new_cs];
        }
        return last_msg_;
    }

    // Inner workings duplicated from consume() so the empty path doesn't
    // construct a Msg and the engaged path returns directly into the
    // optional storage via mandatory copy elision.
    [[nodiscard]] auto try_consume() noexcept -> std::optional<Msg>
    {
        if (gen_.load(std::memory_order_acquire) == last_seen_gen_.load(std::memory_order_relaxed)) {
            return std::nullopt;
        }
        size_t const cs = consumer_slot_.load(std::memory_order_relaxed);
        size_t const new_cs = ready_idx_.exchange(cs, std::memory_order_acq_rel);
        last_seen_gen_.store(gen_.load(std::memory_order_acquire), std::memory_order_relaxed);
        consumer_slot_.store(new_cs, std::memory_order_relaxed);
        // A publish racing this exchange can hand us a slot no newer than the
        // last delivered; report "nothing new" (freeze) rather than snapping
        // backwards to a superseded value. The seq tag, not the generation
        // counter, is the authoritative monotonicity gate.
        uint64_t const seq = slot_seq_[new_cs].load(std::memory_order_relaxed);
        if (seq <= last_delivered_seq_) {
            return std::nullopt;
        }
        last_delivered_seq_ = seq;
        last_msg_ = slots_[new_cs];
        return last_msg_;
    }

  private:
    // ready_idx_ and gen_ cross thread boundaries — they need real
    // synchronization (acq_rel exchange / acquire load).
    //
    // producer_slot_, consumer_slot_, last_seen_gen_ are touched by exactly
    // one thread each (the SPSC contract), so plain non-atomic types would
    // be safe. They are nevertheless declared atomic with relaxed ordering
    // to keep ThreadSanitizer and static analyzers happy without adding
    // measurable cost — relaxed load/store on an aligned size_t is the
    // same machine code as a regular load/store on x86_64 / AArch64.
    std::array<Msg, 3> slots_{};
    // Per-slot publish sequence, cross-thread: producer writes before its
    // release-exchange, consumer reads after acquiring the slot. Relaxed —
    // ordering rides on ready_idx_.
    std::array<std::atomic<uint64_t>, 3> slot_seq_{};
    std::atomic<size_t> ready_idx_{2};
    std::atomic<size_t> gen_{0};
    std::atomic<size_t> producer_slot_{0};
    std::atomic<size_t> consumer_slot_{1};
    std::atomic<size_t> last_seen_gen_{0};
    std::atomic<uint64_t> next_seq_{0};  // producer-only
    uint64_t last_delivered_seq_{0};     // consumer-only
    Msg last_msg_{};                     // consumer-only; last value delivered (freeze target)
};

// ─────────────────────────────────────────────────────────────────────────────
// Fifo specialization: bounded SPSC ring buffer.
//
// Standard wait-free SPSC FIFO using two atomic indices. Producer writes to
// slots[tail_], advances tail_; consumer reads from slots[head_], advances
// head_. Capacity N must be a power of two so the modulus folds to a mask.
//
// Rejects new entries when full (try_publish returns false). The producer
// chooses the loss policy by deciding what to do on a false return.
// ─────────────────────────────────────────────────────────────────────────────

template <typename Msg, size_t N>
struct MessagePipe<Msg, N, Policy::Fifo>
{
    static_assert(N >= 2 && (N & (N - 1)) == 0, "Fifo capacity must be a power of two ≥ 2");
    static_assert(std::is_trivially_copyable_v<Msg>, "Fifo requires trivially-copyable Msg");

    MessagePipe() noexcept = default;
    MessagePipe(MessagePipe const&) = delete;
    auto operator=(MessagePipe const&) -> MessagePipe& = delete;

    // ── Producer side ────────────────────────────────────────────────────

    [[nodiscard]] auto can_publish() const noexcept -> bool
    {
        size_t const t = tail_.load(std::memory_order_relaxed);
        size_t const next_t = (t + 1) & mask_;
        return next_t != head_.load(std::memory_order_acquire);
    }

    // Precondition: can_publish() returned true.
    void publish(Msg const& m) noexcept
    {
        size_t const t = tail_.load(std::memory_order_relaxed);
        slots_[t] = m;
        tail_.store((t + 1) & mask_, std::memory_order_release);
    }

    [[nodiscard]] auto try_publish(Msg const& m) noexcept -> bool
    {
        if (!can_publish()) {
            return false;
        }
        publish(m);
        return true;
    }

    // ── Consumer side ────────────────────────────────────────────────────

    [[nodiscard]] auto can_consume() const noexcept -> bool { return !empty(); }

    // Precondition: can_consume() returned true.
    [[nodiscard]] auto consume() noexcept -> Msg
    {
        size_t const h = head_.load(std::memory_order_relaxed);
        Msg const m = slots_[h];
        head_.store((h + 1) & mask_, std::memory_order_release);
        return m;
    }

    [[nodiscard]] auto try_consume() noexcept -> std::optional<Msg>
    {
        size_t const h = head_.load(std::memory_order_relaxed);
        if (h == tail_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        Msg const m = slots_[h];
        head_.store((h + 1) & mask_, std::memory_order_release);
        return m;
    }

    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

  private:
    static constexpr size_t mask_ = N - 1;
    std::array<Msg, N> slots_{};
    // head_ and tail_ live on separate cache lines: tail_ is written by the
    // producer and read by the consumer (for can_publish full-check); head_
    // is written by the consumer and read by the producer. Sharing a line
    // would cause cache-coherence ping-pong between the two cores at every
    // publish/consume.
    alignas(cache_line_bytes) std::atomic<size_t> head_{0};
    alignas(cache_line_bytes) std::atomic<size_t> tail_{0};
};

// ─────────────────────────────────────────────────────────────────────────────
// Timestamped specialization: SPSC FIFO with per-entry activation times.
//
// Producer enqueues entries with an activation time (typically a monotonic
// clock or PTP nanosecond count). Consumer's try_consume_due returns the
// head only if its activation time has elapsed; otherwise nothing is consumed
// and the consumer can check again later.
//
// Entries are delivered in enqueue order. The producer is expected to enqueue
// in non-decreasing activation-time order — out-of-order enqueues are
// permitted but the FIFO will not reorder them, so an early-time entry
// enqueued after a late-time entry will be held back until its predecessor
// is consumed.
// ─────────────────────────────────────────────────────────────────────────────

template <typename Msg, size_t N>
struct MessagePipe<Msg, N, Policy::Timestamped>
{
    static_assert(N >= 2 && (N & (N - 1)) == 0, "Timestamped capacity must be a power of two ≥ 2");
    static_assert(std::is_trivially_copyable_v<Msg>, "Timestamped requires trivially-copyable Msg");

    struct Entry
    {
        uint64_t activate_at_ns;
        Msg payload;
    };

    MessagePipe() noexcept = default;
    MessagePipe(MessagePipe const&) = delete;
    auto operator=(MessagePipe const&) -> MessagePipe& = delete;

    // ── Producer side ────────────────────────────────────────────────────

    [[nodiscard]] auto can_publish() const noexcept -> bool
    {
        size_t const t = tail_.load(std::memory_order_relaxed);
        size_t const next_t = (t + 1) & mask_;
        return next_t != head_.load(std::memory_order_acquire);
    }

    // Precondition: can_publish() returned true.
    void publish(uint64_t activate_at_ns, Msg const& m) noexcept
    {
        size_t const t = tail_.load(std::memory_order_relaxed);
        slots_[t].activate_at_ns = activate_at_ns;
        slots_[t].payload = m;
        tail_.store((t + 1) & mask_, std::memory_order_release);
    }

    [[nodiscard]] auto try_publish(uint64_t activate_at_ns, Msg const& m) noexcept -> bool
    {
        if (!can_publish()) {
            return false;
        }
        publish(activate_at_ns, m);
        return true;
    }

    // ── Consumer side ────────────────────────────────────────────────────

    // Pure emptiness check — does NOT consider activation time.
    [[nodiscard]] auto can_consume() const noexcept -> bool { return !empty(); }

    // Emptiness AND activation-time check — true when the head entry exists
    // and its activation time has elapsed.
    [[nodiscard]] auto can_consume_due(uint64_t now_ns) const noexcept -> bool
    {
        size_t const h = head_.load(std::memory_order_acquire);
        if (h == tail_.load(std::memory_order_acquire)) {
            return false;
        }
        return slots_[h].activate_at_ns <= now_ns;
    }

    // Precondition: can_consume() (or can_consume_due(now_ns)) returned true.
    // Pops and returns the head's payload regardless of activation time —
    // the activation gating is done by the caller via can_consume_due.
    [[nodiscard]] auto consume() noexcept -> Msg
    {
        size_t const h = head_.load(std::memory_order_relaxed);
        Msg const m = slots_[h].payload;
        head_.store((h + 1) & mask_, std::memory_order_release);
        return m;
    }

    [[nodiscard]] auto try_consume() noexcept -> std::optional<Msg>
    {
        size_t const h = head_.load(std::memory_order_relaxed);
        if (h == tail_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        Msg const m = slots_[h].payload;
        head_.store((h + 1) & mask_, std::memory_order_release);
        return m;
    }

    [[nodiscard]] auto try_consume_due(uint64_t now_ns) noexcept -> std::optional<Msg>
    {
        size_t const h = head_.load(std::memory_order_relaxed);
        if (h == tail_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        if (slots_[h].activate_at_ns > now_ns) {
            return std::nullopt;
        }
        Msg const m = slots_[h].payload;
        head_.store((h + 1) & mask_, std::memory_order_release);
        return m;
    }

    // Activation time of the head entry, or nullopt if empty. Useful for
    // "sleep until next due time" patterns.
    [[nodiscard]] auto peek_activation_time() const noexcept -> std::optional<uint64_t>
    {
        size_t const h = head_.load(std::memory_order_acquire);
        if (h == tail_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        return slots_[h].activate_at_ns;
    }

    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

  private:
    static constexpr size_t mask_ = N - 1;
    std::array<Entry, N> slots_{};
    // See comment on QueuedPipe — head_ and tail_ get their own cache lines
    // to avoid producer/consumer false sharing.
    alignas(cache_line_bytes) std::atomic<size_t> head_{0};
    alignas(cache_line_bytes) std::atomic<size_t> tail_{0};
};

// ─────────────────────────────────────────────────────────────────────────────
// Convenience aliases that hide the policy parameter.
// ─────────────────────────────────────────────────────────────────────────────

template <typename Msg>
using LatestPipe = MessagePipe<Msg, 2, Policy::LatestWins>;

template <typename Msg, size_t N>
using QueuedPipe = MessagePipe<Msg, N, Policy::Fifo>;

template <typename Msg, size_t N>
using TimedPipe = MessagePipe<Msg, N, Policy::Timestamped>;

}  // namespace statusbar::itc
