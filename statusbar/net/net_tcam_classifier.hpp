#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TcamClassifier<N, Capacity> — first-match-wins linear scan of
/// CompiledRule<N> entries against the first N bytes of an Ethernet
/// frame. Scalar implementation; the inner loop is N/8 uint64_t
/// AND+CMP pairs, which modern clang/gcc auto-vectorize to NEON/AVX2
/// at -O2 when profitable.
///
/// Rules are stored in an sg14::inplace_vector, so the classifier
/// allocates exactly zero heap memory after construction — RT-safe
/// by construction. `Capacity` is the compile-time maximum rule
/// count; `set_rules` throws std::bad_alloc if the caller passes
/// more rules than that.

#include "statusbar/net/net_compiled_rule.hpp"
#include "statusbar/sg14/inplace_vector.h"

#include <cstdint>
#include <cstring>
#include <span>

namespace statusbar::net {

/// Default compile-time maximum rule count: AVB/TSN setups use 1-4 rules, a host joining 16
/// multicast groups plus a catch-all 17; 32 keeps the BPF map within a page and the classifier
/// small enough for the stack or another class.
inline constexpr std::size_t tcam_default_capacity = 32;

template <std::size_t N = tcam_default_window_bytes, std::size_t Capacity = tcam_default_capacity>
class TcamClassifier
{
  public:
    static_assert(N >= 32 && (N % 8 == 0), "invalid TCAM window size");
    static_assert(Capacity > 0, "TcamClassifier capacity must be positive");

    static constexpr std::size_t window_bytes = N;
    static constexpr std::size_t lanes = N / 8;
    static constexpr std::size_t capacity = Capacity;

    TcamClassifier() = default;

    /// Replace the rule set. Throws std::bad_alloc if `rules.size()`
    /// exceeds the compile-time `Capacity`.
    void set_rules(std::span<CompiledRule<N> const> rules, std::uint64_t default_flags = 0U)
    {
        rules_.assign(rules.begin(), rules.end());
        default_flags_ = default_flags;
    }

    /// First-match-wins evaluation. Walks rules in insertion order
    /// and returns the first matching rule's `result_flags`; later
    /// rules are not evaluated. Falls back to `default_flags_` if
    /// no rule matches. Use this when flags represent mutually-
    /// exclusive actions (process / forward_tap / drop).
    [[nodiscard]] auto classify_first(std::span<std::uint8_t const> frame) const noexcept -> std::uint64_t
    {
        if (frame.size() < N) {
            return default_flags_;
        }
        std::uint64_t w[lanes];
        std::memcpy(w, frame.data(), N);
        for (auto const& rule : rules_) {
            if (frame.size() < rule.min_frame_size) {
                continue;
            }
            if (matches(w, rule)) {
                return rule.result_flags;
            }
        }
        return default_flags_;
    }

    /// Evaluates every rule and OR-combines the `result_flags` of
    /// all matches. Falls back to `default_flags_` only when zero
    /// rules matched (the `any_match` guard distinguishes that from
    /// a matching rule whose flags happen to be 0). Use this when
    /// flags represent independent boolean attributes that can
    /// co-occur on the same frame.
    [[nodiscard]] auto classify_all(std::span<std::uint8_t const> frame) const noexcept -> std::uint64_t
    {
        if (frame.size() < N) {
            return default_flags_;
        }
        std::uint64_t w[lanes];
        std::memcpy(w, frame.data(), N);
        std::uint64_t acc = 0;
        bool any_match = false;
        for (auto const& rule : rules_) {
            if (frame.size() < rule.min_frame_size) {
                continue;
            }
            if (matches(w, rule)) {
                acc |= rule.result_flags;
                any_match = true;
            }
        }
        return any_match ? acc : default_flags_;
    }

    [[nodiscard]] auto rule_count() const noexcept -> std::size_t { return rules_.size(); }
    [[nodiscard]] auto default_flags() const noexcept -> std::uint64_t { return default_flags_; }

  private:
    static bool matches(std::uint64_t const (&w)[lanes], CompiledRule<N> const& rule) noexcept
    {
        std::uint64_t m[lanes];
        std::uint64_t c[lanes];
        std::memcpy(m, rule.mask.data(), N);
        std::memcpy(c, rule.match.data(), N);
        // Short-circuiting fold — compiler unrolls for small `lanes`
        // and produces identical assembly to the hand-rolled 4-way
        // compare the non-templated version used.
        for (std::size_t i = 0; i < lanes; ++i) {
            if ((w[i] & m[i]) != c[i]) {
                return false;
            }
        }
        return true;
    }

    sg14::inplace_vector<CompiledRule<N>, Capacity> rules_;
    std::uint64_t default_flags_{0};
};

}  // namespace statusbar::net
