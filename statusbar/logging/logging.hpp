#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file logging.hpp
/// @brief Wait-free, allocation-free deferred-formatting logging for real-time
/// threads.
///
/// The producer side never formats, never allocates, and never blocks: a log
/// call is a verbosity gate (one relaxed atomic load), a memcpy of at most 64
/// bytes of argument values into a fixed-size entry, and a wait-free SPSC ring
/// publish (itc::QueuedPipe). All formatting and I/O happen on a consumer
/// thread, which drains entries and renders them with std::format using a
/// per-call-site decode trampoline captured at the log site.
///
/// Static-storage guarantees make the deferral safe: the format string is a
/// std::format_string (consteval — it can only bind to string literals /
/// constant expressions), and string-valued PARAMETERS are only accepted via
/// logging::lit("..."), whose consteval constructor rejects transient strings
/// at compile time. Everything else is passed by value (integers, floats,
/// bool, char), so an entry never references producer memory after publish.
///
/// Threading contract: ONE producer thread per LogChannel (the SPSC contract —
/// create one channel per thread context) and one consumer thread, normally the
/// LogCollector's. A library that needs to log takes a `logging::Logger&`; the
/// Logger is a thin non-template facade so library signatures don't carry the
/// ring-capacity template parameter.
///
/// Verbosity is a per-channel runtime setting (set_verbosity, any thread):
///   None(0) → nothing, Error(1), Warning(2), Status(3), Debug(4) — a message
/// is emitted when its level is <= the channel's verbosity.
///
/// Overflow policy: DROP, never block. When the ring is full the entry is
/// discarded and an atomic drop counter is bumped; the collector reports the
/// count as a synthesized warning line. Entries carry a per-channel sequence
/// number and a timestamp (pluggable clock, default steady-clock nanoseconds).

#include "statusbar/itc/itc_message_pipe.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>

namespace statusbar::logging {

/// Message severity. Values double as the verbosity threshold: a channel set
/// to verbosity V emits messages whose level L satisfies L <= V (None = off).
enum class LogLevel : uint8_t
{
    None = 0,
    Error = 1,
    Warning = 2,
    Status = 3,
    Debug = 4,
};

/// Immediate argument payload per entry (see LogEntry::MAX_ARG_BYTES).
inline constexpr size_t LogEntryArgBudget = 64;

/// One-letter tag for a rendered line ('E', 'W', 'S', 'D').
[[nodiscard]] constexpr auto level_char(LogLevel const level) noexcept -> char
{
    switch (level) {
        case LogLevel::Error:
            return 'E';
        case LogLevel::Warning:
            return 'W';
        case LogLevel::Status:
            return 'S';
        case LogLevel::Debug:
            return 'D';
        default:
            return '?';
    }
}

/// A pointer to a string with STATIC storage duration — the only way to pass a
/// string as a log parameter. The consteval constructor can only be evaluated
/// in a constant expression, so the argument must be a string literal (or a
/// constexpr object with static storage): passing a stack buffer, a
/// std::string's c_str(), or any other transient pointer is a compile error.
/// Construct via logging::lit("...").
class StrLit
{
  public:
    consteval StrLit(char const* s) noexcept  // NOLINT(google-explicit-constructor)
        : ptr_{s}
    {}

    [[nodiscard]] constexpr auto c_str() const noexcept -> char const* { return ptr_; }

  private:
    char const* ptr_;
};

/// Convenience spelling for a StrLit parameter: log.status("mode={}", lit("fast")).
[[nodiscard]] consteval auto lit(char const* s) noexcept -> StrLit
{
    return StrLit{s};
}

/// The runtime escape hatch for name-TABLE lookups: a pointer the CALLER
/// guarantees refers to static storage (e.g. state_string(), status-name
/// tables — string literals selected at runtime, which consteval lit() cannot
/// see). The guarantee is unchecked; never wrap a transient pointer. The loud
/// name keeps call sites greppable/reviewable.
///
/// The pointed-to string must be NUL-TERMINATED: only the data pointer is
/// stored (the entry formats it as a C string), so the string_view overload
/// must wrap a whole C string, never a substring view.
class StaticStr
{
  public:
    explicit constexpr StaticStr(char const* s) noexcept
        : ptr_{s}
    {}
    explicit constexpr StaticStr(std::string_view const s) noexcept
        : ptr_{s.data()}
    {}

    [[nodiscard]] constexpr auto c_str() const noexcept -> char const* { return ptr_; }

  private:
    char const* ptr_;
};

[[nodiscard]] constexpr auto static_str(char const* s) noexcept -> StaticStr
{
    return StaticStr{s};
}
[[nodiscard]] constexpr auto static_str(std::string_view const s) noexcept -> StaticStr
{
    return StaticStr{s};
}

/// A bounded string COPIED into the entry's 64-byte payload — for runtime
/// text that is neither a literal nor a name-table entry (resolved addresses,
/// truncated paths). No pointer is stored, so nothing can dangle; content
/// beyond N-1 characters is truncated. Budget the payload: an embedded string
/// costs its full N bytes. Construct via logging::embed<N>(text).
template <size_t N = 24>
struct ShortStr
{
    static_assert(N >= 2 && N <= LogEntryArgBudget, "ShortStr size out of range");

    constexpr ShortStr() noexcept = default;
    explicit constexpr ShortStr(std::string_view const text) noexcept
    {
        size_t const n = text.size() < N - 1 ? text.size() : N - 1;
        for (size_t i = 0; i < n; ++i) {
            chars[i] = text[i];
        }
        chars[n] = '\0';
    }

    [[nodiscard]] constexpr auto view() const noexcept -> std::string_view { return {chars.data()}; }

    std::array<char, N> chars{};
};

/// Copy up to N-1 characters of @p text into the log entry.
template <size_t N = 24>
[[nodiscard]] constexpr auto embed(std::string_view const text) noexcept -> ShortStr<N>
{
    return ShortStr<N>{text};
}

namespace detail {

template <typename T>
struct is_short_str : std::false_type
{};
template <size_t N>
struct is_short_str<ShortStr<N>> : std::true_type
{};

/// The wire type an argument is stored (and later formatted) as.
template <typename T>
struct stored
{
    static_assert(
        !std::is_pointer_v<T> && !std::is_same_v<T, std::string_view> && !std::is_same_v<T, std::string>,
        "log arguments must not be pointers or transient strings — pass "
        "integers/floats/bool/char by value, strings as logging::lit(\"...\") "
        "(static storage, compile-time enforced), or bounded copies via "
        "logging::embed<N>(text)");
    static_assert(
        std::is_arithmetic_v<T> || is_short_str<T>::value,
        "log arguments must be arithmetic (integers, floats, bool, char), "
        "logging::lit(\"...\") string literals, or logging::embed<N>(text)");
    using type = T;
};

template <>
struct stored<StrLit>
{
    using type = char const*;
};

template <>
struct stored<StaticStr>
{
    using type = char const*;
};

template <typename T>
using stored_t = typename stored<std::remove_cvref_t<T>>::type;

template <typename T>
[[nodiscard]] constexpr auto to_stored(T const& v) noexcept -> stored_t<T>
{
    if constexpr (std::is_same_v<std::remove_cvref_t<T>, StrLit> || std::is_same_v<std::remove_cvref_t<T>, StaticStr>) {
        return v.c_str();
    } else {
        return v;
    }
}

}  // namespace detail

/// Renders one entry's argument blob against its format string. Instantiated
/// per log-site argument pack; the pointer stored in the entry refers to a
/// static function, so it stays valid for the consumer forever.
using FormatFn = auto (*)(std::byte const* args, std::string_view fmt) -> std::string;

/// One fixed-size log record. Trivially copyable (the SPSC ring requirement);
/// contains no pointers into producer memory — fmt/format point at static
/// storage, and the argument VALUES live in the inline 64-byte payload.
struct LogEntry
{
    static constexpr size_t MAX_ARG_BYTES = LogEntryArgBudget;

    uint64_t seq{0};           ///< per-channel sequence number; dropped entries
                               ///< still consume one, so gaps mark where in the
                               ///< stream overflow drops occurred
    uint64_t timestamp_ns{0};  ///< channel clock at the log call (default: steady)
    char const* fmt_data{nullptr};
    uint32_t fmt_size{0};
    LogLevel level{LogLevel::None};
    uint8_t arg_bytes{0};
    FormatFn format{nullptr};
    std::array<std::byte, MAX_ARG_BYTES> args{};

    /// The (static-storage) format string.
    [[nodiscard]] auto fmt() const noexcept -> std::string_view { return {fmt_data, fmt_size}; }

    /// Render the message text (consumer side; allocates, never call on the
    /// producer thread).
    [[nodiscard]] auto message() const -> std::string
    {
        if (format == nullptr) {
            return std::string{fmt()};
        }
        return format(args.data(), fmt());
    }
};

static_assert(std::is_trivially_copyable_v<LogEntry>);

namespace detail {

/// Per-argument-pack encode/decode. encode() packs the stored values
/// back-to-back into the entry payload; format() (the static trampoline whose
/// address the entry carries) unpacks them in the same order and renders with
/// std::format. memcpy is used throughout so alignment never matters.
template <typename... Stored>
struct Codec
{
    static constexpr size_t packed_size = (size_t{0} + ... + sizeof(Stored));

    static void encode(std::byte* out, Stored const&... values) noexcept
    {
        size_t off = 0;
        ((std::memcpy(out + off, &values, sizeof(Stored)), off += sizeof(Stored)), ...);
    }

    [[nodiscard]] static auto format(std::byte const* in, std::string_view fmt) -> std::string
    {
        std::tuple<Stored...> values{};
        size_t off = 0;
        std::apply([&](auto&... v) { ((std::memcpy(&v, in + off, sizeof(v)), off += sizeof(v)), ...); }, values);
        return std::apply([&](auto&... v) { return std::vformat(fmt, std::make_format_args(v...)); }, values);
    }
};

}  // namespace detail

/// The type-erased channel interface: what a Logger publishes into and what a
/// LogCollector drains. The concrete ring capacity lives in LogChannel<N>.
class LogChannelBase
{
  public:
    /// Clock used to stamp entries. Must be async-signal/RT-safe; default is
    /// steady-clock nanoseconds (a vDSO call). Entities on a gPTP timeline can
    /// install their own.
    using ClockFn = auto (*)() noexcept -> uint64_t;

    LogChannelBase(LogChannelBase const&) = delete;
    auto operator=(LogChannelBase const&) -> LogChannelBase& = delete;
    virtual ~LogChannelBase() = default;

    /// Channel name for rendered lines (static storage via StrLit).
    [[nodiscard]] auto name() const noexcept -> char const* { return name_; }

    // ── Verbosity (any thread) ──────────────────────────────────────────────

    void set_verbosity(LogLevel const v) noexcept { verbosity_.store(static_cast<uint8_t>(v), std::memory_order_relaxed); }
    [[nodiscard]] auto verbosity() const noexcept -> LogLevel
    {
        return static_cast<LogLevel>(verbosity_.load(std::memory_order_relaxed));
    }
    /// True when a message of @p level would currently be emitted — use to
    /// skip computing expensive log arguments.
    [[nodiscard]] auto enabled(LogLevel const level) const noexcept -> bool
    {
        return static_cast<uint8_t>(level) <= verbosity_.load(std::memory_order_relaxed) && level != LogLevel::None;
    }

    /// Replace the entry-stamping clock (call before logging starts).
    void set_clock(ClockFn const clock) noexcept { clock_ = clock; }

    // ── Producer side (exactly ONE thread) ─────────────────────────────────

    /// Stamp sequence + timestamp and publish; on a full ring the entry is
    /// dropped and counted. Called by Logger — not usually directly.
    void publish(LogEntry& entry) noexcept
    {
        entry.seq = next_seq_++;
        entry.timestamp_ns = clock_();
        if (!try_publish_entry(entry)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ── Consumer side (exactly ONE thread, normally the LogCollector's) ────

    /// Pop the next entry, if any.
    [[nodiscard]] virtual auto drain_one() noexcept -> std::optional<LogEntry> = 0;

    /// Number of entries dropped since the last call (resets the counter).
    [[nodiscard]] auto take_dropped() noexcept -> uint64_t { return dropped_.exchange(0, std::memory_order_relaxed); }

  protected:
    explicit LogChannelBase(StrLit const name, LogLevel const initial_verbosity) noexcept
        : name_{name.c_str()}
        , verbosity_{static_cast<uint8_t>(initial_verbosity)}
    {}

    [[nodiscard]] virtual auto try_publish_entry(LogEntry const& entry) noexcept -> bool = 0;

  private:
    static auto default_clock() noexcept -> uint64_t;

    char const* name_;
    std::atomic<uint8_t> verbosity_;
    std::atomic<uint64_t> dropped_{0};
    uint64_t next_seq_{0};  // producer-only
    ClockFn clock_{&LogChannelBase::default_clock};
};

/// The producer facade a library takes by reference to log. Thin (one pointer)
/// and non-template, so it appears in library signatures without the ring
/// capacity. All calls must come from the channel's single producer thread.
///
/// A suppressed message costs one relaxed atomic load; an emitted one costs
/// packing at most 64 bytes of argument values and a wait-free ring publish —
/// no formatting, no allocation, no blocking. Safe inside a real-time task.
class Logger
{
  public:
    explicit Logger(LogChannelBase& channel) noexcept
        : channel_{&channel}
    {}

    [[nodiscard]] auto channel() noexcept -> LogChannelBase& { return *channel_; }
    [[nodiscard]] auto enabled(LogLevel const level) const noexcept -> bool { return channel_->enabled(level); }

    template <typename... Args>
    void error(std::format_string<detail::stored_t<Args>...> fmt, Args const&... args) noexcept
    {
        post(LogLevel::Error, fmt.get(), args...);
    }

    template <typename... Args>
    void warning(std::format_string<detail::stored_t<Args>...> fmt, Args const&... args) noexcept
    {
        post(LogLevel::Warning, fmt.get(), args...);
    }

    template <typename... Args>
    void status(std::format_string<detail::stored_t<Args>...> fmt, Args const&... args) noexcept
    {
        post(LogLevel::Status, fmt.get(), args...);
    }

    template <typename... Args>
    void debug(std::format_string<detail::stored_t<Args>...> fmt, Args const&... args) noexcept
    {
        post(LogLevel::Debug, fmt.get(), args...);
    }

  private:
    template <typename... Args>
    void post(LogLevel const level, std::string_view const fmt, Args const&... args) noexcept
    {
        using C = detail::Codec<detail::stored_t<Args>...>;
        static_assert(
            C::packed_size <= LogEntry::MAX_ARG_BYTES,
            "log arguments exceed the 64-byte immediate payload — split the "
            "message or drop arguments");
        if (!channel_->enabled(level)) {
            return;
        }
        LogEntry entry{};
        entry.fmt_data = fmt.data();
        entry.fmt_size = static_cast<uint32_t>(fmt.size());
        entry.level = level;
        entry.arg_bytes = static_cast<uint8_t>(C::packed_size);
        entry.format = &C::format;
        C::encode(entry.args.data(), detail::to_stored(args)...);
        channel_->publish(entry);
    }

    LogChannelBase* channel_;
};

inline auto LogChannelBase::default_clock() noexcept -> uint64_t
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

/// A single-producer/single-consumer log channel with a fixed-capacity ring.
/// Create one per producer thread context, with stable storage (it is pinned:
/// non-copyable, non-movable); hand `logger()` to the code that logs and
/// register the channel with the consuming LogCollector.
template <size_t Capacity = 256>
class LogChannel final : public LogChannelBase
{
    static_assert(Capacity >= 2 && (Capacity & (Capacity - 1)) == 0, "LogChannel capacity must be a power of two >= 2");

  public:
    explicit LogChannel(StrLit const name, LogLevel const initial_verbosity = LogLevel::Status) noexcept
        : LogChannelBase{name, initial_verbosity}
    {}

    /// The producer-side facade (single thread; see class comment).
    [[nodiscard]] auto logger() noexcept -> Logger { return Logger{*this}; }

    [[nodiscard]] auto drain_one() noexcept -> std::optional<LogEntry> override { return pipe_.try_consume(); }

  private:
    [[nodiscard]] auto try_publish_entry(LogEntry const& entry) noexcept -> bool override { return pipe_.try_publish(entry); }

    itc::QueuedPipe<LogEntry, Capacity> pipe_;
};

}  // namespace statusbar::logging

/// Render an embedded ShortStr exactly like a string.
template <size_t N>
struct std::formatter<statusbar::logging::ShortStr<N>> : std::formatter<std::string_view>
{
    auto format(statusbar::logging::ShortStr<N> const& s, std::format_context& ctx) const
    {
        return std::formatter<std::string_view>::format(s.view(), ctx);
    }
};
