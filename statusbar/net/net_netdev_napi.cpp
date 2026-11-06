// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_netdev_napi.hpp"

#if defined(__linux__)

#    include "statusbar/buffer/buffer.hpp"
#    include "statusbar/net/net_socket.hpp"

#    include <sched.h>

#    include <algorithm>
#    include <array>
#    include <cerrno>
#    include <cstddef>
#    include <system_error>
#    include <tuple>

#    include <linux/netlink.h>
#    include <sys/types.h>

#    if __has_include(<linux/netdev.h>)
#        include <linux/netdev.h>
#    endif

namespace statusbar::net::netdev {

// The constants mirrored from the uapi, where the build host's headers have them.
#    if defined(HAVE_NETDEV_QUEUE_NAPI)  // 6.9+, detected by CMake
static_assert(CMD_QUEUE_GET == NETDEV_CMD_QUEUE_GET && CMD_NAPI_GET == NETDEV_CMD_NAPI_GET);
static_assert(QUEUE_ID == NETDEV_A_QUEUE_ID && QUEUE_IFINDEX == NETDEV_A_QUEUE_IFINDEX && QUEUE_TYPE == NETDEV_A_QUEUE_TYPE);
static_assert(QUEUE_NAPI_ID == NETDEV_A_QUEUE_NAPI_ID && NAPI_IFINDEX == NETDEV_A_NAPI_IFINDEX && NAPI_ID == NETDEV_A_NAPI_ID);
static_assert(NAPI_IRQ == NETDEV_A_NAPI_IRQ && NAPI_PID == NETDEV_A_NAPI_PID);
static_assert(QueueType::rx == QueueType{NETDEV_QUEUE_TYPE_RX} && QueueType::tx == QueueType{NETDEV_QUEUE_TYPE_TX});
#    endif
#    if defined(HAVE_NETDEV_NAPI_BUSY_POLL)  // 7.1+, detected by CMake
static_assert(CMD_NAPI_SET == NETDEV_CMD_NAPI_SET && NAPI_THREADED == NETDEV_A_NAPI_THREADED);
static_assert(NapiThreaded::busy_poll == NapiThreaded{NETDEV_NAPI_THREADED_BUSY_POLL});
#    endif

namespace {

using netlink::bad_message;
using netlink::load;
using netlink::walk_attributes;

constexpr size_t U32_ATTRIBUTE = netlink::ATTRIBUTE_HEADER + sizeof(uint32_t);

/// Append one u32 attribute.
void put_u32(BufferSerializerBuilder& b, uint16_t const type, uint32_t const value)
{
    netlink::put_attribute_header(b, sizeof(uint32_t), type);
    b.append(value);
}

/// An attribute's u32 (or NLA_UINT, 4 or 8 octets) value into `out`; bad_message for another size or one past 32 bits.
[[nodiscard]] auto parse_u32(std::span<uint8_t const> const payload, uint32_t& out) -> Status
{
    if (payload.size() == sizeof(uint32_t)) {
        out = load<uint32_t>(payload, 0);
        return success();
    }
    if (payload.size() != sizeof(uint64_t) || load<uint64_t>(payload, 0) > UINT32_MAX) {
        return failure(bad_message());
    }
    out = static_cast<uint32_t>(load<uint64_t>(payload, 0));
    return success();
}

/// parse_u32() into an optional.
[[nodiscard]] auto parse_u32(std::span<uint8_t const> const payload, std::optional<uint32_t>& out) -> Status
{
    return parse_u32(payload, out.emplace());
}

/// A threaded mode the kernel reports, or nullopt for one past busy_poll.
[[nodiscard]] auto threaded_mode(uint32_t const value) noexcept -> std::optional<NapiThreaded>
{
    return value <= static_cast<uint32_t>(NapiThreaded::busy_poll) ? std::optional{NapiThreaded{value}} : std::nullopt;
}

/// The queue attributes `parse_queue` reads, before the required ones are checked.
struct QueueFields
{
    std::optional<uint32_t> id;
    std::optional<uint32_t> ifindex;
    std::optional<uint32_t> type;
    std::optional<uint32_t> napi_id;
};

/// One queue attribute into `fields`.
[[nodiscard]] auto parse_queue_attribute(uint16_t const type, std::span<uint8_t const> const payload, QueueFields& fields) -> Status
{  // NOLINT(statusbar-block-statements): the attribute table
    switch (type & netlink::ATTRIBUTE_TYPE_MASK) {
        case QUEUE_ID:
            return parse_u32(payload, fields.id);
        case QUEUE_IFINDEX:
            return parse_u32(payload, fields.ifindex);
        case QUEUE_TYPE:
            return parse_u32(payload, fields.type);
        case QUEUE_NAPI_ID:
            return parse_u32(payload, fields.napi_id);
        default:
            return success();
    }
}

/// The NAPI attributes `parse_napi` reads.
struct NapiFields
{
    std::optional<uint32_t> id;
    std::optional<uint32_t> ifindex;
    std::optional<uint32_t> threaded;
    NapiInfo napi;
};

/// One NAPI attribute into `fields`.
[[nodiscard]] auto parse_napi_attribute(uint16_t const type, std::span<uint8_t const> const payload, NapiFields& fields) -> Status
{  // NOLINT(statusbar-block-statements): the attribute table
    switch (type & netlink::ATTRIBUTE_TYPE_MASK) {
        case NAPI_ID:
            return parse_u32(payload, fields.id);
        case NAPI_IFINDEX:
            return parse_u32(payload, fields.ifindex);
        case NAPI_IRQ:
            return parse_u32(payload, fields.napi.irq);
        case NAPI_PID:
            return parse_u32(payload, fields.napi.pid);
        case NAPI_THREADED:
            return parse_u32(payload, fields.threaded);
        default:
            return success();
    }
}

/// The NAPI `fields` describe, `id` its id.
[[nodiscard]] auto napi_of(NapiFields const& fields, uint32_t const id) noexcept -> NapiInfo
{
    NapiInfo napi = fields.napi;
    napi.id = id;
    napi.ifindex = static_cast<int>(fields.ifindex.value_or(0));
    napi.threaded = fields.threaded ? threaded_mode(*fields.threaded) : std::nullopt;
    return napi;
}

/// `napis` with NAPI `id` added when it is one and not there yet.
[[nodiscard]] auto with_napi(QueueNapis napis, std::optional<uint32_t> const id) noexcept -> QueueNapis
{
    if (id && std::ranges::find(napis.napi_ids(), *id) == napis.napi_ids().end() && napis.count < napis.ids.size()) {
        napis.ids[napis.count++] = *id;
    }
    return napis;
}

/// The CPU set of `cpu` alone, 0 <= `cpu` < CPU_SETSIZE.
[[nodiscard]] auto one_cpu(int const cpu) noexcept -> cpu_set_t
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<size_t>(cpu), &set);
    return set;
}

}  // namespace

//
// Builders and parsers
//

auto build_queue_get(
    std::span<uint8_t> const out,
    uint16_t const family_id,
    int const ifindex,
    uint32_t const queue_id,
    QueueType const type,
    uint32_t const seq) -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    constexpr size_t length = GENL_HEADER + (3 * U32_ATTRIBUTE);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, family_id, seq, CMD_QUEUE_GET, FAMILY_VERSION);
    put_u32(b, QUEUE_IFINDEX, static_cast<uint32_t>(ifindex));
    put_u32(b, QUEUE_TYPE, static_cast<uint32_t>(type));
    put_u32(b, QUEUE_ID, queue_id);
    return netlink::finish(b, length);
}

auto build_napi_get(std::span<uint8_t> const out, uint16_t const family_id, uint32_t const napi_id, uint32_t const seq)
    -> StatusValue<size_t>
{
    constexpr size_t length = GENL_HEADER + U32_ATTRIBUTE;
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, family_id, seq, CMD_NAPI_GET, FAMILY_VERSION);
    put_u32(b, NAPI_ID, napi_id);
    return netlink::finish(b, length);
}

auto build_napi_set_threaded(
    std::span<uint8_t> const out, uint16_t const family_id, uint32_t const napi_id, NapiThreaded const mode, uint32_t const seq)
    -> StatusValue<size_t>
{  // NOLINT(statusbar-block-statements): the request, field by field
    constexpr size_t length = GENL_HEADER + (2 * U32_ATTRIBUTE);
    MutableBuffer buffer{out};
    BufferSerializerBuilder b{buffer};
    put_genl_header(b, length, family_id, seq, CMD_NAPI_SET, FAMILY_VERSION);
    put_u32(b, NAPI_ID, napi_id);
    put_u32(b, NAPI_THREADED, static_cast<uint32_t>(mode));
    return netlink::finish(b, length);
}

auto parse_queue(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<QueueInfo>
{
    QueueFields fields;
    auto const status = genl_attributes(message, family_id, CMD_QUEUE_GET).and_then([&](std::span<uint8_t const> const attributes) {
        return walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) {
            return parse_queue_attribute(type, payload, fields);
        });
    });
    if (!status || !fields.id || !fields.ifindex || !fields.type || *fields.type > static_cast<uint32_t>(QueueType::tx)) {
        return failure(status ? bad_message() : status.error());
    }
    return QueueInfo{
        .id = *fields.id, .ifindex = static_cast<int>(*fields.ifindex), .type = QueueType{*fields.type}, .napi_id = fields.napi_id};
}

auto parse_napi(std::span<uint8_t const> const message, uint16_t const family_id) -> StatusValue<NapiInfo>
{
    NapiFields fields;
    auto const status = genl_attributes(message, family_id, CMD_NAPI_GET).and_then([&](std::span<uint8_t const> const attributes) {
        return walk_attributes(attributes, [&](uint16_t const type, std::span<uint8_t const> const payload) {
            return parse_napi_attribute(type, payload, fields);
        });
    });
    if (!status || !fields.id) {
        return failure(status ? bad_message() : status.error());
    }
    return napi_of(fields, *fields.id);
}

//
// NapiClient
//

auto NapiClient::queue(int const ifindex, uint32_t const queue_id, QueueType const type) -> StatusValue<QueueInfo>
{
    std::optional<QueueInfo> got;
    auto const family = netdev_.family_id();
    auto const status = netdev_.request(
        [&](std::span<uint8_t> out, uint32_t seq) { return build_queue_get(out, family, ifindex, queue_id, type, seq); },
        [&](std::span<uint8_t const> message) {
            return parse_queue(message, family).transform([&](QueueInfo const& q) { got = q; });
        });
    if (!status || !got) {
        return failure(status ? bad_message() : status.error());  // an ack without a reply is malformed
    }
    return *got;
}

auto NapiClient::napi(uint32_t const napi_id) -> StatusValue<NapiInfo>
{
    std::optional<NapiInfo> got;
    auto const family = netdev_.family_id();
    auto const status = netdev_.request(
        [&](std::span<uint8_t> out, uint32_t seq) { return build_napi_get(out, family, napi_id, seq); },
        [&](std::span<uint8_t const> message) {
            return parse_napi(message, family).transform([&](NapiInfo const& n) { got = n; });
        });
    if (!status || !got) {
        return failure(status ? bad_message() : status.error());
    }
    return *got;
}

auto NapiClient::set_threaded(uint32_t const napi_id, NapiThreaded const mode) -> Status
{
    return netdev_.request(
        [&](std::span<uint8_t> out, uint32_t seq) { return build_napi_set_threaded(out, netdev_.family_id(), napi_id, mode, seq); },
        [](std::span<uint8_t const>) { return success(); });
}

auto NapiClient::queue_napis(int const ifindex, uint32_t const queue_id) -> StatusValue<QueueNapis>
{
    auto const rx = queue(ifindex, queue_id, QueueType::rx);
    if (!rx) {
        return forward_failure(rx);
    }
    auto const tx = queue(ifindex, queue_id, QueueType::tx);
    if (!tx && tx.error() != std::errc::invalid_argument && tx.error() != std::errc::no_such_file_or_directory) {
        return forward_failure(tx);  // EINVAL, ENOENT: no such TX queue, RX's NAPI alone
    }
    auto const napis = with_napi(with_napi(QueueNapis{}, rx->napi_id), tx ? tx->napi_id : std::optional<uint32_t>{});
    return napis.count != 0 ? StatusValue<QueueNapis>{napis} : failure(std::errc::operation_not_supported);
}

//
// Threaded NAPIs - Documentation/networking/napi.rst
//

namespace {

/// Each of `napis` set to `mode`, stopping at the first refusal.
[[nodiscard]] auto set_each(NapiClient& client, QueueNapis const& napis, NapiThreaded const mode) -> Status
{
    for (auto const id : napis.napi_ids()) {
        if (auto status = client.set_threaded(id, mode); !status) {
            return status;
        }
    }
    return success();
}

/// Each of `napis`' kthread into its pids, made SCHED_OTHER on `cpu`; bad_message for a threaded NAPI without one.
[[nodiscard]] auto pin_each(NapiClient& client, QueueNapis& napis, int const cpu) -> Status
{
    for (size_t i = 0; i < napis.count; ++i) {
        auto const napi = client.napi(napis.ids[i]);
        if (!napi || !napi->pid) {
            return failure(napi ? bad_message() : napi.error());
        }
        napis.pids[i] = *napi->pid;
        if (auto status = pin_napi_thread(*napi->pid, cpu); !status) {
            return status;
        }
    }
    return success();
}

/// The threaded mode of each of `napis`, as reported (disabled where the kernel reports none).
using NapiModes = std::array<NapiThreaded, std::tuple_size_v<decltype(QueueNapis::ids)>>;

/// Each of `napis`' mode into `modes`, before any is changed.
[[nodiscard]] auto read_each(NapiClient& client, QueueNapis const& napis, NapiModes& modes) -> Status
{
    for (size_t i = 0; i < napis.count; ++i) {
        auto const napi = client.napi(napis.ids[i]);
        if (!napi) {
            return forward_failure(napi);
        }
        modes[i] = napi->threaded.value_or(NapiThreaded::disabled);
    }
    return success();
}

/// Each of `napis` back to its mode in `modes`, as far as the kernel lets it.
void restore_each(NapiClient& client, QueueNapis const& napis, NapiModes const& modes)
{
    for (size_t i = 0; i < napis.count; ++i) {
        (void)client.set_threaded(napis.ids[i], modes[i]);
    }
}

/// `napis` threaded in `mode`: their kthreads made (enabled: woken by the interrupt only) and pinned to `cpu`
/// before they may spin; each put back in the mode it had on a failure.
[[nodiscard]] auto thread_each(NapiClient& client, QueueNapis& napis, NapiThreaded const mode, int const cpu) -> Status
{
    NapiModes before{};
    if (auto const read = read_each(client, napis, before); !read) {
        return read;
    }
    auto const status =
        set_each(client, napis, NapiThreaded::enabled).and_then([&] { return pin_each(client, napis, cpu); }).and_then([&] {
            return set_each(client, napis, mode);
        });
    if (!status) {
        restore_each(client, napis, before);
    }
    return status;
}

}  // namespace

auto set_queue_threaded(NapiClient& client, int const ifindex, uint32_t const queue_id, NapiThreaded const mode, int const cpu)
    -> StatusValue<QueueNapis>
{
    if (mode != NapiThreaded::disabled && (cpu < 0 || cpu >= CPU_SETSIZE)) {
        return failure(std::errc::invalid_argument);  // before any NAPI changes: one in force stays so
    }
    auto napis = client.queue_napis(ifindex, queue_id);
    if (!napis) {
        return napis;
    }
    auto const status = mode == NapiThreaded::disabled ? set_each(client, *napis, mode) : thread_each(client, *napis, mode, cpu);
    return status ? napis : StatusValue<QueueNapis>{failure(status.error())};
}

auto pin_napi_thread(uint32_t const pid, int const cpu) -> Status
{
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        return failure(std::errc::invalid_argument);
    }
    sched_param const other{.sched_priority = 0};
    if (::sched_setscheduler(static_cast<pid_t>(pid), SCHED_OTHER, &other) < 0) {
        return failure(errno_code());
    }
    auto const set = one_cpu(cpu);
    return ::sched_setaffinity(static_cast<pid_t>(pid), sizeof(set), &set) < 0 ? Status{failure(errno_code())} : success();
}

}  // namespace statusbar::net::netdev

#endif  // __linux__
