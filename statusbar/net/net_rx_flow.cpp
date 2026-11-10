// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/net/net_rx_flow.hpp"

#include <algorithm>
#include <system_error>
#include <utility>

#if defined(__linux__)
#    include "statusbar/net/net_posix_util.hpp"

#    include <arpa/inet.h>
#endif

namespace statusbar::net {

auto rss_indirection_excluding(size_t const entries, uint32_t const rx_queues, std::span<uint32_t const> const excluded)
    -> RssIndirection
{
    std::vector<uint32_t> queues;
    for (uint32_t queue = 0; queue < rx_queues; ++queue) {
        if (std::ranges::find(excluded, queue) == excluded.end()) {
            queues.push_back(queue);
        }
    }
    RssIndirection table;
    for (size_t bucket = 0; !queues.empty() && bucket < entries; ++bucket) {
        table.push_back(queues[bucket % queues.size()]);
    }
    return table;
}

namespace detail {

auto check_rx_flow_plan(RxFlowPlan const& plan, uint32_t const rx_queues) -> Status
{
    bool const rules_fit = std::ranges::all_of(plan.rules, [&plan, rx_queues](RxFlowRule const& rule) {
        bool const matches = rule.ethertype.has_value() || rule.vlan_pcp.has_value();
        return matches && plan.locations.contains(rule.location) && rule.queue < rx_queues;
    });
    bool const excluded_fit =
        std::ranges::all_of(plan.rss_excluded, [rx_queues](uint32_t const queue) { return queue < rx_queues; });
    if (!rules_fit || !excluded_fit) {
        return failure(std::make_error_code(std::errc::invalid_argument));
    }
    return success();
}

}  // namespace detail

#if defined(__linux__)

namespace {

constexpr uint16_t FULL_MASK = 0xffff;
constexpr uint16_t VLAN_PCP_MASK = 0xe000;
constexpr unsigned VLAN_PCP_SHIFT = 13;

/// Whether any byte of `bytes` is set.
[[nodiscard]] auto any_set(std::span<uint8_t const> const bytes) noexcept -> bool
{
    return std::ranges::any_of(bytes, [](uint8_t const byte) { return byte != 0; });
}

/// Whether a FLOW_EXT spec's extension matches on anything but the VLAN priority.
[[nodiscard]] auto has_other_ext_fields(ethtool_rx_flow_spec const& spec) noexcept -> bool
{
    if ((spec.flow_type & FLOW_EXT) == 0) {
        return false;
    }
    auto const tci = ntohs(spec.m_ext.vlan_tci);
    return spec.m_ext.vlan_etype != 0 || any_set(make_const_span(spec.m_ext.data)) || (tci != 0 && tci != VLAN_PCP_MASK);
}

/// Whether an ETHER_FLOW spec matches on anything but a whole EtherType and a VLAN priority.
[[nodiscard]] auto has_other_fields(ethtool_rx_flow_spec const& spec) noexcept -> bool
{
    auto const& mask = spec.m_u.ether_spec;
    bool const partial_type = mask.h_proto != 0 && mask.h_proto != FULL_MASK;
    bool const macs = any_set(mask.h_dest) || any_set(mask.h_source);
    return partial_type || macs || has_other_ext_fields(spec);
}

/// The match fields of `rule` written into `spec`.
auto set_matches(ethtool_rx_flow_spec& spec, RxFlowRule const& rule) noexcept -> void
{
    if (rule.ethertype) {
        spec.h_u.ether_spec.h_proto = htons(*rule.ethertype);
        spec.m_u.ether_spec.h_proto = FULL_MASK;
    }
    if (rule.vlan_pcp) {
        spec.h_ext.vlan_tci = htons(static_cast<uint16_t>((*rule.vlan_pcp & 7U) << VLAN_PCP_SHIFT));
        spec.m_ext.vlan_tci = htons(VLAN_PCP_MASK);
    }
}

}  // namespace

namespace detail {

auto flow_spec_of(RxFlowRule const& rule) noexcept -> ethtool_rx_flow_spec
{
    ethtool_rx_flow_spec spec{};
    spec.flow_type = rule.vlan_pcp ? (ETHER_FLOW | FLOW_EXT) : ETHER_FLOW;
    spec.ring_cookie = rule.queue;
    spec.location = rule.location;
    set_matches(spec, rule);
    return spec;
}

auto rule_of(ethtool_rx_flow_spec const& spec) noexcept -> RxFlowRule
{
    RxFlowRule rule{.location = spec.location, .queue = static_cast<uint32_t>(spec.ring_cookie & ETHTOOL_RX_FLOW_SPEC_RING)};
    rule.other_fields =
        (spec.flow_type & ~uint32_t{FLOW_EXT}) != ETHER_FLOW || spec.ring_cookie == RX_CLS_FLOW_DISC || has_other_fields(spec);
    if (rule.other_fields) {
        return rule;
    }
    if (spec.m_u.ether_spec.h_proto == FULL_MASK) {
        rule.ethertype = ntohs(spec.h_u.ether_spec.h_proto);
    }
    if ((spec.flow_type & FLOW_EXT) != 0 && ntohs(spec.m_ext.vlan_tci) == VLAN_PCP_MASK) {
        rule.vlan_pcp = static_cast<uint8_t>(ntohs(spec.h_ext.vlan_tci) >> VLAN_PCP_SHIFT);
    }
    return rule;
}

}  // namespace detail

namespace {

/// A classifier request: `cmd` at `location`.
[[nodiscard]] auto rule_request(uint32_t const cmd, uint32_t const location) noexcept -> ethtool_rxnfc
{
    ethtool_rxnfc nfc{};
    nfc.cmd = cmd;
    nfc.fs.location = location;
    return nfc;
}

/// The interface's legacy ethtool flags (ETH_FLAG_*).
[[nodiscard]] auto ethtool_flags(std::string_view const interface_name) -> StatusValue<uint32_t>
{
    ethtool_value value{.cmd = ETHTOOL_GFLAGS, .data = 0};
    if (auto const status = ethtool_ioctl(interface_name, &value); !status) {
        return failure(status.error());
    }
    return value.data;
}

}  // namespace

auto ntuple_enabled(std::string_view const interface_name) -> StatusValue<bool>
{
    return ethtool_flags(interface_name).transform([](uint32_t const flags) { return (flags & ETH_FLAG_NTUPLE) != 0; });
}

auto set_ntuple(std::string_view const interface_name, bool const enabled) -> Status
{
    auto const flags = ethtool_flags(interface_name);
    if (!flags) {
        return failure(flags.error());
    }
    uint32_t const others = *flags & ~uint32_t{ETH_FLAG_NTUPLE};
    ethtool_value value{.cmd = ETHTOOL_SFLAGS, .data = enabled ? (others | ETH_FLAG_NTUPLE) : others};
    return ethtool_ioctl(interface_name, &value);
}

auto rx_flow_rule(std::string_view const interface_name, uint32_t const location) -> StatusValue<std::optional<RxFlowRule>>
{
    auto nfc = rule_request(ETHTOOL_GRXCLSRULE, location);
    auto const status = ethtool_ioctl(interface_name, &nfc);
    if (!status && (status.error() == std::errc::invalid_argument || status.error() == std::errc::no_such_file_or_directory)) {
        return std::optional<RxFlowRule>{};  // igb and igc answer EINVAL for an empty slot, others ENOENT
    }
    if (!status) {
        return failure(status.error());
    }
    return std::optional{detail::rule_of(nfc.fs)};
}

auto insert_rx_flow_rule(std::string_view const interface_name, RxFlowRule const& rule) -> Status
{
    auto nfc = rule_request(ETHTOOL_SRXCLSRLINS, rule.location);
    nfc.fs = detail::flow_spec_of(rule);
    return ethtool_ioctl(interface_name, &nfc);
}

auto delete_rx_flow_rule(std::string_view const interface_name, uint32_t const location) -> Status
{
    auto nfc = rule_request(ETHTOOL_SRXCLSRLDEL, location);
    return ethtool_ioctl(interface_name, &nfc);
}

#else  // !__linux__

auto ntuple_enabled(std::string_view const) -> StatusValue<bool>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto set_ntuple(std::string_view const, bool const) -> Status
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto rx_flow_rule(std::string_view const, uint32_t const) -> StatusValue<std::optional<RxFlowRule>>
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto insert_rx_flow_rule(std::string_view const, RxFlowRule const&) -> Status
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

auto delete_rx_flow_rule(std::string_view const, uint32_t const) -> Status
{
    return failure(std::make_error_code(std::errc::operation_not_supported));
}

#endif  // __linux__

auto clear_rx_flow_rules(RxFlowControl& control, std::string_view const interface_name, RxFlowRange const range)
    -> StatusValue<size_t>
{
    size_t removed = 0;
    for (uint32_t location = range.first; location - range.first < range.count; ++location) {
        auto const rule = control.rule(interface_name, location);
        if (!rule) {
            return failure(rule.error());
        }
        if (rule->has_value()) {
            if (auto const status = control.remove(interface_name, location); !status) {
                return failure(status.error());
            }
            ++removed;
        }
    }
    return removed;
}

//
// RxFlowSteering
//

RxFlowSteering::RxFlowSteering(RxFlowControl& flows, RssControl& rss, std::string_view const interface_name, RxFlowPlan plan)
    : flows_{&flows}
    , rss_{&rss}
    , interface_{interface_name}
    , plan_{std::move(plan)}
{}

RxFlowSteering::RxFlowSteering(RxFlowSteering&& other) noexcept
    : flows_{other.flows_}
    , rss_{other.rss_}
    , interface_{std::move(other.interface_)}
    , plan_{std::move(other.plan_)}
    , previous_{std::move(other.previous_)}
    , inserted_{other.inserted_}
    , leftovers_{other.leftovers_}
    , rx_queues_{other.rx_queues_}
    , enabled_ntuple_{other.enabled_ntuple_}
    , default_rss_on_restore_{other.default_rss_on_restore_}
{
    other.release();
}

auto RxFlowSteering::operator=(RxFlowSteering&& other) noexcept -> RxFlowSteering&
{
    if (this != &other) {
        (void)restore();
        move_from(other);
    }
    return *this;
}

auto RxFlowSteering::move_from(RxFlowSteering& other) noexcept -> void
{  // NOLINT(statusbar-block-statements): a member-wise move
    flows_ = other.flows_;
    rss_ = other.rss_;
    interface_ = std::move(other.interface_);
    plan_ = std::move(other.plan_);
    previous_ = std::move(other.previous_);
    inserted_ = other.inserted_;
    leftovers_ = other.leftovers_;
    rx_queues_ = other.rx_queues_;
    enabled_ntuple_ = other.enabled_ntuple_;
    default_rss_on_restore_ = other.default_rss_on_restore_;
    other.release();
}

RxFlowSteering::~RxFlowSteering()
{
#if __cpp_exceptions
    try {
#endif
        (void)restore();
#if __cpp_exceptions
    } catch (...) {  // NOLINT(bugprone-empty-catch) a destructor has nobody to report to
    }
#endif
}

auto RxFlowSteering::release() noexcept -> void
{
    flows_ = nullptr;
    rss_ = nullptr;
    previous_.clear();
    inserted_ = 0;
    enabled_ntuple_ = false;
    default_rss_on_restore_ = false;
}

auto RxFlowSteering::clear_leftovers() -> Status
{
    auto const removed = clear_rx_flow_rules(*flows_, interface_, plan_.locations);
    if (!removed) {
        return failure(removed.error());
    }
    leftovers_ = *removed;
    return success();
}

auto RxFlowSteering::enable_ntuple() -> Status
{
    if (!plan_.ntuple) {
        return success();
    }
    auto const enabled = flows_->ntuple(interface_);
    if (!enabled || *enabled) {
        return enabled.transform([](bool) {});
    }
    if (auto const status = flows_->set_ntuple(interface_, true); !status) {
        return status;
    }
    enabled_ntuple_ = true;
    return success();
}

auto RxFlowSteering::insert_rules() -> Status
{
    for (auto const& rule : plan_.rules) {
        if (auto const status = flows_->insert(interface_, rule); !status) {
            return status;
        }
        ++inserted_;
    }
    return success();
}

auto RxFlowSteering::steer_rss() -> Status
{
    auto current = rss_->indirection(interface_);
    if (!current) {
        // no RSS: the rules alone steer
        return current.error() == std::errc::operation_not_supported ? Status{} : Status{failure(current.error())};
    }
    auto const wanted = rss_indirection_excluding(current->size(), rx_queues_, plan_.rss_excluded);
    if (wanted.empty() || wanted == *current) {
        default_rss_on_restore_ = leftovers_ != 0;  // already spread so by the owner that left them
        return success();
    }
    return write_rss(wanted, std::move(*current));
}

auto RxFlowSteering::write_rss(RssIndirection const& wanted, RssIndirection current) -> Status
{
    if (auto const status = rss_->set_indirection(interface_, wanted); !status) {
        return status;
    }
    previous_ = std::move(current);
    return success();
}

auto RxFlowSteering::install() -> Status
{
    if (auto const status = clear_leftovers(); !status) {
        return status;
    }
    if (auto const status = enable_ntuple(); !status) {
        return status;
    }
    if (auto const status = insert_rules(); !status) {
        return status;
    }
    return steer_rss();
}

auto RxFlowSteering::steer(RxFlowControl& flows, RssControl& rss, std::string_view const interface_name, RxFlowPlan plan)
    -> StatusValue<RxFlowSteering>
{
    auto const queues = flows.rx_queues(interface_name).and_then([&plan](uint32_t const count) -> StatusValue<uint32_t> {
        return detail::check_rx_flow_plan(plan, count).transform([count] { return count; });
    });
    if (!queues) {
        return failure(queues.error());
    }
    RxFlowSteering steering{flows, rss, interface_name, std::move(plan)};
    steering.rx_queues_ = *queues;
    if (auto const status = steering.install(); !status) {
        (void)steering.restore();
        return failure(status.error());
    }
    return steering;
}

auto RxFlowSteering::restore_rss() -> Status
{
    if (previous_.empty()) {
        return default_rss_on_restore_ ? rss_->set_indirection(interface_, {}) : success();
    }
    auto const current = rss_->indirection(interface_);
    if (current && current->size() != previous_.size()) {
        return failure(std::make_error_code(std::errc::state_not_recoverable));  // the channel count changed under us
    }
    return rss_->set_indirection(interface_, previous_);
}

auto RxFlowSteering::remove_rules() -> Status
{
    Status result;
    for (size_t index = 0; index < inserted_; ++index) {
        if (auto const status = flows_->remove(interface_, plan_.rules[index].location); !status && result) {
            result = status;
        }
    }
    return result;
}

auto RxFlowSteering::restore() -> Status
{
    if (flows_ == nullptr) {
        return success();
    }
    Status result = restore_rss();
    if (auto const status = remove_rules(); !status && result) {
        result = status;
    }
    release();
    return result;
}

}  // namespace statusbar::net
