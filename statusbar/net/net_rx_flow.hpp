#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// ethtool RX flow rules (`ethtool -N <if> flow-type ether ...`): frames of one EtherType or one
/// VLAN priority steered to an RX queue. RxFlowSteering installs a set of them, with an RSS table
/// that keeps the other traffic off their queues, and removes both again.

#include "statusbar/net/net_rss.hpp"
#include "statusbar/status/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#    include <linux/ethtool.h>
#endif

namespace statusbar::net {

/// One ETHER_FLOW classification rule: frames matching every field that is set go to `queue`.
struct RxFlowRule
{
    uint32_t location{0};               ///< the rule's slot in the NIC's classifier table
    uint32_t queue{0};                  ///< the RX queue matching frames go to
    std::optional<uint16_t> ethertype;  ///< the frame's EtherType, matched in full
    std::optional<uint8_t> vlan_pcp;    ///< the VLAN tag's priority (0 to 7), matched alone
    bool other_fields{false};           ///< a rule read back that matches on fields this type does not hold

    auto operator==(RxFlowRule const&) const noexcept -> bool = default;
};

/// A run of classifier slots: an owner treats any rule in its run as its own.
struct RxFlowRange
{
    uint32_t first{0};
    uint32_t count{0};

    [[nodiscard]] constexpr auto contains(uint32_t const location) const noexcept -> bool
    {
        return location >= first && location - first < count;
    }
};

/// What RxFlowSteering installs: rules within `locations`, and RSS kept off `rss_excluded`; `ntuple`
/// turns the ntuple flag on first (igb needs it for VLAN priority rules; igc honours rules without it).
struct RxFlowPlan
{
    RxFlowRange locations;
    std::vector<RxFlowRule> rules;
    std::vector<uint32_t> rss_excluded;
    bool ntuple{true};
};

/// Whether the interface's ntuple filters are on (ETHTOOL_GFLAGS, ETH_FLAG_NTUPLE). No privilege.
[[nodiscard]] auto ntuple_enabled(std::string_view interface_name) -> StatusValue<bool>;

/// Turn the ntuple filters on or off (ETHTOOL_SFLAGS), the other flags kept. CAP_NET_ADMIN;
/// igb and igc reset the adapter on a change, and drop every rule when turned off.
[[nodiscard]] auto set_ntuple(std::string_view interface_name, bool enabled) -> Status;

/// The rule at `location` (ETHTOOL_GRXCLSRULE), nullopt for an empty slot; `operation_not_supported`
/// for an interface without flow rules.
[[nodiscard]] auto rx_flow_rule(std::string_view interface_name, uint32_t location) -> StatusValue<std::optional<RxFlowRule>>;

/// Insert `rule` at its location, replacing what is there (ETHTOOL_SRXCLSRLINS). CAP_NET_ADMIN.
[[nodiscard]] auto insert_rx_flow_rule(std::string_view interface_name, RxFlowRule const& rule) -> Status;

/// Remove the rule at `location` (ETHTOOL_SRXCLSRLDEL). CAP_NET_ADMIN.
[[nodiscard]] auto delete_rx_flow_rule(std::string_view interface_name, uint32_t location) -> Status;

/// A table of `entries` buckets spread round robin over the queues below `rx_queues` that `excluded`
/// does not name; empty when none is left.
[[nodiscard]] auto rss_indirection_excluding(size_t entries, uint32_t rx_queues, std::span<uint32_t const> excluded)
    -> RssIndirection;

namespace detail {

/// `invalid_argument` unless every rule lies in the plan's range, matches on an EtherType or a VLAN
/// priority (igc reads a rule on neither as its default-queue wildcard) and every queue is below `rx_queues`.
[[nodiscard]] auto check_rx_flow_plan(RxFlowPlan const& plan, uint32_t rx_queues) -> Status;

#if defined(__linux__)
/// The ethtool spec SRXCLSRLINS is given for `rule`.
[[nodiscard]] auto flow_spec_of(RxFlowRule const& rule) noexcept -> ethtool_rx_flow_spec;

/// The rule GRXCLSRULE reported: `other_fields` when it matches on more than an EtherType and a PCP.
[[nodiscard]] auto rule_of(ethtool_rx_flow_spec const& spec) noexcept -> RxFlowRule;
#endif

}  // namespace detail

/// The calls RxFlowSteering makes of a NIC's classifier; RxFlowEthtool is the real one and
/// RxFlowRecorder (net_rx_flow_recorder.hpp) the test double.
class RxFlowControl
{
  public:
    RxFlowControl() = default;
    virtual ~RxFlowControl() = default;
    RxFlowControl(RxFlowControl const&) = delete;
    auto operator=(RxFlowControl const&) -> RxFlowControl& = delete;
    RxFlowControl(RxFlowControl&&) = delete;
    auto operator=(RxFlowControl&&) -> RxFlowControl& = delete;

    [[nodiscard]] virtual auto ntuple(std::string_view interface_name) -> StatusValue<bool> = 0;
    [[nodiscard]] virtual auto set_ntuple(std::string_view interface_name, bool enabled) -> Status = 0;
    [[nodiscard]] virtual auto rule(std::string_view interface_name, uint32_t location)
        -> StatusValue<std::optional<RxFlowRule>> = 0;
    [[nodiscard]] virtual auto insert(std::string_view interface_name, RxFlowRule const& rule) -> Status = 0;
    [[nodiscard]] virtual auto remove(std::string_view interface_name, uint32_t location) -> Status = 0;
    [[nodiscard]] virtual auto rx_queues(std::string_view interface_name) -> StatusValue<uint32_t> = 0;
};

/// The RxFlowControl that talks to a NIC through ethtool's ioctls.
class RxFlowEthtool final : public RxFlowControl
{
  public:
    [[nodiscard]] auto ntuple(std::string_view interface_name) -> StatusValue<bool> override
    {
        return ntuple_enabled(interface_name);
    }
    [[nodiscard]] auto set_ntuple(std::string_view interface_name, bool enabled) -> Status override
    {
        return net::set_ntuple(interface_name, enabled);
    }
    [[nodiscard]] auto rule(std::string_view interface_name, uint32_t location) -> StatusValue<std::optional<RxFlowRule>> override
    {
        return rx_flow_rule(interface_name, location);
    }
    [[nodiscard]] auto insert(std::string_view interface_name, RxFlowRule const& rule) -> Status override
    {
        return insert_rx_flow_rule(interface_name, rule);
    }
    [[nodiscard]] auto remove(std::string_view interface_name, uint32_t location) -> Status override
    {
        return delete_rx_flow_rule(interface_name, location);
    }
    [[nodiscard]] auto rx_queues(std::string_view interface_name) -> StatusValue<uint32_t> override
    {
        return rx_queue_count(interface_name);
    }
};

/// Remove every rule in `range`: the leftovers of an owner that died. Returns how many there were.
[[nodiscard]] auto clear_rx_flow_rules(RxFlowControl& control, std::string_view interface_name, RxFlowRange range)
    -> StatusValue<size_t>;

/// Holds a plan's rules and RSS table on an interface: steer() clears the plan's range of a previous
/// owner's leftovers, turns ntuple on if the plan asks, inserts the rules and writes the RSS table.
/// ntuple is never turned off again: igb and igc reset the adapter (and igb its PHC) for it.
class RxFlowSteering
{
  public:
    /// A guard that owes nothing.
    RxFlowSteering() = default;
    ~RxFlowSteering();

    RxFlowSteering(RxFlowSteering&& other) noexcept;
    /// The guard assigned over restores first: steer() a plan for a held range only after its
    /// restore(), which would otherwise remove the new rules.
    auto operator=(RxFlowSteering&& other) noexcept -> RxFlowSteering&;
    RxFlowSteering(RxFlowSteering const&) = delete;
    auto operator=(RxFlowSteering const&) -> RxFlowSteering& = delete;

    /// Install `plan` on `interface_name`; on any refusal what was done is undone and the error returned.
    /// A NIC without RSS keeps the rules alone. `flows` and `rss` must outlive the guard.
    [[nodiscard]] static auto steer(RxFlowControl& flows, RssControl& rss, std::string_view interface_name, RxFlowPlan plan)
        -> StatusValue<RxFlowSteering>;

    /// The RSS table back (the driver's default after a previous owner's leftovers) and the rules
    /// removed; ntuple stays as it is. Tried once:
    /// the first failure is returned and nothing more is owed.
    [[nodiscard]] auto restore() -> Status;

    /// Give up the restore, leaving the NIC steered.
    auto release() noexcept -> void;

    /// Whether a restore is owed.
    [[nodiscard]] auto holds() const noexcept -> bool { return flows_ != nullptr; }
    /// How many rules a previous owner had left in the range.
    [[nodiscard]] auto leftovers() const noexcept -> size_t { return leftovers_; }
    /// Whether steer() turned ntuple on (it stays on).
    [[nodiscard]] auto enabled_ntuple() const noexcept -> bool { return enabled_ntuple_; }
    /// Whether steer() wrote an RSS table.
    [[nodiscard]] auto wrote_rss() const noexcept -> bool { return !previous_.empty(); }
    /// The plan installed.
    [[nodiscard]] auto plan() const noexcept -> RxFlowPlan const& { return plan_; }

  private:
    RxFlowSteering(RxFlowControl& flows, RssControl& rss, std::string_view interface_name, RxFlowPlan plan);

    [[nodiscard]] auto clear_leftovers() -> Status;
    [[nodiscard]] auto enable_ntuple() -> Status;
    [[nodiscard]] auto insert_rules() -> Status;
    [[nodiscard]] auto steer_rss() -> Status;
    [[nodiscard]] auto write_rss(RssIndirection const& wanted, RssIndirection current) -> Status;
    [[nodiscard]] auto install() -> Status;
    [[nodiscard]] auto restore_rss() -> Status;
    auto move_from(RxFlowSteering& other) noexcept -> void;
    [[nodiscard]] auto remove_rules() -> Status;

    RxFlowControl* flows_{nullptr};
    RssControl* rss_{nullptr};
    std::string interface_;
    RxFlowPlan plan_;
    RssIndirection previous_;
    size_t inserted_{0};
    size_t leftovers_{0};
    uint32_t rx_queues_{0};
    bool enabled_ntuple_{false};
    bool default_rss_on_restore_{false};
};

}  // namespace statusbar::net
