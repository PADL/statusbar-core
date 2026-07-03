// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/ieee/ieee_ethernet.hpp"

namespace statusbar::ieee {

auto to_string(Eui48 const& mac) -> ::statusbar::fmt::fixed_str<17>
{
    auto const& v = mac.value;
    return ::statusbar::fmt::format<"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}">(v[0], v[1], v[2], v[3], v[4], v[5]);
}

auto to_string(Eui64 const& mac) -> ::statusbar::fmt::fixed_str<23>
{
    auto const s = mac.span();
    return ::statusbar::fmt::format<"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}">(
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
}

auto from_string(std::string_view str, Eui48* /*tag*/) noexcept -> std::optional<Eui48>
{
    Eui48 result;
    str = trim_whitespace(str);

    if (str.size() == 17) {
        // Format with separators: "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff"
        char const sep = str[2];
        if (sep != ':' && sep != '-') {
            return std::nullopt;
        }
        for (size_t i = 0; i < 6; ++i) {
            size_t const pos = i * 3;
            if (i < 5 && str[pos + 2] != sep) {
                return std::nullopt;
            }
            uint8_t const hi = parse_hex_digit(str[pos]);
            uint8_t const lo = parse_hex_digit(str[pos + 1]);
            if (hi == 255 || lo == 255) {
                return std::nullopt;
            }
            result.value[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
    } else if (str.size() == 12) {
        // Format without separators: "aabbccddeeff"
        for (size_t i = 0; i < 6; ++i) {
            uint8_t const hi = parse_hex_digit(str[(i * 2)]);
            uint8_t const lo = parse_hex_digit(str[((i * 2) + 1)]);
            if (hi == 255 || lo == 255) {
                return std::nullopt;
            }
            result.value[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
    } else {
        return std::nullopt;
    }

    return result;
}

auto from_string(std::string_view str, Eui64* /*tag*/) noexcept -> std::optional<Eui64>
{
    Eui64 result;
    str = trim_whitespace(str);

    if (str.size() == 23) {
        // Format with separators: "aa:bb:cc:dd:ee:ff:00:11" or "aa-bb-cc-dd-ee-ff-00-11"
        char const sep = str[2];
        if (sep != ':' && sep != '-') {
            return std::nullopt;
        }
        for (size_t i = 0; i < 8; ++i) {
            size_t const pos = i * 3;
            if (i < 7 && str[pos + 2] != sep) {
                return std::nullopt;
            }
            uint8_t const hi = parse_hex_digit(str[pos]);
            uint8_t const lo = parse_hex_digit(str[pos + 1]);
            if (hi == 255 || lo == 255) {
                return std::nullopt;
            }
            result.span()[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
    } else if (str.size() == 16) {
        // Format without separators: "aabbccddeeff0011"
        for (size_t i = 0; i < 8; ++i) {
            uint8_t const hi = parse_hex_digit(str[(i * 2)]);
            uint8_t const lo = parse_hex_digit(str[((i * 2) + 1)]);
            if (hi == 255 || lo == 255) {
                return std::nullopt;
            }
            result.span()[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
    } else {
        return std::nullopt;
    }

    return result;
}

auto can_load(std::span<uint8_t const> const buf, VlanTag const* const item) noexcept -> StatusValue<size_t>
{
    // If buffer is empty or has less than 2 bytes, no VLAN tag present
    if (buf.size() < 2) {
        return success(size_t{0});
    }

    // Peek at TPID to determine if VLAN tag is present
    doublet_t tpid;
    span_load(tpid, buf);

    if (tpid != VlanTag::ETHERTYPE) {
        // Not a VLAN tag, return 0 bytes
        return success(size_t{0});
    }

    // VLAN tag present, need 4 bytes total
    if (buf.size() < VlanTag::LENGTH) {
        return failure(BufferError::insufficient_data);
    }

    return success(VlanTag::LENGTH);
}

auto load_unchecked(std::span<uint8_t const> const buf, VlanTag* const item) noexcept -> size_t
{
    if (buf.size() < 2) {
        // No VLAN tag present
        item->tpid = 0;
        item->tci = 0;
        return size_t{0};
    }

    // Peek at TPID
    doublet_t tpid;
    span_load(tpid, buf);

    if (tpid != VlanTag::ETHERTYPE || buf.size() < VlanTag::LENGTH) {
        // Not a VLAN tag, or a truncated one. The 2-byte guard above is enough to
        // peek the TPID, but a full tag is 4 bytes: without this a 2-3 byte 0x8100
        // prefix would read past the span in the parse below (OOB read).
        item->tpid = 0;
        item->tci = 0;
        return size_t{0};
    }

    // Parse full VLAN tag
    BufferDeserializerBuilder{buf}.parse_unchecked(&item->tpid).parse_unchecked(&item->tci);
    return VlanTag::LENGTH;
}

auto store_unchecked(std::span<uint8_t> const buf, VlanTag const& item) noexcept -> size_t
{
    if (!item.is_set()) {
        return size_t{0};
    }

    BufferSerializerBuilderWithBuffer{buf}.append_unchecked(item.tpid).append_unchecked(item.tci);
    return VlanTag::LENGTH;
}

auto can_load(std::span<uint8_t const> const buf, EthernetFrame const* const item) noexcept -> StatusValue<size_t>
{
    // Need at least 14 bytes for untagged frame
    if (buf.size() < 14) {
        return failure(BufferError::insufficient_data);
    }

    // Peek at ethertype to determine actual size needed
    doublet_t ethertype;
    span_load(ethertype, buf.subspan(12));

    size_t const required_size = (ethertype == VlanTag::ETHERTYPE) ? 18 : 14;
    if (buf.size() < required_size) {
        return failure(BufferError::insufficient_data);
    }

    return success(required_size);
}

auto load_unchecked(std::span<uint8_t const> const buf, EthernetFrame* const item) noexcept -> size_t
{
    // Copy dest_mac and src_mac (6 bytes each)
    span_load(item->dest_mac, buf.subspan(0));
    span_load(item->src_mac, buf.subspan(6));

    // Peek at potential TPID to determine if VLAN tagged
    doublet_t potential_tpid;
    span_load(potential_tpid, buf.subspan(12));

    if (potential_tpid == VlanTag::ETHERTYPE) {
        // VLAN tagged frame: copy VLAN tag (4 bytes) and ethertype (2 bytes)
        span_load(item->vlan_tag, buf.subspan(12));
        span_load(item->ethertype, buf.subspan(16));
        return 18;
    }
    // Untagged frame: no VLAN tag, copy ethertype directly
    item->vlan_tag = make_empty_vlan_tag();
    span_load(item->ethertype, buf.subspan(12));
    return 14;
}

auto store_unchecked(std::span<uint8_t> const buf, EthernetFrame const& item) noexcept -> size_t
{
    if (item.vlan_tag.is_set()) {
        // VLAN tagged frame: copy all 18 bytes (dest_mac + src_mac + vlan_tag + ethertype)
        span_store(buf.subspan(0, 18), item);
        return 18;
    }
    // Untagged frame: dest_mac (6 bytes) + src_mac (6 bytes) + ethertype (2 bytes)
    span_copy(buf.subspan(0, 6), item.dest_mac.value);
    span_copy(buf.subspan(6, 6), item.src_mac.value);
    span_store(buf.subspan(12), item.ethertype);
    return 14;
}

}  // namespace statusbar::ieee
