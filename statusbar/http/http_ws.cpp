// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/http/http_ws.hpp"

namespace statusbar::http {

auto ws_parse_frame_header(std::span<uint8_t const> bytes, WsFrameHeader& out) noexcept -> WsParse
{
    if (bytes.size() < 2) {
        return WsParse::need_more;
    }
    uint8_t const b0 = bytes[0];
    uint8_t const b1 = bytes[1];
    if ((b0 & 0x70U) != 0) {
        return WsParse::protocol_error;  // RSV bits without a negotiated extension
    }
    auto const opcode = WsOpcode(b0 & 0x0FU);
    switch (opcode) {
        case WsOpcode::continuation:
        case WsOpcode::text:
        case WsOpcode::binary:
        case WsOpcode::close:
        case WsOpcode::ping:
        case WsOpcode::pong:
            break;
        default:
            return WsParse::protocol_error;
    }
    out.fin = (b0 & 0x80U) != 0;
    out.opcode = opcode;
    out.masked = (b1 & 0x80U) != 0;

    uint64_t len = b1 & 0x7FU;
    size_t at = 2;
    if (len == 126) {
        if (bytes.size() < at + 2) {
            return WsParse::need_more;
        }
        len = (uint64_t(bytes[at]) << 8) | uint64_t(bytes[at + 1]);
        at += 2;
    } else if (len == 127) {
        if (bytes.size() < at + 8) {
            return WsParse::need_more;
        }
        len = 0;
        for (int i = 0; i < 8; ++i) {
            len = (len << 8) | uint64_t(bytes[at + size_t(i)]);
        }
        if ((len >> 63) != 0) {
            return WsParse::protocol_error;  // top bit must be zero
        }
        at += 8;
    }
    if (ws_is_control(opcode) && (!out.fin || len > 125)) {
        return WsParse::protocol_error;  // control frames: short, unfragmented
    }
    if (out.masked) {
        if (bytes.size() < at + 4) {
            return WsParse::need_more;
        }
        out.mask = {bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]};
        at += 4;
    }
    out.payload_len = len;
    out.header_len = at;
    return WsParse::ok;
}

void ws_unmask(std::span<uint8_t> payload, std::array<uint8_t, 4> const& mask, uint64_t offset) noexcept
{
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] ^= mask[(offset + i) % 4];
    }
}

auto ws_write_frame_header(std::span<uint8_t> out, WsOpcode opcode, bool fin, uint64_t payload_len) noexcept -> size_t
{
    size_t const need = payload_len <= 125 ? 2 : payload_len <= 0xFFFF ? 4 : 10;
    if (out.size() < need) {
        return 0;
    }
    out[0] = uint8_t((fin ? 0x80U : 0x00U) | uint8_t(opcode));
    if (payload_len <= 125) {
        out[1] = uint8_t(payload_len);
    } else if (payload_len <= 0xFFFF) {
        out[1] = 126;
        out[2] = uint8_t(payload_len >> 8);
        out[3] = uint8_t(payload_len);
    } else {
        out[1] = 127;
        for (int i = 0; i < 8; ++i) {
            out[2 + size_t(i)] = uint8_t(payload_len >> (56 - (8 * i)));
        }
    }
    return need;
}

}  // namespace statusbar::http
