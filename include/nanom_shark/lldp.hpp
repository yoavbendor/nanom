// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/core/lldp.hpp — LLDP (IEEE 802.1AB) TLV walk, promoted from
// examples/nanotins_parity/dpar_lite.cpp's lldp_hdr/lldp_tlv/p_lldp_tlv and the "lldp" branch of
// its run_kind() (that file is untouched; this factors the same decode logic into a reusable
// walk() called directly from decode_pass.hpp rather than through the DPAR rule engine).

#include <nanom_shark/json_tree.hpp>
#include <nanom_shark/lldp_rows.hpp>
#include <nanom_shark/node_row.hpp>
#include <nanom_shark/protocol.hpp>

#include <nanom/nanom.hpp>

#include <algorithm>
#include <array>
#include <cstring>

namespace nanom_shark::lldp {

namespace nm = nanom;

// LLDP rides directly on Ethernet (optionally under one VLAN tag) with this EtherType.
inline constexpr std::uint16_t kEtherTypeLldp = 0x88CC;

inline constexpr std::uint16_t kTlvEnd = 0, kTlvChassisId = 1, kTlvPortId = 2, kTlvTtl = 3,
                               kTlvSysCaps = 7, kTlvMgmtAddr = 8;

// [type:7][length:9] header; End TLV (type 0) stops the walk.
struct lldp_hdr {
  nm::ubits<7> type;
  nm::ubits<9> length;
};

}  // namespace nanom_shark::lldp

NANOM_DESCRIBE(nanom_shark::lldp::lldp_hdr, type, length);

namespace nanom_shark::lldp {

// The longest prefix of a TLV value decode_row() below ever reads: the Management Address TLV's
// [addr_str_len:1][addr_subtype:1][addr..][iface_subtype:1][iface_num:4], with addr_str_len at its
// u8 maximum -> 1 + 255 + 1 + 4 = 261 bytes. Every other decoded field (subtype, TTL, system
// capabilities, the 32-byte value_head snapshot) lies well inside that. The walk therefore gathers
// at most this many bytes of each value; the rest of the value is never materialized, which is what
// lets one code path serve both a contiguous and a segmented (reassembled) LLDPDU.
inline constexpr std::size_t kLldpValueProbe = 261;

// One decoded TLV: the header fields, the value's logical offset within the walked region, and the
// bounded value prefix above. Deliberately NOT an nm::bytes view of the value -- a value that
// straddles a segment seam has no contiguous view, and a row that stores only a bounded snapshot
// does not need one.
struct lldp_tlv {
  std::uint16_t type       = 0;
  std::uint16_t length     = 0;
  std::size_t   value_at   = 0;  // ABSOLUTE cursor offset of the value (walk() rebases it)
  std::uint16_t head_len   = 0;  // valid bytes in `head` == min(length, kLldpValueProbe)
  std::array<std::byte, kLldpValueProbe> head{};
};

// Reads one TLV off a seg_input cursor: the [type:7][length:9] header (End TLV, type 0, stops the
// walk with a recoverable error, exactly like the verify() the contiguous parser used), then the
// bounded value prefix, then advances past the whole value without copying it.
inline nm::seg_result<lldp_tlv> p_lldp_tlv_seg(nm::seg_input in) {
  auto h = nm::strct_seg<lldp_hdr>()(in);
  if (!h) return nm::unexp(h.error());
  if (std::uint16_t(h->value.type) == kTlvEnd) return nm::seg_make_err(in, "lldp TLV (end of LLDPDU)");

  const std::size_t len  = std::size_t(h->value.length);
  const nm::seg_input body = h->rest;
  if (body.size() < len) return nm::seg_make_incomplete(body, len - body.size());

  lldp_tlv t{};
  t.type     = std::uint16_t(h->value.type);
  t.length   = std::uint16_t(len);
  t.value_at = body.offset();
  t.head_len = std::uint16_t(std::min(len, kLldpValueProbe));
  if (t.head_len > 0) body.gather(std::span<std::byte>(t.head.data(), t.head_len));
  return nm::seg_done{t, body.advance(len)};
}

inline std::uint16_t rd_be16(const std::byte* v) {
  return (std::uint16_t(std::uint8_t(v[0])) << 8) | std::uint8_t(v[1]);
}

// Decodes one TLV into a row, including the structured sub-TLVs (TTL/SysCaps/MgmtAddr) -- every
// read is bounded by the TLV's own declared length, so a truncated/malformed TLV simply leaves
// the not-yet-read columns at 0 rather than reading out of bounds. `base` is the walked region's
// own start offset, so value_offset stays relative to the region exactly as before.
inline LldpTlvRow decode_row(packet_id_t pid, std::uint32_t tlv_index, std::size_t base,
                             const lldp_tlv& t) {
  LldpTlvRow row{};
  row.packet_id = pid;
  row.tlv_index = tlv_index;
  row.tlv_type = t.type;
  row.tlv_length = t.length;
  row.value_offset = std::uint16_t(t.length == 0 ? 0 : t.value_at - base);
  // Every read below indexes `t.head`, whose valid prefix is min(length, kLldpValueProbe) bytes --
  // and each read is guarded by the same t.length test as before, at an index < kLldpValueProbe,
  // so a guarded read is always within the gathered prefix.
  const std::byte* v = t.head.data();
  if ((t.type == kTlvChassisId || t.type == kTlvPortId) && t.length >= 1) {
    row.subtype = std::uint8_t(v[0]);
  }
  const std::size_t head = std::min<std::size_t>(t.length, row.value_head.size());
  if (head > 0) std::memcpy(row.value_head.data(), v, head);

  if (t.type == kTlvTtl && t.length >= 2) {
    row.ttl_seconds = rd_be16(v);
  } else if (t.type == kTlvSysCaps && t.length >= 4) {
    row.caps_supported = rd_be16(v);
    row.caps_enabled = rd_be16(v + 2);
  } else if (t.type == kTlvMgmtAddr && t.length >= 1) {
    // [addr_str_len:1][addr_subtype:1][addr..][iface_subtype:1][iface_num:4][oid..]
    const std::uint8_t addr_str_len = std::uint8_t(v[0]);
    if (addr_str_len >= 1 && std::size_t(t.length) >= 1u + addr_str_len) {
      row.mgmt_addr_subtype = std::uint8_t(v[1]);
      const std::size_t after_addr = 1u + addr_str_len;
      if (std::size_t(t.length) >= after_addr + 1u) row.mgmt_iface_subtype = std::uint8_t(v[after_addr]);
      if (std::size_t(t.length) >= after_addr + 5u) {
        const std::byte* n = v + after_addr + 1;
        row.mgmt_iface_number = (std::uint32_t(std::uint8_t(n[0])) << 24) |
                                (std::uint32_t(std::uint8_t(n[1])) << 16) |
                                (std::uint32_t(std::uint8_t(n[2])) << 8) | std::uint32_t(std::uint8_t(n[3]));
      }
    }
  }
  return row;
}

// Walks every TLV in `region` (a packet's LLDP payload), pushing one row per TLV and, when a JSON
// sink is attached, one "lldp" layer entry per TLV (auto-promoted to an array by PacketJson).
//
// `region` is a seg_input, so this walks a genuinely segmented LLDPDU (a reassembled datagram, or
// any caller-supplied scatter-gather payload) as correctly as a contiguous one: many0_seg drives
// the repetition and p_lldp_tlv_seg windows each TLV across whatever seams it happens to straddle.
// This function used to take contiguous nm::bytes and run nm::many0 over them, which meant the
// seg_input the protocol was handed had to be collapsed (silently mis-parsing anything that could
// not be collapsed losslessly) before it could be walked at all.
template <class LldpTable>
inline void walk(nm::seg_input region, packet_id_t pid, LldpTable& table, PacketJson* json) {
  const auto r = nm::many0_seg(p_lldp_tlv_seg)(region);
  if (!r) return;  // only a non-recoverable error (a live cursor's `incomplete`) reaches here
  const std::size_t base = region.offset();
  std::uint32_t     idx  = 0;
  for (const lldp_tlv& t : r->value) {
    LldpTlvRow row = decode_row(pid, idx++, base, t);
    table.push(row);
    if (json) json->add_layer("lldp", row);
  }
}

/// Contiguous convenience overload: wraps the bytes as a one-part segment list and runs the SAME
/// walk, so there is exactly one LLDP decode path and the two forms cannot drift apart.
template <class LldpTable>
inline void walk(nm::bytes region, packet_id_t pid, LldpTable& table, PacketJson* json) {
  const nm::single_segment one{region};
  walk(nm::from(one.view()), pid, table, json);
}

}  // namespace nanom_shark::lldp

namespace nanom_shark {

// LLDP rides directly on Ethernet (optionally under VLAN tags), so its trigger is a plain
// compile-time ethertype compare -- codegen-identical to the `ethertype == 0x88CC` it replaces.
struct Lldp {
  using trigger = ethertype<lldp::kEtherTypeLldp>;
  using state   = no_state;

  static constexpr auto tables = table_spec<table_decl<"lldp", LldpTlvRow>>{};

  // Walks the seg_input it is handed, rather than collapsing to c.eth_payload_bytes() first: an
  // eth_payload dispatch is single-segment today, but a protocol that ignores its cursor is only
  // accidentally correct, and would silently mis-parse the moment its payload arrives segmented.
  static void parse(const decode_ctx& c, nanom::seg_input payload, no_state&, auto& t,
                    PacketJson* json) {
    lldp::walk(payload, c.packet_id, t.template get<"lldp">(), json);
  }
};

}  // namespace nanom_shark
