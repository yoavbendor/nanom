// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/lldp.hpp — LLDP (IEEE 802.1AB) TLV walk, promoted from
// examples/nanotins_parity/dpar_lite.cpp's lldp_hdr/lldp_tlv/p_lldp_tlv and the "lldp" branch of
// its run_kind() (that file is untouched; this factors the same decode logic into a reusable
// walk() called directly from decode_pass.hpp rather than through the DPAR rule engine).

#include "json_tree.hpp"
#include "lldp_rows.hpp"
#include "node_row.hpp"

#include <nanom/nanom.hpp>

#include <cstring>

namespace nano_shark::lldp {

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

}  // namespace nano_shark::lldp

NANOM_DESCRIBE(nano_shark::lldp::lldp_hdr, type, length);

namespace nano_shark::lldp {

struct lldp_tlv {
  std::uint16_t type;
  std::uint16_t length;
  nm::bytes     value;
};

inline nm::result<lldp_tlv> p_lldp_tlv(nm::input in) {
  return nm::flat_map(nm::verify(nm::strct<lldp_hdr>(), [](const lldp_hdr& h) { return h.type != 0; }),
                      [](lldp_hdr h) {
                        return nm::map(nm::take(h.length), [h](nm::bytes v) {
                          return lldp_tlv{std::uint16_t(h.type), std::uint16_t(h.length), v};
                        });
                      })(in);
}

inline std::uint16_t rd_be16(const std::byte* v) {
  return (std::uint16_t(std::uint8_t(v[0])) << 8) | std::uint8_t(v[1]);
}

// Decodes one TLV into a row, including the structured sub-TLVs (TTL/SysCaps/MgmtAddr) -- every
// read is bounded by the TLV's own declared length, so a truncated/malformed TLV simply leaves
// the not-yet-read columns at 0 rather than reading out of bounds.
inline LldpTlvRow decode_row(packet_id_t pid, std::uint32_t tlv_index, nm::bytes region,
                             const lldp_tlv& t) {
  LldpTlvRow row{};
  row.packet_id = pid;
  row.tlv_index = tlv_index;
  row.tlv_type = t.type;
  row.tlv_length = t.length;
  row.value_offset =
      std::uint16_t(t.value.empty() ? 0 : std::size_t(t.value.data() - region.data()));
  if ((t.type == kTlvChassisId || t.type == kTlvPortId) && t.length >= 1 && !t.value.empty()) {
    row.subtype = std::uint8_t(t.value[0]);
  }
  const std::size_t head = std::min<std::size_t>(t.length, row.value_head.size());
  if (head > 0) std::memcpy(row.value_head.data(), t.value.data(), head);

  if (t.type == kTlvTtl && t.length >= 2) {
    row.ttl_seconds = rd_be16(t.value.data());
  } else if (t.type == kTlvSysCaps && t.length >= 4) {
    row.caps_supported = rd_be16(t.value.data());
    row.caps_enabled = rd_be16(t.value.data() + 2);
  } else if (t.type == kTlvMgmtAddr && t.length >= 1) {
    // [addr_str_len:1][addr_subtype:1][addr..][iface_subtype:1][iface_num:4][oid..]
    const std::uint8_t addr_str_len = std::uint8_t(t.value[0]);
    if (addr_str_len >= 1 && std::size_t(t.length) >= 1u + addr_str_len) {
      row.mgmt_addr_subtype = std::uint8_t(t.value[1]);
      const std::size_t after_addr = 1u + addr_str_len;
      if (std::size_t(t.length) >= after_addr + 1u) row.mgmt_iface_subtype = std::uint8_t(t.value[after_addr]);
      if (std::size_t(t.length) >= after_addr + 5u) {
        const std::byte* v = t.value.data() + after_addr + 1;
        row.mgmt_iface_number = (std::uint32_t(std::uint8_t(v[0])) << 24) |
                                (std::uint32_t(std::uint8_t(v[1])) << 16) |
                                (std::uint32_t(std::uint8_t(v[2])) << 8) | std::uint32_t(std::uint8_t(v[3]));
      }
    }
  }
  return row;
}

// Walks every TLV in `region` (a packet's LLDP payload), pushing one row per TLV and, when a JSON
// sink is attached, one "lldp" layer entry per TLV (auto-promoted to an array by PacketJson).
template <class LldpTable>
inline void walk(nm::bytes region, packet_id_t pid, LldpTable& table, PacketJson* json) {
  auto r = nm::many0(p_lldp_tlv)(nm::from(region));
  if (!r) return;
  std::uint32_t idx = 0;
  for (const lldp_tlv& t : r->value) {
    LldpTlvRow row = decode_row(pid, idx++, region, t);
    table.push(row);
    if (json) json->add_layer("lldp", row);
  }
}

}  // namespace nano_shark::lldp
