// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/lldp_rows.hpp — the LLDP TLV row, promoted from
// examples/nanotins_parity/dpar_lite.cpp's LldpTlvRow (that file is untouched; this is a copy).

#include "node_row.hpp"

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>

namespace nano_shark {

// One row per TLV. Variable-length values (a system name, a chassis id) can't be SoA columns
// (columns are scalars or fixed-size byte arrays), so -- like nanotins' own LldpTlvRow -- this
// stores a fixed 32-byte value_head snapshot alongside the offset/length, plus the structured
// TLVs (TTL, System Capabilities, Management Address) decoded into their own typed columns.
struct LldpTlvRow {
  packet_id_t   packet_id;
  std::uint32_t tlv_index;
  std::uint16_t tlv_type;
  std::uint16_t tlv_length;
  std::uint8_t  subtype;             // chassis/port-id subtype (types 1/2); else 0
  std::uint16_t value_offset;
  std::uint16_t ttl_seconds;         // type 3
  std::uint16_t caps_supported;      // type 7
  std::uint16_t caps_enabled;        // type 7
  std::uint8_t  mgmt_addr_subtype;   // type 8
  std::uint8_t  mgmt_iface_subtype;  // type 8
  std::uint32_t mgmt_iface_number;   // type 8
  std::array<std::uint8_t, 32> value_head;
};

}  // namespace nano_shark

NANOM_DESCRIBE(nano_shark::LldpTlvRow, packet_id, tlv_index, tlv_type, tlv_length, subtype,
              value_offset, ttl_seconds, caps_supported, caps_enabled, mgmt_addr_subtype,
              mgmt_iface_subtype, mgmt_iface_number, value_head);
