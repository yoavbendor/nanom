// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/someip_rows.hpp — SOME/IP (AUTOSAR PRS_SOMEIP) row structs. Field layout
// cross-checked against nanotins/nanotins/include/nanotins/{protocol_specs_someip,someip_sd}.hpp,
// re-expressed as ordinary NANOM_DESCRIBE'd structs rather than copied: nanotins needed an
// explicit-byte-offset WireSpec for the SD entry's byte-8..11 "major_version:8 | ttl:24" split;
// nanom's bit-field packing handles that natively in normal struct-field order, so it becomes a
// plain described struct parsed via strct<>(), not a hand-rolled offset accessor.

#include "node_row.hpp"

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>

namespace nano_shark {

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t;

// The fixed 16-byte SOME/IP message header. `length` covers client_id..end of payload, so the
// payload after this header is (length - 8) bytes.
struct SomeipHeader {
  nm::be<u16> service_id, method_id;
  nm::be<u32> length;
  nm::be<u16> client_id, session_id;
  u8          protocol_version, interface_version, message_type, return_code;
};

// A 16-byte SOME/IP-SD entry. Service entries (FindService/OfferService) use the trailing word as
// a Minor Version; eventgroup entries (Subscribe/SubscribeAck) pack reserved+counter+eventgroup-id
// there instead -- exposed as the raw `minor_version` word, reinterpreted by the consumer per `type`.
struct SomeipSdEntry {
  u8            type, index_1st_opts, index_2nd_opts;
  nm::ubits<4>  num_opt_1, num_opt_2;
  nm::be<u16>   service_id, instance_id;
  u8            major_version;
  nm::ubits<24> ttl;
  nm::be<u32>   minor_version;
};

}  // namespace nano_shark

NANOM_DESCRIBE(nano_shark::SomeipHeader, service_id, method_id, length, client_id, session_id,
              protocol_version, interface_version, message_type, return_code);
NANOM_DESCRIBE(nano_shark::SomeipSdEntry, type, index_1st_opts, index_2nd_opts, num_opt_1,
              num_opt_2, service_id, instance_id, major_version, ttl, minor_version);

namespace nano_shark {

static_assert(nm::wire_size_v<SomeipHeader> == 16 && nm::wire_size_v<SomeipSdEntry> == 16);

using SomeipNode = Node<SomeipHeader>;  // fits the generic Node<Body> pattern directly

}  // namespace nano_shark

// SomeipNode's describe<> registration comes from node_row.hpp's shared Node<Body> partial
// specialization (see l2l3_nodes.hpp) -- no separate NANOM_DESCRIBE line needed here.

namespace nano_shark {

// One row per SD entry (option shape varies by option type below, but an entry is always this
// fixed 16-byte struct, so it's reused verbatim as `body` -- an extra `entry_index` field beyond
// Node<Body>'s fixed shape is why this isn't Node<>-wrapped, same precedent as Ipv6ExtOptRow).
struct SomeipSdEntryRow {
  packet_id_t   packet_id;
  std::uint8_t  entry_index;
  SomeipSdEntry body;
};

// One row per SD option: its Length/Type, and -- for the endpoint options (IPv4/IPv6,
// uni/multicast/SD) -- the decoded L4 protocol, port, and address (zero for non-endpoint types).
// No single wire struct fits every option type, so this is a synthesized row, like Ipv6OptionRow.
struct SomeipSdOptionRow {
  packet_id_t                 packet_id;
  std::uint8_t                option_index;
  std::uint16_t                length;
  std::uint8_t                type;
  std::uint8_t                l4proto;
  std::uint16_t                port;
  std::array<std::uint8_t, 16> address;
};

// One row per generic SOME/IP TLV member (the optional TLV serialization format's
// [wire_type:3|data_id:12] tag cursor) -- promoted from dpar_lite.cpp's someip_tag/someip_member.
struct SomeipTlvMemberRow {
  packet_id_t   packet_id;
  std::uint32_t tlv_index;
  std::uint16_t data_id;
  std::uint8_t  wire_type;
  std::uint32_t length;
};

}  // namespace nano_shark

NANOM_DESCRIBE(nano_shark::SomeipSdEntryRow, packet_id, entry_index, body);
NANOM_DESCRIBE(nano_shark::SomeipSdOptionRow, packet_id, option_index, length, type, l4proto, port,
              address);
NANOM_DESCRIBE(nano_shark::SomeipTlvMemberRow, packet_id, tlv_index, data_id, wire_type, length);
