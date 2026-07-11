// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/l4_dispatch.hpp — the one TCP/UDP row-push, shared by the normal per-packet walk
// (decode_pass.hpp's PacketVisitor, over an already-decoded value from walk_packet_ext) and defrag's
// completion re-entry (over a raw reassembled buffer, which needs its own strct<>() parse since
// walk_packet_ext cannot be re-entered mid-buffer). Keeps the AllTables-push + JSON-layer logic in
// exactly one place regardless of which of those two shapes the caller has on hand. Also the one
// place SOME/IP port-matching happens, so the normal and reassembled paths can't disagree.

#include "decode_options.hpp"
#include "json_tree.hpp"
#include "l2l3_nodes.hpp"
#include "someip.hpp"

#include "nm_protocols.hpp"  // nmproto::{Tcp,Udp,kIpProtoTcp,kIpProtoUdp}

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>

namespace nano_shark {

inline void push_tcp_row(const nmproto::Tcp& v, packet_id_t pid, std::uint32_t datagram_id,
                         bool is_reassembled, AllTables& tables, PacketJson* json) {
  tables.tcp.push(TcpNode{pid, datagram_id, is_reassembled, v});
  if (json) json->add_layer("tcp", v);
}
inline void push_udp_row(const nmproto::Udp& v, packet_id_t pid, std::uint32_t datagram_id,
                         bool is_reassembled, AllTables& tables, PacketJson* json) {
  tables.udp.push(UdpNode{pid, datagram_id, is_reassembled, v});
  if (json) json->add_layer("udp", v);
}

// Shared by both the normal (decode_pass.hpp's on_udp) and reassembled (dispatch_l4 below) UDP
// paths so port-matching can't disagree between them. `payload` is the bytes after the UDP header.
inline void maybe_dispatch_someip_from_udp(const nmproto::Udp& udp, nanom::bytes payload, packet_id_t pid,
                                           AllTables& tables, PacketJson* json, const DecodeOptions& opts) {
  const std::uint16_t sport = udp.src_port, dport = udp.dst_port;
  const auto& ports = opts.someip_ports;
  const bool matched =
      std::find(ports.begin(), ports.end(), sport) != ports.end() ||
      std::find(ports.begin(), ports.end(), dport) != ports.end();
  if (!matched) return;
  const auto& tlv_ports = opts.someip_tlv_ports;
  const bool assume_tlv =
      std::find(tlv_ports.begin(), tlv_ports.end(), sport) != tlv_ports.end() ||
      std::find(tlv_ports.begin(), tlv_ports.end(), dport) != tlv_ports.end();
  someip::maybe_dispatch(payload, pid, assume_tlv, tables.someip, tables.someip_sd_entry,
                         tables.someip_sd_option, tables.someip_tlv, json);
}

// Parses the L4 header directly from raw bytes (`after_l3`) and pushes its row -- the shape defrag's
// completion callback needs, since it only has a reassembled byte buffer, not a decoded value.
inline void dispatch_l4(std::uint8_t ip_proto, nanom::input after_l3, packet_id_t pid,
                        std::uint32_t datagram_id, bool is_reassembled, AllTables& tables,
                        PacketJson* json, const DecodeOptions& opts) {
  if (ip_proto == nmproto::kIpProtoTcp) {
    auto tcp = nanom::strct<nmproto::Tcp>()(after_l3);
    if (tcp) push_tcp_row(tcp->value, pid, datagram_id, is_reassembled, tables, json);
  } else if (ip_proto == nmproto::kIpProtoUdp) {
    auto udp = nanom::strct<nmproto::Udp>()(after_l3);
    if (udp) {
      push_udp_row(udp->value, pid, datagram_id, is_reassembled, tables, json);
      maybe_dispatch_someip_from_udp(udp->value, udp->rest.span(), pid, tables, json, opts);
    }
  }
}

}  // namespace nano_shark
