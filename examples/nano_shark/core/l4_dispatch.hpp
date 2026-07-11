// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/l4_dispatch.hpp — the one TCP/UDP row-push, shared by the normal per-packet walk
// (decode_pass.hpp's PacketVisitor, over an already-decoded value from walk_packet_ext) and defrag's
// completion re-entry (over a raw reassembled buffer, which needs its own strct<>() parse since
// walk_packet_ext cannot be re-entered mid-buffer). Keeps the AllTables-push + JSON-layer logic in
// exactly one place regardless of which of those two shapes the caller has on hand.

#include "json_tree.hpp"
#include "l2l3_nodes.hpp"

#include "nm_protocols.hpp"  // nmproto::{Tcp,Udp,kIpProtoTcp,kIpProtoUdp}

#include <nanom/nanom.hpp>

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

// Parses the L4 header directly from raw bytes (`after_l3`) and pushes its row -- the shape defrag's
// completion callback needs, since it only has a reassembled byte buffer, not a decoded value.
inline void dispatch_l4(std::uint8_t ip_proto, nanom::input after_l3, packet_id_t pid,
                        std::uint32_t datagram_id, bool is_reassembled, AllTables& tables,
                        PacketJson* json) {
  if (ip_proto == nmproto::kIpProtoTcp) {
    auto tcp = nanom::strct<nmproto::Tcp>()(after_l3);
    if (tcp) push_tcp_row(tcp->value, pid, datagram_id, is_reassembled, tables, json);
  } else if (ip_proto == nmproto::kIpProtoUdp) {
    auto udp = nanom::strct<nmproto::Udp>()(after_l3);
    if (udp) push_udp_row(udp->value, pid, datagram_id, is_reassembled, tables, json);
  }
}

}  // namespace nano_shark
