// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/l4_dispatch.hpp — the ONE L4 entry point.
//
// There used to be two: the normal per-packet walk (decode_pass.hpp's PacketVisitor::on_udp) and
// defrag's reassembly re-entry (dispatch_l4 here) each re-implemented SOME/IP port matching, and the
// comment that used to sit here admitted the arrangement was maintained by hand. Both now funnel
// through `on_udp_layer` / `on_tcp_layer`, which push the L4 row and then hand off to the single
// `dispatch<layer::l4_payload, Decoder>` fold -- so "the normal and reassembled paths can't
// disagree" is now structural rather than a promise in a comment. SOME/IP port matching itself
// lives in exactly one place, `Someip::trigger` (someip.hpp).

#include <nanom_shark/json_tree.hpp>
#include <nanom_shark/l2l3_nodes.hpp>
#include <nanom_shark/protocol.hpp>

#include <nanom_shark/protocols.hpp>  // nmproto::{Tcp,Udp,kIpProtoTcp,kIpProtoUdp}

#include <nanom/nanom.hpp>

#include <cstdint>

namespace nanom_shark {

// `payload` is a seg_input over the bytes AFTER the L4 header -- a 1-part segment on the normal
// path (contiguous, so seg_input's fast path keeps it pointer-based) and the multi-part reassembled
// datagram on the defrag path. `c` is taken by value: the port/proto fields it fills in are scoped
// to this layer and must not leak back into the caller's context.

template <class Decoder, class Tables, class States>
inline void on_tcp_layer(decode_ctx c, const nmproto::Tcp& v, nanom::seg_input payload,
                         Tables& tables, States& states, PacketJson* json) {
  tables.template get<"tcp">().push(TcpNode{c.packet_id, c.datagram_id, c.is_reassembled, v});
  if (json) json->add_layer("tcp", v);

  c.ip_proto = nmproto::kIpProtoTcp;
  c.src_port = v.src_port;
  c.dst_port = v.dst_port;
  dispatch<layer::l4_payload, Decoder>(c, payload, tables, states, json);
}

template <class Decoder, class Tables, class States>
inline void on_udp_layer(decode_ctx c, const nmproto::Udp& v, nanom::seg_input payload,
                         Tables& tables, States& states, PacketJson* json) {
  tables.template get<"udp">().push(UdpNode{c.packet_id, c.datagram_id, c.is_reassembled, v});
  if (json) json->add_layer("udp", v);

  c.ip_proto = nmproto::kIpProtoUdp;
  c.src_port = v.src_port;
  c.dst_port = v.dst_port;
  dispatch<layer::l4_payload, Decoder>(c, payload, tables, states, json);
}

// The reassembled-datagram re-entry: parses the L4 header straight out of `after_l3` (a seg_input
// over the zero-copy segment list of a completed reassembly), then joins the SAME path the normal
// per-packet walk takes. `c.ip_proto` selects the L4 kind; `c.datagram_id` / `c.is_reassembled`
// are already set by the caller.
template <class Decoder, class Tables, class States>
inline void dispatch_l4(const decode_ctx& c, nanom::seg_input after_l3, Tables& tables,
                        States& states, PacketJson* json) {
  if (c.ip_proto == nmproto::kIpProtoTcp) {
    auto tcp = nanom::strct_seg<nmproto::Tcp>()(after_l3);
    if (tcp) on_tcp_layer<Decoder>(c, tcp->value, tcp->rest, tables, states, json);
  } else if (c.ip_proto == nmproto::kIpProtoUdp) {
    auto udp = nanom::strct_seg<nmproto::Udp>()(after_l3);
    if (udp) on_udp_layer<Decoder>(c, udp->value, udp->rest, tables, states, json);
  }
}

}  // namespace nanom_shark
