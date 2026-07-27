// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/decode_pass.hpp — the one decode pass: pcap/pcapng scan -> per-packet
// Eth/VLAN*/IPv4/IPv6(+extension-header chain, SRv6)/TCP/UDP walk, with IPv4/IPv6 fragment
// reassembly (defrag.hpp) re-entering the same L4 dispatch (l4_dispatch.hpp) over the reassembled
// (zero-copy, segmented) datagram. Populates the decoder's table set (always) and, when a JSON sink
// is attached, one PacketJson per packet covering every layer the walk exposes.
//
// Phase 2 changed two things here:
//
//   * Byte offsets come from the walk. walk_packet_ext now reports each layer's offset through
//     on_offset/on_l2_done, so this file no longer re-derives `14` / `14 + 4*vlan_count` in five
//     separate places from decoded values it had already been handed. What is left is a
//     `decode_ctx` the visitor keeps up to date and hands to dispatch.
//
//   * Protocol dispatch is a fold over the decoder's type list, at two points: right after
//     Ethernet+VLAN (`layer::eth_payload` -- gPTP, LLDP) and right after TCP/UDP
//     (`layer::l4_payload` -- SOME/IP). Both the normal walk and defrag's completion re-entry reach
//     the L4 point through the same `dispatch_l4`, so there is exactly ONE dispatch path.

#include <nanom_shark/decode_options.hpp>
#include <nanom_shark/defrag.hpp>
#include <nanom_shark/json_tree.hpp>
#include <nanom_shark/l2l3_nodes.hpp>
#include <nanom_shark/l4_dispatch.hpp>
#include <nanom_shark/protocol.hpp>

#include <nanom_shark/pcap.hpp>       // nmpcap::scan_blocks / parse_idb / parse_epb
#include <nanom_shark/protocols.hpp>  // nmproto::walk_packet_ext

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace nanom_shark {

namespace detail {

inline std::string ipv6_addr_hex(const std::array<std::uint8_t, 16>& a) {
  static constexpr char hexd[] = "0123456789abcdef";
  std::string out;
  out.reserve(39);
  for (int i = 0; i < 16; ++i) {
    if (i != 0 && i % 2 == 0) out += ':';
    out += hexd[a[i] >> 4];
    out += hexd[a[i] & 0xF];
  }
  return out;
}

inline std::string frame_json(const nmpcap::EpbView& e, std::uint16_t link_type) {
  std::string s = "{\"interface_id\":";
  s += std::to_string(e.interface_id);
  s += ",\"timestamp_raw\":";
  s += std::to_string(e.ts_raw);
  s += ",\"caplen\":";
  s += std::to_string(e.caplen);
  s += ",\"origlen\":";
  s += std::to_string(e.origlen);
  s += ",\"link_type\":";
  s += std::to_string(link_type);
  s += '}';
  return s;
}

inline std::string fragment_json(std::uint32_t datagram_id, std::uint32_t frag_offset_bytes,
                                 bool more_fragments, bool is_first, bool is_last) {
  std::string s = "{\"datagram_id\":";
  s += std::to_string(datagram_id);
  s += ",\"frag_offset_bytes\":";
  s += std::to_string(frag_offset_bytes);
  s += ",\"more_fragments\":";
  s += (more_fragments ? "true" : "false");
  s += ",\"is_first\":";
  s += (is_first ? "true" : "false");
  s += ",\"is_last\":";
  s += (is_last ? "true" : "false");
  s += '}';
  return s;
}

inline std::string datagram_json(const defrag::DatagramRow& d) {
  std::string s = "{\"datagram_id\":";
  s += std::to_string(d.datagram_id);
  s += ",\"total_length\":";
  s += std::to_string(d.total_length);
  s += ",\"fragment_count\":";
  s += std::to_string(d.fragment_count);
  s += ",\"completion_status\":";
  s += std::to_string(d.completion_status);
  s += '}';
  return s;
}

// The walk_packet_ext visitor for one packet: pushes the base L2-L4 rows, feeds fragment-eligible
// IPv4/IPv6 packets into defrag, keeps a decode_ctx current, and hands that ctx to the protocol
// dispatch at each dispatch point.
template <class Decoder, class Tables, class States>
struct PacketVisitor {
  decode_ctx           ctx{};
  Tables*              tables;
  States*              states;
  PacketJson*          json;          // nullptr when no JSON sink is attached
  defrag::DefragState* defrag_state;  // nullptr when defrag is disabled

  // walk_packet_ext reports each layer header's byte offset here, immediately before that layer's
  // callback -- so nothing in this file recomputes an offset from decoded header lengths.
  std::size_t at = 0;
  void on_offset(std::size_t off) { at = off; }

  bool          is_fragment = false;  // suppresses the normal on_tcp/on_udp push when set
  std::size_t   ipv6_base_offset = 0;     // offset of the IPv6 base header's first byte in pkt
  std::uint16_t ipv6_payload_length = 0;  // IPv6 base header's payload_length (bytes after it)

  void on_eth(const nmproto::Ethernet& v) {
    tables->template get<"eth">().push(EthNode{ctx.packet_id, 0, false, v});
    if (json) json->add_layer("eth", v);
  }
  void on_vlan(const nmproto::VlanTag& v) {
    tables->template get<"vlan">().push(VlanNode{ctx.packet_id, 0, false, v});
    if (json) json->add_layer("vlan", v);
    ++ctx.vlan_count;
  }

  // Dispatch point 1: the Ethernet payload. gPTP (0x88F7) and LLDP (0x88CC) ride directly on
  // Ethernet, optionally under VLAN tags, with no further layers -- walk_packet_ext returns right
  // after this hook once it sees a non-IPv4/IPv6 ethertype.
  void on_l2_done(std::uint16_t ethertype, std::size_t l2_end) {
    ctx.ethertype = ethertype;
    ctx.l2_end = l2_end;
    if (l2_end > ctx.pkt.size()) return;
    const nanom::bytes           region = ctx.pkt.subspan(l2_end, ctx.pkt.size() - l2_end);
    const nanom::single_segment  one{region};
    dispatch<layer::eth_payload, Decoder>(ctx, nanom::from(one.view()), *tables, *states, json);
  }

  void on_ipv4(const nmproto::Ipv4& v) {
    tables->template get<"ipv4">().push(Ipv4Node{ctx.packet_id, 0, false, v});
    if (json) json->add_layer("ip", v);
    ctx.ip_version = 4;

    const std::size_t hdr_len =
        std::max<std::size_t>(std::size_t(v.ihl) * 4, nanom::wire_size_v<nmproto::Ipv4>);
    const std::size_t payload_offset = at + hdr_len;  // `at` is the IPv4 header's own offset

    const bool more_fragments = (std::uint8_t(v.flags) & 0x1) != 0;
    const bool eligible = v.frag_offset != 0 || more_fragments;
    if (!eligible || !defrag_state) return;
    is_fragment = true;
    if (payload_offset > ctx.pkt.size()) return;  // truncated capture; nothing usable

    const std::size_t declared = std::size_t(std::uint16_t(v.total_length));
    const std::size_t declared_payload = declared > hdr_len ? declared - hdr_len : 0;
    const std::size_t avail = ctx.pkt.size() - payload_offset;
    const std::size_t payload_len = std::min(declared_payload, avail);
    const nanom::bytes payload = ctx.pkt.subspan(payload_offset, payload_len);

    const std::uint32_t frag_offset_bytes = std::uint32_t(std::uint16_t(v.frag_offset)) * 8;
    const defrag::Ipv4Key key{v.src, v.dst, v.protocol, std::uint16_t(v.identification)};
    const auto result = defrag_state->ipv4.add_fragment(
        key, ctx.packet_id, frag_offset_bytes, more_fragments,
        std::span<const std::byte>(payload.data(), payload.size()));

    const bool is_first = v.frag_offset == 0;
    tables->template get<"ipv4_frag">().push(
        defrag::Ipv4FragMeta{ctx.packet_id, result.datagram_id, std::uint16_t(frag_offset_bytes),
                             more_fragments, is_first, !more_fragments});
    if (json) {
      json->add_layer_json("ip.fragment",
                           detail::fragment_json(result.datagram_id, frag_offset_bytes,
                                                 more_fragments, is_first, !more_fragments));
    }
    if (result.completed) {
      complete_datagram(result, defrag_state->ipv4.find(result.datagram_id), 4, v.protocol);
    }
  }

  void on_ipv6(const nmproto::Ipv6& v) {
    tables->template get<"ipv6">().push(Ipv6Node{ctx.packet_id, 0, false, v});
    if (json) json->add_layer("ipv6", v);
    ctx.ip_version = 6;
    ipv6_base_offset = at;  // `at` is the IPv6 base header's own offset
    ipv6_payload_length = std::uint16_t(v.payload_length);
    last_ipv6_ = v;  // on_fragment (a separate callback) needs src/dst for the Ipv6Key
  }

  void on_tcp(const nmproto::Tcp& v) {
    if (is_fragment) return;  // handled by the reassembly completion path instead
    ctx.l3_end = at;          // `at` is the TCP header's own offset

    const std::size_t hdr_len =
        std::max<std::size_t>(std::size_t(v.data_offset) * 4, nanom::wire_size_v<nmproto::Tcp>);
    const std::size_t payload_offset = at + hdr_len;
    ctx.l4_end = payload_offset;
    const nanom::bytes payload =
        payload_offset <= ctx.pkt.size()
            ? ctx.pkt.subspan(payload_offset, ctx.pkt.size() - payload_offset)
            : nanom::bytes{};
    const nanom::single_segment one{payload};
    on_tcp_layer<Decoder>(ctx, v, nanom::from(one.view()), *tables, *states, json);
  }

  void on_udp(const nmproto::Udp& v) {
    if (is_fragment) return;  // handled by the reassembly completion path instead
    ctx.l3_end = at;          // `at` is the UDP header's own offset

    // udp.length covers the 8-byte header, so the payload length is length - 8, clamped to what was
    // actually captured.
    const std::size_t payload_offset = at + nanom::wire_size_v<nmproto::Udp>;
    ctx.l4_end = payload_offset;
    nanom::bytes payload{};
    if (payload_offset <= ctx.pkt.size()) {
      const std::size_t declared = std::size_t(std::uint16_t(v.length));
      const std::size_t declared_payload = declared > 8 ? declared - 8 : 0;
      const std::size_t avail = ctx.pkt.size() - payload_offset;
      payload = ctx.pkt.subspan(payload_offset, std::min(declared_payload, avail));
    }
    // Wrap the contiguous UDP payload as a 1-part segment so the normal and reassembled paths share
    // one seg_input-based code path; seg_input's fast path keeps this pointer-based.
    const nanom::single_segment one{payload};
    on_udp_layer<Decoder>(ctx, v, nanom::from(one.view()), *tables, *states, json);
  }

  void on_ext_opt(nmproto::Ipv6ExtKind kind, const nmproto::Ipv6ExtOpt& v) {
    if (json) {
      json->add_layer(kind == nmproto::Ipv6ExtKind::hop_by_hop ? "ipv6.hop_by_hop" : "ipv6.dest_opts", v);
    }
  }
  void on_srh(const nmproto::Ipv6Srh& v) {
    if (json) json->add_layer("ipv6.routing", v);
  }
  void on_ah(const nmproto::Ipv6Ah& v) {
    if (json) json->add_layer("ipv6.ah", v);
  }

  void on_fragment(const nmproto::Ipv6Fragment& v) {
    if (json) json->add_layer("ipv6.fragment_hdr", v);
    ipv6_ident_ = std::uint32_t(v.identification);  // IPv6's identification lives on this ext header
    if (!defrag_state) return;
    is_fragment = true;

    const std::uint16_t offset_flags = std::uint16_t(v.offset_flags);
    const bool          more_fragments = (offset_flags & 0x1) != 0;
    const std::uint32_t frag_offset_bytes = std::uint32_t(offset_flags >> 3) * 8;

    // `at` is this Fragment header's own offset; the header is always 8 bytes, so the fragment
    // DATA starts right after it.
    const std::size_t data_offset = at + 8;
    if (data_offset > ctx.pkt.size()) return;  // truncated capture

    // payload_length counts every byte after the 40-byte base header for THIS packet; subtract what
    // came before the fragment payload (preceding ext headers + this Fragment header) to get the
    // declared length of the fragment DATA that follows, then clamp to what was actually captured.
    const std::size_t before_payload =
        data_offset - ipv6_base_offset - nanom::wire_size_v<nmproto::Ipv6>;
    const std::size_t declared_payload = std::size_t(ipv6_payload_length) > before_payload
                                             ? std::size_t(ipv6_payload_length) - before_payload
                                             : 0;
    const std::size_t avail = ctx.pkt.size() - data_offset;
    const std::size_t payload_len = std::min(declared_payload, avail);
    const nanom::bytes payload = ctx.pkt.subspan(data_offset, payload_len);

    const defrag::Ipv6Key key{last_ipv6_.src, last_ipv6_.dst, ipv6_ident_};
    const auto result = defrag_state->ipv6.add_fragment(
        key, ctx.packet_id, frag_offset_bytes, more_fragments,
        std::span<const std::byte>(payload.data(), payload.size()));

    const bool is_first = (offset_flags >> 3) == 0;
    tables->template get<"ipv6_frag">().push(
        defrag::Ipv6FragMeta{ctx.packet_id, result.datagram_id, frag_offset_bytes, more_fragments,
                             is_first, !more_fragments});
    if (json) {
      json->add_layer_json("ipv6.fragment",
                           detail::fragment_json(result.datagram_id, frag_offset_bytes,
                                                 more_fragments, is_first, !more_fragments));
    }
    if (result.completed) {
      complete_datagram(result, defrag_state->ipv6.find(result.datagram_id), 6, v.next_header);
    }
  }

  void on_srh_segment(std::uint8_t srh_order, std::uint8_t segment_index,
                      std::array<std::uint8_t, 16> address) {
    if (!json) return;
    std::string s = "{\"srh_order\":";
    s += std::to_string(srh_order);
    s += ",\"segment_index\":";
    s += std::to_string(segment_index);
    s += ",\"address\":\"";
    s += ipv6_addr_hex(address);
    s += "\"}";
    json->add_layer_json("ipv6.srh_segment", std::move(s));
  }
  void on_ipv6_option(std::uint8_t container, std::uint8_t opt_type, std::uint8_t opt_len) {
    if (!json) return;
    std::string s = "{\"container\":";
    s += std::to_string(container);
    s += ",\"type\":";
    s += std::to_string(opt_type);
    s += ",\"length\":";
    s += std::to_string(opt_len);
    s += '}';
    json->add_layer_json("ipv6.option", std::move(s));
  }

  // Shared IPv4/IPv6 reassembly-completion tail: push the datagram row, then re-enter the ONE L4
  // dispatch over the reassembled datagram's segment list (views into the source file -- no
  // stitched buffer; see defrag.hpp / nanom/segmented.hpp).
  // `entry` comes from the caller's own ReassemblyTable::find(): find() still resolves here
  // because add_fragment() only frees the KEY index on completion (so a new datagram reusing the
  // same 4-tuple starts fresh), not the by-id storage that evict_stale() later cleans up. It is a
  // parameter rather than a lookup here only because the IPv4 and IPv6 tables have distinct types.
  template <class Result, class Entry>
  void complete_datagram(const Result& result, const Entry* r, std::uint8_t ip_version,
                         std::uint8_t ip_proto) {
    defrag::DatagramRow row{};
    row.datagram_id = result.datagram_id;
    row.ip_version = ip_version;
    row.total_length = std::uint32_t(result.parts.size());
    row.fragment_count = r ? std::uint32_t(r->fragments.size()) : 0;
    row.first_packet_id = r ? r->first_packet_id : ctx.packet_id;
    row.last_packet_id = ctx.packet_id;
    row.completion_status = 0;  // complete
    tables->template get<"datagram">().push(row);
    if (json) json->add_layer_json("ip.reassembled", detail::datagram_json(row));

    decode_ctx c = ctx;
    c.datagram_id = result.datagram_id;
    c.is_reassembled = true;
    c.ip_version = ip_version;
    c.ip_proto = ip_proto;
    c.pkt = nanom::bytes{};  // a reassembled datagram has no single contiguous packet
    dispatch_l4<Decoder>(c, nanom::from(result.parts), *tables, *states, json);
  }

  // on_ipv6 and on_fragment are separate callbacks; these carry IPv6 src/dst/identification from
  // the former to the latter so the Ipv6Key is available when a Fragment ext header is seen.
  nmproto::Ipv6 last_ipv6_{};
  std::uint32_t ipv6_ident_ = 0;
};

}  // namespace detail

struct SinkHub {
  std::vector<PacketJson>* json_packets = nullptr;  // non-null => build one PacketJson per packet
};

// The ONE decode pass: scan_blocks -> per EPB/pcap-record, walk_packet_ext (feeding IPv4/IPv6
// fragments to defrag; a completed reassembly re-enters the same L4 dispatch over the zero-copy
// reassembled segment list). Pushes every row into `tables` always, and (when sink.json_packets is
// set) a "frame" + one entry per decoded layer into that packet's PacketJson.
//
// `Decoder` is deduced from `tables` -- `tables_of<my_decoder> t; run_decode_pass(file, t, ...)`
// selects that decoder's protocol set, with no other change at the call site. A malformed layer
// stops that packet's walk only (walk_packet contract, see protocols.hpp); this function returns
// false only when the pcap/pcapng block scan itself fails (a corrupt file, not a corrupt packet).
template <class Decoder>
inline bool run_decode_pass(nanom::bytes file, tables_of<Decoder>& tables, SinkHub sink,
                            const DecodeOptions& opts, std::string& error) {
  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, error)) return false;

  defrag::DefragState defrag_state{defrag::ReassemblyTable<defrag::Ipv4Key>(opts.ipv4_defrag),
                                   defrag::ReassemblyTable<defrag::Ipv6Key>(opts.ipv6_defrag)};
  states_of<Decoder> states{};  // per-pass mutable protocol state (gPTP's msg_index, ...)

  std::vector<std::uint16_t> iface_link;  // per-interface link type, reset at each SHB
  packet_id_t pid = 0;

  for (const nmpcap::BlockRef& ref : refs) {
    if (ref.kind == nmpcap::Kind::Shb) {
      iface_link.clear();
      continue;
    }
    if (ref.kind == nmpcap::Kind::Idb) {
      nmpcap::IdbView idb{};
      if (nmpcap::parse_idb(file, ref, idb)) iface_link.push_back(idb.link_type);
      continue;
    }
    if (ref.kind != nmpcap::Kind::Epb && ref.kind != nmpcap::Kind::PcapRecord) continue;

    nmpcap::EpbView e{};
    if (!nmpcap::parse_epb(file, ref, e)) continue;
    const std::uint16_t link_type =
        e.interface_id < iface_link.size() ? iface_link[e.interface_id] : std::uint16_t{0};

    tables.template get<"packets">().push(PacketRow{pid, e.payload_file_offset, e.caplen, e.origlen});

    PacketJson* pj = nullptr;
    if (sink.json_packets) {
      sink.json_packets->emplace_back(pid);
      pj = &sink.json_packets->back();
      pj->add_layer_json("frame", detail::frame_json(e, link_type));
    }

    const std::size_t poff = std::size_t(e.payload_file_offset);
    if (opts.decode_l2l3 && poff + e.caplen <= file.size()) {
      const nanom::bytes pkt = file.subspan(poff, e.caplen);
      decode_ctx ctx{};
      ctx.opts = &opts;
      ctx.packet_id = pid;
      ctx.link_type = link_type;
      ctx.pkt = pkt;
      detail::PacketVisitor<Decoder, tables_of<Decoder>, states_of<Decoder>> visitor{
          ctx, &tables, &states, pj, opts.decode_defrag ? &defrag_state : nullptr};
      nmproto::walk_packet_ext(link_type, pkt, visitor);
    }

    // completion_status 0 (complete) was already pushed immediately at completion time (on_ipv4 /
    // on_fragment above); only timed_out/conflict/capacity entries are new information here.
    for (const auto& s : defrag_state.ipv4.evict_stale(pid)) {
      if (s.completion_status != 0)
        tables.template get<"datagram">().push(defrag::to_datagram_row(s, 4));
    }
    for (const auto& s : defrag_state.ipv6.evict_stale(pid)) {
      if (s.completion_status != 0)
        tables.template get<"datagram">().push(defrag::to_datagram_row(s, 6));
    }
    ++pid;
  }
  return true;
}

}  // namespace nanom_shark
