// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/decode_pass.hpp — the one decode pass: pcap/pcapng scan -> per-packet
// Eth/VLAN*/IPv4/IPv6(+extension-header chain, SRv6)/TCP/UDP walk, with IPv4/IPv6 fragment
// reassembly (core/defrag.hpp) re-entering the same TCP/UDP dispatch (core/l4_dispatch.hpp) over
// the reassembled buffer. Populates AllTables (always) and, when a JSON sink is attached, one
// PacketJson per packet covering every layer the walk exposes -- including the IPv6 extension
// headers, SRv6 segments and TLV options that AllTables does not yet tabulate (those land in
// AllTables once a sink that needs them, e.g. Parquet/Lance in a later phase, actually consumes
// them; the JSON sink already renders them directly from the decoded values at each
// walk_packet_ext callback, so nothing here is deferred for that sink).
//
// Fragment byte-offset bookkeeping: walk_packet_ext's visitor callbacks hand back DECODED VALUES,
// not byte offsets, so this file independently tracks the cumulative offset through Ethernet ->
// VLAN* -> IPv4/IPv6(+ext headers) purely by counting what each callback already tells us (14
// bytes Ethernet, 4 bytes per VLAN tag, ihl*4 / 40+ext-header-lengths for IPv4/IPv6) -- this keeps
// nm_protocols.hpp itself untouched rather than having it expose offsets it doesn't need for its
// own (offset-free) callback contract.

#include "decode_options.hpp"
#include "defrag.hpp"
#include "gptp.hpp"
#include "json_tree.hpp"
#include "l2l3_nodes.hpp"
#include "l4_dispatch.hpp"
#include "lldp.hpp"
#include "someip.hpp"

#include "nm_pcap.hpp"       // nmpcap::scan_blocks / parse_idb / parse_epb — include path set by CMake
#include "nm_protocols.hpp"  // nmproto::walk_packet_ext

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace nano_shark {

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

// The walk_packet_ext visitor for one packet: pushes AllTables rows for the base L2-L4 layers,
// feeds fragment-eligible IPv4/IPv6 packets into defrag, and (when `json` is non-null) renders
// every layer the walk exposes into that packet's PacketJson.
struct PacketVisitor {
  packet_id_t          pid;
  AllTables*           tables;
  PacketJson*          json;          // nullptr when no JSON sink is attached
  defrag::DefragState* defrag_state;  // nullptr when defrag is disabled
  nanom::bytes         pkt;           // the whole packet's captured bytes, for offset bookkeeping
  const DecodeOptions* opts;

  std::uint32_t vlan_count = 0;
  bool          is_fragment = false;  // suppresses the normal on_tcp/on_udp push when set

  std::size_t   ipv6_ext_cursor = 0;      // running byte offset through the IPv6 ext-header chain
  std::size_t   ipv6_base_offset = 0;     // offset of the IPv6 base header's first byte in pkt
  std::uint16_t ipv6_payload_length = 0;  // IPv6 base header's payload_length (bytes after it)
  std::size_t   ipv4_l3_after_offset = 0; // offset right after the IPv4 header (options included)
  int           ip_version_seen = 0;      // 0 = neither yet, else 4 or 6 -- which offset on_udp uses

  // gPTP (ethertype 0x88F7) and LLDP (0x88CC) both ride directly on Ethernet, optionally under one
  // VLAN tag, with no further layers -- walk_packet_ext returns early right after on_eth/on_vlan
  // once it sees a non-IPv4/IPv6 ethertype, so dispatching here needs no change to that function.
  void maybe_dispatch_l2_protocol(std::uint16_t ethertype, std::size_t offset) {
    if (offset > pkt.size()) return;
    const nanom::bytes region = pkt.subspan(offset, pkt.size() - offset);
    if (ethertype == nmgptp::kEtherTypeGptp) {
      nmgptp::parse_gptp_message(tables->gptp, pid, nanom::from(region), json);
    } else if (ethertype == lldp::kEtherTypeLldp) {
      lldp::walk(region, pid, tables->lldp, json);
    }
  }

  void on_eth(const nmproto::Ethernet& v) {
    tables->eth.push(EthNode{pid, 0, false, v});
    if (json) json->add_layer("eth", v);
    maybe_dispatch_l2_protocol(std::uint16_t(v.ethertype), 14);
  }
  void on_vlan(const nmproto::VlanTag& v) {
    tables->vlan.push(VlanNode{pid, 0, false, v});
    if (json) json->add_layer("vlan", v);
    ++vlan_count;
    maybe_dispatch_l2_protocol(std::uint16_t(v.inner_ethertype), 14 + 4 * std::size_t(vlan_count));
  }
  void on_ipv4(const nmproto::Ipv4& v) {
    tables->ipv4.push(Ipv4Node{pid, 0, false, v});
    if (json) json->add_layer("ip", v);
    ip_version_seen = 4;

    const std::size_t hdr_len =
        std::max<std::size_t>(std::size_t(v.ihl) * 4, nanom::wire_size_v<nmproto::Ipv4>);
    const std::size_t base_offset = 14 + 4 * std::size_t(vlan_count);  // Ethernet + N VLAN tags
    const std::size_t payload_offset = base_offset + hdr_len;
    ipv4_l3_after_offset = payload_offset;

    const bool more_fragments = (std::uint8_t(v.flags) & 0x1) != 0;
    const bool eligible = v.frag_offset != 0 || more_fragments;
    if (!eligible || !defrag_state) return;
    is_fragment = true;
    if (payload_offset > pkt.size()) return;  // truncated capture; nothing usable

    const std::size_t declared = std::size_t(std::uint16_t(v.total_length));
    const std::size_t declared_payload = declared > hdr_len ? declared - hdr_len : 0;
    const std::size_t avail = pkt.size() - payload_offset;
    const std::size_t payload_len = std::min(declared_payload, avail);
    const nanom::bytes payload = pkt.subspan(payload_offset, payload_len);

    const std::uint32_t frag_offset_bytes = std::uint32_t(std::uint16_t(v.frag_offset)) * 8;
    const defrag::Ipv4Key key{v.src, v.dst, v.protocol, std::uint16_t(v.identification)};
    const auto result = defrag_state->ipv4.add_fragment(
        key, pid, frag_offset_bytes, more_fragments,
        std::span<const std::byte>(payload.data(), payload.size()));

    const bool is_first = v.frag_offset == 0;
    tables->ipv4_frag.push(defrag::Ipv4FragMeta{pid, result.datagram_id,
                                                std::uint16_t(frag_offset_bytes), more_fragments,
                                                is_first, !more_fragments});
    if (json) {
      json->add_layer_json("ip.fragment", detail::fragment_json(result.datagram_id, frag_offset_bytes,
                                                                 more_fragments, is_first, !more_fragments));
    }
    if (result.completed) {
      // find() still resolves the entry here: add_fragment() only frees the KEY index on
      // completion (so a new datagram reusing the same 4-tuple starts fresh), not the by-id
      // storage evict_stale() later cleans up.
      const auto* r = defrag_state->ipv4.find(result.datagram_id);
      defrag::DatagramRow row{};
      row.datagram_id = result.datagram_id;
      row.ip_version = 4;
      row.total_length = std::uint32_t(result.assembled.size());
      row.fragment_count = r ? std::uint32_t(r->fragments.size()) : 0;
      row.first_packet_id = r ? r->first_packet_id : pid;
      row.last_packet_id = pid;
      row.completion_status = 0;  // complete
      tables->datagram.push(row);
      if (json) json->add_layer_json("ip.reassembled", detail::datagram_json(row));
      dispatch_l4(v.protocol, nanom::from(result.assembled), pid, result.datagram_id,
                 /*is_reassembled=*/true, *tables, json, *opts);
    }
  }
  void on_ipv6(const nmproto::Ipv6& v) {
    tables->ipv6.push(Ipv6Node{pid, 0, false, v});
    if (json) json->add_layer("ipv6", v);
    ip_version_seen = 6;
    ipv6_base_offset = 14 + 4 * std::size_t(vlan_count);
    ipv6_ext_cursor = ipv6_base_offset + nanom::wire_size_v<nmproto::Ipv6>;
    ipv6_payload_length = std::uint16_t(v.payload_length);
    last_ipv6_ = v;  // on_fragment (a separate callback) needs src/dst for the Ipv6Key
  }
  void on_tcp(const nmproto::Tcp& v) {
    if (is_fragment) return;  // handled by the reassembly completion path instead
    push_tcp_row(v, pid, 0, false, *tables, json);
  }
  void on_udp(const nmproto::Udp& v) {
    if (is_fragment) return;  // handled by the reassembly completion path instead
    push_udp_row(v, pid, 0, false, *tables, json);

    // Locate the UDP payload the same way Phase 2 locates fragment payloads: the L3-header-end
    // offset this visitor already tracks (ipv4_l3_after_offset / ipv6_ext_cursor), plus the fixed
    // 8-byte UDP header. udp.length covers the header, so payload length is length - 8.
    const std::size_t l3_after = (ip_version_seen == 4) ? ipv4_l3_after_offset : ipv6_ext_cursor;
    const std::size_t payload_offset = l3_after + nanom::wire_size_v<nmproto::Udp>;
    if (payload_offset > pkt.size()) return;
    const std::size_t declared = std::size_t(std::uint16_t(v.length));
    const std::size_t declared_payload = declared > 8 ? declared - 8 : 0;
    const std::size_t avail = pkt.size() - payload_offset;
    const nanom::bytes payload = pkt.subspan(payload_offset, std::min(declared_payload, avail));
    maybe_dispatch_someip_from_udp(v, payload, pid, *tables, json, *opts);
  }
  void on_ext_opt(nmproto::Ipv6ExtKind kind, const nmproto::Ipv6ExtOpt& v) {
    if (json) {
      json->add_layer(kind == nmproto::Ipv6ExtKind::hop_by_hop ? "ipv6.hop_by_hop" : "ipv6.dest_opts", v);
    }
    ipv6_ext_cursor += (std::size_t(v.hdr_ext_len) + 1) * 8;
  }
  void on_srh(const nmproto::Ipv6Srh& v) {
    if (json) json->add_layer("ipv6.routing", v);
    ipv6_ext_cursor += (std::size_t(v.hdr_ext_len) + 1) * 8;
  }
  void on_ah(const nmproto::Ipv6Ah& v) {
    if (json) json->add_layer("ipv6.ah", v);
    ipv6_ext_cursor += (std::size_t(v.payload_len) + 2) * 4;
  }
  void on_fragment(const nmproto::Ipv6Fragment& v) {
    if (json) json->add_layer("ipv6.fragment_hdr", v);
    ipv6_ident_ = std::uint32_t(v.identification);  // IPv6's identification lives on this ext header
    if (!defrag_state) return;
    is_fragment = true;

    const std::uint16_t offset_flags = std::uint16_t(v.offset_flags);
    const bool           more_fragments = (offset_flags & 0x1) != 0;
    const std::uint32_t  frag_offset_bytes = std::uint32_t(offset_flags >> 3) * 8;

    ipv6_ext_cursor += 8;  // the Fragment header itself is always 8 bytes
    if (ipv6_ext_cursor > pkt.size()) return;  // truncated capture

    // payload_length counts every byte after the 40-byte base header for THIS packet; subtract what
    // came before the fragment payload (preceding ext headers + this Fragment header) to get the
    // declared length of the fragment DATA that follows, then clamp to what was actually captured.
    const std::size_t before_payload = ipv6_ext_cursor - ipv6_base_offset - nanom::wire_size_v<nmproto::Ipv6>;
    const std::size_t declared_payload =
        std::size_t(ipv6_payload_length) > before_payload ? std::size_t(ipv6_payload_length) - before_payload : 0;
    const std::size_t avail = pkt.size() - ipv6_ext_cursor;
    const std::size_t payload_len = std::min(declared_payload, avail);
    const nanom::bytes payload = pkt.subspan(ipv6_ext_cursor, payload_len);

    const defrag::Ipv6Key key{last_ipv6_.src, last_ipv6_.dst, ipv6_ident_};
    const auto result = defrag_state->ipv6.add_fragment(
        key, pid, frag_offset_bytes, more_fragments,
        std::span<const std::byte>(payload.data(), payload.size()));

    const bool is_first = (offset_flags >> 3) == 0;
    tables->ipv6_frag.push(defrag::Ipv6FragMeta{pid, result.datagram_id, frag_offset_bytes,
                                                more_fragments, is_first, !more_fragments});
    if (json) {
      json->add_layer_json("ipv6.fragment", detail::fragment_json(result.datagram_id, frag_offset_bytes,
                                                                   more_fragments, is_first, !more_fragments));
    }
    if (result.completed) {
      const auto* r = defrag_state->ipv6.find(result.datagram_id);
      defrag::DatagramRow row{};
      row.datagram_id = result.datagram_id;
      row.ip_version = 6;
      row.total_length = std::uint32_t(result.assembled.size());
      row.fragment_count = r ? std::uint32_t(r->fragments.size()) : 0;
      row.first_packet_id = r ? r->first_packet_id : pid;
      row.last_packet_id = pid;
      row.completion_status = 0;  // complete
      tables->datagram.push(row);
      if (json) json->add_layer_json("ip.reassembled", detail::datagram_json(row));
      dispatch_l4(v.next_header, nanom::from(result.assembled), pid, result.datagram_id,
                 /*is_reassembled=*/true, *tables, json, *opts);
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
// fragments to defrag; a completed reassembly re-enters the same UDP/TCP dispatch over the owned
// reassembled buffer). Pushes every row into `tables` always, and (when sink.json_packets is set)
// a "frame" + one entry per decoded layer into that packet's PacketJson. A malformed layer stops
// that packet's walk only (existing walk_packet contract, see nm_protocols.hpp); this function
// returns false only when the pcap/pcapng block scan itself fails (a corrupt file, not a corrupt
// packet).
inline bool run_decode_pass(nanom::bytes file, AllTables& tables, SinkHub sink,
                            const DecodeOptions& opts, std::string& error) {
  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, error)) return false;

  defrag::DefragState defrag_state{defrag::ReassemblyTable<defrag::Ipv4Key>(opts.ipv4_defrag),
                                   defrag::ReassemblyTable<defrag::Ipv6Key>(opts.ipv6_defrag)};

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

    tables.packets.push(PacketRow{pid, e.payload_file_offset, e.caplen, e.origlen});

    PacketJson* pj = nullptr;
    if (sink.json_packets) {
      sink.json_packets->emplace_back(pid);
      pj = &sink.json_packets->back();
      pj->add_layer_json("frame", detail::frame_json(e, link_type));
    }

    const std::size_t poff = std::size_t(e.payload_file_offset);
    if (opts.decode_l2l3 && poff + e.caplen <= file.size()) {
      const nanom::bytes pkt = file.subspan(poff, e.caplen);
      detail::PacketVisitor visitor{pid, &tables, pj, opts.decode_defrag ? &defrag_state : nullptr,
                                    pkt, &opts};
      nmproto::walk_packet_ext(link_type, pkt, visitor);
    }

    // completion_status 0 (complete) was already pushed immediately at completion time (on_ipv4 /
    // on_fragment above); only timed_out/conflict/capacity entries are new information here.
    for (const auto& s : defrag_state.ipv4.evict_stale(pid)) {
      if (s.completion_status != 0) tables.datagram.push(defrag::to_datagram_row(s, 4));
    }
    for (const auto& s : defrag_state.ipv6.evict_stale(pid)) {
      if (s.completion_status != 0) tables.datagram.push(defrag::to_datagram_row(s, 6));
    }
    ++pid;
  }
  return true;
}

}  // namespace nano_shark
