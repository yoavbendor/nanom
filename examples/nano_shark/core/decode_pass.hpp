// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/decode_pass.hpp — the one decode pass: pcap/pcapng scan -> per-packet
// Eth/VLAN*/IPv4/IPv6(+extension-header chain, SRv6)/TCP/UDP walk. Populates AllTables (always)
// and, when a JSON sink is attached, one PacketJson per packet covering every layer the walk
// exposes -- including the IPv6 extension headers, SRv6 segments and TLV options that AllTables
// does not yet tabulate (those land in AllTables once a sink that needs them, e.g. Parquet/Lance
// in a later phase, actually consumes them; the JSON sink already renders them directly from the
// decoded values at each walk_packet_ext callback, so nothing here is deferred for that sink).
//
// Later phases extend DecodeOptions/run_decode_pass with IPv4/IPv6 defragmentation (re-entering
// this same UDP/TCP dispatch over a reassembled buffer) and SOME/IP/gPTP/LLDP dispatch on top of
// the UDP/Ethernet layers this pass already reaches.

#include "json_tree.hpp"
#include "l2l3_nodes.hpp"

#include "nm_pcap.hpp"       // nmpcap::scan_blocks / parse_idb / parse_epb — include path set by CMake
#include "nm_protocols.hpp"  // nmproto::walk_packet_ext

#include <nanom/nanom.hpp>

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

// The walk_packet_ext visitor for one packet: pushes AllTables rows for the base L2-L4 layers and,
// when `json` is non-null, renders every layer the walk exposes (base layers + IPv6 extension
// headers/SRv6/options) into that packet's PacketJson. Every method is optional per walk_packet_ext's
// `requires{}` contract, but this visitor defines them all.
struct PacketVisitor {
  packet_id_t pid;
  AllTables*  tables;
  PacketJson* json;  // nullptr when no JSON sink is attached

  void on_eth(const nmproto::Ethernet& v) {
    tables->eth.push(EthNode{pid, 0, false, v});
    if (json) json->add_layer("eth", v);
  }
  void on_vlan(const nmproto::VlanTag& v) {
    tables->vlan.push(VlanNode{pid, 0, false, v});
    if (json) json->add_layer("vlan", v);
  }
  void on_ipv4(const nmproto::Ipv4& v) {
    tables->ipv4.push(Ipv4Node{pid, 0, false, v});
    if (json) json->add_layer("ip", v);
  }
  void on_ipv6(const nmproto::Ipv6& v) {
    tables->ipv6.push(Ipv6Node{pid, 0, false, v});
    if (json) json->add_layer("ipv6", v);
  }
  void on_tcp(const nmproto::Tcp& v) {
    tables->tcp.push(TcpNode{pid, 0, false, v});
    if (json) json->add_layer("tcp", v);
  }
  void on_udp(const nmproto::Udp& v) {
    tables->udp.push(UdpNode{pid, 0, false, v});
    if (json) json->add_layer("udp", v);
  }
  void on_ext_opt(nmproto::Ipv6ExtKind kind, const nmproto::Ipv6ExtOpt& v) {
    if (!json) return;
    json->add_layer(kind == nmproto::Ipv6ExtKind::hop_by_hop ? "ipv6.hop_by_hop" : "ipv6.dest_opts", v);
  }
  void on_srh(const nmproto::Ipv6Srh& v) {
    if (json) json->add_layer("ipv6.routing", v);
  }
  void on_fragment(const nmproto::Ipv6Fragment& v) {
    if (json) json->add_layer("ipv6.fragment_hdr", v);
  }
  void on_ah(const nmproto::Ipv6Ah& v) {
    if (json) json->add_layer("ipv6.ah", v);
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
};

}  // namespace detail

struct SinkHub {
  std::vector<PacketJson>* json_packets = nullptr;  // non-null => build one PacketJson per packet
};

struct DecodeOptions {
  bool decode_l2l3 = true;  // Eth/VLAN*/IPv4/IPv6(+ext headers, SRv6)/TCP/UDP
};

// The ONE decode pass: scan_blocks -> per EPB/pcap-record, walk_packet_ext. Pushes every base-layer
// row into `tables` always, and (when sink.json_packets is set) a "frame" + one entry per decoded
// layer into that packet's PacketJson. A malformed layer stops that packet's walk only (existing
// walk_packet contract, see nm_protocols.hpp); this function returns false only when the pcap/pcapng
// block scan itself fails (a corrupt file, not a corrupt packet).
inline bool run_decode_pass(nanom::bytes file, AllTables& tables, SinkHub sink,
                            const DecodeOptions& opts, std::string& error) {
  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, error)) return false;

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

    PacketJson* pj = nullptr;
    if (sink.json_packets) {
      sink.json_packets->emplace_back(pid);
      pj = &sink.json_packets->back();
      pj->add_layer_json("frame", detail::frame_json(e, link_type));
    }

    const std::size_t poff = std::size_t(e.payload_file_offset);
    if (opts.decode_l2l3 && poff + e.caplen <= file.size()) {
      const nanom::bytes pkt = file.subspan(poff, e.caplen);
      detail::PacketVisitor visitor{pid, &tables, pj};
      nmproto::walk_packet_ext(link_type, pkt, visitor);
    }
    ++pid;
  }
  return true;
}

}  // namespace nano_shark
