// SPDX-License-Identifier: MIT
#pragma once

// L2/L3/L4 protocol structs + the packet walk — the parity port of nanotins'
// protocols.hpp / protocol_decode.hpp walk_packet. Identical traversal
// semantics: Ethernet -> VLAN*(0x8100/0x88a8) -> IPv4 (honoring ihl, gating
// L4 on frag_offset==0) / IPv6 -> TCP (honoring data_offset) / UDP.
//
// nanotins declares each header with a wire_spec (explicit byte offsets +
// bits<> words); here the same headers are nanom-described structs — the bit
// fields are individual ubits<> members instead of packed bits<> words, and
// the walk is built from overlay<T>() (zero-copy views, decode on access).
// Allocation-free: callbacks receive views, nothing is collected.

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>

namespace nmproto {

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t;

struct Ethernet {
  std::array<u8, 6> dst, src;
  nm::be<u16>       ethertype;
};
struct VlanTag {
  nm::ubits<3>  pcp;
  nm::ubits<1>  dei;
  nm::ubits<12> vid;
  nm::be<u16>   inner_ethertype;
};
struct Ipv4 {
  nm::ubits<4>      version;
  nm::ubits<4>      ihl;
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_length;
  nm::be<u16>       identification;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_offset;
  u8                ttl;
  u8                protocol;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
struct Ipv6 {
  nm::ubits<4>       version;
  nm::ubits<8>       traffic_class;
  nm::ubits<20>      flow_label;
  nm::be<u16>        payload_length;
  u8                 next_header;
  u8                 hop_limit;
  std::array<u8, 16> src, dst;
};
struct Udp {
  nm::be<u16> src_port, dst_port, length, checksum;
};
struct Tcp {
  nm::be<u16>  src_port, dst_port;
  nm::be<u32>  seq, ack;
  nm::ubits<4> data_offset;
  nm::ubits<3> reserved;
  nm::ubits<9> flags;
  nm::be<u16>  window, checksum, urgent;
};

}  // namespace nmproto

NANOM_DESCRIBE(nmproto::Ethernet, dst, src, ethertype);
NANOM_DESCRIBE(nmproto::VlanTag, pcp, dei, vid, inner_ethertype);
NANOM_DESCRIBE(nmproto::Ipv4, version, ihl, dscp, ecn, total_length, identification,
               flags, frag_offset, ttl, protocol, checksum, src, dst);
NANOM_DESCRIBE(nmproto::Ipv6, version, traffic_class, flow_label, payload_length,
               next_header, hop_limit, src, dst);
NANOM_DESCRIBE(nmproto::Udp, src_port, dst_port, length, checksum);
NANOM_DESCRIBE(nmproto::Tcp, src_port, dst_port, seq, ack, data_offset, reserved,
               flags, window, checksum, urgent);

namespace nmproto {

static_assert(nm::wire_size_v<Ethernet> == 14 && nm::wire_size_v<VlanTag> == 4 &&
              nm::wire_size_v<Ipv4> == 20 && nm::wire_size_v<Ipv6> == 40 &&
              nm::wire_size_v<Udp> == 8 && nm::wire_size_v<Tcp> == 20);

inline constexpr u16 kEtherTypeVlan = 0x8100, kEtherTypeQinQ = 0x88A8;
inline constexpr u16 kEtherTypeIpv4 = 0x0800, kEtherTypeIpv6 = 0x86DD;
inline constexpr u8  kIpProtoTcp = 6, kIpProtoUdp = 17;
inline constexpr u32 kLinkTypeEthernet = 1;

struct WalkResult {
  std::size_t   l4_payload_offset = 0;
  std::uint64_t l4_ports = 0;  // (src<<16)|dst — the L5 dispatch key
  bool          reached_l4 = false;
};

/// One Eth -> VLAN* -> IPv4/IPv6 -> TCP/UDP traversal, visited by callbacks
/// taking parsed header structs. Same layer order, gates and consumption as
/// nanotins walk_packet; parsing is nanom strct<T>() over the packet bytes.
template <class FEth, class FVlan, class FIpv4, class FIpv6, class FTcp, class FUdp>
inline WalkResult walk_packet(u32 link_type, nm::bytes pkt, FEth on_eth, FVlan on_vlan,
                              FIpv4 on_ipv4, FIpv6 on_ipv6, FTcp on_tcp, FUdp on_udp) {
  WalkResult res;
  if (link_type != kLinkTypeEthernet) return res;
  nm::input in = nm::from(pkt);

  auto eth = nm::strct<Ethernet>()(in);
  if (!eth) return res;
  on_eth(eth->value);
  u16 ethertype = eth->value.ethertype;
  nm::input cur = eth->rest;
  while (ethertype == kEtherTypeVlan || ethertype == kEtherTypeQinQ) {
    auto tag = nm::strct<VlanTag>()(cur);
    if (!tag) return res;
    on_vlan(tag->value);
    ethertype = tag->value.inner_ethertype;
    cur = tag->rest;
  }

  u8 ip_proto = 0;
  bool has_l4 = true;  // IPv4 non-first fragments carry data, not an L4 header
  nm::input after_l3 = cur;
  if (ethertype == kEtherTypeIpv4) {
    auto ip = nm::strct<Ipv4>()(cur);
    if (!ip) return res;
    on_ipv4(ip->value);
    const std::size_t hdr = std::size_t(ip->value.ihl) * 4;
    const std::size_t l3 = hdr >= nm::wire_size_v<Ipv4> ? hdr : nm::wire_size_v<Ipv4>;
    if (l3 > cur.size()) return res;
    after_l3 = cur.advance(l3);
    ip_proto = ip->value.protocol;
    has_l4 = ip->value.frag_offset == 0;
  } else if (ethertype == kEtherTypeIpv6) {
    auto ip = nm::strct<Ipv6>()(cur);
    if (!ip) return res;
    on_ipv6(ip->value);
    after_l3 = ip->rest;  // extension headers out of scope (same as nanotins step 1)
    ip_proto = ip->value.next_header;
  } else {
    return res;
  }
  if (!has_l4) return res;

  if (ip_proto == kIpProtoTcp) {
    auto tcp = nm::strct<Tcp>()(after_l3);
    if (!tcp) return res;
    on_tcp(tcp->value);
    const std::size_t hdr = std::size_t(tcp->value.data_offset) * 4;
    res.l4_payload_offset = after_l3.offset() + (hdr >= nm::wire_size_v<Tcp> ? hdr : nm::wire_size_v<Tcp>);
    res.l4_ports = (std::uint64_t(u16(tcp->value.src_port)) << 16) | u16(tcp->value.dst_port);
    res.reached_l4 = true;
  } else if (ip_proto == kIpProtoUdp) {
    auto udp = nm::strct<Udp>()(after_l3);
    if (!udp) return res;
    on_udp(udp->value);
    res.l4_payload_offset = udp->rest.offset();
    res.l4_ports = (std::uint64_t(u16(udp->value.src_port)) << 16) | u16(udp->value.dst_port);
    res.reached_l4 = true;
  }
  return res;
}

}  // namespace nmproto
