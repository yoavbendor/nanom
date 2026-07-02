// SPDX-License-Identifier: Apache-2.0
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
#include <cstring>

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

// =====================================================================================================
// IPv6 extension headers + SRv6 — the ext-header-aware walk (additive; walk_packet above is unchanged).
//
// walk_packet stops at the base IPv6 header (matching nanotins' JSON example). walk_packet_ext instead
// DESCENDS the IPv6 extension-header chain — Hop-by-Hop (0), Routing / SRv6 SRH (43), Fragment (44),
// Destination Options (60), Authentication Header (51) — to reach the real L4 header, and reports each
// ext header, each SRv6 segment, and each IPv6/SRH TLV option. Same advance rules and TLV/segment
// semantics as nanotins' spec_dag + ipv6_children (RFC 8200): ext-header length (hdr_ext_len + 1) * 8,
// fragment fixed 8, AH (payload_len + 2) * 4; options are [type][len][value] with type 0 = Pad1.
// =====================================================================================================

namespace nmproto {

struct Ipv6ExtOpt {  // Hop-by-Hop / Destination Options fixed part (options follow, walked as TLVs)
  u8 next_header;
  u8 hdr_ext_len;
};
struct Ipv6Srh {  // Routing header / SRv6 Segment Routing Header fixed part (segment list + TLVs follow)
  u8          next_header;
  u8          hdr_ext_len;
  u8          routing_type;
  u8          segments_left;
  u8          last_entry;
  u8          flags;
  nm::be<u16> tag;
};
struct Ipv6Fragment {
  u8          next_header;
  u8          reserved;
  nm::be<u16> offset_flags;  // frag_offset(13) | res(2) | more_fragments(1)
  nm::be<u32> identification;
};
struct Ipv6Ah {  // Authentication Header
  u8          next_header;
  u8          payload_len;  // in 4-byte units; total header = (payload_len + 2) * 4
  nm::be<u16> reserved;
  nm::be<u32> spi;
  nm::be<u32> seq;
};

}  // namespace nmproto

NANOM_DESCRIBE(nmproto::Ipv6ExtOpt, next_header, hdr_ext_len);
NANOM_DESCRIBE(nmproto::Ipv6Srh, next_header, hdr_ext_len, routing_type, segments_left, last_entry, flags, tag);
NANOM_DESCRIBE(nmproto::Ipv6Fragment, next_header, reserved, offset_flags, identification);
NANOM_DESCRIBE(nmproto::Ipv6Ah, next_header, payload_len, reserved, spi, seq);

namespace nmproto {

static_assert(nm::wire_size_v<Ipv6ExtOpt> == 2 && nm::wire_size_v<Ipv6Srh> == 8 &&
              nm::wire_size_v<Ipv6Fragment> == 8 && nm::wire_size_v<Ipv6Ah> == 12);

// The IPv6 next_header values that name an extension header this walk descends (everything else is an
// upper-layer protocol — TCP/UDP/… — that ends the chain).
inline constexpr bool is_ipv6_ext(u8 nh) {
  return nh == 0 || nh == 43 || nh == 44 || nh == 60 || nh == 51;
}

// Walk the [type][len][value] IPv6 option TLVs in the packet byte range [start, end) (offsets), RFC 8200
// 4.2: type 0 is a lone Pad1 byte (emitted with length 0), every other option is [type][len][value].
// Bounds-clamped to the packet; a malformed record stops the walk (never reads out of bounds).
template <class OnOpt>
inline void for_each_ipv6_option(nm::bytes pkt, std::size_t start, std::size_t end, OnOpt on_opt) {
  const std::size_t lim = end <= pkt.size() ? end : pkt.size();
  std::size_t i = start;
  while (i < lim) {
    const u8 t = u8(pkt[i]);
    if (t == 0) {  // Pad1
      on_opt(u8(0), u8(0));
      i += 1;
      continue;
    }
    if (i + 2 > lim) break;
    const u8 len = u8(pkt[i + 1]);
    if (i + std::size_t{2} + len > lim) break;
    on_opt(t, len);
    i += std::size_t{2} + len;
  }
}

// Call v.method(args...) only if the visitor defines it (every visitor method is optional).
#define NMPROTO_VISIT(call)                    \
  do {                                         \
    if constexpr (requires { v.call; }) v.call; \
  } while (0)

// Full Ethernet -> VLAN* -> IPv4 / IPv6(+extension chain) -> TCP / UDP walk. `v` is a visitor whose
// methods are ALL optional (invoked only when present):
//   on_eth(Ethernet) on_vlan(VlanTag) on_ipv4(Ipv4) on_ipv6(Ipv6) on_tcp(Tcp) on_udp(Udp)
//   on_ext_opt(Ipv6ExtKind, Ipv6ExtOpt)  // Hop-by-Hop / Destination Options fixed part
//   on_srh(Ipv6Srh) on_fragment(Ipv6Fragment) on_ah(Ipv6Ah)
//   on_srh_segment(u8 srh_order, u8 segment_index, std::array<u8,16> address)
//   on_ipv6_option(u8 container_type, u8 opt_type, u8 opt_len)   // container: 0 HbH, 60 DstOpt, 43 SRH
// Returns the same WalkResult as walk_packet (reached_l4 / l4_payload_offset / l4_ports), now computed
// through the extension chain — so SRv6 packets correctly reach their L4 header.
enum class Ipv6ExtKind : u8 { hop_by_hop = 0, routing = 43, fragment = 44, dest_opts = 60, ah = 51 };

template <class V>
inline WalkResult walk_packet_ext(u32 link_type, nm::bytes pkt, V&& v) {
  WalkResult res;
  if (link_type != kLinkTypeEthernet) return res;
  nm::input in = nm::from(pkt);

  auto eth = nm::strct<Ethernet>()(in);
  if (!eth) return res;
  NMPROTO_VISIT(on_eth(eth->value));
  u16 ethertype = eth->value.ethertype;
  nm::input cur = eth->rest;
  while (ethertype == kEtherTypeVlan || ethertype == kEtherTypeQinQ) {
    auto tag = nm::strct<VlanTag>()(cur);
    if (!tag) return res;
    NMPROTO_VISIT(on_vlan(tag->value));
    ethertype = tag->value.inner_ethertype;
    cur = tag->rest;
  }

  u8 ip_proto = 0;
  bool has_l4 = true;
  std::size_t after_l3_off = cur.offset();
  if (ethertype == kEtherTypeIpv4) {
    auto ip = nm::strct<Ipv4>()(cur);
    if (!ip) return res;
    NMPROTO_VISIT(on_ipv4(ip->value));
    const std::size_t hdr = std::size_t(ip->value.ihl) * 4;
    const std::size_t l3 = hdr >= nm::wire_size_v<Ipv4> ? hdr : nm::wire_size_v<Ipv4>;
    if (l3 > cur.size()) return res;
    after_l3_off = cur.offset() + l3;
    ip_proto = ip->value.protocol;
    has_l4 = ip->value.frag_offset == 0;
  } else if (ethertype == kEtherTypeIpv6) {
    auto ip = nm::strct<Ipv6>()(cur);
    if (!ip) return res;
    NMPROTO_VISIT(on_ipv6(ip->value));
    std::size_t off = cur.offset() + nm::wire_size_v<Ipv6>;  // past the 40-byte base header
    u8 nh = ip->value.next_header;
    u8 srh_order = 0;
    for (int guard = 0; guard < 64 && is_ipv6_ext(nh); ++guard) {
      if (off >= pkt.size()) return res;
      nm::input at = nm::from(pkt).advance(off);
      if (nh == 0 || nh == 60) {  // Hop-by-Hop / Destination Options
        auto h = nm::strct<Ipv6ExtOpt>()(at);
        if (!h) return res;
        const Ipv6ExtKind kind = nh == 0 ? Ipv6ExtKind::hop_by_hop : Ipv6ExtKind::dest_opts;
        NMPROTO_VISIT(on_ext_opt(kind, h->value));
        const std::size_t hlen = (std::size_t(h->value.hdr_ext_len) + 1) * 8;
        const u8 container = nh;  // 0 or 60
        for_each_ipv6_option(pkt, off + 2, off + hlen,
                             [&](u8 t, u8 l) { NMPROTO_VISIT(on_ipv6_option(container, t, l)); });
        nh = h->value.next_header;
        off += hlen;
      } else if (nh == 43) {  // Routing header / SRv6 SRH
        auto h = nm::strct<Ipv6Srh>()(at);
        if (!h) return res;
        NMPROTO_VISIT(on_srh(h->value));
        const std::size_t hlen = (std::size_t(h->value.hdr_ext_len) + 1) * 8;
        const std::size_t end = (off + hlen <= pkt.size()) ? off + hlen : pkt.size();
        const std::size_t seg_base = off + 8;
        const std::uint32_t nseg = std::uint32_t(h->value.last_entry) + 1;
        for (std::uint32_t i = 0; i < nseg; ++i) {
          const std::size_t s = seg_base + std::size_t(i) * 16;
          if (s + 16 > end) break;  // remaining segments don't fit -> stop (bounds-safe)
          std::array<u8, 16> addr{};
          std::memcpy(addr.data(), pkt.data() + s, 16);
          NMPROTO_VISIT(on_srh_segment(srh_order, u8(i), addr));
        }
        const std::size_t tlv_start = seg_base + std::size_t(nseg) * 16;
        for_each_ipv6_option(pkt, tlv_start, end,
                             [&](u8 t, u8 l) { NMPROTO_VISIT(on_ipv6_option(u8(43), t, l)); });
        ++srh_order;
        nh = h->value.next_header;
        off += hlen;
      } else if (nh == 44) {  // Fragment (fixed 8 bytes)
        auto h = nm::strct<Ipv6Fragment>()(at);
        if (!h) return res;
        NMPROTO_VISIT(on_fragment(h->value));
        nh = h->value.next_header;
        off += 8;
      } else {  // nh == 51 -> Authentication Header
        auto h = nm::strct<Ipv6Ah>()(at);
        if (!h) return res;
        NMPROTO_VISIT(on_ah(h->value));
        nh = h->value.next_header;
        off += (std::size_t(h->value.payload_len) + 2) * 4;
      }
    }
    ip_proto = nh;
    after_l3_off = off;
  } else {
    return res;
  }
  if (!has_l4 || after_l3_off > pkt.size()) return res;

  nm::input after_l3 = nm::from(pkt).advance(after_l3_off);
  if (ip_proto == kIpProtoTcp) {
    auto tcp = nm::strct<Tcp>()(after_l3);
    if (!tcp) return res;
    NMPROTO_VISIT(on_tcp(tcp->value));
    const std::size_t hdr = std::size_t(tcp->value.data_offset) * 4;
    res.l4_payload_offset = after_l3_off + (hdr >= nm::wire_size_v<Tcp> ? hdr : nm::wire_size_v<Tcp>);
    res.l4_ports = (std::uint64_t(u16(tcp->value.src_port)) << 16) | u16(tcp->value.dst_port);
    res.reached_l4 = true;
  } else if (ip_proto == kIpProtoUdp) {
    auto udp = nm::strct<Udp>()(after_l3);
    if (!udp) return res;
    NMPROTO_VISIT(on_udp(udp->value));
    res.l4_payload_offset = udp->rest.offset();
    res.l4_ports = (std::uint64_t(u16(udp->value.src_port)) << 16) | u16(udp->value.dst_port);
    res.reached_l4 = true;
  }
  return res;
}

#undef NMPROTO_VISIT

}  // namespace nmproto
