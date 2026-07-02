// nanom example: Ethernet II → VLAN → IPv4 → UDP → TLV payload.
// Shows: strct<>, bit fields, be<> wire integers, runtime protocol switches,
// take/length_data for options and payloads, many0 over a TLV stream,
// context() error labels, and columnar soa<> output ready for nanoarrow.
#include <nanom/nanom.hpp>

#include <cstdio>
#include <string>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t;

// --- wire structs (bit layout straight from the RFC diagrams) --------------
struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16>       eth_type;
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);

struct vlan_hdr {           // 802.1Q
  nm::ubits<3>  pcp;
  nm::ubits<1>  dei;
  nm::ubits<12> vid;
  nm::be<u16>   eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);

struct ipv4_hdr {
  nm::ubits<4>      version;
  nm::ubits<4>      ihl;        // header length in 32-bit words
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_len;
  nm::be<u16>       ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl;
  u8                proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_hdr, version, ihl, dscp, ecn, total_len, ident, flags,
               frag_off, ttl, proto, checksum, src, dst);

struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);

// One flattened row per packet, for columnar export.
struct pkt_row {
  u16               vlan_vid;
  std::array<u8, 4> ip_src, ip_dst;
  u8                proto;
  u16               src_port, dst_port;
  u16               payload_len;
};
NANOM_DESCRIBE(pkt_row, vlan_vid, ip_src, ip_dst, proto, src_port, dst_port,
               payload_len);

// --- packet parser ----------------------------------------------------------
struct parsed_pkt { pkt_row row; nm::bytes payload; };

nm::result<parsed_pkt> parse_packet(nm::input in) {
  auto eth = nm::context("ethernet", nm::strct<eth_hdr>())(in);
  if (!eth) return nm::unexp(eth.error());

  u16 etype = eth->value.eth_type;
  nm::input cur = eth->rest;
  u16 vid = 0;
  if (etype == 0x8100) {                                   // 802.1Q tag
    auto vlan = nm::context("vlan", nm::strct<vlan_hdr>())(cur);
    if (!vlan) return nm::unexp(vlan.error());
    vid   = vlan->value.vid;
    etype = vlan->value.eth_type;
    cur   = vlan->rest;
  }
  if (etype != 0x0800) return nm::make_err(cur, "IPv4 ethertype");

  // IPv4: fixed 20 bytes validated with verify(), then ihl-5 option words.
  auto ip = nm::context("ipv4",
      nm::verify(nm::strct<ipv4_hdr>(),
                 [](const ipv4_hdr& h) { return h.version == 4 && h.ihl >= 5; }))(cur);
  if (!ip) return nm::unexp(ip.error());
  auto opts = nm::take(std::size_t(ip->value.ihl - 5) * 4)(ip->rest);
  if (!opts) return nm::unexp(opts.error());

  if (ip->value.proto != 17) return nm::make_err(opts->rest, "UDP protocol");

  auto udp = nm::context("udp", nm::strct<udp_hdr>())(opts->rest);
  if (!udp) return nm::unexp(udp.error());
  auto payload = nm::take(std::size_t(u16(udp->value.length)) - sizeof(udp_hdr))(udp->rest);
  if (!payload) return nm::unexp(payload.error());

  parsed_pkt out{};
  out.row.vlan_vid    = vid;
  out.row.ip_src      = ip->value.src;
  out.row.ip_dst      = ip->value.dst;
  out.row.proto       = ip->value.proto;
  out.row.src_port    = udp->value.src_port;
  out.row.dst_port    = udp->value.dst_port;
  out.row.payload_len = u16(payload->value.size());
  out.payload         = payload->value;
  return nm::done{out, payload->rest};
}

// --- TLV walk: type:u8 len:u8 value[len], repeated to end of payload -------
struct tlv_row { u8 type; u8 len; };
NANOM_DESCRIBE(tlv_row, type, len);

int main() {
  // Eth + VLAN 42 + IPv4(10.0.0.1 -> 10.0.0.2) + UDP 53 -> 1234, 2 TLVs
  const u8 pkt[] = {
      /*eth*/ 0x02,0,0,0,0,1, 0x02,0,0,0,0,2, 0x81,0x00,
      /*vlan*/0x00,0x2a, 0x08,0x00,
      /*ip*/  0x45,0x00, 0x00,0x2e, 0x00,0x01, 0x00,0x00, 0x40,0x11, 0x00,0x00,
              10,0,0,1, 10,0,0,2,
      /*udp*/ 0x00,0x35, 0x04,0xd2, 0x00,0x12, 0x00,0x00,
      /*tlv*/ 0x01,0x03,'a','b','c', 0x02,0x03,'x','y','z',
  };
  nm::input in = nm::from(pkt, sizeof pkt);

  auto r = parse_packet(in);
  if (!r) { std::puts(r.error().render(in).c_str()); return 1; }
  const pkt_row& row = r->value.row;
  std::printf("vlan=%u %u.%u.%u.%u -> %u.%u.%u.%u  udp %u -> %u  payload=%u\n",
              row.vlan_vid, row.ip_src[0], row.ip_src[1], row.ip_src[2], row.ip_src[3],
              row.ip_dst[0], row.ip_dst[1], row.ip_dst[2], row.ip_dst[3],
              row.src_port, row.dst_port, row.payload_len);

  // TLVs: parse the fixed header, then flat_map into take(len) — nom style.
  auto tlv_p = nm::many0(nm::flat_map(nm::strct<tlv_row>(), [](tlv_row h) {
    return nm::map(nm::take(h.len), [h](nm::bytes v) { return std::pair{h, v}; });
  }));
  nm::input pin{r->value.payload.data(),
                r->value.payload.data() + r->value.payload.size(), in.base};
  auto tl = nm::all_consuming(tlv_p)(pin);
  if (!tl) { std::puts(tl.error().render(in).c_str()); return 1; }
  for (auto& [h, v] : tl->value)
    std::printf("tlv type=%u len=%u value=%.*s\n", h.type, h.len, int(v.size()),
                reinterpret_cast<const char*>(v.data()));

  // columnar export: schema + rows, ready for nanoarrow/nanolance buffers
  nm::soa<pkt_row> table(/*chunk_rows=*/1024);
  table.push(row);
  for (const auto& c : table.columns())
    std::printf("column %-12s arrow=%s\n", c.name.c_str(), c.arrow.c_str());
  std::printf("avro: %s\n", nm::avro_schema<pkt_row>().c_str());
  std::printf("csv:  %s\n      %s\n", nm::csv_header<pkt_row>().c_str(),
              nm::csv_row(row).c_str());

  // and the localized error message you get when bytes are wrong:
  u8 bad[sizeof pkt]; std::memcpy(bad, pkt, sizeof pkt);
  bad[18] = 0x65;  // IPv4 version nibble 6 -> verify() fails
  auto br = parse_packet(nm::from(bad, sizeof bad));
  if (!br) std::printf("--- expected failure demo ---\n%s\n",
                       br.error().render(nm::from(bad, sizeof bad)).c_str());
  return 0;
}
