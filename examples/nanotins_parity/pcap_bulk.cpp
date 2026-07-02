// SPDX-License-Identifier: MIT

// pcap_bulk — data-parallel columnar decode on nanom (the "bulk" path).
//
// Scans a capture once (Phase A is inherently serial), collects a flat pkt_ref[]
// (POD, device-transferable), then decodes ALL packets in parallel into SoA
// columns via nm::bulk_decode. The per-packet kernel is a pure, allocation-free,
// NANOM_HD function written with overlay<>/get<> — the same code a GPU launch
// would run; here the executor is a CPU thread pool.
//
// It (1) checks the bulk result is bit-identical to the serial soa<> path
// (correctness), and (2) times serial vs parallel decode to show the structural
// speedup a per-packet scalar walk cannot reach.

#include "nm_pcap.hpp"
#include "nm_protocols.hpp"

#include <nanom/bulk.hpp>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using u64 = std::uint64_t;

// One flat row per packet (the L1 PacketRow shape + a few decoded L3/L4 fields).
struct PacketRow {
  u64               ts_raw;
  u32               caplen;
  u16               link_type;
  u16               eth_type;
  std::array<u8, 4> ip_src, ip_dst;
  u8                protocol;
  u16               src_port, dst_port;
};
NANOM_DESCRIBE(PacketRow, ts_raw, caplen, link_type, eth_type, ip_src, ip_dst,
               protocol, src_port, dst_port);
static_assert(std::is_trivially_copyable_v<PacketRow>);

// ---- the device-safe kernel: decode one packet into a PacketRow ------------
// Pure, allocation-free, no std::vector / std::string / throw. NANOM_HD so the
// same function is compilable for a GPU. Returns true = keep the row.
NANOM_HD inline bool decode_row(const nm::pkt_ref& pk, PacketRow& row) {
  row.ts_raw = 0;  // (timestamp is carried on pkt_ref in a fuller design)
  row.caplen = pk.len;
  row.link_type = u16(pk.link);
  if (pk.link != nmproto::kLinkTypeEthernet) return true;

  nm::bytes pkt{pk.data, pk.len};
  nm::input in = nm::from(pkt);
  auto eth = nm::overlay<nmproto::Ethernet>()(in);
  if (!eth) return true;
  u16 et = eth->value.get<"ethertype">();
  nm::input cur = eth->rest;
  while (et == nmproto::kEtherTypeVlan || et == nmproto::kEtherTypeQinQ) {
    auto v = nm::overlay<nmproto::VlanTag>()(cur);
    if (!v) return true;
    et = v->value.get<"inner_ethertype">();
    cur = v->rest;
  }
  row.eth_type = et;

  nm::input after = cur;
  u8 proto = 0;
  bool has_l4 = true;
  if (et == nmproto::kEtherTypeIpv4) {
    auto ip = nm::overlay<nmproto::Ipv4>()(cur);
    if (!ip) return true;
    auto src = ip->value.get<"src">(), dst = ip->value.get<"dst">();
    for (int k = 0; k < 4; ++k) { row.ip_src[k] = src[k]; row.ip_dst[k] = dst[k]; }
    proto = ip->value.get<"protocol">();
    row.protocol = proto;
    const auto fo = ip->value.get<"frag_offset">();
    std::size_t hdr = std::size_t(ip->value.get<"ihl">()) * 4;
    std::size_t l3 = hdr >= nm::wire_size_v<nmproto::Ipv4> ? hdr : nm::wire_size_v<nmproto::Ipv4>;
    if (l3 > cur.size()) return true;
    after = cur.advance(l3);
    has_l4 = fo == 0;
  } else if (et == nmproto::kEtherTypeIpv6) {
    auto ip = nm::overlay<nmproto::Ipv6>()(cur);
    if (!ip) return true;
    proto = ip->value.get<"next_header">();
    row.protocol = proto;
    after = ip->rest;
  } else {
    return true;
  }
  if (!has_l4) return true;
  if (proto == nmproto::kIpProtoTcp) {
    auto t = nm::overlay<nmproto::Tcp>()(after);
    if (t) { row.src_port = t->value.get<"src_port">(); row.dst_port = t->value.get<"dst_port">(); }
  } else if (proto == nmproto::kIpProtoUdp) {
    auto u = nm::overlay<nmproto::Udp>()(after);
    if (u) { row.src_port = u->value.get<"src_port">(); row.dst_port = u->value.get<"dst_port">(); }
  }
  return true;
}

// Collect pkt_ref[] from the scan (Phase A), replicated `mult` times so the
// bulk timing is over a meaningful packet count.
static std::vector<nm::pkt_ref> collect(nm::bytes file, std::size_t mult) {
  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  if (!nmpcap::scan_blocks(file, refs, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return {}; }
  std::vector<u16> iface_link;
  std::vector<nm::pkt_ref> pkts;
  for (const auto& ref : refs) {
    if (ref.kind == nmpcap::Kind::Shb) { iface_link.clear(); continue; }
    if (ref.kind == nmpcap::Kind::Idb) {
      nmpcap::IdbView idb{};
      if (nmpcap::parse_idb(file, ref, idb)) iface_link.push_back(idb.link_type);
      continue;
    }
    if (ref.kind != nmpcap::Kind::Epb && ref.kind != nmpcap::Kind::PcapRecord) continue;
    nmpcap::EpbView e{};
    if (!nmpcap::parse_epb(file, ref, e)) continue;
    const u16 link = e.interface_id < iface_link.size() ? iface_link[e.interface_id] : u16{0};
    pkts.push_back(nm::pkt_ref{file.data() + e.payload_file_offset, e.caplen, link});
  }
  std::vector<nm::pkt_ref> out;
  out.reserve(pkts.size() * mult);
  for (std::size_t m = 0; m < mult; ++m) out.insert(out.end(), pkts.begin(), pkts.end());
  return out;
}

int main(int argc, char** argv) {
  if (argc < 2) { std::fprintf(stderr, "usage: %s <capture> [mult] [iters]\n", argv[0]); return 2; }
  const std::size_t mult = argc > 2 ? std::stoul(argv[2]) : 200;
  const int iters = argc > 3 ? std::atoi(argv[3]) : 50;

  std::FILE* f = std::fopen(argv[1], "rb");
  if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
  std::vector<u8> buf; u8 c[65536]; std::size_t n;
  while ((n = std::fread(c, 1, sizeof c, f)) > 0) buf.insert(buf.end(), c, c + n);
  std::fclose(f);
  const nm::bytes file(reinterpret_cast<const std::byte*>(buf.data()), buf.size());

  std::vector<nm::pkt_ref> pkts = collect(file, mult);
  if (pkts.empty()) return 1;
  std::span<const nm::pkt_ref> span(pkts);
  std::printf("packets: %zu\n", pkts.size());

  // --- correctness: bulk (parallel) must equal the serial soa<> path ---
  nm::bulk_table<PacketRow> tpar, tseq;
  nm::bulk_decode(span, tseq, decode_row, nm::seq_exec{});
  nm::bulk_decode(span, tpar, decode_row, nm::par_exec{});
  bool ok = tpar.rows() == tseq.rows();
  for (std::size_t cc = 0; cc < tseq.columns().size() && ok; ++cc)
    ok = ok && tseq.column_bytes(cc).size() == tpar.column_bytes(cc).size() &&
         std::memcmp(tseq.column_bytes(cc).data(), tpar.column_bytes(cc).data(),
                     tseq.column_bytes(cc).size()) == 0;
  std::printf("parallel == serial columns: %s (%zu rows, %zu columns)\n",
              ok ? "yes" : "NO", tseq.rows(), tseq.columns().size());

  // --- timing: serial vs parallel decode (decode only; scan excluded) ---
  auto bench = [&](const char* name, auto exec) {
    double best = 1e300;
    nm::bulk_table<PacketRow> t;
    for (int it = 0; it < iters; ++it) {
      auto t0 = std::chrono::steady_clock::now();
      nm::bulk_decode(span, t, decode_row, exec);
      auto t1 = std::chrono::steady_clock::now();
      best = std::min(best, std::chrono::duration<double, std::nano>(t1 - t0).count());
    }
    const double per = best / double(pkts.size());
    std::printf("%-16s best=%.2f ms  %.1f ns/pkt  %.0f Mpkt/s\n",
                name, best / 1e6, per, 1000.0 / per);
    return per;
  };
  const double s = bench("bulk-serial", nm::seq_exec{});
  const double p = bench("bulk-parallel", nm::par_exec{});
  std::printf("parallel speedup: %.2fx  (threads=%u)\n", s / p,
              std::max(1u, std::thread::hardware_concurrency()));
  return ok ? 0 : 1;
}
