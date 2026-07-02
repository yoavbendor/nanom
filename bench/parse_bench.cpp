// SPDX-License-Identifier: MIT

// Parse-only microbenchmark for the nanom packet walk. Loads a capture into
// memory ONCE, then times only the decode over the resident bytes for N
// iterations — no file I/O, no JSON, no output-string allocation in the timed
// loop. Reports ns/packet and decoded MB/s. A checksum of decoded fields is
// accumulated so the optimizer cannot elide the walk (and so the number can be
// compared field-for-field against the nanotins core: identical checksum ==
// identical decode).
//
// It runs the walk two ways, because the choice matters and nanom offers both:
//
//   strct<T>()   materializes EVERY field of each header by value (convenient:
//                you get a plain struct; every bit field is extracted). This is
//                what pcapng2json / dpar_lite use.
//
//   overlay<T>() is a zero-copy view; get<"field">() decodes only the fields
//                you touch. This is the hot-path technique (it is what nanotins'
//                wire_spec overlay does), and on this walk it is ~2.3x faster
//                than strct<> because the walk reads only ~5 of 13 IPv4 fields.
//
// Take-away: for tabulation where you keep every column, strct<>/soa<> is
// right; for a hot classification walk, overlay<> is right and competitive with
// a hand-tuned overlay parser.

#include "../examples/nanotins_parity/nm_pcap.hpp"
#include "../examples/nanotins_parity/nm_protocols.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

using u8 = std::uint8_t;
namespace nm = nanom;
namespace P = nmproto;

struct Sink {  // FNV-1a over decoded fields
  std::uint64_t hash = 1469598103934665603ull;
  void mix(std::uint64_t v) { hash = (hash ^ v) * 1099511628211ull; }
};

// --- strct<>: materialize every field of each header ---
void walk_strct(std::uint32_t link, nm::bytes pkt, Sink& s) {
  P::walk_packet(
      link, pkt,
      [&](const P::Ethernet& x) { s.mix(x.ethertype); s.mix(x.dst[0]); },
      [&](const P::VlanTag& x) { s.mix(x.vid); s.mix(x.inner_ethertype); },
      [&](const P::Ipv4& x) { s.mix(x.protocol); s.mix(x.ttl); s.mix(x.total_length);
                              s.mix(x.src[0]); s.mix(x.frag_offset); },
      [&](const P::Ipv6& x) { s.mix(x.next_header); s.mix(x.hop_limit); s.mix(x.flow_label); },
      [&](const P::Tcp& x) { s.mix(x.src_port); s.mix(x.dst_port); s.mix(x.data_offset); },
      [&](const P::Udp& x) { s.mix(x.src_port); s.mix(x.dst_port); });
}

// --- overlay<>: decode only the fields the walk actually reads ---
void walk_overlay(std::uint32_t link, nm::bytes pkt, Sink& s) {
  if (link != P::kLinkTypeEthernet) return;
  nm::input in = nm::from(pkt);
  auto eth = nm::overlay<P::Ethernet>()(in);
  if (!eth) return;
  s.mix(eth->value.get<"ethertype">()); s.mix(eth->value.get<"dst">()[0]);
  std::uint16_t et = eth->value.get<"ethertype">();
  nm::input cur = eth->rest;
  while (et == P::kEtherTypeVlan || et == P::kEtherTypeQinQ) {
    auto v = nm::overlay<P::VlanTag>()(cur);
    if (!v) return;
    s.mix(v->value.get<"vid">()); s.mix(v->value.get<"inner_ethertype">());
    et = v->value.get<"inner_ethertype">(); cur = v->rest;
  }
  u8 proto = 0; bool has_l4 = true; nm::input after = cur;
  if (et == P::kEtherTypeIpv4) {
    auto ip = nm::overlay<P::Ipv4>()(cur);
    if (!ip) return;
    s.mix(ip->value.get<"protocol">()); s.mix(ip->value.get<"ttl">());
    s.mix(ip->value.get<"total_length">()); s.mix(ip->value.get<"src">()[0]);
    auto fo = ip->value.get<"frag_offset">(); s.mix(fo);
    std::size_t hdr = std::size_t(ip->value.get<"ihl">()) * 4;
    std::size_t l3 = hdr >= nm::wire_size_v<P::Ipv4> ? hdr : nm::wire_size_v<P::Ipv4>;
    if (l3 > cur.size()) return;
    after = cur.advance(l3); proto = ip->value.get<"protocol">(); has_l4 = fo == 0;
  } else if (et == P::kEtherTypeIpv6) {
    auto ip = nm::overlay<P::Ipv6>()(cur);
    if (!ip) return;
    s.mix(ip->value.get<"next_header">()); s.mix(ip->value.get<"hop_limit">());
    s.mix(ip->value.get<"flow_label">());
    after = ip->rest; proto = ip->value.get<"next_header">();
  } else {
    return;
  }
  if (!has_l4) return;
  if (proto == P::kIpProtoTcp) {
    auto t = nm::overlay<P::Tcp>()(after);
    if (!t) return;
    s.mix(t->value.get<"src_port">()); s.mix(t->value.get<"dst_port">());
    s.mix(t->value.get<"data_offset">());
  } else if (proto == P::kIpProtoUdp) {
    auto u = nm::overlay<P::Udp>()(after);
    if (!u) return;
    s.mix(u->value.get<"src_port">()); s.mix(u->value.get<"dst_port">());
  }
}

template <class Walk>
std::uint64_t one_pass(nm::bytes file, const std::vector<nmpcap::BlockRef>& refs, Sink& s, Walk walk) {
  std::vector<std::uint16_t> iface_link;
  std::uint64_t packets = 0;
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
    const std::uint16_t link = e.interface_id < iface_link.size() ? iface_link[e.interface_id] : 0;
    walk(link, file.subspan(std::size_t(e.payload_file_offset), e.caplen), s);
    ++packets;
  }
  return packets;
}

template <class Walk>
void run(const char* label, nm::bytes file, const std::vector<nmpcap::BlockRef>& refs,
         std::size_t bytes, int iters, Walk walk) {
  Sink warm;
  const std::uint64_t packets = one_pass(file, refs, warm, walk);
  double best = 1e300;
  Sink acc;
  for (int it = 0; it < iters; ++it) {
    Sink local;
    auto t0 = std::chrono::steady_clock::now();
    one_pass(file, refs, local, walk);
    auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    if (ns < best) best = ns;
    acc.hash ^= local.hash;
  }
  const double mbps = (double(bytes) / 1048576.0) / (best / 1e9);
  std::printf("%-14s packets=%llu  best=%.3f ms  %5.1f ns/pkt  %6.0f MB/s  (checksum %016llx)\n",
              label, (unsigned long long)packets, best / 1e6, best / double(packets ? packets : 1),
              mbps, (unsigned long long)(acc.hash ^ warm.hash));
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <capture.pcap|pcapng> [iterations]\n", argv[0]);
    return 2;
  }
  const int iters = argc > 2 ? std::atoi(argv[2]) : 200;

  std::FILE* f = std::fopen(argv[1], "rb");
  if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
  std::vector<u8> buf;
  u8 chunk[65536];
  std::size_t n;
  while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) buf.insert(buf.end(), chunk, chunk + n);
  std::fclose(f);

  const nm::bytes file(reinterpret_cast<const std::byte*>(buf.data()), buf.size());
  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  if (!nmpcap::scan_blocks(file, refs, err)) { std::fprintf(stderr, "scan: %s\n", err.c_str()); return 1; }

  // The scan is done once, outside timing: we benchmark the DECODE (the part
  // nanotins parallelizes); the boundary scan is inherently serial in both.
  run("nanom-overlay", file, refs, buf.size(), iters, walk_overlay);
  run("nanom-strct", file, refs, buf.size(), iters, walk_strct);
  return 0;
}
