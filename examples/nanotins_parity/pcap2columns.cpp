// SPDX-License-Identifier: Apache-2.0

// pcap2columns — the columnar data path of nanolance's pcapng2lance, on nanom.
// It scans a capture, tabulates one flat row per packet into nanom's soa<T>
// (Struct-of-Arrays, chunked), and demonstrates the three things a Lance /
// nanoarrow writer needs from the parser side:
//
//   1. the Arrow C-Data schema (one format string per flattened column) —
//      exactly what ArrowSchemaSetFormat wants;
//   2. contiguous per-column byte buffers — exactly what ArrowArray imports
//      (no transpose, no per-row copy);
//   3. losslessness — every column value equals what was parsed.
//
// The actual Lance file write is a nanoarrow/lance call on top of (1)+(2); it
// is omitted here only because nanoarrow isn't vendored in this repo. This is
// the L1 PacketRow path from nanolance/examples/pcapng2lance/include/packet_row.hpp,
// reproduced with one NANOM_DESCRIBE instead of boost.describe + soatins.
//
// A per-packet L3 row (src/dst IP as fixed-size-binary) is also built to show
// address columns map to Arrow fixed-binary ("w:4" / "w:16"), like the
// nanotins PDU tables.

#include "nm_pcap.hpp"
#include "nm_protocols.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using u64 = std::uint64_t;

// L1 row: one per packet (mirrors pcapng2lance PacketRow).
struct PacketRow {
  u64 packet_id;
  u32 interface_id;
  u64 ts_raw;
  u32 caplen;
  u32 origlen;
  u16 link_type;
  u8  reached_l4;   // small denormalized decode flag
};
NANOM_DESCRIBE(PacketRow, packet_id, interface_id, ts_raw, caplen, origlen, link_type, reached_l4);

// L3 row: IPv4 addresses as fixed-size-binary columns (Arrow "w:4").
struct Ipv4Row {
  u64               packet_id;
  std::array<u8, 4> src, dst;
  u8                protocol;
  u16               total_length;
};
NANOM_DESCRIBE(Ipv4Row, packet_id, src, dst, protocol, total_length);

int main(int argc, char** argv) {
  if (argc < 2) { std::fprintf(stderr, "usage: %s <capture.pcap|pcapng>\n", argv[0]); return 2; }
  std::FILE* f = std::fopen(argv[1], "rb");
  if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
  std::vector<u8> buf; u8 chunk[65536]; std::size_t n;
  while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) buf.insert(buf.end(), chunk, chunk + n);
  std::fclose(f);
  const nm::bytes file(reinterpret_cast<const std::byte*>(buf.data()), buf.size());

  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  if (!nmpcap::scan_blocks(file, refs, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }

  nm::soa<PacketRow> l1(/*chunk_rows=*/4096);
  nm::soa<Ipv4Row>   l3(/*chunk_rows=*/4096);
  std::vector<PacketRow> expect_l1;   // kept for the round-trip check
  std::vector<u16>       iface_link;
  u64 pid = 0;

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
    const nm::bytes pkt = file.subspan(std::size_t(e.payload_file_offset), e.caplen);

    auto wr = nmproto::walk_packet(
        link, pkt, [](auto&&) {}, [](auto&&) {},
        [&](const nmproto::Ipv4& x) { l3.push({pid, x.src, x.dst, x.protocol, u16(x.total_length)}); },
        [](auto&&) {}, [](auto&&) {}, [](auto&&) {});

    PacketRow row{pid, e.interface_id, e.ts_raw, e.caplen, e.origlen, link, u8(wr.reached_l4)};
    l1.push(row);
    expect_l1.push_back(row);
    ++pid;
  }

  // (1) Arrow schema for the L1 table
  std::printf("== L1 packet table: %llu rows, %zu columns ==\n",
              (unsigned long long)l1.rows(), l1.columns().size());
  for (const auto& c : l1.columns())
    std::printf("  %-14s arrow=%-6s %zu B/row\n", c.name.c_str(), c.arrow.c_str(), c.elem_bytes);
  std::printf("== L3 ipv4 table: %llu rows (addresses as fixed-binary) ==\n",
              (unsigned long long)l3.rows());
  for (const auto& c : l3.columns())
    std::printf("  %-14s arrow=%-6s\n", c.name.c_str(), c.arrow.c_str());

  // (2)+(3) round-trip: reconstruct each PacketRow from the contiguous column
  // buffers and compare to what we parsed. This is the losslessness a Lance
  // reader relies on; the column spans are exactly what ArrowArray imports.
  std::size_t row = 0, bad = 0;
  l1.for_each_chunk([&](const auto& ch) {
    auto pid_c  = ch.template as<u64>(0);
    auto ifc_c  = ch.template as<u32>(1);
    auto ts_c   = ch.template as<u64>(2);
    auto cap_c  = ch.template as<u32>(3);
    auto orig_c = ch.template as<u32>(4);
    auto link_c = ch.template as<u16>(5);
    auto l4_c   = ch.template as<u8>(6);
    for (std::size_t i = 0; i < ch.rows; ++i, ++row) {
      const PacketRow& e = expect_l1[row];
      bad += !(pid_c[i] == e.packet_id && ifc_c[i] == e.interface_id && ts_c[i] == e.ts_raw &&
               cap_c[i] == e.caplen && orig_c[i] == e.origlen && link_c[i] == e.link_type &&
               l4_c[i] == e.reached_l4);
    }
  });
  std::printf("round-trip: %zu rows reconstructed from columns, %zu mismatches\n", row, bad);
  return bad ? 1 : 0;
}
