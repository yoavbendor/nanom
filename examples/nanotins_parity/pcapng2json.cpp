// SPDX-License-Identifier: MIT

// pcapng2json (nanom port) — the parity rewrite of nanotins'
// examples/pcapng2json: read a pcap/pcapng capture, print one JSON object per
// packet (NDJSON) with the decoded L2/L3/L4 layers. Output is BYTE-IDENTICAL
// to the nanotins original on the same capture (that is the point: same scan,
// same walk, same JSON — different parsing core). Parse and emit are separate
// functions so a benchmark can time decode without the JSON cost.

#include "nm_pcap.hpp"
#include "nm_protocols.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

using namespace nmproto;

void append_u64(std::string& s, const char* key, std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
  s += '"'; s += key; s += "\":"; s += buf;
}
std::string hex16(std::uint16_t v) {
  char buf[8];
  std::snprintf(buf, sizeof buf, "0x%04x", v);
  return buf;
}
std::string mac(const std::array<std::uint8_t, 6>& a) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
  return buf;
}
std::string ipv4s(const std::array<std::uint8_t, 4>& a) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return buf;
}
std::string ipv6s(const std::array<std::uint8_t, 16>& a) {
  char buf[40];
  std::snprintf(buf, sizeof buf,
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11],
                a[12], a[13], a[14], a[15]);
  return buf;
}

struct LayerList {
  std::string s;
  bool first = true;
  void open() {
    if (!first) s += ',';
    first = false;
    s += '{';
  }
};

bool to_ndjson(nanom::bytes file, std::string& out, std::string& err) {
  out.clear();
  err.clear();

  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, err)) return false;

  std::vector<std::uint16_t> iface_link;  // per-interface link type, reset at each SHB
  std::uint64_t packet_id = 0;

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

    std::string line = "{";
    append_u64(line, "packet_id", packet_id);
    line += ',';
    append_u64(line, "interface_id", e.interface_id);
    line += ',';
    append_u64(line, "timestamp_raw", e.ts_raw);
    line += ',';
    append_u64(line, "caplen", e.caplen);
    line += ',';
    append_u64(line, "origlen", e.origlen);
    line += ',';
    append_u64(line, "link_type", link_type);

    const nanom::bytes pkt = file.subspan(std::size_t(e.payload_file_offset), e.caplen);
    LayerList layers;
    walk_packet(
        link_type, pkt,
        [&](const Ethernet& x) {
          layers.open();
          layers.s += "\"type\":\"ethernet\",\"dst\":\"" + mac(x.dst) + "\",\"src\":\"" + mac(x.src) +
                      "\",\"ethertype\":\"" + hex16(x.ethertype) + "\"}";
        },
        [&](const VlanTag& x) {
          layers.open();
          layers.s += "\"type\":\"vlan\",";
          append_u64(layers.s, "vid", x.vid);
          layers.s += ",\"inner_ethertype\":\"" + hex16(x.inner_ethertype) + "\"}";
        },
        [&](const Ipv4& x) {
          layers.open();
          layers.s += "\"type\":\"ipv4\",\"src\":\"" + ipv4s(x.src) + "\",\"dst\":\"" + ipv4s(x.dst) + "\",";
          append_u64(layers.s, "protocol", x.protocol);
          layers.s += ',';
          append_u64(layers.s, "ttl", x.ttl);
          layers.s += ',';
          append_u64(layers.s, "total_length", x.total_length);
          layers.s += '}';
        },
        [&](const Ipv6& x) {
          layers.open();
          layers.s += "\"type\":\"ipv6\",\"src\":\"" + ipv6s(x.src) + "\",\"dst\":\"" + ipv6s(x.dst) + "\",";
          append_u64(layers.s, "next_header", x.next_header);
          layers.s += ',';
          append_u64(layers.s, "hop_limit", x.hop_limit);
          layers.s += '}';
        },
        [&](const Tcp& x) {
          layers.open();
          layers.s += "\"type\":\"tcp\",";
          append_u64(layers.s, "src_port", x.src_port);
          layers.s += ',';
          append_u64(layers.s, "dst_port", x.dst_port);
          layers.s += '}';
        },
        [&](const Udp& x) {
          layers.open();
          layers.s += "\"type\":\"udp\",";
          append_u64(layers.s, "src_port", x.src_port);
          layers.s += ',';
          append_u64(layers.s, "dst_port", x.dst_port);
          layers.s += '}';
        });

    line += ",\"layers\":[" + layers.s + "]}";
    out += line;
    out += '\n';
    ++packet_id;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <input.pcap|pcapng>\n", argv[0]);
    std::fprintf(stderr, "       prints one JSON object per packet (NDJSON) to stdout.\n");
    return 2;
  }
  std::FILE* f = std::fopen(argv[1], "rb");
  if (!f) {
    std::fprintf(stderr, "pcapng2json: cannot open %s\n", argv[1]);
    return 1;
  }
  std::vector<std::uint8_t> bytes;
  std::uint8_t chunk[65536];
  std::size_t n = 0;
  while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) bytes.insert(bytes.end(), chunk, chunk + n);
  std::fclose(f);

  std::string out, err;
  if (!to_ndjson(nanom::bytes(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()), out, err)) {
    std::fprintf(stderr, "pcapng2json: %s\n", err.c_str());
    return 1;
  }
  std::fwrite(out.data(), 1, out.size(), stdout);
  return 0;
}
