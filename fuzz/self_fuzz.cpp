// SPDX-License-Identifier: MIT

// Self-contained robustness fuzzer for the nanom packet walk — no external
// deps, so it runs in CI. Feeds random, bit-flipped, truncated and extended
// bytes into the full pcap-scan + Eth/VLAN/IPv4/IPv6/TCP/UDP walk and asserts
// the library never crashes or reads out of bounds. Build with
// -fsanitize=address,undefined to make a bounds violation fatal.
//
// The companion differential_fuzz.cpp additionally checks that nanom and
// nanotins DECODE identically on the same inputs (600k cases, 0 mismatches);
// it needs the nanotins headers on the include path, so it is not part of the
// default CI build. See fuzz/README.md.

#include "../examples/nanotins_parity/nm_pcap.hpp"
#include "../examples/nanotins_parity/nm_protocols.hpp"

#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

using u8 = std::uint8_t; using u16 = std::uint16_t;

namespace {

// FNV-ish fold so the optimizer can't drop the walk; value is otherwise unused.
std::uint64_t walk_one(nanom::bytes pkt) {
  std::uint64_t h = 0;
  nmproto::walk_packet(
      1, pkt,
      [&](const nmproto::Ethernet& x) { h ^= x.ethertype; },
      [&](const nmproto::VlanTag& x) { h ^= x.vid; },
      [&](const nmproto::Ipv4& x) { h ^= x.protocol ^ u16(x.total_length) ^ u16(x.frag_offset); },
      [&](const nmproto::Ipv6& x) { h ^= x.next_header ^ x.hop_limit ^ x.flow_label; },
      [&](const nmproto::Tcp& x) { h ^= u16(x.src_port) ^ u16(x.data_offset); },
      [&](const nmproto::Udp& x) { h ^= u16(x.src_port); });
  return h;
}

// Wrap arbitrary bytes as a single-record classic pcap so scan_blocks accepts
// them, exercising the whole scan + parse_epb + walk chain on garbage.
std::vector<u8> as_pcap(const std::vector<u8>& payload) {
  std::vector<u8> f = {0xd4,0xc3,0xb2,0xa1, 2,0,4,0, 0,0,0,0, 0,0,0,0,
                       0xff,0xff,0,0, 1,0,0,0};                       // LE micros global hdr, link=1
  const std::uint32_t n = std::uint32_t(payload.size());
  u8 rh[16] = {0,0,0,0, 0,0,0,0, u8(n), u8(n>>8), u8(n>>16), u8(n>>24), u8(n), u8(n>>8), u8(n>>16), u8(n>>24)};
  f.insert(f.end(), rh, rh + 16);
  f.insert(f.end(), payload.begin(), payload.end());
  return f;
}

}  // namespace

int main() {
  std::mt19937_64 rng(0xBADC0DE);
  std::uint64_t sink = 0, cases = 0;

  auto run = [&](const std::vector<u8>& payload) {
    ++cases;
    // 1) walk the raw bytes directly
    sink ^= walk_one(nanom::bytes(reinterpret_cast<const std::byte*>(payload.data()), payload.size()));
    // 2) and through the full pcap scan + Phase B
    std::vector<u8> f = as_pcap(payload);
    nanom::bytes file(reinterpret_cast<const std::byte*>(f.data()), f.size());
    std::vector<nmpcap::BlockRef> refs;
    std::string err;
    if (nmpcap::scan_blocks(file, refs, err)) {
      for (const auto& ref : refs) {
        nmpcap::EpbView e{};
        if (nmpcap::parse_epb(file, ref, e))
          sink += walk_one(file.subspan(std::size_t(e.payload_file_offset), e.caplen)) * 0x9E3779B97F4A7C15ull + e.caplen;
      }
    }
  };

  std::vector<u8> seed = {2,0,0,0,0,2, 2,0,0,0,0,1, 0x08,0x00,
                          0x45,0,0,0x1c,0,1,0,0,64,17,0,0, 10,0,0,1, 10,0,0,2, 0,53,4,0xd2,0,8,0,0};
  for (int i = 0; i < 300000; ++i) {
    std::vector<u8> p(rng() % 96);
    for (auto& x : p) x = u8(rng());
    run(p);
  }
  for (int i = 0; i < 300000; ++i) {
    std::vector<u8> p = seed;
    const int muts = 1 + int(rng() % 8);
    for (int m = 0; m < muts && !p.empty(); ++m) {
      switch (rng() % 4) {
        case 0: p[rng() % p.size()] ^= u8(1u << (rng() % 8)); break;
        case 1: p[rng() % p.size()] = u8(rng()); break;
        case 2: p.resize(rng() % (p.size() + 1)); break;
        case 3: p.push_back(u8(rng())); break;
      }
    }
    run(p);
  }

  std::printf("self fuzz: %llu cases, no crash (sink %016llx)\n",
              (unsigned long long)cases, (unsigned long long)sink);
  return 0;
}
