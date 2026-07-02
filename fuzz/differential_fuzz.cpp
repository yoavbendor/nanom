// SPDX-License-Identifier: MIT

// Differential fuzzer: nanom vs nanotins on random / mutated packet bytes.
// For each input we run BOTH libs' Eth->VLAN->IPv4/IPv6->TCP/UDP walk and
// require: (1) neither crashes / reads OOB (run under ASan+UBSan), and (2)
// they agree layer-for-layer and field-for-field. Seeds are real headers,
// then bit-flipped / truncated / extended to hammer the bounds logic.
#include "../examples/nanotins_parity/nm_protocols.hpp"
#include "nanotins/protocol_decode.hpp"
#include "nanotins/protocols.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using u8 = std::uint8_t; using u16 = std::uint16_t;

// Canonical trace of a walk: (layer tag, key field) pairs, in emission order.
struct Trace {
  std::vector<std::uint64_t> ev;
  void e(int tag, std::uint64_t a, std::uint64_t b = 0) { ev.push_back((std::uint64_t(tag) << 56) ^ (a * 1000003 + b)); }
  bool operator==(const Trace& o) const { return ev == o.ev; }
};

static Trace nanom_walk(const std::vector<u8>& p) {
  Trace t;
  nanom::bytes b(reinterpret_cast<const std::byte*>(p.data()), p.size());
  nmproto::walk_packet(
      1, b,
      [&](const nmproto::Ethernet& x) { t.e(1, x.ethertype, x.dst[0]); },
      [&](const nmproto::VlanTag& x) { t.e(2, x.vid, x.inner_ethertype); },
      [&](const nmproto::Ipv4& x) { t.e(3, x.protocol, u16(x.total_length) ^ x.ttl ^ (u16(x.frag_offset) << 3)); },
      [&](const nmproto::Ipv6& x) { t.e(4, x.next_header, x.hop_limit); },
      [&](const nmproto::Tcp& x) { t.e(5, u16(x.src_port), u16(x.dst_port) ^ (u16(x.data_offset) << 20)); },
      [&](const nmproto::Udp& x) { t.e(6, u16(x.src_port), u16(x.dst_port)); });
  return t;
}
static Trace tins_walk(const std::vector<u8>& p) {
  Trace t;
  protocols::Bytes b(p.data(), p.size());
  protocols::walk_packet(
      1, b,
      [&](const protocols::Ethernet& x) { t.e(1, x.ethertype.host(), x.dst[0]); },
      [&](const protocols::VlanTag& x) { t.e(2, x.tci.word_host() & 0x0FFF, x.inner_ethertype.host()); },
      [&](const protocols::Ipv4& x) { t.e(3, x.protocol, x.total_length.host() ^ x.ttl ^ ((x.flags_frag.word_host() & 0x1FFF) << 3)); },
      [&](const protocols::Ipv6& x) { t.e(4, x.next_header, x.hop_limit); },
      [&](const protocols::Tcp& x) { t.e(5, x.src_port.host(), x.dst_port.host() ^ (((x.off_flags.word_host() >> 12) & 0xF) << 20)); },
      [&](const protocols::Udp& x) { t.e(6, x.src_port.host(), x.dst_port.host()); });
  return t;
}

static std::vector<u8> seed_ipv4_udp() {
  std::vector<u8> p = {2,0,0,0,0,2, 2,0,0,0,0,1, 0x08,0x00,
                       0x45,0,0,0x20,0,1,0,0,64,17,0,0, 10,0,0,1, 10,0,0,2,
                       0,53,4,0xd2,0,8,0,0};
  p[16] = u8((20 + 8) >> 8); p[17] = u8(20 + 8);
  return p;
}
static std::vector<u8> seed_vlan_ipv6_tcp() {
  std::vector<u8> p = {2,0,0,0,0,2, 2,0,0,0,0,1, 0x81,0x00, 0x00,0x2a, 0x86,0xdd,
                       0x60,0,0,0, 0,20, 6,64, 0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,
                       0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2,
                       0,80, 0x30,0x39, 0,0,0,0, 0,0,0,0, 0x50,0x02, 0x20,0,0,0,0,0};
  return p;
}

int main() {
  std::mt19937_64 rng(0xC0FFEE);
  std::vector<std::vector<u8>> seeds = {seed_ipv4_udp(), seed_vlan_ipv6_tcp(), {}, {0x08,0x00}};

  std::uint64_t cases = 0, mismatches = 0;
  auto check = [&](const std::vector<u8>& p) {
    ++cases;
    Trace a = nanom_walk(p), b = tins_walk(p);
    if (!(a == b)) {
      if (mismatches < 8) {
        std::printf("MISMATCH len=%zu nanom_ev=%zu tins_ev=%zu\n", p.size(), a.ev.size(), b.ev.size());
      }
      ++mismatches;
    }
  };

  // 1) pure random of assorted lengths
  for (int i = 0; i < 200000; ++i) {
    std::vector<u8> p(rng() % 80);
    for (auto& x : p) x = u8(rng());
    check(p);
  }
  // 2) seed mutations: bit flips, byte sets, truncation, extension
  for (int i = 0; i < 400000; ++i) {
    std::vector<u8> p = seeds[rng() % seeds.size()];
    if (p.empty()) { check(p); continue; }
    const int muts = 1 + int(rng() % 6);
    for (int m = 0; m < muts; ++m) {
      switch (rng() % 4) {
        case 0: if (!p.empty()) p[rng() % p.size()] ^= u8(1u << (rng() % 8)); break;
        case 1: if (!p.empty()) p[rng() % p.size()] = u8(rng()); break;
        case 2: if (!p.empty()) p.resize(rng() % (p.size() + 1)); break;         // truncate
        case 3: p.push_back(u8(rng())); break;                                    // extend
      }
    }
    check(p);
  }

  std::printf("differential fuzz: %llu cases, %llu mismatches\n",
              (unsigned long long)cases, (unsigned long long)mismatches);
  return mismatches ? 1 : 0;
}
