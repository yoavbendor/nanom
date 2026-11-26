// SPDX-License-Identifier: Apache-2.0
// Crafting & emission microbenchmark: compares nm::emit, nm::to_bytes_exact, nm::mut_view in-place
// patching + recompute, and nm::craft 3-layer Eth+IPv4+UDP zero-copy framing against a hand-written
// IPv4 serializer baseline.
#include <nanom/craft.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nm = nanom;
namespace nc = nanom::craft;

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16>       eth_type;
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);

struct ipv4_plain {
  nm::ubits<4>      version, ihl;
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_len, ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl, proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_plain, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum,
               src, dst);

struct ipv4_computed {
  nm::ubits<4>      version, ihl;
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_len, ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl, proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_computed, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum,
               src, dst);

struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);

inline u16 ones_complement(std::span<const std::byte> b) {
  u32 sum = 0;
  for (std::size_t i = 0; i + 1 < b.size(); i += 2) sum += (u32(u8(b[i])) << 8) | u8(b[i + 1]);
  if (b.size() % 2) sum += u32(u8(b.back())) << 8;
  while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
  return u16(~sum);
}

template <>
struct nm::computed<ipv4_computed> {
  static constexpr auto fields = std::tuple{
      nm::calc<"ihl">([](const ipv4_computed&) { return 5; }),
      nm::calc<"total_len">([](const ipv4_computed&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h) { return ones_complement(h); }),
  };
};

template <>
struct nm::computed<udp_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const udp_hdr&, const nm::emit_ctx& c) { return 8 + c.payload.size(); }),
  };
};

static inline void hand_emit_ipv4(const ipv4_plain& h, std::byte* p) {
  p[0] = std::byte((h.version.v << 4) | (h.ihl.v & 0xf));
  p[1] = std::byte((h.dscp.v << 2) | (h.ecn.v & 0x3));
  std::memcpy(p + 2, h.total_len.raw.data(), 2);
  std::memcpy(p + 4, h.ident.raw.data(), 2);
  const u16 ff = u16((h.flags.v << 13) | (h.frag_off.v & 0x1fff));
  p[6] = std::byte(ff >> 8);
  p[7] = std::byte(ff & 0xff);
  p[8] = std::byte(h.ttl);
  p[9] = std::byte(h.proto);
  std::memcpy(p + 10, h.checksum.raw.data(), 2);
  std::memcpy(p + 12, h.src.data(), 4);
  std::memcpy(p + 16, h.dst.data(), 4);
}

template <class Fn>
static void bench(const char* name, int reps, std::size_t ops, Fn&& fn) {
  volatile u64 sink = fn();
  double best = 1e30;
  for (int r = 0; r < reps; ++r) {
    const auto t0 = std::chrono::steady_clock::now();
    sink += fn();
    const auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    if (ns < best) best = ns;
  }
  std::printf("%-34s %6.2f ns/op  (ops=%zu)\n", name, best / double(ops), ops);
}

int main(int argc, char** argv) {
  const std::size_t ops = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 2'000'000;
  const int reps        = argc > 2 ? std::atoi(argv[2]) : 5;

  eth_hdr eth{{1, 2, 3, 4, 5, 6}, {7, 8, 9, 10, 11, 12}, u16(0x0800)};
  ipv4_plain hp{.version = 4, .ihl = 5, .dscp = 0, .ecn = 0, .total_len = 60, .ident = 0,
                .flags = 2, .frag_off = 0, .ttl = 64, .proto = 17, .checksum = 0,
                .src = {192, 168, 0, 1}, .dst = {192, 168, 0, 2}};
  ipv4_computed hc{};
  hc.version = 4; hc.flags = 2; hc.ttl = 64; hc.proto = 17;
  hc.src = {192, 168, 0, 1}; hc.dst = {192, 168, 0, 2};
  udp_hdr udp{5000, 53, 0, 0};

  std::array<std::byte, 32> payload{};
  std::array<std::byte, 128> out{};

  bench("emit(eth_hdr)", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      eth.eth_type = u16(i);
      auto r = nm::emit(eth, out);
      acc += u8(out[12]) + (r ? *r : 0);
    }
    return acc;
  });

  bench("emit(ipv4_plain)", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      hp.ident = u16(i);
      auto r = nm::emit(hp, out);
      acc += u8(out[4]) + (r ? *r : 0);
    }
    return acc;
  });

  bench("hand_emit_ipv4 (baseline)", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      hp.ident = u16(i);
      hand_emit_ipv4(hp, out.data());
      acc += u8(out[4]) + 20;
    }
    return acc;
  });

  bench("emit(ipv4_computed csum+len)", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      hc.ident = u16(i);
      auto r = nm::emit(hc, out, nm::emit_ctx{payload});
      acc += u8(out[10]) + (r ? *r : 0);
    }
    return acc;
  });

  // Template emitted once, then patched in place via mut_view + recompute
  (void)nm::emit(hc, out, nm::emit_ctx{payload});
  auto mv = *nm::overlay_mut<ipv4_computed>(out);
  bench("mut_view patch(ident)+recompute", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      (void)mv.set<"ident">(u16(i));
      (void)mv.recompute(nm::emit_ctx{payload});
      acc += u8(out[10]) + u8(out[11]);
    }
    return acc;
  });

  bench("craft Eth+IPv4+UDP+32B span_sink", reps, ops, [&] {
    u64 acc = 0;
    for (std::size_t i = 0; i < ops; ++i) {
      hc.ident = u16(i);
      auto pkt = nc::put_bytes(payload)
               | nc::framed_by(udp)
               | nc::framed_by(hc)
               | nc::framed_by(eth);
      nm::span_sink ss{out};
      auto r = nc::write(pkt, ss);
      acc += u8(out[24]) + (r ? *r : 0);
    }
    return acc;
  });

  return 0;
}
