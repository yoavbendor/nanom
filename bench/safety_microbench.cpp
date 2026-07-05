// SPDX-License-Identifier: Apache-2.0
//
// Safety-overhead microbenchmarks for proposed nanom hardening.
//
// Each line reports best-of-N wall time per operation (lower is better). Lines
// prefixed "sim-" add branches or copies that *model* a proposed guard without
// changing the library — use them to estimate overhead ceilings before landing
// a tier. Re-run after each tier lands and compare against these baselines.
//
// usage: nm_safety_microbench [iterations]
//   iterations — outer repeat count per scenario (default 50)

#include "../examples/nanotins_parity/nm_protocols.hpp"

#include <nanom/nanom.hpp>
#include <nanom/bulk.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace nm = nanom;
namespace P = nmproto;

struct Sink {
  std::uint64_t h = 1469598103934665603ull;
  void mix(std::uint64_t v) { h = (h ^ v) * 1099511628211ull; }
};

// Minimal Ethernet/IPv4/UDP frame (54 B) used for overlay hot-path timing.
static std::vector<std::byte> synthetic_packet() {
  static const std::uint8_t raw[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
      0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x30, 0x39,
      0x30, 0x39, 0x00, 0x35, 0x00, 0x21, 0x00, 0x00};
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(raw),
                                reinterpret_cast<const std::byte*>(raw) + sizeof raw);
}

// Overlay walk matching parse_bench field touches (Tier B/D probe).
static void walk_overlay(nm::bytes pkt, Sink& s) {
  nm::input in = nm::from(pkt);
  auto eth = nm::overlay<P::Ethernet>()(in);
  if (!eth) return;
  std::uint16_t et = eth->value.get<"ethertype">();
  s.mix(et);
  s.mix(eth->value.get<"dst">()[0]);
  nm::input cur = eth->rest;
  if (et == P::kEtherTypeIpv4) {
    auto ip = nm::overlay<P::Ipv4>()(cur);
    if (!ip) return;
    s.mix(ip->value.get<"protocol">());
    s.mix(ip->value.get<"ttl">());
    s.mix(ip->value.get<"total_length">());
    s.mix(ip->value.get<"src">()[0]);
    s.mix(ip->value.get<"frag_offset">());
    nm::input after = cur.advance(std::size_t(ip->value.get<"ihl">()) * 4);
    auto u = nm::overlay<P::Udp>()(after);
    if (!u) return;
    s.mix(u->value.get<"src_port">());
    s.mix(u->value.get<"dst_port">());
  }
}

template <class Fn>
static double bench_best(const char* label, int outer, std::uint64_t inner, Fn fn) {
  Sink warm;
  fn(warm);
  double best = 1e300;
  Sink acc;
  for (int i = 0; i < outer; ++i) {
    Sink local;
    auto t0 = std::chrono::steady_clock::now();
    fn(local);
    auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    if (ns < best) best = ns;
    acc.h ^= local.h;
  }
  const double per = best / double(inner ? inner : 1);
  std::printf("%-28s iters=%d  inner=%llu  best=%.3f ms  %8.2f ns/op  (mix %016llx)\n",
              label, outer, (unsigned long long)inner, best / 1e6, per,
              (unsigned long long)acc.h);
  return per;
}

int main(int argc, char** argv) {
  const int outer = argc > 1 ? std::atoi(argv[1]) : 50;
  const auto pkt_bytes = synthetic_packet();
  const nm::bytes pkt(pkt_bytes.data(), pkt_bytes.size());
  const char tag_wire[] = "GET /resource HTTP/1.1";
  constexpr std::uint64_t kPacketOps = 500'000;
  constexpr std::uint64_t kFromOps = 20'000'000;
  constexpr std::uint64_t kTagOps = 5'000'000;
  constexpr std::uint64_t kRenderOps = 100'000;

  std::printf("nm_safety_microbench  outer=%d  (Release -O3 -march=native recommended)\n", outer);

  // Tier D reference — full overlay walk (lifetime-token changes show up here).
  bench_best("overlay-walk", outer, kPacketOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kPacketOps; ++i) walk_overlay(pkt, s);
  });

  // Tier B — input validation at from() / checked advance (opt-in).
  bench_best("from-construct", outer, kFromOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kFromOps; ++i) {
      nm::input in = nm::from(pkt.data(), pkt.size());
      s.mix(std::uint64_t(in.size()));
    }
  });

  bench_best("advance-take", outer, kFromOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kFromOps; ++i) {
      nm::input in = nm::from(pkt);
      auto r = nm::take(4)(in);
      if (r) s.mix(std::uint64_t(r->value.size()));
    }
  });

  bench_best("sim-checked-advance", outer, kFromOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kFromOps; ++i) {
      nm::input in = nm::from(pkt);
      constexpr std::size_t n = 4;
      if (in.size() < n) continue;  // model checked_advance branch
      nm::input out = in.advance(n);
      s.mix(std::uint64_t(out.size()));
    }
  });

  bench_best("sim-null-from-reject", outer, kFromOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kFromOps; ++i) {
      const void* p = (i & 1) ? static_cast<const void*>(pkt.data()) : nullptr;
      const std::size_t n = (i & 1) ? pkt.size() : 8;
      if (!p && n) continue;  // model reject from(nullptr,n>0)
      nm::input in = nm::from(p, n);
      s.mix(std::uint64_t(in.size()));
    }
  });

  // Tier D — generation check on every view::get (worst case).
  bench_best("view-get", outer, kPacketOps, [&](Sink& s) {
    for (std::uint64_t i = 0; i < kPacketOps; ++i) {
      auto ip = nm::overlay<P::Ipv4>()(nm::from(pkt).advance(14));
      if (!ip) continue;
      s.mix(ip->value.get<"protocol">());
      s.mix(ip->value.get<"ttl">());
      s.mix(ip->value.get<"src">()[0]);
    }
  });

  bench_best("sim-gen-check-get", outer, kPacketOps, [&](Sink& s) {
    std::uint64_t gen = 1;
    for (std::uint64_t i = 0; i < kPacketOps; ++i) {
      auto ip = nm::overlay<P::Ipv4>()(nm::from(pkt).advance(14));
      if (!ip) continue;
      const std::uint64_t view_gen = gen;
      if (view_gen != gen) continue;  // model stale check
      s.mix(ip->value.get<"protocol">());
      s.mix(ip->value.get<"ttl">());
      s.mix(ip->value.get<"src">()[0]);
    }
  });

  // Tier B — tag pattern ownership (copy vs string_view capture).
  bench_best("tag-match", outer, kTagOps, [&](Sink& s) {
    auto p = nm::tag("GET");
    nm::input in = nm::from(tag_wire, sizeof tag_wire - 1);
    for (std::uint64_t i = 0; i < kTagOps; ++i) {
      auto r = p(in);
      if (r) s.mix(std::uint64_t(r->value.size()));
    }
  });

  bench_best("sim-tag-owned", outer, kTagOps, [&](Sink& s) {
    std::array<char, 16> owned{'G', 'E', 'T'};
    auto p = [owned](nm::input in) -> nm::result<nm::bytes> {
      std::string_view pattern(owned.data(), 3);
      if (in.size() < pattern.size()) return nm::unexp(nm::error{});
      if (std::memcmp(in.first, pattern.data(), pattern.size()) != 0)
        return nm::unexp(nm::error{});
      return nm::done{in.take_span(pattern.size()), in.advance(pattern.size())};
    };
    nm::input in = nm::from(tag_wire, sizeof tag_wire - 1);
    for (std::uint64_t i = 0; i < kTagOps; ++i) {
      auto r = p(in);
      if (r) s.mix(std::uint64_t(r->value.size()));
    }
  });

  // Tier A — error::render clamp (cold path).
  bench_best("error-render", outer, kRenderOps, [&](Sink& s) {
    const char wire[] = "deadbeef";
    nm::input whole = nm::from(wire, 8);
    nm::error e{};
    e.kind = nm::errk::err;
    e.offset = 4;
    e.expected = "tag";
    for (std::uint64_t i = 0; i < kRenderOps; ++i) {
      std::string msg = e.render(whole);
      s.mix(msg.size());
    }
  });

  bench_best("sim-render-clamp", outer, kRenderOps, [&](Sink& s) {
    const char wire[] = "deadbeef";
    nm::input whole = nm::from(wire, 8);
    nm::error e{};
    e.kind = nm::errk::err;
    e.offset = 4;
    e.expected = "tag";
    for (std::uint64_t i = 0; i < kRenderOps; ++i) {
      const std::size_t total = std::size_t(whole.last - whole.base);
      const std::size_t off = e.offset <= total ? e.offset : total;  // model clamp
      (void)off;
      std::string msg = e.render(whole);
      s.mix(msg.size());
    }
  });

  // Tier A — incomplete needed saturation (streaming cold path).
  bench_best("incomplete-needed", outer, kFromOps / 10, [&](Sink& s) {
    const std::uint8_t b[] = {0x01, 0x02, 0x03, 0x04};
    for (std::uint64_t i = 0; i < kFromOps / 10; ++i) {
      auto r = nm::take(1'000'000)(nm::streaming(nm::from(b, sizeof b)));
      if (!r) s.mix(r.error().needed);
    }
  });

  bench_best("sim-needed-cap", outer, kFromOps / 10, [&](Sink& s) {
    const std::uint8_t b[] = {0x01, 0x02, 0x03, 0x04};
    constexpr std::uint32_t cap = 64 * 1024;
    for (std::uint64_t i = 0; i < kFromOps / 10; ++i) {
      auto r = nm::take(1'000'000)(nm::streaming(nm::from(b, sizeof b)));
      if (!r) {
        const std::uint32_t need = std::min(r.error().needed, cap);
        s.mix(need);
      }
    }
  });

  // Tier A — bulk pkt_ref validation at entry.
  bench_best("bulk-pkt-validate", outer, kFromOps, [&](Sink& s) {
    nm::pkt_ref pk{};
    pk.data = pkt.data();
    pk.len = std::uint32_t(pkt.size());
    pk.link = 1;
    for (std::uint64_t i = 0; i < kFromOps; ++i) {
      if (!pk.data || !pk.len) continue;  // model entry validation
      s.mix(pk.len);
    }
  });

  return 0;
}
