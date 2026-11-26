// SPDX-License-Identifier: Apache-2.0
//
// nanom_shark decode throughput on a capture file (bench/automotive_gen.py makes a synthetic
// automotive one: VLAN + IPv4/IPv6 + UDP + SOME/IP, SOME/IP-SD, SOME/IP-TP, IPv4 fragments).
//
//   A  zero-copy floor   walk the pcap records and touch each SOME/IP header (pointer arithmetic
//                        only): what reading the file costs at all -- the memory-bound floor
//   B  bare walk         container scan + record header + nmproto::walk_packet_ext with an empty
//                        visitor: the L2-L4 decode, no tables
//   C  decode, tables    run_decode_pass into a fresh default_decoder table set (every table)
//   D  decode, projected the same with only the "packets" and "someip" tables enabled
//   E  streaming         StreamingDecodeSession::feed_epb per block (blocks pre-scanned, untimed),
//                        a distinct buffer token per packet, every released token checked
//
// Reported per packet: best-of-N wall time, heap allocations (operator new calls in the timed
// region) and, on Linux, minor page faults (fresh table memory being touched for the first time is
// a large part of C's cost). Instruction counts come from callgrind:
//
//   valgrind --tool=callgrind ./nm_shark_bench small.pcap 1 C    # one section, one rep
//
// usage: nm_shark_bench <capture.pcap|pcapng> [reps=3] [sections=ABCDE]
#include <nanom_shark/nanom_shark.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <new>
#include <string>
#include <vector>

#if __has_include(<sys/resource.h>)
#  include <sys/resource.h>
#  define NM_BENCH_HAVE_RUSAGE 1
#endif

// ---- allocation counter (this executable only) ----
// Kept out of line: an inlined replacement delete makes GCC report free() on memory from
// `operator new` (-Wmismatched-new-delete), although malloc / free do match here.
#if defined(__GNUC__) || defined(__clang__)
#  define NM_BENCH_NOINLINE __attribute__((noinline))
#else
#  define NM_BENCH_NOINLINE
#endif
static std::atomic<std::uint64_t> g_allocs{0};
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#  define NM_BENCH_SANITIZED 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#    define NM_BENCH_SANITIZED 1
#  else
#    define NM_BENCH_SANITIZED 0
#  endif
#else
#  define NM_BENCH_SANITIZED 0
#endif
#if !NM_BENCH_SANITIZED
NM_BENCH_NOINLINE void* operator new(std::size_t n) {
  g_allocs.fetch_add(1, std::memory_order_relaxed);
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc{};
}
NM_BENCH_NOINLINE void* operator new[](std::size_t n) { return ::operator new(n); }
NM_BENCH_NOINLINE void* operator new(std::size_t n, std::align_val_t a) {
  g_allocs.fetch_add(1, std::memory_order_relaxed);
  const std::size_t al = std::size_t(a);
  const std::size_t sz = n ? ((n + al - 1) / al * al) : al;
  if (void* p = std::aligned_alloc(al, sz)) return p;
  throw std::bad_alloc{};
}
NM_BENCH_NOINLINE void* operator new[](std::size_t n, std::align_val_t a) { return ::operator new(n, a); }
NM_BENCH_NOINLINE void operator delete(void* p) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete(void* p, std::size_t) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete[](void* p) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
NM_BENCH_NOINLINE void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
#endif

namespace {

namespace ns = nanom_shark;
using clk = std::chrono::steady_clock;

double secs(clk::time_point a) { return std::chrono::duration<double>(clk::now() - a).count(); }
long minor_faults() {
#ifdef NM_BENCH_HAVE_RUSAGE
  rusage u{};
  getrusage(RUSAGE_SELF, &u);
  return u.ru_minflt;
#else
  return 0;
#endif
}

struct Stat {
  double best = 1e30;
  std::uint64_t allocs = 0;
  long faults = 0;
};
// Run `body` `reps` times; keep the best time, and the allocations / faults of that run.
template <class Body>
Stat measure(int reps, Body&& body) {
  Stat s;
  for (int i = 0; i < reps; ++i) {
    const std::uint64_t a0 = g_allocs.load();
    const long f0 = minor_faults();
    const double t = body();
    if (t < s.best) {
      s.best = t;
      s.allocs = g_allocs.load() - a0;
      s.faults = minor_faults() - f0;
    }
  }
  return s;
}

void report(const char* name, const Stat& s, double pkts, const char* extra = "") {
  std::printf("%-26s %8.1f ns/pkt  %6.2f Mpkt/s  %7.3f allocs/pkt  %6.3f faults/pkt  %s\n", name,
              s.best * 1e9 / pkts, pkts / s.best / 1e6, double(s.allocs) / pkts, double(s.faults) / pkts, extra);
}

std::size_t table_bytes(const ns::AllTables& t) {
  std::size_t bytes = 0;
  t.for_each_table([&](std::string_view, const auto& soa) {
    std::size_t row = 0;
    for (const auto& c : soa.columns()) row += c.elem_bytes;
    bytes += row * soa.rows();
  });
  return bytes;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <capture.pcap|pcapng> [reps=3] [sections=ABCDE]\n", argv[0]);
    return 2;
  }
  std::ifstream f(argv[1], std::ios::binary);
  if (!f) {
    std::fprintf(stderr, "cannot open %s\n", argv[1]);
    return 2;
  }
  std::vector<char> raw((std::istreambuf_iterator<char>(f)), {});
  const nanom::bytes file(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
  const int reps = argc > 2 ? std::max(1, std::atoi(argv[2])) : 3;
  const std::string sections = argc > 3 ? argv[3] : "ABCDE";
  auto want = [&](char c) { return sections.find(c) != std::string::npos; };

  ns::DecodeOptions opts;
  opts.someip_ports = {30490, 30501};
  std::string err;

  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, err)) {
    std::fprintf(stderr, "scan: %s\n", err.c_str());
    return 1;
  }
  double pkts = 0;
  for (const auto& r : refs) pkts += (r.kind == nmpcap::Kind::PcapRecord || r.kind == nmpcap::Kind::Epb);
  if (pkts == 0) {
    std::fprintf(stderr, "no packets\n");
    return 1;
  }
  std::printf("%s: %.0f packets, %.1f MB, %d rep(s), best shown\n", argv[1], pkts, file.size() / 1e6, reps);
  int failures = 0;

  // ---- A: zero-copy floor (classic little-endian pcap only) ----
  if (want('A') && raw.size() >= 24 && std::memcmp(raw.data(), "\xd4\xc3\xb2\xa1", 4) == 0) {
    std::uint64_t acc = 0;
    const auto s = measure(reps, [&] {
      const auto* b = reinterpret_cast<const std::uint8_t*>(raw.data());
      acc = 0;
      const auto t0 = clk::now();
      for (std::size_t off = 24; off + 16 <= raw.size();) {
        std::uint32_t cap;
        std::memcpy(&cap, b + off + 8, 4);
        const std::uint8_t* p = b + off + 16;
        off += 16 + cap;
        if (cap < 18) continue;
        std::size_t l2 = 14;
        std::uint16_t et = std::uint16_t(p[12] << 8 | p[13]);
        if (et == 0x8100) {
          et = std::uint16_t(p[16] << 8 | p[17]);
          l2 = 18;
        }
        std::size_t l4;
        if (et == 0x0800) {
          if (l2 + 20 > cap || ((p[l2 + 6] & 0x3f) | p[l2 + 7])) continue;
          l4 = l2 + (p[l2] & 0xf) * 4;
        } else if (et == 0x86dd) {
          l4 = l2 + 40;
        } else {
          continue;
        }
        if (l4 + 8 + 16 > cap) continue;
        const std::uint8_t* sm = p + l4 + 8;
        acc += (std::uint32_t(sm[0]) << 8 | sm[1]) + (std::uint32_t(sm[10]) << 8 | sm[11]);
      }
      return secs(t0);
    });
    char extra[64];
    std::snprintf(extra, sizeof extra, "(chk %llu)", (unsigned long long)acc);
    report("A zero-copy floor", s, pkts, extra);
  }

  // ---- B: bare walk (scan + record header + L2-L4 walk, no tables) ----
  if (want('B')) {
    std::uint64_t sink = 0;
    const auto s = measure(reps, [&] {
      sink = 0;
      std::string e;
      const auto t0 = clk::now();
      nmpcap::for_each_block(file, [&](const nmpcap::BlockRef& r) {
        if (r.kind != nmpcap::Kind::PcapRecord && r.kind != nmpcap::Kind::Epb) return;
        nmpcap::EpbView v{};
        if (!nmpcap::parse_epb(file, r, v)) return;
        struct Vis {
          std::uint64_t* s;
          void on_udp(const nmproto::Udp& u) { *s += u.dst_port; }
        } vis{&sink};
        const auto w = nmproto::walk_packet_ext(1, file.subspan(std::size_t(v.payload_file_offset), v.caplen), vis);
        sink += w.reached_l4;
      }, e);
      return secs(t0);
    });
    char extra[64];
    std::snprintf(extra, sizeof extra, "(chk %llu)", (unsigned long long)sink);
    report("B bare walk", s, pkts, extra);
  }

  // ---- C: full decode into every table ----
  std::size_t c_rows = 0, c_someip = 0;
  if (want('C')) {
    std::size_t bytes = 0;
    const auto s = measure(reps, [&] {
      ns::AllTables t;
      const auto t0 = clk::now();
      if (!ns::run_decode_pass(file, t, ns::SinkHub{}, opts, err)) ++failures;
      const double el = secs(t0);
      c_rows = 0;
      t.for_each_table([&](std::string_view, const auto& soa) { c_rows += soa.rows(); });
      c_someip = t.get<"someip">().rows();
      bytes = table_bytes(t);
      return el;
    });
    char extra[96];
    std::snprintf(extra, sizeof extra, "(%zu rows, %.1f B/pkt of tables)", c_rows, bytes / pkts);
    report("C decode, all tables", s, pkts, extra);
  }

  // ---- D: projection ----
  if (want('D')) {
    std::size_t someip = 0;
    const auto s = measure(reps, [&] {
      ns::AllTables t;
      t.enable_only({"packets", "someip"});
      const auto t0 = clk::now();
      if (!ns::run_decode_pass(file, t, ns::SinkHub{}, opts, err)) ++failures;
      const double el = secs(t0);
      someip = t.get<"someip">().rows();
      return el;
    });
    char extra[64];
    std::snprintf(extra, sizeof extra, "(someip rows %zu)", someip);
    report("D decode, packets+someip", s, pkts, extra);
    if (want('C') && someip != c_someip) {
      std::printf("MISMATCH: projected someip rows %zu != %zu\n", someip, c_someip);
      ++failures;
    }
  }

  // ---- E: streaming session, one token per packet ----
  if (want('E')) {
    std::size_t rows = 0;
    bool tokens_ok = true;
    const auto s = measure(reps, [&] {
      ns::AllTables t;
      ns::StreamingDecodeSession<ns::default_decoder> session(t, ns::SinkHub{}, opts);
      std::uint64_t tok = 1, released = 0;
      const auto t0 = clk::now();
      for (const auto& r : refs) {
        const std::size_t len =
            r.kind == nmpcap::Kind::Idb ? std::max<std::size_t>(r.length, 28) : std::size_t(r.length);
        const auto b = file.subspan(std::size_t(r.file_offset), std::min(len, file.size() - std::size_t(r.file_offset)));
        if (r.kind == nmpcap::Kind::Shb) session.feed_shb(b);
        else if (r.kind == nmpcap::Kind::Idb) session.feed_idb(b, r.little_endian, r.length);
        else if (r.kind == nmpcap::Kind::PcapRecord || r.kind == nmpcap::Kind::Epb) {
          const auto fr = session.feed_epb(b, r.little_endian, tok++, r.kind, r.file_offset);
          released += fr.released.size();
        }
      }
      const double el = secs(t0);
      // every token is released exactly once by the end, except those still pinned
      tokens_ok = released + session.pinned_buffers() == tok - 1;
      rows = 0;
      t.for_each_table([&](std::string_view, const auto& soa) { rows += soa.rows(); });
      return el;
    });
    report("E streaming, tokens", s, pkts, tokens_ok ? "(tokens ok)" : "(TOKEN MISMATCH)");
    if (!tokens_ok) ++failures;
    if (want('C') && rows != c_rows) {
      std::printf("MISMATCH: streaming rows %zu != whole-file rows %zu\n", rows, c_rows);
      ++failures;
    }
  }
  return failures ? 1 : 0;
}
