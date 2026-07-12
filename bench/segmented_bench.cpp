// SPDX-License-Identifier: Apache-2.0

// Microbenchmark for segmented (scatter-gather) input, quantifying the two claims the segmented
// design rests on:
//
//   (A) STITCH vs SEGMENTS on the reassembly re-entry. When an IP datagram completes, nano_shark
//       re-parses its L4 header. The OLD path stitched every fragment into one owned buffer first
//       (a copy of the whole datagram, up to 64 KiB) and parsed that; the NEW path parses straight
//       over the fragment views (strct_seg gathers only the L4 header's bytes). For anything past a
//       couple of fragments the stitch copy dominates, so segments-parse should win by a growing
//       margin as the datagram grows -- this bench prints both, at {2,4,16} fragments x {1.5K,64K}.
//
//   (B) FIXED PER-WRAP OVERHEAD. When SOME/IP dispatch wraps a contiguous UDP payload as a 1-part
//       segments and parses it with strct_seg, that wrap + seg cursor costs a fixed few tens of ns
//       over a raw strct<> on input. This is NOT on the every-packet hot path: normal packets' L4
//       headers are still parsed by walk_packet_ext (contiguous, unchanged -- see parse_bench,
//       which is byte-identical with/without this work); only a SOME/IP payload gets wrapped, once
//       per SOME/IP packet, where it is dwarfed by the subsequent SD entry/option parsing. This
//       bench quantifies that fixed overhead for transparency; it is the floor cost of the
//       segmented abstraction, paid only by code that opts into it.
//
// Reports best-of-N ns per completed datagram (A) and ns per wrapped parse (B). A checksum keeps
// the optimizer honest and proves both forms decode identically. No file I/O; in-memory buffers.

#include <nanom/nanom.hpp>

#include "../examples/nanotins_parity/nm_protocols.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

namespace nm = nanom;
namespace P = nmproto;

namespace {

struct Sink {
  std::uint64_t hash = 1469598103934665603ull;
  void mix(std::uint64_t v) { hash = (hash ^ v) * 1099511628211ull; }
};

// Build a datagram of `total` bytes with a valid UDP header at the front, then split it into
// `n_frags` equal-ish fragments (views into `storage`). Fragment boundaries fall on 8-byte units,
// as real IP fragmentation requires -- so the UDP header (8 bytes) always sits inside fragment 0
// (the realistic case; the re-entry reads the header zero-copy via seg_input's fast path).
std::vector<std::span<const std::byte>> make_fragments(std::vector<std::byte>& storage,
                                                       std::size_t total, std::size_t n_frags) {
  storage.assign(total, std::byte{});
  // UDP header: src 4660, dst 22136, length = total, checksum 0
  auto put16 = [&](std::size_t off, std::uint16_t v) {
    storage[off] = std::byte(v >> 8);
    storage[off + 1] = std::byte(v & 0xFF);
  };
  put16(0, 4660);
  put16(2, 22136);
  put16(4, std::uint16_t(total < 0xFFFF ? total : 0xFFFF));
  put16(6, 0);
  for (std::size_t i = 8; i < total; ++i) storage[i] = std::byte(i & 0xFF);

  std::vector<std::span<const std::byte>> parts;
  const std::size_t units = (total + 7) / 8;
  const std::size_t per = ((units + n_frags - 1) / n_frags) * 8;  // 8-byte-aligned chunk
  for (std::size_t off = 0; off < total; off += per)
    parts.emplace_back(storage.data() + off, std::min(per, total - off));
  return parts;
}

template <class Fn>
double best_ns(int iters, std::size_t reps, Fn fn) {
  double best = 1e300;
  for (int it = 0; it < iters; ++it) {
    auto t0 = std::chrono::steady_clock::now();
    for (std::size_t r = 0; r < reps; ++r) fn();
    auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / double(reps);
    if (ns < best) best = ns;
  }
  return best;
}

void bench_stitch_vs_segments(std::size_t total, std::size_t n_frags, int iters, std::size_t reps) {
  std::vector<std::byte> storage;
  const auto parts = make_fragments(storage, total, n_frags);

  Sink chk_stitch, chk_seg;

  // (A1) stitch-then-parse: copy every fragment into one owned buffer, then parse the UDP header.
  const double ns_stitch = best_ns(iters, reps, [&] {
    std::vector<std::byte> buf;
    buf.reserve(total);
    for (const auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    auto udp = nm::strct<P::Udp>()(nm::from(nm::bytes(buf.data(), buf.size())));
    if (udp) chk_stitch.mix(std::uint16_t(udp->value.dst_port));
  });

  // (A2) segments-parse: parse the UDP header straight over the fragment views (zero copy).
  const double ns_seg = best_ns(iters, reps, [&] {
    const nm::segments segs{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
    auto udp = nm::strct_seg<P::Udp>()(nm::from(segs));
    if (udp) chk_seg.mix(std::uint16_t(udp->value.dst_port));
  });

  const char* faster = ns_seg < ns_stitch ? "segments" : "STITCH";
  std::printf("A  %5zuB x %2zu frags   stitch %8.1f ns   segments %8.1f ns   %.2fx  (%s)  chk %s\n",
              total, n_frags, ns_stitch, ns_seg, ns_stitch / ns_seg, faster,
              chk_stitch.hash == chk_seg.hash ? "ok" : "MISMATCH");
}

void bench_normal_path(int iters, std::size_t reps) {
  // A single contiguous 8-byte UDP header -- the normal (non-fragmented) per-packet case.
  std::vector<std::byte> storage;
  const auto parts = make_fragments(storage, 64, 1);
  const nm::bytes hdr(storage.data(), storage.size());

  Sink chk_raw, chk_wrap;

  const double ns_raw = best_ns(iters, reps, [&] {
    auto udp = nm::strct<P::Udp>()(nm::from(hdr));
    if (udp) chk_raw.mix(std::uint16_t(udp->value.dst_port));
  });

  const double ns_wrap = best_ns(iters, reps, [&] {
    const nm::single_segment one{hdr};
    auto udp = nm::strct_seg<P::Udp>()(nm::from(one.view()));
    if (udp) chk_wrap.mix(std::uint16_t(udp->value.dst_port));
  });

  std::printf("B  per-wrap cost     raw input %6.2f ns   1-part wrap %6.2f ns   +%.1f ns fixed  chk %s\n"
              "   (off the every-packet hot path -- only SOME/IP payloads get wrapped; parse_bench\n"
              "    is byte-identical with/without this work)\n",
              ns_raw, ns_wrap, ns_wrap - ns_raw, chk_raw.hash == chk_wrap.hash ? "ok" : "MISMATCH");
}

}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 50;
  const std::size_t reps = 2000;

  std::printf("=== (A) reassembly re-entry: stitch-then-parse vs zero-copy segments-parse ===\n");
  for (std::size_t total : {std::size_t(1500), std::size_t(64 * 1024)})
    for (std::size_t nf : {std::size_t(2), std::size_t(4), std::size_t(16)})
      bench_stitch_vs_segments(total, nf, iters, reps);

  std::printf("\n=== (B) normal path: raw input vs 1-part single_segment wrapper ===\n");
  bench_normal_path(iters, reps * 20);
  return 0;
}
