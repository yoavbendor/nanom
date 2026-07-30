// SPDX-License-Identifier: Apache-2.0

// Differential libFuzzer harness for segmented.hpp: for a fuzzer-chosen buffer AND a fuzzer-chosen
// segmentation of that same buffer, a fixed parse script (struct parses, scalar reads, skips,
// subranges) must produce IDENTICAL results over the segmented and contiguous forms -- same
// success/failure kinds, same values, same final offsets. Any divergence, OOB read (ASan), or UB
// (UBSan) is a crash. This is the continuous counterpart to tests/test_segmented.cpp's exhaustive
// small-split property test: libFuzzer hunts the seam placements the exhaustive test can't afford.
//
// Input format: [n_cuts:1][cut offsets: n_cuts bytes, each interpreted modulo buffer size][buffer].
// Build via -DNANOM_BUILD_FUZZERS with Clang; run: ./fuzz_segmented -max_total_time=60 corpus/

#include <nanom/nanom.hpp>

#include <nanom_shark/protocols.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace nm = nanom;

namespace {

[[noreturn]] void die(const char* what, std::size_t at) {
  std::fprintf(stderr, "fuzz_segmented divergence: %s (offset %zu)\n", what, at);
  __builtin_trap();
}

// One scripted parse over either cursor; returns a value trace (hashed events) so the two runs
// can be compared event-for-event. Every branch appends: distinct tags for ok/err/incomplete.
struct Trace {
  std::vector<std::uint64_t> ev;
  void ok(std::uint64_t v) { ev.push_back(0x1000000000000000ull ^ v); }
  void err(nm::errk k, std::size_t off) {
    ev.push_back(0x2000000000000000ull ^ (std::uint64_t(k) << 32) ^ off);
  }
};

template <class T>
std::uint64_t fold_struct(const T& v) {
  // to_json covers every field (incl. bit fields/arrays) deterministically
  const std::string j = nm::to_json(v);
  std::uint64_t h = 1469598103934665603ull;
  for (char c : j) h = (h ^ std::uint8_t(c)) * 1099511628211ull;
  return h;
}

Trace run_contiguous(std::span<const std::byte> buf) {
  Trace t;
  nm::input in = nm::from(buf);
  if (auto r = nm::strct<nmproto::Ethernet>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::strct<nmproto::Ipv4>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::be_u16(in); r) {
    t.ok(r->value);
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::be_u32(in); r) {
    t.ok(r->value);
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (in.size() >= 3) in = in.advance(3);
  if (auto r = nm::strct<nmproto::Udp>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  t.ok(in.offset());

  // repetition, from a fresh cursor: the whole buffer as a train of 8-byte records. Records land
  // on every alignment relative to the fuzzer's seams, so this hunts a repetition that loses,
  // duplicates or mis-decodes an element at a boundary -- and the leftover tail pins where the
  // walk stopped.
  if (auto r = nm::many0(nm::strct<nmproto::Udp>(std::endian::big))(nm::from(buf)); r) {
    t.ok(r->value.size());
    for (const auto& v : r->value) t.ok(fold_struct(v));
    t.ok(r->rest.offset());
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  // ...and the capped form, with a cap small enough that longer inputs trip it
  if (auto r = nm::checked_many0(nm::strct<nmproto::Udp>(std::endian::big), 4)(nm::from(buf)); r) {
    t.ok(r->value.size());
    t.ok(r->rest.offset());
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  return t;
}

Trace run_segmented(const nm::segments& segs) {
  Trace t;
  nm::seg_input in = nm::from(segs);
  if (auto r = nm::strct_seg<nmproto::Ethernet>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::strct_seg<nmproto::Ipv4>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::seg_be16(in); r) {
    t.ok(r->value);
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::seg_be32(in); r) {
    t.ok(r->value);
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (in.size() >= 3) in = in.advance(3);
  if (auto r = nm::strct_seg<nmproto::Udp>()(in); r) {
    t.ok(fold_struct(r->value));
    in = r->rest;
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  t.ok(in.offset());

  if (auto r = nm::many0_seg(nm::strct_seg<nmproto::Udp>(std::endian::big))(nm::from(segs)); r) {
    t.ok(r->value.size());
    for (const auto& v : r->value) t.ok(fold_struct(v));
    t.ok(r->rest.offset());
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  if (auto r = nm::checked_many0_seg(nm::strct_seg<nmproto::Udp>(std::endian::big), 4)(nm::from(segs));
      r) {
    t.ok(r->value.size());
    t.ok(r->rest.offset());
  } else {
    t.err(r.error().kind, r.error().offset);
  }
  return t;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  const std::size_t n_cuts = data[0] & 0x0F;  // up to 15 seams
  if (size < 1 + n_cuts) return 0;
  const std::uint8_t* cut_bytes = data + 1;
  const std::uint8_t* payload   = data + 1 + n_cuts;
  const std::size_t   len       = size - 1 - n_cuts;
  const auto* bytes = reinterpret_cast<const std::byte*>(payload);
  const std::span<const std::byte> buf(bytes, len);

  // segmentation: sorted cut offsets modulo len (duplicates -> empty parts, deliberately)
  std::vector<std::size_t> cuts(n_cuts);
  for (std::size_t i = 0; i < n_cuts; ++i) cuts[i] = len ? cut_bytes[i] % (len + 1) : 0;
  std::sort(cuts.begin(), cuts.end());

  std::vector<std::span<const std::byte>> parts;
  std::size_t at = 0;
  for (std::size_t c : cuts) {
    parts.push_back(buf.subspan(at, c - at));
    at = c;
  }
  parts.push_back(buf.subspan(at));
  const nm::segments segs{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};

  const Trace a = run_contiguous(buf);
  const Trace b = run_segmented(segs);
  if (a.ev.size() != b.ev.size()) die("trace length", a.ev.size());
  for (std::size_t i = 0; i < a.ev.size(); ++i)
    if (a.ev[i] != b.ev[i]) die("trace event", i);

  // subrange must reproduce the flat bytes wherever it fits
  nm::seg_input in = nm::from(segs);
  const std::size_t sub_n = std::min<std::size_t>(len, 24);
  if (auto sub = in.subrange(sub_n); sub) {
    const nm::segments sv  = sub->view();
    nm::seg_input      sin = nm::from(sv);
    for (std::size_t i = 0; i < sub_n; ++i)
      if (sin[i] != std::uint8_t(buf[i])) die("subrange byte", i);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Standalone driver (opt-in): the same harness without libFuzzer.
// ---------------------------------------------------------------------------
// libFuzzer needs clang's compiler-rt fuzzer runtime, which is not present everywhere this repo is
// built. This driver feeds LLVMFuzzerTestOneInput pseudo-random and seed-mutated inputs from a
// plain main(), so the differential property can still be exercised for hundreds of thousands of
// cases anywhere a compiler with -fsanitize=address,undefined is available:
//
//   g++ -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
//       -DNANOM_FUZZ_STANDALONE -I include -o fuzz_segmented_standalone fuzz/fuzz_segmented.cpp
//   ./fuzz_segmented_standalone 300000
//
// The libFuzzer build (-DNANOM_BUILD_FUZZERS) does not define NANOM_FUZZ_STANDALONE, so it keeps
// libFuzzer's own main and is unaffected.
#ifdef NANOM_FUZZ_STANDALONE
#include <cstdlib>
#include <random>

int main(int argc, char** argv) {
  const long iters = argc > 1 ? std::strtol(argv[1], nullptr, 10) : 300000;
  std::mt19937_64 rng(0x5E6E11EDull ^ 0x9E3779B97F4A7C15ull);
  // A seed shaped like the harness's input format: 3 cuts, then Ethernet+IPv4+UDP-ish bytes.
  const std::vector<std::uint8_t> seed = {
      3, 7, 20, 41,
      2,0,0,0,0,2, 2,0,0,0,0,1, 0x08,0x00,
      0x45,0,0,0x1c,0,1,0,0,64,17,0,0, 10,0,0,1, 10,0,0,2, 0,53,4,0xd2,0,8,0,0};

  std::vector<std::uint8_t> p;
  for (long i = 0; i < iters; ++i) {
    if (i % 2 == 0) {  // pure random bytes
      p.resize(rng() % 96);
      for (auto& x : p) x = std::uint8_t(rng());
    } else {  // seed with a few bytes flipped and a random-length tail
      p = seed;
      for (int k = 0, n = int(rng() % 5); k < n; ++k) p[rng() % p.size()] ^= std::uint8_t(rng());
      p.resize(p.size() + rng() % 24);
    }
    LLVMFuzzerTestOneInput(p.data(), p.size());
  }
  std::printf("fuzz_segmented standalone: %ld cases, no divergence\n", iters);
  return 0;
}
#endif
