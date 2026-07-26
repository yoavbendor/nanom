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

#include "../examples/nanotins_parity/nm_protocols.hpp"

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
