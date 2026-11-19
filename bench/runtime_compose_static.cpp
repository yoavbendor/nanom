// The layout of bench/runtime_compose_bench.cpp, composed STATICALLY (known at build time):
// the same spec, written out by hand as one nanom combinator expression, with no type erasure
// anywhere. It produces the same hash; the gap to the dyn version is the price of deciding the
// layout at run time. See docs/RUNTIME_COMPOSE.md.
//
//   tag(1:seq(u8,u16be,str8,rep(seq(u32le,u8))),
//       2:seq(u64be,str8),
//       7:rep(rep(u16be)),
//       9:alt(seq(lit(170),u32le),seq(lit(187),str8),seq(lit(204),u16be)))
//
// usage: nm_runtime_compose_static <spec.txt (ignored; must be the one above)> <data.bin> [reps]
#include <nanom/dyn.hpp>  // length_fold (a plain static combinator; no dyn is used here)

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <tuple>
#include <vector>

namespace nm = nanom;
using H = std::uint64_t;

constexpr H mix(H h, H x) { return (h ^ x) * 1099511628211ull; }
constexpr auto mix_into = [](H& acc, H v) { acc = mix(acc, v); };

template <class P> constexpr auto W(P p) { return nm::map(p, [](auto v) { return H(v); }); }
constexpr auto str8 = nm::map(nm::length_data(nm::u8), [](nm::bytes b) {
  H h = mix(0xcbf29ce484222325ull, b.size());
  for (auto c : b) h = mix(h, H(c));
  return h;
});
template <class... P> constexpr auto SEQ(P... p) {
  return nm::map(nm::seq(p...), [](auto t) {
    return std::apply([](auto... v) { H h = 0x5e9; ((h = mix(h, H(v))), ...); return h; }, t);
  });
}
template <class P> constexpr auto REP(P p) {
  return nm::length_fold(nm::u8, p, [](std::size_t c) { return mix(0x52e9, c); }, mix_into);
}
constexpr auto LIT(std::uint8_t v) { return W(nm::verify(nm::u8, [v](std::uint8_t b) { return b == v; })); }
template <class P> constexpr auto IDX(H i, P p) { return nm::map(p, [i](H v) { return mix(i, v); }); }

const auto b1 = SEQ(W(nm::u8), W(nm::be_u16), str8, REP(SEQ(W(nm::le_u32), W(nm::u8))));
const auto b2 = SEQ(W(nm::be_u64), str8);
const auto b7 = REP(REP(W(nm::be_u16)));
const auto b9 = nm::alt(IDX(0, SEQ(LIT(170), W(nm::le_u32))), IDX(1, SEQ(LIT(187), str8)),
                        IDX(2, SEQ(LIT(204), W(nm::be_u16))));
const auto msg = [](nm::input in) -> nm::result<H> {
  auto t = nm::u8(in);
  if (!t) return nm::unexp(t.error());
  nm::result<H> r = nm::make_err(in, "a known dispatch key");
  switch (t->value) {
    case 1: r = b1(t->rest); break;
    case 2: r = b2(t->rest); break;
    case 7: r = b7(t->rest); break;
    case 9: r = b9(t->rest); break;
    default: return r;
  }
  if (!r) return r;
  return nm::done{mix(t->value, r->value), r->rest};
};

int main(int argc, char** argv) {
  if (argc < 3) { std::fprintf(stderr, "usage: %s <spec.txt> <data.bin> [reps]\n", argv[0]); return 2; }
  std::ifstream df(argv[2], std::ios::binary);
  const std::vector<char> data((std::istreambuf_iterator<char>(df)), {});
  const int reps = argc > 3 ? std::atoi(argv[3]) : 7;
  double best = 1e9;
  H total = 0;
  std::size_t n = 0;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = std::chrono::steady_clock::now();
    const nm::input whole = nm::from(std::string_view(data.data(), data.size()));
    nm::input in = whole;
    total = 0x811c;
    n = 0;
    while (!in.empty()) {
      auto r = msg(in);
      if (!r) { std::puts(r.error().render(whole).c_str()); return 1; }
      total = mix(total, r->value);
      in = r->rest;
      ++n;
    }
    best = std::min(best, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
  }
  std::printf("nanom static  msgs=%zu hash=%016llx  %.1f ns/msg\n", n,
              static_cast<unsigned long long>(total), n ? best * 1e9 / double(n) : 0.0);
}
