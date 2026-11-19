// Runtime-composed parser benchmark: the message layout is NOT known at build time. It is
// read from a spec string at run time and assembled from nanom combinators into an
// nm::dyn<> tree (nanom's analogue of Rust's Rc<dyn Fn>). Counterparts with identical
// output: bench/runtime_compose_static.cpp (same layout composed at compile time) and
// bench/rust_nom/src/runtime_compose.rs (Rust nom 8). See docs/RUNTIME_COMPOSE.md.
//
//   spec  := node
//   node  := u8 | u16be | u32le | u64be | str8          fixed-width ints, u8-length string
//          | lit(N)                                     the byte N
//          | seq(node, ...)                             all, in order
//          | alt(node, ...)                             first that parses
//          | rep(node)                                  u8 count, then that many nodes
//          | tag(N:node, ...)                           u8 tag selects the payload
//
// Every node yields a 64-bit hash of what it parsed (a FNV-style mix), so the three
// implementations can be checked for identical output.
//
// usage: nm_runtime_compose_bench <spec.txt> <data.bin> [reps]
//        (data from bench/runtime_compose_gen.py <spec.txt> <data.bin> <messages>)
#include <nanom/dyn.hpp>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace nm = nanom;
using H = std::uint64_t;

constexpr H mix(H h, H x) { return (h ^ x) * 1099511628211ull; }
constexpr auto hash_bytes = [](nm::bytes b) {
  H h = mix(0xcbf29ce484222325ull, b.size());
  for (auto c : b) h = mix(h, H(c));
  return h;
};
constexpr auto mix_into = [](H& acc, H v) { acc = mix(acc, v); };

// The spec reader: a hand-written recursive-descent parser for the spec text that returns
// the message parser it describes.
struct spec_reader {
  std::string s;
  std::size_t pos = 0;

  std::string name() {
    const std::size_t b = pos;
    while (pos < s.size() && std::isalnum(static_cast<unsigned char>(s[pos]))) ++pos;
    return s.substr(b, pos - b);
  }
  unsigned number() { return static_cast<unsigned>(std::stoul(name())); }
  void eat(char c) {
    if (pos >= s.size() || s[pos] != c) throw std::runtime_error(std::string("spec: expected ") + c);
    ++pos;
  }
  bool more() { return pos < s.size() && s[pos] == ',' && (++pos, true); }

  std::vector<nm::dyn<H>> list() {  // node, node, ... ')'
    std::vector<nm::dyn<H>> kids{node()};
    while (more()) kids.push_back(node());
    eat(')');
    return kids;
  }

  nm::dyn<H> node() {
    const std::string n = name();
    if (n == "u8")    return nm::u8;      // widened to H on the way out; stateless: no allocation
    if (n == "u16be") return nm::be_u16;
    if (n == "u32le") return nm::le_u32;
    if (n == "u64be") return nm::be_u64;
    if (n == "str8")  return nm::map(nm::length_data(nm::u8), hash_bytes);
    eat('(');
    if (n == "lit") {
      const auto v = static_cast<std::uint8_t>(number());
      eat(')');
      return nm::verify(nm::u8, [v](std::uint8_t b) { return b == v; });
    }
    if (n == "seq")  // a runtime-length sequence, folded
      return nm::seq_fold(list(), [] { return H(0x5e9); }, mix_into);
    if (n == "rep") {  // u8 count, then that many repetitions, folded
      nm::dyn<H> item = node();
      eat(')');
      return nm::length_fold(nm::u8, item, [](std::size_t c) { return mix(0x52e9, c); }, mix_into);
    }
    if (n == "alt") {  // a runtime-length alt; the branch index goes into the hash
      auto kids = list();
      for (std::size_t i = 0; i < kids.size(); ++i)
        kids[i] = nm::map(kids[i], [i](H v) { return mix(i, v); });
      return nm::alt(kids);
    }
    if (n == "tag") {  // tag byte -> payload parser (256-slot table); the tag goes into the hash
      std::vector<std::pair<std::uint8_t, nm::dyn<H>>> arms;
      do {
        const auto t = static_cast<std::uint8_t>(number());
        eat(':');
        arms.emplace_back(t, nm::map(node(), [t](H v) { return mix(t, v); }));
      } while (more());
      eat(')');
      return nm::dispatch(nm::u8, arms);
    }
    throw std::runtime_error("spec: unknown node " + n);
  }
};

int main(int argc, char** argv) {
  if (argc < 3) { std::fprintf(stderr, "usage: %s <spec.txt> <data.bin> [reps]\n", argv[0]); return 2; }
  std::ifstream sf(argv[1]);
  std::string spec((std::istreambuf_iterator<char>(sf)), {});
  while (!spec.empty() && std::isspace(static_cast<unsigned char>(spec.back()))) spec.pop_back();
  std::ifstream df(argv[2], std::ios::binary);
  const std::vector<char> data((std::istreambuf_iterator<char>(df)), {});
  const int reps = argc > 3 ? std::atoi(argv[3]) : 7;

  const nm::dyn<H> msg = spec_reader{spec}.node();

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
  std::printf("nanom dyn     msgs=%zu hash=%016llx  %.1f ns/msg\n", n,
              static_cast<unsigned long long>(total), n ? best * 1e9 / double(n) : 0.0);
}
