// nanom/dyn.hpp: the type-erased nm::dyn<T> handle and the runtime-length combinators
// (alt/seq/seq_fold over ranges, length_fold, dispatch, recursive). Every combinator is
// checked for success values, error/Failure/Incomplete propagation, empty ranges, streaming
// mode, copy semantics (shared, non-atomic refcount) and lifetime (no leak, no double free:
// run under ASan/LSan to make the last two bite).
#include <nanom/nanom.hpp>

#include <array>
#include <cstdio>
#include <map>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace nm = nanom;

static int failures = 0;
#define CHECK(cond)                                                \
  do {                                                             \
    if (!(cond)) {                                                 \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      ++failures;                                                  \
    }                                                              \
  } while (0)

// literals may embed NULs: keep their full length
template <std::size_t N> static nm::input in(const char (&s)[N]) { return nm::from(std::string_view(s, N - 1)); }
template <std::size_t N> static nm::input sin(const char (&s)[N]) { return nm::streaming(in(s)); }
template <class R> static std::size_t off(const R& r) { return r.error().offset; }

// A stateful parser that counts its live copies: proves nodes are shared, not copied, and
// destroyed exactly once.
static int live_counters = 0;
struct counted {
  int id = 0;
  explicit counted(int i) : id(i) { ++live_counters; }
  counted(const counted& o) : id(o.id) { ++live_counters; }
  counted(counted&& o) noexcept : id(o.id) { ++live_counters; }
  ~counted() { --live_counters; }
  nm::result<int> operator()(nm::input i) const {
    auto r = nm::u8(i);
    if (!r) return nm::unexp(r.error());
    return nm::done{int(r->value) + id, r->rest};
  }
};

// ---------------------------------------------------------------------------
static void test_dyn_basics() {
  static_assert(nm::Parser<nm::dyn<int>>);
  static_assert(sizeof(nm::dyn<int>) == 2 * sizeof(void*));
  static_assert(std::is_same_v<nm::dyn_parser<int>, nm::dyn<int>>);
  // lossless conversions only: widening is implicit, narrowing is not offered
  static_assert(std::is_convertible_v<decltype(nm::be_u16), nm::dyn<std::uint64_t>>);
  static_assert(!std::is_convertible_v<decltype(nm::be_u64), nm::dyn<std::uint8_t>>);

  // stateless parsers need no node
  nm::dyn<std::uint64_t> w = nm::be_u16;
  CHECK(w.use_count() == 0);
  auto r = w(in("\x01\x02rest"));
  CHECK(r && r->value == 0x0102u && r->rest.size() == 4);

  // stateful parsers: one shared node, copies bump a counter, calls never do
  {
    nm::dyn<std::uint64_t> m = nm::map(nm::u8, [k = 3u](std::uint8_t b) { return b * k; });
    CHECK(m.use_count() == 1);
    nm::dyn<std::uint64_t> c = m;
    CHECK(m.use_count() == 2 && c.use_count() == 2);
    for (int i = 0; i < 3; ++i) CHECK(c(in("\x05"))->value == 15u);
    CHECK(m.use_count() == 2);
    nm::dyn<std::uint64_t> mv = std::move(c);
    CHECK(mv.use_count() == 2 && c.use_count() == 0);  // NOLINT(bugprone-use-after-move)
    c = mv;
    CHECK(mv.use_count() == 3);
  }

  // errors propagate unchanged through the erased call
  auto e = w(in("\x01"));
  CHECK(!e && e.error().kind == nm::errk::err && off(e) == 1);  // ran out: at the end
  auto inc = w(sin("\x01"));
  CHECK(!inc && inc.error().kind == nm::errk::incomplete && inc.error().needed == 1);
  nm::dyn<std::string_view> cutp = nm::preceded(nm::tag("a"), nm::cut(nm::alpha1));
  auto f = cutp(in("a1"));
  CHECK(!f && f.error().kind == nm::errk::fail && off(f) == 1);

  // empty handle: false, and calling it is a recoverable error, not a crash
  nm::dyn<int> empty;
  CHECK(!empty);
  CHECK(w);
  auto er = empty(in("x"));
  CHECK(!er && er.error().kind == nm::errk::err);

  // dyn inside static combinators, and static combinators inside dyn
  nm::dyn<char> digit = nm::satisfy([](std::uint8_t b) { return b >= '0' && b <= '9'; });
  auto many = nm::many1(digit)(in("123x"));
  CHECK(many && many->value.size() == 3 && many->rest.size() == 1);
  nm::dyn<std::vector<char>> dm = nm::many1(digit);
  CHECK(dm(in("45"))->value.size() == 2);

  // dyn<T> from dyn<U> (wrapping) and non-trivial value types
  nm::dyn<std::uint32_t> narrow = nm::be_u16;
  nm::dyn<std::uint64_t> wide = narrow;
  CHECK(wide(in("\x00\x07"))->value == 7u);
  nm::dyn<std::string> s = nm::map(nm::alpha1, [](std::string_view v) { return std::string(v) + "!"; });
  CHECK(s(in("abc1"))->value == "abc!");

  // the counted node: shared by copies, destroyed exactly once when the last handle goes
  CHECK(live_counters == 0);
  {
    nm::dyn<int> a = counted(10);
    CHECK(live_counters == 1);
    std::vector<nm::dyn<int>> copies(5, a);
    CHECK(live_counters == 1 && a.use_count() == 6);
    CHECK(copies[3](in("\x01"))->value == 11);
  }
  CHECK(live_counters == 0);

  // lifetime: a grammar built in a scope that has ended keeps working (the root owns it)
  auto make = [] {
    nm::dyn<int> leaf = counted(1);
    std::vector<nm::dyn<int>> kids{leaf, leaf};
    return nm::dyn<int>(nm::seq_fold(kids, [] { return 0; }, [](int& a, int v) { a += v; }));
  };
  {
    nm::dyn<int> g = make();
    CHECK(live_counters == 1);
    auto gr = g(in("\x02\x03"));
    CHECK(gr && gr->value == 7);
  }
  CHECK(live_counters == 0);
}

// ---------------------------------------------------------------------------
static void test_alt_range() {
  std::vector<nm::dyn<nm::bytes>> v{nm::tag("GET"), nm::tag("PUT"), nm::tag("POST")};
  auto a = nm::alt(v);
  auto r = a(in("PUT /"));
  CHECK(r && nm::as_str(r->value) == "PUT" && r->rest.size() == 2);
  CHECK(nm::as_str(a(in("POST"))->value) == "POST");

  // all recoverable failures -> the error that got furthest
  std::vector<nm::dyn<nm::bytes>> w{nm::tag("abc"), nm::preceded(nm::tag("ab"), nm::tag("x")),
                                           nm::tag("q")};
  auto e = nm::alt(w)(in("abz"));
  CHECK(!e && e.error().kind == nm::errk::err && off(e) == 2);

  // first success wins (order matters)
  std::vector<nm::dyn<int>> order{nm::value(1, nm::tag("a")), nm::value(2, nm::tag("ab"))};
  CHECK(nm::alt(order)(in("ab"))->value == 1);

  // Failure (cut) stops the alt even though a later branch would match
  std::vector<nm::dyn<nm::bytes>> c{nm::preceded(nm::tag("a"), nm::cut(nm::tag("1"))), nm::tag("ab")};
  auto cr = nm::alt(c)(in("ab"));
  CHECK(!cr && cr.error().kind == nm::errk::fail && off(cr) == 1);
  // ... also when the failure comes after an earlier recoverable error
  std::vector<nm::dyn<nm::bytes>> c2{nm::tag("zz"), nm::preceded(nm::tag("a"), nm::cut(nm::tag("1"))),
                                            nm::tag("ab")};
  auto cr2 = nm::alt(c2)(in("ab"));
  CHECK(!cr2 && cr2.error().kind == nm::errk::fail && off(cr2) == 1);

  // Incomplete stops it in streaming mode
  auto ir = nm::alt(v)(sin("PO"));
  CHECK(!ir && ir.error().kind == nm::errk::incomplete);

  // empty range: an error at the input
  std::vector<nm::dyn<int>> none;
  auto er = nm::alt(none)(in("xyz"));
  CHECK(!er && er.error().kind == nm::errk::err && off(er) == 0);
  CHECK(std::string_view(er.error().expected) == "one of the alternatives");

  // a range of same-typed STATIC parsers (nom 8's alt([tag("a"), tag("b")]))
  std::array<decltype(nm::tag("x")), 3> st{nm::tag("x"), nm::tag("yy"), nm::tag("z")};
  auto sa = nm::alt(st);
  CHECK(sa(in("yyy"))->rest.size() == 1);
  CHECK(!sa(in("w")));

  // copies share the child list
  auto a2 = a;
  CHECK(a.kids.use_count() == 2);
  nm::dyn<nm::bytes> da = a2;  // converts with one node, no extra hop
  CHECK(nm::as_str(da(in("GET"))->value) == "GET");

  // composes with the variadic alt and with dyn
  auto mixed = nm::alt(nm::alt(v), nm::tag("HEAD"));
  CHECK(nm::as_str(mixed(in("HEAD"))->value) == "HEAD");
}

// ---------------------------------------------------------------------------
static void test_seq_range() {
  std::vector<nm::dyn<std::uint32_t>> v{nm::u8, nm::be_u16, nm::u8};
  auto s = nm::seq(v);
  auto r = s(in("\x01\x00\x02\x03rest"));
  CHECK(r && r->value == (std::vector<std::uint32_t>{1, 2, 3}) && r->rest.size() == 4);

  auto f = nm::seq_fold(v, [] { return 0u; }, [](std::uint32_t& a, std::uint32_t x) { a = a * 10 + x; });
  CHECK(f(in("\x01\x00\x02\x03"))->value == 123u);

  // errors propagate with their kind and offset
  auto e = s(in("\x01\x00"));  // be_u16 runs out: reported at the end of the input
  CHECK(!e && e.error().kind == nm::errk::err && off(e) == 2);
  auto i = s(sin("\x01\x00\x02"));
  CHECK(!i && i.error().kind == nm::errk::incomplete);
  std::vector<nm::dyn<nm::bytes>> c{nm::tag("a"), nm::cut(nm::tag("b"))};
  auto cf = nm::seq(c)(in("ax"));
  CHECK(!cf && cf.error().kind == nm::errk::fail && off(cf) == 1);

  // empty range: empty / init(), nothing consumed
  std::vector<nm::dyn<int>> none;
  auto er = nm::seq(none)(in("ab"));
  CHECK(er && er->value.empty() && er->rest.size() == 2);
  auto ef = nm::seq_fold(none, [] { return 42; }, [](int&, int) {})(in("ab"));
  CHECK(ef && ef->value == 42 && ef->rest.size() == 2);

  // non-trivial element values
  std::vector<nm::dyn<std::string>> words{nm::map(nm::alpha1, [](std::string_view x) { return std::string(x); }),
                                          nm::map(nm::digit1, [](std::string_view x) { return std::string(x); })};
  auto w = nm::seq(words)(in("abc123"));
  CHECK(w && w->value.size() == 2 && w->value[0] == "abc" && w->value[1] == "123");
}

// ---------------------------------------------------------------------------
static void test_length_fold() {
  auto sum = nm::length_fold(nm::u8, nm::u8, [] { return 0u; }, [](unsigned& a, std::uint8_t b) { a += b; });
  auto r = sum(in("\x03\x01\x02\x03rest"));
  CHECK(r && r->value == 6u && r->rest.size() == 4);
  auto z = sum(in("\x00zz"));
  CHECK(z && z->value == 0u && z->rest.size() == 2);

  // init(count) form
  auto withn = nm::length_fold(nm::u8, nm::u8, [](std::size_t n) { return n * 100; },
                               [](std::size_t& a, std::uint8_t b) { a += b; });
  CHECK(withn(in("\x02\x01\x01"))->value == 202u);

  // too few elements: the element's error (complete) / incomplete (streaming)
  auto e = sum(in("\x03\x01"));
  CHECK(!e && e.error().kind == nm::errk::err && off(e) == 2);
  auto i = sum(sin("\x03\x01"));
  CHECK(!i && i.error().kind == nm::errk::incomplete);
  auto k = sum(sin(""));  // count itself missing
  CHECK(!k && k.error().kind == nm::errk::incomplete);

  // a non-consuming element is rejected (and a hostile count cannot spin)
  auto spin = nm::length_fold(nm::be_u64, nm::success(1), [] { return 0; }, [](int& a, int b) { a += b; });
  auto sr = spin(in("\xff\xff\xff\xff\xff\xff\xff\xff"));
  CHECK(!sr && sr.error().kind == nm::errk::err);

  // a dyn element, cut inside
  nm::dyn<std::string_view> el = nm::preceded(nm::tag(","), nm::cut(nm::alpha1));
  auto cnt = nm::length_fold(nm::u8, el, [] { return 0; }, [](int& a, std::string_view) { ++a; });
  CHECK(cnt(in("\x02,a,b"))->value == 2);
  auto cf = cnt(in("\x02,a,1"));
  CHECK(!cf && cf.error().kind == nm::errk::fail && off(cf) == 4);

  // it is a static combinator too (constexpr-composable, no dyn involved)
  static_assert(nm::Parser<decltype(sum)>);
}

// ---------------------------------------------------------------------------
static void test_dispatch() {
  // u8 keys: the 256-slot table
  std::vector<std::pair<std::uint8_t, nm::dyn<std::uint32_t>>> arms{
      {1, nm::u8}, {2, nm::be_u16}, {200, nm::value(7u, nm::success(0))}};
  auto d = nm::dispatch(nm::u8, arms);
  CHECK(d(in("\x01\x09"))->value == 9u);
  CHECK(d(in("\x02\x01\x00"))->value == 256u);
  auto hi = d(in("\xc8rest"));
  CHECK(hi && hi->value == 7u && hi->rest.size() == 4);

  // unknown key: recoverable, at the KEY's offset (so an enclosing alt can backtrack)
  auto u = d(in("zz\x05\x00"));
  CHECK(!u);
  auto u2 = nm::preceded(nm::tag("zz"), d)(in("zz\x05\x00"));
  CHECK(!u2 && u2.error().kind == nm::errk::err && off(u2) == 2);
  CHECK(std::string_view(u2.error().expected) == "a known dispatch key");
  auto bt = nm::alt(d, nm::value(99u, nm::u8))(in("\x05"));
  CHECK(bt && bt->value == 99u);

  // otherwise
  auto dd = nm::dispatch(nm::u8, arms, nm::value(5u, nm::success(0)));
  CHECK(dd(in("\x05"))->value == 5u && dd(in("\x01\x02"))->value == 2u);

  // key and arm errors propagate unchanged
  auto ke = d(sin(""));
  CHECK(!ke && ke.error().kind == nm::errk::incomplete);
  auto ae = d(sin("\x02\x01"));
  CHECK(!ae && ae.error().kind == nm::errk::incomplete);
  std::vector<std::pair<std::uint8_t, nm::dyn<nm::bytes>>> carms{{1, nm::cut(nm::tag("ok"))}};
  auto cf = nm::dispatch(nm::u8, carms)(in("\x01no"));
  CHECK(!cf && cf.error().kind == nm::errk::fail && off(cf) == 1);

  // empty table: every key is unknown
  std::vector<std::pair<std::uint8_t, nm::dyn<int>>> none;
  CHECK(!nm::dispatch(nm::u8, none)(in("\x01")));

  // first arm wins on duplicate keys (all table kinds)
  std::vector<std::pair<std::uint8_t, nm::dyn<int>>> dup{{1, nm::value(1, nm::success(0))},
                                                         {1, nm::value(2, nm::success(0))}};
  CHECK(nm::dispatch(nm::u8, dup)(in("\x01"))->value == 1);

  // braced list (T explicit), std::map arms, signed 1-byte keys
  auto bl = nm::dispatch<int>(nm::i8, {{-1, nm::value(10, nm::success(0))}, {1, nm::value(20, nm::success(0))}});
  CHECK(bl(in("\xff"))->value == 10 && bl(in("\x01"))->value == 20 && !bl(in("\x02")));
  std::map<std::uint8_t, nm::dyn<int>> m{{3, nm::value(3, nm::success(0))}};
  CHECK(nm::dispatch(nm::u8, m)(in("\x03"))->value == 3);

  // wider integral keys: dense (compact) and sorted (sparse) tables
  std::vector<std::pair<std::uint16_t, nm::dyn<int>>> dense{{0x1000, nm::value(1, nm::success(0))},
                                                            {0x1003, nm::value(2, nm::success(0))},
                                                            {0x1003, nm::value(9, nm::success(0))}};
  auto dk = nm::dispatch(nm::be_u16, dense);
  CHECK(dk(in("\x10\x00"))->value == 1 && dk(in("\x10\x03"))->value == 2);
  CHECK(!dk(in("\x10\x01")) && !dk(in("\x0f\xff")) && !dk(in("\x20\x00")));
  std::vector<std::pair<std::uint32_t, nm::dyn<int>>> sparse{{7, nm::value(1, nm::success(0))},
                                                             {0xdeadbeef, nm::value(2, nm::success(0))},
                                                             {1u << 20, nm::value(3, nm::success(0))},
                                                             {7, nm::value(9, nm::success(0))}};
  auto sk = nm::dispatch(nm::be_u32, sparse, nm::value(-1, nm::success(0)));
  CHECK(sk(in("\xde\xad\xbe\xef"))->value == 2 && sk(in("\x00\x10\x00\x00"))->value == 3);
  CHECK(sk(in("\x00\x00\x00\x07"))->value == 1 && sk(in("\x00\x00\x00\x08"))->value == -1);

  // string keys (sorted table, heterogeneous lookup: std::string arms, string_view keys)
  std::vector<std::pair<std::string, nm::dyn<int>>> words{
      {"get", nm::value(1, nm::success(0))}, {"put", nm::value(2, nm::success(0))},
      {"del", nm::preceded(nm::chr(' '), nm::map(nm::digit1, [](std::string_view s) { return int(s.size()); }))}};
  auto wk = nm::dispatch(nm::alpha1, words);
  CHECK(wk(in("put"))->value == 2 && wk(in("del 123"))->value == 3);
  auto wu = wk(in("patch"));
  CHECK(!wu && off(wu) == 0);

  // copies share the table
  auto d2 = d;
  CHECK(d.table.use_count() == 2);
  nm::dyn<std::uint32_t> dyn_d = d2;
  CHECK(dyn_d(in("\x01\x04"))->value == 4u);
}

// ---------------------------------------------------------------------------
static void test_map_and_thin() {
  nm::dyn<int> one = nm::value(1, nm::tag("a"));
  auto m = nm::map(one, [](int v) { return v + 1; });
  static_assert(nm::detail::thin_parser<decltype(m), int>);  // the dyn-aware overload was picked
  CHECK(m(in("a"))->value == 2);
  auto me = m(in("b"));
  CHECK(!me && off(me) == 0);
  // map over the plain static parsers is still nom.hpp's map
  auto sm = nm::map(nm::u8, [](std::uint8_t v) { return v + 1; });
  static_assert(!nm::detail::thin_parser<decltype(sm), int>);
}

// ---------------------------------------------------------------------------
static void test_recursive() {
  // depth of nested parens around a digit: "((7))" -> 2
  CHECK(live_counters == 0);
  {
    nm::dyn<int> depth = nm::recursive<int>([](nm::dyn<int> self) {
      std::vector<nm::dyn<int>> branches{
          nm::map(nm::delimited(nm::chr('('), self, nm::chr(')')), [](int d) { return d + 1; }),
          nm::value(0, nm::satisfy([](std::uint8_t b) { return b >= '0' && b <= '9'; })),
          nm::preceded(nm::tag("#"), counted(1000))};  // stateful node in the cycle: freed with it
      return nm::alt(branches);
    });
    CHECK(live_counters == 1);
    CHECK(depth(in("7"))->value == 0);
    CHECK(depth(in("(((7)))"))->value == 3);
    auto bad = depth(in("((7)"));
    CHECK(!bad);
    nm::dyn<int> copy = depth;  // copies keep it alive
    depth = nm::dyn<int>();
    CHECK(copy(in("(7)"))->value == 1);
  }
  CHECK(live_counters == 0);  // no refcount cycle: everything was released
}

// ---------------------------------------------------------------------------
static void test_concurrent_calls() {
  // calling is const and refcount-free: one grammar, many threads
  std::vector<nm::dyn<std::uint64_t>> kids{nm::u8, nm::be_u16};
  nm::dyn<std::uint64_t> g = nm::seq_fold(kids, [] { return std::uint64_t(0); },
                                          [](std::uint64_t& a, std::uint64_t v) { a += v; });
  const std::string_view data("\x01\x00\x02", 3);
  std::vector<std::thread> ts;
  std::array<std::uint64_t, 4> sums{};
  for (std::size_t t = 0; t < sums.size(); ++t)
    ts.emplace_back([&, t] {
      for (int i = 0; i < 10000; ++i) sums[t] += g(nm::from(data))->value;
    });
  for (auto& t : ts) t.join();
  for (auto s : sums) CHECK(s == 30000u);
  CHECK(g.use_count() == 1);
}

static void test_returning_folds() {
  std::vector<nm::dyn<std::uint64_t>> ps;
  ps.push_back(nm::map(nm::u8, [](std::uint8_t b) { return std::uint64_t(b); }));
  ps.push_back(nm::map(nm::be_u16, [](std::uint16_t v) { return std::uint64_t(v); }));
  auto sf = nm::seq_fold(ps, [] { return std::uint64_t{0}; },
                         [](std::uint64_t acc, std::uint64_t v) { return acc + v; });
  const std::string_view d1("\x05\x00\x0a", 3);
  auto r1 = sf(nm::from(d1));
  CHECK(r1 && r1->value == 15u);

  auto lf = nm::length_fold(nm::u8, nm::u8, [] { return 0; },
                            [](int acc, std::uint8_t v) { return acc + int(v); });
  const std::string_view d2("\x03\x01\x02\x03", 4);
  auto r2 = lf(nm::from(d2));
  CHECK(r2 && r2->value == 6);
}

int main() {
  test_dyn_basics();
  test_alt_range();
  test_seq_range();
  test_length_fold();
  test_dispatch();
  test_map_and_thin();
  test_recursive();
  test_concurrent_calls();
  test_returning_folds();
  if (failures == 0) std::printf("PASS: nanom dyn / runtime-composition tests\n");
  return failures == 0 ? 0 : 1;
}
