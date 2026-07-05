// Parity audit vs Rust nom 8.0.0's own test suite (tests/*.rs, cached locally from
// bench/rust_nom's Cargo.lock). Each test below is an original C++ port of the *behavior*
// exercised by one of nom's real test files -- not a copy of nom's source -- built and run to
// verify nanom's combinators are functionally equivalent, not just similarly named. See
// docs/NOM_PARITY_AUDIT.md for the full writeup and the genuine divergences this surfaced.
#include <nanom/nanom.hpp>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace nm = nanom;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

// =====================================================================================
// mp4.rs: alt() + map() into a shared enum -- nom's OWN canonical "which tag matched"
// dispatch idiom (nom.hpp's alt() requires one common return type across branches,
// exactly like Rust's own alt -- this is not a nanom-specific constraint).
// =====================================================================================
namespace mp4_parity {

enum class MP4BoxType { Ftyp, Moov, Mdat, Free, Skip, Wide, Unknown };

nm::result<MP4BoxType> box_type(nm::input i) {
  return nm::alt(
      nm::map(nm::tag("ftyp"), [](auto) { return MP4BoxType::Ftyp; }),
      nm::map(nm::tag("moov"), [](auto) { return MP4BoxType::Moov; }),
      nm::map(nm::tag("mdat"), [](auto) { return MP4BoxType::Mdat; }),
      nm::map(nm::tag("free"), [](auto) { return MP4BoxType::Free; }),
      nm::map(nm::tag("skip"), [](auto) { return MP4BoxType::Skip; }),
      nm::map(nm::tag("wide"), [](auto) { return MP4BoxType::Wide; }),
      nm::map(nm::rest, [](auto) { return MP4BoxType::Unknown; }))(i);
}

struct MP4BoxHeader { std::uint32_t length; MP4BoxType tag; };

nm::result<MP4BoxHeader> box_header(nm::input i) {
  auto len = nm::be_u32(i);
  if (!len) return nm::unexp(len.error());
  auto t = box_type(len->rest);
  if (!t) return nm::unexp(t.error());
  return nm::done{MP4BoxHeader{len->value, t->value}, t->rest};
}

void run() {
  const std::uint8_t data[] = {0, 0, 0, 16, 'f', 't', 'y', 'p', 'X', 'X', 'X', 'X'};
  auto r = box_header(nm::from(data, sizeof data));
  CHECK(r && r->value.length == 16 && r->value.tag == MP4BoxType::Ftyp && r->rest.size() == 4);

  const std::uint8_t unk[] = {0, 0, 0, 8, 'z', 'z', 'z', 'z'};
  auto r2 = box_header(nm::from(unk, sizeof unk));
  CHECK(r2 && r2->value.tag == MP4BoxType::Unknown);
}

}  // namespace mp4_parity

// =====================================================================================
// json.rs: alt()+map() dispatching into a RECURSIVE tagged union. C++17's incomplete-type
// support for std::vector<T> lets a std::variant hold a std::vector<JsonValue> directly
// inside JsonValue itself -- the same "no manual Box wrapper needed" property Rust gets
// from Vec<T> being automatically indirect.
// =====================================================================================
namespace json_parity {

struct JsonValue;
using JsonArray = std::vector<JsonValue>;
struct JsonValue { std::variant<std::monostate, bool, double, std::string, JsonArray> v; };

JsonValue Bool(bool b) { return JsonValue{b}; }
JsonValue Num(double d) { return JsonValue{d}; }
JsonValue Str(std::string s) { return JsonValue{std::move(s)}; }
JsonValue Array(JsonArray a) { return JsonValue{std::move(a)}; }

nm::result<bool> boolean(nm::input i) {
  return nm::alt(nm::value(false, nm::tag("false")), nm::value(true, nm::tag("true")))(i);
}
nm::result<std::string> json_string(nm::input i) {
  return nm::map(nm::delimited(nm::chr('"'), nm::take_while([](std::uint8_t c) { return c != 0x22; }),
                                nm::chr('"')),
                 [](nm::bytes b) { return std::string(reinterpret_cast<const char*>(b.data()), b.size()); })(i);
}
nm::result<JsonValue> json_value(nm::input i);
nm::result<JsonArray> json_array(nm::input i) {
  return nm::delimited(nm::chr('['), nm::separated_list0(nm::chr(','), json_value), nm::chr(']'))(i);
}
// Compare against nom's json.rs:129-137 `alt((value(Null,...), map(boolean,Bool), map(string,Str),
// map(double,Num), map(array,Array), ...))` -- once each variant has a named constructor function
// (the C++ analog of a Rust tuple-variant constructor being a first-class function value), the
// call sites are token-for-token as terse as nom's own.
nm::result<JsonValue> json_value(nm::input i) {
  return nm::alt(
      nm::map(nm::value(nullptr, nm::tag("null")), [](auto) { return JsonValue{}; }),
      nm::map(boolean, Bool),
      nm::map(json_string, Str),
      nm::map(nm::double_, Num),
      nm::map(json_array, Array))(i);
}

void run() {
  auto r = json_value(nm::from(std::string_view(R"([1,"a",true])")));
  CHECK(r && r->rest.empty());
  if (!r) return;
  auto& arr = std::get<JsonArray>(r->value.v);
  CHECK(arr.size() == 3);
  if (arr.size() == 3) {
    CHECK(std::get<double>(arr[0].v) == 1.0);
    CHECK(std::get<std::string>(arr[1].v) == "a");
    CHECK(std::get<bool>(arr[2].v) == true);
  }
}

}  // namespace json_parity

// =====================================================================================
// fnmut.rs: a parser mutating EXTERNAL state on each invocation (Rust's FnMut closure
// capturing by mutable reference). nanom's Parser concept requires const-P&-invocable;
// a reference-capturing (non-`mutable`) lambda satisfies this while still mutating the
// referenced external variable -- the correct C++ analog of Rust's FnMut.
// =====================================================================================
namespace fnmut_parity {

void run() {
  int counter = 0;
  auto parser = nm::many0(nm::map(nm::tag("abc"), [&counter](nm::bytes s) {
    ++counter;
    return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
  }));
  static_assert(nm::Parser<decltype(parser)>);

  auto r = parser(nm::from(std::string_view("abcabcabcabc")));
  CHECK(r && r->value.size() == 4);
  CHECK(counter == 4);
}

}  // namespace fnmut_parity

// =====================================================================================
// overflow.rs: adversarial huge-length safety. nom's own expected result for
// many0(length_data(be_u64)) on a truncated 2nd item is Err(Incomplete(Needed::new(u64::MAX)))
// -- streaming many0 must PROPAGATE an inner Incomplete (not silently stop with partial
// results), since more data might still complete it. Verified under ASan+UBSan.
// =====================================================================================
namespace overflow_parity {

void run() {
  const std::uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 1, 0xaa,
                                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  auto r = nm::many0(nm::length_data(nm::be_u64))(nm::streaming(nm::from(data, sizeof data)));
  CHECK(!r);
  CHECK(!r && r.error().kind == nm::errk::incomplete);
}

}  // namespace overflow_parity

// =====================================================================================
// arithmetic.rs: factor/term/expr/parens recursive-descent grammar via fold_many0.
// GENUINE FINDING: nanom's fold_many0/fold_many1 mutate the accumulator BY REFERENCE
// (`f(acc&, value)`, return value discarded) -- unlike Rust's `multi::fold`, whose
// fold_fn is FUNCTIONAL (`FnMut(Acc, O) -> Acc`). A naive Rust-style return-based lambda
// silently produces a stuck accumulator (nanom discards the return value). Confirmed
// undocumented in docs/CHEATSHEET.md at the time of this audit.
// =====================================================================================
namespace arithmetic_parity {

nm::result<std::int64_t> expr(nm::input i);

nm::result<std::int64_t> parens(nm::input i) {
  return nm::delimited(nm::space0, nm::delimited(nm::tag("("), expr, nm::tag(")")), nm::space0)(i);
}

nm::result<std::int64_t> factor(nm::input i) {
  return nm::alt(
      nm::map(nm::delimited(nm::space0, nm::digit1, nm::space0),
              [](std::string_view b) { return std::int64_t(std::strtoll(b.data(), nullptr, 10)); }),
      parens)(i);
}

nm::result<std::int64_t> term(nm::input i) {
  auto f = factor(i);
  if (!f) return nm::unexp(f.error());
  return nm::fold_many0(
      nm::pair(nm::alt(nm::chr('*'), nm::chr('/')), factor),
      [v = f->value] { return v; },
      [](std::int64_t& acc, auto pr) {  // mutate-by-reference; return value is discarded
        acc = (pr.first == '*') ? acc * pr.second : acc / pr.second;
      })(f->rest);
}

nm::result<std::int64_t> expr(nm::input i) {
  auto t = term(i);
  if (!t) return nm::unexp(t.error());
  return nm::fold_many0(
      nm::pair(nm::alt(nm::chr('+'), nm::chr('-')), term),
      [v = t->value] { return v; },
      [](std::int64_t& acc, auto pr) {
        acc = (pr.first == '+') ? acc + pr.second : acc - pr.second;
      })(t->rest);
}

static std::int64_t eval(std::string_view s) {
  auto r = expr(nm::from(s));
  CHECK(r && r->rest.empty());
  return r ? r->value : 0;
}

void run() {
  CHECK(eval("3") == 3);
  CHECK(eval(" 12") == 12);
  CHECK(eval("537  ") == 537);
  CHECK(eval("  24   ") == 24);
  CHECK(eval(" 12 *2 /  3") == 8);
  CHECK(eval(" 2* 3  *2 *2 /  3") == 8);
  CHECK(eval(" 48 /  3/2") == 8);
  CHECK(eval(" 1 +  2 ") == 3);
  CHECK(eval(" 12 + 6 - 4+  3") == 17);
  CHECK(eval(" 1 + 2*3 + 4") == 11);
  CHECK(eval(" (  2 )") == 2);
  CHECK(eval(" 2* (  3 + 4 ) ") == 14);
  CHECK(eval("  2*2 / ( 5 - 1) + 3") == 4);
}

}  // namespace arithmetic_parity

// =====================================================================================
// arithmetic_ast.rs: explicit single-value recursion via std::unique_ptr<Expr> -- the
// direct C++ analog of Rust's Box<Expr> (unlike json.rs's implicit container-based
// recursion via std::vector).
// =====================================================================================
namespace arith_ast_parity {

struct Expr;
using ExprPtr = std::unique_ptr<Expr>;
struct Expr {
  enum class Kind { Value, Add, Sub, Mul, Div } kind;
  std::int64_t value = 0;
  ExprPtr lhs, rhs;
  static ExprPtr val(std::int64_t v) {
    auto e = std::make_unique<Expr>();
    e->kind = Kind::Value;
    e->value = v;
    return e;
  }
  static ExprPtr bin(Kind k, ExprPtr l, ExprPtr r) {
    auto e = std::make_unique<Expr>();
    e->kind = k;
    e->lhs = std::move(l);
    e->rhs = std::move(r);
    return e;
  }
};

std::int64_t eval(const Expr& e) {
  switch (e.kind) {
    case Expr::Kind::Value: return e.value;
    case Expr::Kind::Add: return eval(*e.lhs) + eval(*e.rhs);
    case Expr::Kind::Sub: return eval(*e.lhs) - eval(*e.rhs);
    case Expr::Kind::Mul: return eval(*e.lhs) * eval(*e.rhs);
    case Expr::Kind::Div: return eval(*e.lhs) / eval(*e.rhs);
  }
  __builtin_unreachable();
}

nm::result<ExprPtr> ast_expr(nm::input i);

nm::result<ExprPtr> ast_factor(nm::input i) {
  return nm::alt(
      nm::map(nm::delimited(nm::multispace0, nm::digit1, nm::multispace0),
              [](std::string_view b) { return Expr::val(std::int64_t(std::strtoll(b.data(), nullptr, 10))); }),
      nm::delimited(nm::multispace0, nm::delimited(nm::tag("("), ast_expr, nm::tag(")")), nm::multispace0))(i);
}

nm::result<ExprPtr> ast_term(nm::input i) {
  auto f = ast_factor(i);
  if (!f) return nm::unexp(f.error());
  return nm::fold_many0(
      nm::pair(nm::alt(nm::chr('*'), nm::chr('/')), ast_factor),
      [&f] { return std::move(f->value); },
      [](ExprPtr& acc, auto pr) {
        auto k = (pr.first == '*') ? Expr::Kind::Mul : Expr::Kind::Div;
        acc = Expr::bin(k, std::move(acc), std::move(pr.second));
      })(f->rest);
}

nm::result<ExprPtr> ast_expr(nm::input i) {
  auto t = ast_term(i);
  if (!t) return nm::unexp(t.error());
  return nm::fold_many0(
      nm::pair(nm::alt(nm::chr('+'), nm::chr('-')), ast_term),
      [&t] { return std::move(t->value); },
      [](ExprPtr& acc, auto pr) {
        auto k = (pr.first == '+') ? Expr::Kind::Add : Expr::Kind::Sub;
        acc = Expr::bin(k, std::move(acc), std::move(pr.second));
      })(t->rest);
}

void run() {
  auto r = ast_expr(nm::from(std::string_view("1 + 2 * 3")));
  CHECK(r && r->rest.empty());
  if (r) {
    CHECK(r->value->kind == Expr::Kind::Add);
    CHECK(r->value->rhs->kind == Expr::Kind::Mul);
    CHECK(eval(*r->value) == 7);
  }

  auto r2 = ast_expr(nm::from(std::string_view("(1 + 2) * 3")));
  CHECK(r2 && eval(*r2->value) == 9);
}

}  // namespace arith_ast_parity

// =====================================================================================
// css.rs: hex-color parsing via take_while_m_n + map_opt (nanom's map_res is an alias of
// map_opt, since C++ has no std::Result -- functionally identical to nom's map_res).
// =====================================================================================
namespace css_parity {

struct Color { std::uint8_t red, green, blue; };

nm::result<std::uint8_t> hex_primary(nm::input i) {
  return nm::map_opt(
      nm::take_while_m_n(2, 2, [](std::uint8_t c) { return std::isxdigit(c) != 0; }),
      [](nm::bytes b) -> std::optional<std::uint8_t> {
        char buf[3] = {char(b[0]), char(b[1]), 0};
        char* end = nullptr;
        long v = std::strtol(buf, &end, 16);
        if (end != buf + 2) return std::nullopt;
        return std::uint8_t(v);
      })(i);
}

nm::result<Color> hex_color(nm::input i) {
  auto tag_r = nm::tag("#")(i);
  if (!tag_r) return nm::unexp(tag_r.error());
  auto r = hex_primary(tag_r->rest);
  if (!r) return nm::unexp(r.error());
  auto g = hex_primary(r->rest);
  if (!g) return nm::unexp(g.error());
  auto b = hex_primary(g->rest);
  if (!b) return nm::unexp(b.error());
  return nm::done{Color{r->value, g->value, b->value}, b->rest};
}

void run() {
  auto r = hex_color(nm::from(std::string_view("#2F14DF")));
  CHECK(r && r->rest.empty());
  CHECK(r && r->value.red == 47 && r->value.green == 20 && r->value.blue == 223);
}

}  // namespace css_parity

// =====================================================================================
// float.rs: binary IEEE-754 reads (be_f32/le_f32/be_f64/le_f64) against fixed hex-byte
// fixtures for 12.5, plus nanom's own text-float parser (double_).
// =====================================================================================
namespace float_parity {

void run() {
  const std::uint8_t be32[] = {0x41, 0x48, 0x00, 0x00};
  auto r1 = nm::be_f32(nm::from(be32, 4));
  CHECK(r1 && r1->rest.empty() && r1->value == 12.5f);

  const std::uint8_t le32[] = {0x00, 0x00, 0x48, 0x41};
  auto r2 = nm::le_f32(nm::from(le32, 4));
  CHECK(r2 && r2->rest.empty() && r2->value == 12.5f);

  const std::uint8_t be64[] = {0x40, 0x29, 0, 0, 0, 0, 0, 0};
  auto r3 = nm::be_f64(nm::from(be64, 8));
  CHECK(r3 && r3->rest.empty() && r3->value == 12.5);

  const std::uint8_t le64[] = {0, 0, 0, 0, 0, 0, 0x29, 0x40};
  auto r4 = nm::le_f64(nm::from(le64, 8));
  CHECK(r4 && r4->rest.empty() && r4->value == 12.5);

  // Truncated input -> a clean error in complete/non-streaming mode, matching nom's own test
  // (Err(Err::Error(_)) for a 3-byte input fed to a fixed 8-byte f64 reader).
  const std::uint8_t incomplete[] = {'a', 'b', 'c'};
  auto r5 = nm::be_f64(nm::from(incomplete, 3));
  CHECK(!r5);

  auto r6 = nm::double_(nm::from(std::string_view("-2.5e2rest")));
  CHECK(r6 && r6->value == -250.0 && r6->rest.size() == 4);
}

}  // namespace float_parity

// =====================================================================================
// ini.rs: structured [section]/key=value config grammar (own fixtures, not nom's exact
// test data) via take_while/separated_pair/fold_many0/delimited.
// =====================================================================================
namespace ini_parity {

using KeyValues = std::map<std::string, std::string>;
using Sections = std::map<std::string, KeyValues>;

nm::result<std::string> section_name(nm::input i) {
  return nm::map(nm::delimited(nm::chr('['), nm::take_while([](std::uint8_t c) { return c != ']'; }),
                                nm::chr(']')),
                 [](nm::bytes b) { return std::string(reinterpret_cast<const char*>(b.data()), b.size()); })(i);
}

nm::result<std::pair<std::string, std::string>> kv_line(nm::input i) {
  return nm::map(
      nm::delimited(nm::multispace0, nm::separated_pair(nm::alphanumeric1, nm::chr('='), nm::alphanumeric1),
                    nm::multispace0),
      [](auto pr) { return std::pair(std::string(pr.first), std::string(pr.second)); })(i);
}

nm::result<std::pair<std::string, KeyValues>> section(nm::input i) {
  auto name = nm::delimited(nm::multispace0, section_name, nm::multispace0)(i);
  if (!name) return nm::unexp(name.error());
  return nm::map(nm::fold_many0(kv_line, [] { return KeyValues{}; },
                                [](KeyValues& acc, auto kv) { acc.emplace(std::move(kv.first), std::move(kv.second)); }),
                 [n = name->value](KeyValues kvs) { return std::pair(n, std::move(kvs)); })(name->rest);
}

nm::result<Sections> config(nm::input i) {
  return nm::fold_many0(section, [] { return Sections{}; },
                        [](Sections& acc, auto sec) { acc.emplace(std::move(sec.first), std::move(sec.second)); })(i);
}

void run() {
  const char* text =
      "[server]\n"
      "host=localhost\n"
      "port=8080\n"
      "[limits]\n"
      "maxconn=100\n"
      "timeout=30\n";

  auto r = config(nm::from(std::string_view(text)));
  CHECK(r && r->rest.empty());
  if (!r) return;
  CHECK(r->value.size() == 2);
  CHECK(r->value.at("server").at("host") == "localhost");
  CHECK(r->value.at("server").at("port") == "8080");
  CHECK(r->value.at("limits").at("maxconn") == "100");
  CHECK(r->value.at("limits").at("timeout") == "30");
}

}  // namespace ini_parity

// =====================================================================================
// multiline.rs: many0(terminated(alphanumeric1, line_ending)) reading repeated line
// records (own fixture).
// =====================================================================================
namespace multiline_parity {

nm::result<std::string_view> read_line(nm::input i) {
  return nm::terminated(nm::alphanumeric1, nm::line_ending)(i);
}

void run() {
  const char* text = "alpha\nbeta\ngamma42\n";
  auto r = nm::many0(read_line)(nm::from(std::string_view(text)));
  CHECK(r && r->rest.empty());
  CHECK(r && r->value.size() == 3);
  if (r && r->value.size() == 3) {
    CHECK(r->value[0] == "alpha" && r->value[1] == "beta" && r->value[2] == "gamma42");
  }
}

}  // namespace multiline_parity

// =====================================================================================
// escaped.rs: escaped()/escaped_transform() don't exist in nanom (confirmed: zero
// mentions in nom.hpp or docs/CHEATSHEET.md -- a real, narrow coverage gap). This
// composes the equivalent behavior from EXISTING primitives to confirm the gap is a
// missing convenience wrapper, not a structural limitation.
// =====================================================================================
namespace escaped_parity {

nm::result<nm::bytes> escaped_digits(nm::input i) {
  return nm::recognize(nm::many0(nm::alt(
      nm::map(nm::digit1, [](auto) { return nm::unit{}; }),
      nm::map(nm::preceded(nm::chr('\\'), nm::one_of("\"n\\")), [](auto) { return nm::unit{}; }))))(i);
}

void run() {
  auto r1 = escaped_digits(nm::from(std::string_view("123\\n456")));
  CHECK(r1 && r1->rest.empty());
  if (r1) {
    auto sp = r1->value;
    CHECK(std::string(reinterpret_cast<const char*>(sp.data()), sp.size()) == "123\\n456");
  }

  // Stops cleanly at a byte that's neither a digit nor a valid escape ("\x" is not in the set).
  auto r2 = escaped_digits(nm::from(std::string_view("12\\x34")));
  CHECK(r2 && r2->rest.size() == 4);
}

}  // namespace escaped_parity

int main() {
  mp4_parity::run();
  json_parity::run();
  fnmut_parity::run();
  overflow_parity::run();
  arithmetic_parity::run();
  arith_ast_parity::run();
  css_parity::run();
  float_parity::run();
  ini_parity::run();
  multiline_parity::run();
  escaped_parity::run();

  if (failures == 0) {
    std::printf("PASS: all nom-8.0.0 test-suite parity checks (mp4/json/fnmut/overflow/"
                "arithmetic/arithmetic_ast/css/float/ini/multiline/escaped) passed.\n");
  }
  return failures == 0 ? 0 : 1;
}
