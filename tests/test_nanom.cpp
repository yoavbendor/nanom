// nanom test suite — plain asserts, no framework needed.
#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace nm = nanom;
using std::uint8_t; using std::uint16_t; using std::uint32_t; using std::uint64_t;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

static nm::input in(std::string_view s) { return nm::from(s); }

// ---------------------------------------------------------------- structs
struct vlan_tag {
  nm::ubits<3>          pcp;
  nm::ubits<1>          dei;
  nm::ubits<12>         vid;
  nm::be<uint16_t>      ether;
};
NANOM_DESCRIBE(vlan_tag, pcp, dei, vid, ether);

struct mixed_endian {
  nm::be<uint16_t> big;
  nm::le<uint32_t> little;
  uint8_t          plain;
};
NANOM_DESCRIBE(mixed_endian, big, little, plain);

struct inner_pt { nm::le<uint16_t> x, y; };
NANOM_DESCRIBE(inner_pt, x, y);
struct outer_msg {
  uint8_t                     kind;
  inner_pt                    pt;
  std::array<uint8_t, 4>      raw;
  nm::be<float>               scale;
};
NANOM_DESCRIBE(outer_msg, kind, pt, raw, scale);

struct signed_bits {
  nm::ibits<4>  a;   // -8..7
  nm::ubits<4>  b;
  nm::ibits<6, nm::bit_order::lsb0> c;
  nm::ubits<2, nm::bit_order::lsb0> d;
};
NANOM_DESCRIBE(signed_bits, a, b, c, d);

// ---------------------------------------------------------------- tests
static void test_primitives() {
  auto r = nm::tag("GET")(in("GET /"));
  CHECK(r && nm::as_str(r->value) == "GET" && r->rest.size() == 2);
  CHECK(!nm::tag("GET")(in("PUT /")));
  auto ri = nm::tag("GETX")(in("GET"));                 // complete mode: plain error
  CHECK(!ri && ri.error().kind == nm::errk::err && ri.error().needed == 1);
  auto rs = nm::tag("GETX")(nm::streaming(in("GET")));  // streaming: incomplete
  CHECK(!rs && rs.error().kind == nm::errk::incomplete);

  CHECK(nm::tag_no_case("http")(in("HTTP/1.1")));
  auto t = nm::take(4)(in("abcdef"));
  CHECK(t && nm::as_str(t->value) == "abcd");

  auto tw = nm::take_while([](uint8_t b) { return b == 'a'; })(in("aaab"));
  CHECK(tw && tw->value.size() == 3);
  CHECK(!nm::take_while1([](uint8_t b) { return b == 'z'; })(in("abc")));
  auto tmn = nm::take_while_m_n(2, 3, [](uint8_t b) { return b == 'x'; })(in("xxxxy"));
  CHECK(tmn && tmn->value.size() == 3);

  auto tt = nm::take_till([](uint8_t b) { return b == ':'; })(in("key:val"));
  CHECK(tt && nm::as_str(tt->value) == "key");
  auto tu = nm::take_until("\r\n")(in("line\r\nrest"));
  CHECK(tu && nm::as_str(tu->value) == "line" && nm::as_str(tu->rest.span()) == "\r\nrest");

  auto ia = nm::is_a("0123456789")(in("123abc"));
  CHECK(ia && ia->value.size() == 3);
  auto ino = nm::is_not(" \t")(in("word next"));
  CHECK(ino && nm::as_str(ino->value) == "word");
}

static void test_characters() {
  CHECK(nm::chr('=')(in("=x")));
  CHECK(!nm::chr('=')(in("x=")));
  auto oo = nm::one_of("+-")(in("-3"));
  CHECK(oo && oo->value == '-');
  CHECK(nm::none_of("\r\n")(in("a")));
  CHECK(nm::anychar(in("z")));
  CHECK(!nm::anychar(in("")));

  auto a1 = nm::alpha1(in("abc123"));
  CHECK(a1 && a1->value == "abc");
  auto d1 = nm::digit1(in("42x"));
  CHECK(d1 && d1->value == "42");
  CHECK(nm::hex_digit1(in("dEadBEef!"))->value == "dEadBEef");
  CHECK(nm::multispace0(in("  \r\n\tx"))->value.size() == 5);
  CHECK(nm::line_ending(in("\r\nx"))->value == "\r\n");
  CHECK(nm::line_ending(in("\nx"))->value == "\n");
  CHECK(nm::not_line_ending(in("ab\r\n"))->value == "ab");

  CHECK(nm::dec<int>()(in("-42;"))->value == -42);
  CHECK(nm::dec<unsigned>()(in("7"))->value == 7u);
  CHECK(!nm::dec<uint8_t>()(in("300")));  // overflow rejected
  CHECK(nm::hex<uint32_t>()(in("ff10"))->value == 0xff10u);
  CHECK(nm::double_(in("-2.5e2rest"))->value == -250.0);
}

static void test_sequences() {
  auto p = nm::seq(nm::tag("a"), nm::dec<int>(), nm::tag("b"));
  auto r = p(in("a17b!"));
  CHECK(r && std::get<1>(r->value) == 17 && r->rest.size() == 1);

  auto pr = nm::pair(nm::alpha1, nm::digit1)(in("ab12"));
  CHECK(pr && pr->value.first == "ab" && pr->value.second == "12");
  auto sp = nm::separated_pair(nm::alpha1, nm::chr('='), nm::digit1)(in("k=9"));
  CHECK(sp && sp->value.first == "k" && sp->value.second == "9");
  CHECK(nm::preceded(nm::tag("0x"), nm::hex<uint32_t>())(in("0xff"))->value == 0xffu);
  CHECK(nm::terminated(nm::digit1, nm::tag(";"))(in("12;"))->value == "12");
  CHECK(nm::delimited(nm::chr('('), nm::dec<int>(), nm::chr(')'))(in("(8)"))->value == 8);
}

static void test_branch() {
  auto p = nm::alt(nm::tag("GET"), nm::tag("POST"), nm::tag("PUT"));
  CHECK(nm::as_str(p(in("POST"))->value) == "POST");
  CHECK(!p(in("HEAD")));

  // alt reports the error that got FURTHEST (better than nom)
  auto deep = nm::alt(nm::preceded(nm::tag("ab"), nm::tag("XY")), nm::tag("zz"));
  auto e = deep(in("abQQ"));
  CHECK(!e && e.error().offset == 2);

  // cut inside alt aborts remaining alternatives
  auto c = nm::alt(nm::preceded(nm::tag("a"), nm::cut(nm::tag("1"))), nm::tag("ab"));
  auto ce = c(in("ab"));
  CHECK(!ce && ce.error().kind == nm::errk::fail);

  auto perm = nm::permutation(nm::alpha1, nm::digit1, nm::chr('#'));
  auto pv = perm(in("42#xy"));
  CHECK(pv && std::get<0>(pv->value) == "xy" && std::get<1>(pv->value) == "42");
}

static void test_multi() {
  auto m0 = nm::many0(nm::tag("ab"))(in("ababX"));
  CHECK(m0 && m0->value.size() == 2 && nm::as_str(m0->rest.span()) == "X");
  CHECK(nm::many0(nm::tag("q"))(in("x"))->value.empty());
  CHECK(!nm::many1(nm::tag("q"))(in("x")));
  // zero-consumption guard
  CHECK(!nm::many0(nm::take_while([](uint8_t) { return false; }))(in("abc")));

  auto mn = nm::many_m_n(1, 2, nm::tag("a"))(in("aaa"));
  CHECK(mn && mn->value.size() == 2);
  auto mt = nm::many_till(nm::anychar, nm::tag("end"))(in("xyend."));
  CHECK(mt && mt->value.first.size() == 2 && nm::as_str(mt->rest.span()) == ".");
  CHECK(nm::count(nm::be_u16, 2)(nm::from("\x00\x01\x00\x02\xff", 5))->value[1] == 2);

  auto sl = nm::separated_list1(nm::chr(','), nm::dec<int>())(in("1,2,3;"));
  CHECK(sl && sl->value.size() == 3 && sl->value[2] == 3);
  CHECK(nm::separated_list0(nm::chr(','), nm::dec<int>())(in(";"))->value.empty());

  auto fm = nm::fold_many1(nm::dec<int>(), [] { return 0; },
                           [](int& acc, int v) { acc += v; })(in("5"));
  CHECK(fm && fm->value == 5);

  const uint8_t lv[] = {3, 'a', 'b', 'c', 'Z'};
  auto ld = nm::length_data(nm::u8)(nm::from(lv, sizeof lv));
  CHECK(ld && nm::as_str(ld->value) == "abc");
  auto lval = nm::length_value(nm::u8, nm::alpha1)(nm::from(lv, sizeof lv));
  CHECK(lval && lval->value == "abc" && nm::as_str(lval->rest.span()) == "Z");
  const uint8_t lc[] = {2, 5, 0, 6, 0};   // n=2, then 5 and 6 (LE)
  auto lcr = nm::length_count(nm::u8, nm::le_u16)(nm::from(lc, sizeof lc));
  CHECK(lcr && lcr->value.size() == 2 && lcr->value[1] == 6);
}

static void test_modifiers() {
  CHECK(nm::map(nm::dec<int>(), [](int v) { return v * 2; })(in("21"))->value == 42);
  auto mo = nm::map_opt(nm::dec<int>(), [](int v) {
    return v < 100 ? std::optional<int>(v) : std::nullopt;
  });
  CHECK(mo(in("42")) && !mo(in("101")));

  auto mp = nm::map_parser(nm::take(2), nm::dec<int>())(in("12x"));
  CHECK(mp && mp->value == 12 && nm::as_str(mp->rest.span()) == "x");

  auto fmp = nm::flat_map(nm::u8, [](uint8_t n) { return nm::take(n); })(
      nm::from("\x02" "abz", 4));
  CHECK(fmp && nm::as_str(fmp->value) == "ab");

  auto o = nm::opt(nm::tag("-"))(in("x"));
  CHECK(o && !o->value && o->rest.size() == 1);
  CHECK(nm::opt(nm::tag("-"))(in("-x"))->value.has_value());
  CHECK(!nm::cond(true, nm::tag("a"))(in("b")));
  CHECK(nm::cond(false, nm::tag("a"))(in("b")));

  auto pk = nm::peek(nm::tag("ab"))(in("abc"));
  CHECK(pk && pk->rest.size() == 3);
  CHECK(nm::not_(nm::tag("x"))(in("ab")));
  CHECK(!nm::not_(nm::tag("a"))(in("ab")));

  auto rec = nm::recognize(nm::seq(nm::alpha1, nm::digit1))(in("ab12."));
  CHECK(rec && nm::as_str(rec->value) == "ab12");
  auto con = nm::consumed(nm::dec<int>())(in("42x"));
  CHECK(con && nm::as_str(con->value.first) == "42" && con->value.second == 42);

  CHECK(nm::value(7, nm::tag("ok"))(in("ok"))->value == 7);
  CHECK(nm::verify(nm::dec<int>(), [](int v) { return v > 0; })(in("5")));
  CHECK(!nm::verify(nm::dec<int>(), [](int v) { return v > 0; })(in("-5")));
  CHECK(nm::success(1)(in(""))->value == 1);
  CHECK(!nm::fail()(in("x")));

  auto cm = nm::complete(nm::tag("abc"))(nm::streaming(in("ab")));
  CHECK(!cm && cm.error().kind == nm::errk::err);  // incomplete downgraded
  CHECK(nm::all_consuming(nm::tag("ab"))(in("ab")));
  CHECK(!nm::all_consuming(nm::tag("ab"))(in("abc")));
  CHECK(nm::eof(in("")) && !nm::eof(in("x")));
  CHECK(nm::rest_len(in("abc"))->value == 3);
  CHECK(nm::into<std::string>(nm::alpha1)(in("hi!"))->value == "hi");
}

static void test_numbers() {
  const uint8_t b[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  nm::input i = nm::from(b, sizeof b);
  CHECK(nm::be_u16(i)->value == 0x0102);
  CHECK(nm::le_u16(i)->value == 0x0201);
  CHECK(nm::be_u24(i)->value == 0x010203u);
  CHECK(nm::be_u32(i)->value == 0x01020304u);
  CHECK(nm::le_u32(i)->value == 0x04030201u);
  CHECK(nm::be_u64(i)->value == 0x0102030405060708ull);
  CHECK(nm::le_u64(i)->value == 0x0807060504030201ull);

  const uint8_t neg[] = {0xff, 0xfe};
  CHECK(nm::be_i16(nm::from(neg, 2))->value == -2);
  CHECK(nm::le_i16(nm::from(neg, 2))->value == -257);

  const uint8_t f32be[] = {0x40, 0x49, 0x0f, 0xdb};  // pi
  auto pi = nm::be_f32(nm::from(f32be, 4));
  CHECK(pi && pi->value > 3.14f && pi->value < 3.15f);

  // runtime-selected endianness (the ELF trick)
  CHECK(nm::uint_<uint32_t>(std::endian::big)(i)->value == 0x01020304u);
  CHECK(nm::uint_<uint32_t>(std::endian::little)(i)->value == 0x04030201u);

  auto short_ = nm::be_u32(nm::streaming(nm::from(b, 2)));
  CHECK(!short_ && short_.error().kind == nm::errk::incomplete && short_.error().needed == 2);
  CHECK(nm::be_u32(nm::from(b, 2)).error().kind == nm::errk::err);
}

static void test_bits() {
  // 0b1010'1100, 0b0101'0011
  const uint8_t bb[] = {0xac, 0x53};
  // MSB0: 3 bits = 101, 5 bits = 01100, 8 bits = 01010011
  auto p = nm::bits(nm::bseq(nm::take_bits<uint8_t>(3), nm::take_bits<uint8_t>(5),
                             nm::take_bits<uint8_t>(8)));
  auto r = p(nm::from(bb, 2));
  CHECK(r && std::get<0>(r->value) == 0b101 && std::get<1>(r->value) == 0b01100 &&
        std::get<2>(r->value) == 0x53);

  // LSB0: 3 bits = 100 (low bits first), 5 bits = 10101
  auto pl = nm::bits(nm::bseq(nm::take_bits<uint8_t>(3, nm::bit_order::lsb0),
                              nm::take_bits<uint8_t>(5, nm::bit_order::lsb0)));
  auto rl = pl(nm::from(bb, 2));
  CHECK(rl && std::get<0>(rl->value) == 0b100 && std::get<1>(rl->value) == 0b10101);

  CHECK(nm::bits(nm::tag_bits(0b101, 3))(nm::from(bb, 2)));
  CHECK(!nm::bits(nm::tag_bits(0b111, 3))(nm::from(bb, 2)));
  CHECK(nm::bits(nm::bool_bit())(nm::from(bb, 2))->value == true);

  // partial byte rounds up on exit from bits()
  auto pr = nm::bits(nm::take_bits<uint8_t>(3))(nm::from(bb, 2));
  CHECK(pr && pr->rest.size() == 1);

  // bytes_() drops back to byte mode when aligned
  auto mix = nm::bits(nm::bseq(nm::take_bits<uint8_t>(8), nm::bytes_(nm::u8)));
  auto mr = mix(nm::from(bb, 2));
  CHECK(mr && std::get<1>(mr->value) == 0x53);
}

static void test_strct() {
  static_assert(nm::wire_size_v<vlan_tag> == 4);
  static_assert(nm::wire_size_v<mixed_endian> == 7);
  static_assert(nm::wire_size_v<outer_msg> == 13);

  const uint8_t vt[] = {0x60, 0x2a, 0x08, 0x00};  // pcp=3 dei=0 vid=42 ether=0x800
  auto r = nm::strct<vlan_tag>()(nm::from(vt, 4));
  CHECK(r && r->value.pcp == 3 && r->value.dei == 0 && r->value.vid == 42 &&
        uint16_t(r->value.ether) == 0x0800);

  const uint8_t me[] = {0x12, 0x34, 0x78, 0x56, 0x34, 0x12, 0x99};
  auto m = nm::strct<mixed_endian>()(nm::from(me, 7));
  CHECK(m && uint16_t(m->value.big) == 0x1234 && uint32_t(m->value.little) == 0x12345678u &&
        m->value.plain == 0x99);

  const uint8_t om[] = {7, 0x0a, 0x00, 0x14, 0x00, 0xde, 0xad, 0xbe, 0xef,
                        0x40, 0x00, 0x00, 0x00};  // scale = 2.0f BE
  auto o = nm::strct<outer_msg>()(nm::from(om, sizeof om));
  CHECK(o && o->value.kind == 7 && uint16_t(o->value.pt.x) == 10 &&
        uint16_t(o->value.pt.y) == 20 && o->value.raw[3] == 0xef &&
        float(o->value.scale) == 2.0f);

  // ibits sign extension: a = 0b1111 -> -1;  lsb0 pair in third byte
  const uint8_t sb[] = {0xf5, 0b11'100001, 0x00};
  static_assert(nm::wire_size_v<signed_bits> == 2);
  auto s = nm::strct<signed_bits>()(nm::from(sb, 3));
  CHECK(s && s->value.a == -1 && s->value.b == 5);
  CHECK(s && s->value.c == -31 && s->value.d == 3);  // lsb0: c=0b100001(-31), d=0b11

  // composes with combinators
  auto two = nm::count(nm::strct<vlan_tag>(), 2)(
      nm::from("\x60\x2a\x08\x00\x20\x01\x86\xdd", 8));
  CHECK(two && two->value[1].vid == 1 && uint16_t(two->value[1].ether) == 0x86dd);

  auto inc = nm::strct<vlan_tag>()(nm::streaming(nm::from(vt, 2)));
  CHECK(!inc && inc.error().kind == nm::errk::incomplete && inc.error().needed == 2);
}

static void test_view() {
  const uint8_t vt[] = {0x60, 0x2a, 0x08, 0x00, 0xff};
  auto r = nm::overlay<vlan_tag>()(nm::from(vt, 5));
  CHECK(r && r->rest.size() == 1);
  auto v = r->value;
  CHECK(v.get<"pcp">() == 3);
  CHECK(v.get<"vid">() == 42);
  CHECK(v.get<"ether">() == 0x0800);
  CHECK(v.raw().size() == 4);
  vlan_tag t = v.to_struct();
  CHECK(t.vid == 42);

  const uint8_t om[] = {7, 0x0a, 0x00, 0x14, 0x00, 0xde, 0xad, 0xbe, 0xef,
                        0x40, 0x00, 0x00, 0x00};
  auto ov = nm::overlay<outer_msg>()(nm::from(om, sizeof om));
  CHECK(ov->value.get<"kind">() == 7);
  CHECK(ov->value.get<"pt">().get<"y">() == 20);  // nested views
  auto raw = ov->value.get<"raw">();
  CHECK(raw[0] == 0xde && raw.size() == 4);
  CHECK(ov->value.get<"scale">() == 2.0f);
}

static void test_schema() {
  const auto& s = nm::schema_of<outer_msg>();
  CHECK(s.name == "outer_msg" && s.fields.size() == 4);
  CHECK(s.fields[0].kind == nm::dkind::u8);
  CHECK(s.fields[1].kind == nm::dkind::record && s.fields[1].nested->fields.size() == 2);
  CHECK(s.fields[2].kind == nm::dkind::fixed_bin && s.fields[2].size == 4);
  CHECK(s.fields[3].kind == nm::dkind::f32);

  CHECK(nm::arrow_format(s.fields[0]) == "C");
  CHECK(nm::arrow_format(s.fields[1]) == "+s");
  CHECK(nm::arrow_format(s.fields[2]) == "w:4");
  CHECK(nm::arrow_format(s.fields[3]) == "f");

  auto avro = nm::avro_schema<outer_msg>();
  CHECK(avro.find("\"type\":\"record\"") != std::string::npos);
  CHECK(avro.find("\"name\":\"pt\"") != std::string::npos);
  CHECK(avro.find("\"float\"") != std::string::npos);

  outer_msg om{};
  om.kind = 3; om.pt.x = 1; om.pt.y = 2; om.raw = {0xde, 0xad, 0xbe, 0xef};
  om.scale = 1.5f;
  CHECK(nm::to_json(om) ==
        R"({"kind":3,"pt":{"x":1,"y":2},"raw":"deadbeef","scale":1.5})");
  CHECK(nm::csv_header<outer_msg>() == "kind,pt.x,pt.y,raw,scale");
  CHECK(nm::csv_row(om) == "3,1,2,\"deadbeef\",1.5");
}

static void test_soa() {
  nm::soa<outer_msg> cols(2);
  CHECK(cols.columns().size() == 5);  // kind, pt.x, pt.y, raw, scale
  CHECK(cols.columns()[1].name == "pt.x");
  CHECK(cols.columns()[3].kind == nm::dkind::fixed_bin && cols.columns()[3].elem_bytes == 4);
  CHECK(cols.columns()[4].arrow == "f");

  outer_msg om{};
  for (int i = 0; i < 5; ++i) {
    om.kind = uint8_t(i);
    om.pt.x = uint16_t(i * 10);
    om.scale = float(i);
    cols.push(om);
  }
  CHECK(cols.rows() == 5);
  std::size_t chunks = 0, seen = 0;
  cols.for_each_chunk([&](const auto& ch) {
    ++chunks;
    auto kinds = ch.template as<uint8_t>(0);
    auto xs    = ch.template as<uint16_t>(1);
    for (std::size_t r = 0; r < ch.rows; ++r, ++seen) {
      CHECK(kinds[r] == seen);
      CHECK(xs[r] == seen * 10);
    }
    CHECK(ch.col(3).size() == ch.rows * 4);
  });
  CHECK(chunks == 3 && seen == 5);  // 2 + 2 + 1
}

static void test_errors() {
  auto p = nm::context("frame", nm::preceded(nm::tag("\xaa"), nm::context("body",
              nm::cut(nm::tag("\xbb")))));
  nm::input i = nm::from("\xaa\xcc\xdd", 3);
  auto r = p(i);
  CHECK(!r && r.error().kind == nm::errk::fail && r.error().offset == 1);
  std::string msg = r.error().render(i);
  CHECK(msg.find("offset 1") != std::string::npos);
  CHECK(msg.find("in body") != std::string::npos);
  CHECK(msg.find("in frame") != std::string::npos);
  CHECK(msg.find("^^") != std::string::npos);
  CHECK(msg.find("cc") != std::string::npos);  // hex window shows the bad byte

  auto inc = nm::be_u32(nm::from("\x01", 1));
  std::string m2 = inc.error().render(nm::from("\x01", 1));
  CHECK(m2.find("need 3 more") != std::string::npos);
}

// Device-purity guard: the zero-copy decode path (be/le, bit fields, plain
// scalars) must be fully constexpr — i.e. free of allocation, I/O, exceptions
// and other host-only runtime dependencies. If it evaluates at compile time it
// is eligible to run in a GPU kernel (see docs/GPU.md). Checked at compile time.
namespace cx_proof {
constexpr std::array<std::byte, 8> vlan_bytes = [] {
  std::array<std::byte, 8> a{};
  const unsigned char b[8] = {0x60, 0x2a, 0x08, 0x00, /*mixed*/ 0x12, 0x34, 0x56, 0x78};
  for (int i = 0; i < 8; ++i) a[i] = std::byte(b[i]);
  return a;
}();
constexpr vlan_tag decode_vlan() {
  nm::input in{nm::bytes(vlan_bytes.data(), 4)};
  return nm::overlay<vlan_tag>()(in)->value.to_struct();
}
static_assert(decode_vlan().pcp == 3, "constexpr bit-field decode (msb0)");
static_assert(decode_vlan().vid == 42, "constexpr multi-byte bit-field decode");
static_assert(std::uint16_t(decode_vlan().ether) == 0x0800, "constexpr be<> decode");
static_assert(nm::strct<vlan_tag>()(nm::input{nm::bytes(vlan_bytes.data(), 4)})->value.dei == 0,
              "constexpr strct<> decode");
}  // namespace cx_proof

int main() {
  test_primitives();
  test_characters();
  test_sequences();
  test_branch();
  test_multi();
  test_modifiers();
  test_numbers();
  test_bits();
  test_strct();
  test_view();
  test_schema();
  test_soa();
  test_errors();
  if (failures) {
    std::printf("%d FAILURE(S)\n", failures);
    return 1;
  }
  std::printf("all tests passed\n");
  return 0;
}
