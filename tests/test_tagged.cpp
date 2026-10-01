// Tests for the varint / count-guard / le_array primitives (nom.hpp §12b–12d) and the reflected
// tagged-message Thrift compact codec (tagged.hpp) + the Parquet metadata model.
#include <nanom/nanom.hpp>
#include <nanom/tagged.hpp>
#include <nanom/formats/parquet_thrift.hpp>

#include <cstdio>
#include <random>

namespace nm = nanom;
namespace pq = nanom_formats::parquet;
using std::int16_t; using std::int32_t; using std::int64_t; using std::int8_t;
using std::uint8_t; using std::uint32_t; using std::uint64_t;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

static std::vector<std::byte> B(std::initializer_list<int> v) {
  std::vector<std::byte> out;
  for (int x : v) out.push_back(std::byte(x));
  return out;
}
static nm::input I(const std::vector<std::byte>& v) { return nm::from(std::span<const std::byte>(v)); }

// ------------------------------------------------------------------ compile-time proofs
// Decoding inside a constant expression: any UB on these paths would be a compile error.
consteval uint64_t ct_uleb(std::array<std::byte, 3> b) {
  auto r = nm::varint_u64(nm::from(std::span<const std::byte>(b)));
  return r ? r->value : ~uint64_t(0);
}
static_assert(ct_uleb({std::byte{0xac}, std::byte{0x02}, std::byte{0}}) == 300);
static_assert(nm::zigzag_decode(uint32_t(0)) == 0 && nm::zigzag_decode(uint32_t(1)) == -1 &&
              nm::zigzag_decode(uint32_t(2)) == 1 && nm::zigzag_decode(uint32_t(3)) == -2);
static_assert(nm::zigzag_encode(int64_t(INT64_MIN)) == ~uint64_t(0));
static_assert(nm::zigzag_decode(nm::zigzag_encode(int16_t(-32768))) == -32768);
static_assert(nm::leb128_max_bytes<uint32_t> == 5 && nm::leb128_max_bytes<uint64_t> == 10);

// ------------------------------------------------------------------ varints
static void test_uleb128() {
  struct tv { std::vector<std::byte> b; uint64_t v; };
  for (const auto& t : {tv{B({0x00}), 0}, tv{B({0x7f}), 127}, tv{B({0x80, 0x01}), 128},
                        tv{B({0xe5, 0x8e, 0x26}), 624485},
                        tv{B({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}), ~uint64_t(0)}}) {
    auto r = nm::varint_u64(I(t.b));
    CHECK(r && r->value == t.v && r->rest.empty());
  }
  // u32: the 5th byte may carry only 4 payload bits; a 6th byte is never allowed
  CHECK(nm::varint_u32(I(B({0xff, 0xff, 0xff, 0xff, 0x0f}))));
  CHECK(!nm::varint_u32(I(B({0xff, 0xff, 0xff, 0xff, 0x1f}))));
  CHECK(!nm::varint_u32(I(B({0x80, 0x80, 0x80, 0x80, 0x80, 0x00}))));
  // u64: the 10th byte may carry only bit 0
  CHECK(!nm::varint_u64(I(B({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}))));
  // truncated: plain error on complete input, `incomplete` on streaming input
  auto t = B({0x80, 0x80});
  auto c = nm::varint_u64(I(t));
  CHECK(!c && c.error().kind == nm::errk::err);
  auto s = nm::varint_u64(nm::streaming(I(t)));
  CHECK(!s && s.error().kind == nm::errk::incomplete && s.error().offset == 2);
  CHECK(!nm::varint_u64(I({})));

  // randomized round trip incl. every power-of-two boundary
  std::mt19937_64 rng(42);
  std::byte buf[10];
  for (int i = 0; i < 20000; ++i) {
    uint64_t v = i < 64 ? (uint64_t(1) << i) - (i & 1) : rng() >> (rng() % 64);
    const std::size_t n = nm::uleb128_encode(v, buf);
    auto r = nm::varint_u64(nm::from(std::span<const std::byte>(buf, n)));
    CHECK(r && r->value == v && r->rest.empty());
    if (v <= 0xffffffffu) {
      auto r32 = nm::varint_u32(nm::from(std::span<const std::byte>(buf, n)));
      CHECK(r32 && r32->value == v);
    }
  }
}

static void test_sleb128() {
  struct tv { std::vector<std::byte> b; int64_t v; };
  for (const auto& t : {tv{B({0x02}), 2}, tv{B({0x7e}), -2}, tv{B({0xff, 0x00}), 127},
                        tv{B({0x81, 0x7f}), -127}, tv{B({0x80, 0x01}), 128},
                        tv{B({0x80, 0x7f}), -128}, tv{B({0xc0, 0xbb, 0x78}), -123456}}) {
    auto r = nm::sleb128<int64_t>()(I(t.b));
    CHECK(r && r->value == t.v && r->rest.empty());
  }
  // int32 extremes and the last-byte sign-extension rule
  CHECK(nm::sleb128<int32_t>()(I(B({0xff, 0xff, 0xff, 0xff, 0x07})))->value == INT32_MAX);
  CHECK(nm::sleb128<int32_t>()(I(B({0x80, 0x80, 0x80, 0x80, 0x78})))->value == INT32_MIN);
  CHECK(!nm::sleb128<int32_t>()(I(B({0xff, 0xff, 0xff, 0xff, 0x17}))));  // bits beyond int32
  CHECK(!nm::sleb128<int32_t>()(I(B({0x80, 0x80, 0x80, 0x80, 0x80, 0x00}))));
}

static void test_zigzag_varint() {
  CHECK(nm::zigzag_varint<int32_t>()(I(B({0x03})))->value == -2);
  CHECK(nm::zigzag_varint<int16_t>()(I(B({0xfe, 0xff, 0x03})))->value == 32767);
  CHECK(!nm::zigzag_varint<int16_t>()(I(B({0x80, 0x80, 0x04}))));  // 32768 does not fit i16
  CHECK(!nm::zigzag_varint<int8_t>()(I(B({0x80, 0x02}))));          // 256 zigzags to 128: not an int8
}

static void test_guards_and_le_array() {
  auto buf = B({1, 0, 0, 0, 2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff});
  CHECK(nm::count_fits(I(buf), 3, 4) && !nm::count_fits(I(buf), 4, 4));
  CHECK(!nm::count_fits(I(buf), ~uint64_t(0), 8));  // no multiply, no overflow
  CHECK(!nm::checked_mul(~uint64_t(0), uint64_t(2)) && *nm::checked_add(uint32_t(1), uint32_t(2)) == 3);
  auto r = nm::le_array_of<int32_t>(3)(I(buf));
  CHECK(r && r->value.size() == 3 && r->value[0] == 1 && r->value[1] == 2 && r->value[2] == -1);
  CHECK(!r->value.at(3) && *r->value.at(2) == -1);
  std::array<int32_t, 3> out{};
  CHECK(r->value.copy_to(out) && out[1] == 2);
  std::array<int32_t, 2> small{};
  CHECK(!r->value.copy_to(small));
  CHECK(!nm::le_array_of<int32_t>(4)(I(buf)));
  CHECK(!nm::le_array_of<int64_t>(~std::size_t(0) / 2)(I(buf)));  // hostile count, no overflow
}

// ------------------------------------------------------------------ footer<T>()
// Lance v2 file footer: the last 40 bytes of every .lance data file (little-endian).
struct lance_footer {
  nm::le<uint64_t>       column_meta_start;
  nm::le<uint64_t>       column_meta_offsets_start;
  nm::le<uint64_t>       global_buff_offsets_start;
  nm::le<uint32_t>       num_global_buffers;
  nm::le<uint32_t>       num_columns;
  nm::le<uint16_t>       major_version;
  nm::le<uint16_t>       minor_version;
  std::array<uint8_t, 4> magic;
};
NANOM_DESCRIBE(lance_footer, column_meta_start, column_meta_offsets_start, global_buff_offsets_start,
               num_global_buffers, num_columns, major_version, minor_version, magic);
static_assert(nm::wire_size_v<lance_footer> == 40);

static void test_footer() {
  std::vector<std::byte> file = B({0xde, 0xad, 0xbe, 0xef, 0x00});  // body
  auto put = [&](uint64_t v, int n) { for (int i = 0; i < n; ++i) file.push_back(std::byte(v >> (8 * i))); };
  put(1000, 8); put(2000, 8); put(3000, 8); put(1, 4); put(12, 4); put(2, 2); put(1, 2);
  for (char c : std::string_view("LANC")) file.push_back(std::byte(c));
  auto r = nm::footer<lance_footer>()(I(file));
  CHECK(r && r->value.column_meta_start == 1000u && r->value.num_columns == 12u &&
        r->value.major_version == 2 && r->value.minor_version == 1 && r->value.magic[0] == 'L');
  CHECK(r && r->rest.size() == 5 && r->rest[0] == 0xde);  // rest = the body before the footer
  file.resize(30);
  CHECK(!nm::footer<lance_footer>()(I(file)));
}

// ------------------------------------------------------------------ thrift compact
enum class Color : int32_t { red = 0, green = 1, blue = 2 };

struct Inner {
  nm::field<1, int32_t> a;
  nm::field<2, std::optional<std::string_view>> s;
};
struct Outer {
  nm::field<1, bool>                               flag;
  nm::field<2, int8_t>                             tiny;
  nm::field<3, int16_t>                            small;
  nm::field<4, int64_t>                            big;
  nm::field<5, double>                             dbl;
  nm::field<6, Color>                              color;
  nm::field<7, std::string_view>                   name;
  nm::field<8, nm::list<int32_t>>                  nums;
  nm::field<9, std::vector<Inner>>                 inners;
  nm::field<10, std::optional<Inner>>              maybe;
  nm::field<11, nm::lazy<Inner>>                   later;
  nm::field<12, nm::list<bool>>                    bits;
  nm::field<40, std::optional<int32_t>>            far;      // long-form field header (delta > 15)
  nm::field<41, int32_t, nm::presence::defaulted>  dflt;
  nm::field<42, std::optional<nm::empty_struct>>   marker;
};
NANOM_DESCRIBE(Inner, a, s);
NANOM_DESCRIBE(Outer, flag, tiny, small, big, dbl, color, name, nums, inners, maybe, later, bits,
               far, dflt, marker);

static_assert(nm::Message<Outer> && nm::Message<Inner>);

struct Seed {
  nm::field<8, std::vector<int32_t>> nums;
  nm::field<11, Inner>               later;
  nm::field<12, std::vector<bool>>   bits;
};
struct SeedView {
  nm::field<8, nm::list<int32_t>>    nums;
  nm::field<11, nm::lazy<Inner>>     later;
  nm::field<12, nm::list<bool>>      bits;
};
NANOM_DESCRIBE(Seed, nums, later, bits);
NANOM_DESCRIBE(SeedView, nums, later, bits);

static void test_thrift_handcoded() {
  // Hand-assembled from the compact spec: { 1: i32 a = -2, 2: string s = "hi" } STOP
  auto wire = B({0x15, 0x03, 0x18, 0x02, 'h', 'i', 0x00});
  auto r = nm::thrift_compact<Inner>()(I(wire));
  CHECK(r && *r->value.a == -2 && r->value.s->has_value() && **r->value.s == "hi" && r->rest.empty());
  std::vector<std::byte> back;
  nm::thrift_compact_encode(r->value, back);
  CHECK(back == wire);

  // optional absent; unknown fields of every kind skipped (i64, double, list<string>, map, struct)
  auto w2 = B({0x15, 0x04,                               // a = 2
               0x26, 0x02,                               // id 3: i64 = 1
               0x17, 1, 2, 3, 4, 5, 6, 7, 8,             // id 4: double
               0x19, 0x28, 0x01, 'a', 0x01, 'b',         // id 5: list<binary> ["a","b"]
               0x1b, 0x01, 0x55, 0x02, 0x04,             // id 6: map<i32,i32> {1:2}
               0x1c, 0x15, 0x02, 0x11, 0x00,             // id 7: struct {1: i32, 2: bool true}
               0x00});
  auto r2 = nm::thrift_compact<Inner>()(I(w2));
  CHECK(r2 && *r2->value.a == 2 && !r2->value.s->has_value() && r2->rest.empty());
}

static void test_thrift_roundtrip() {
  Seed seed;
  seed.nums = std::vector<int32_t>{1, -1, 1 << 20, INT32_MIN, INT32_MAX};
  seed.later = Inner{42, std::string_view("lazy")};
  seed.bits = std::vector<bool>{true, false, true};
  std::vector<std::byte> seed_wire;
  nm::thrift_compact_encode(seed, seed_wire);
  auto sv = nm::thrift_compact<SeedView>()(I(seed_wire));
  CHECK(sv.has_value());
  if (!sv) return;

  Outer o;
  o.flag = true;
  o.tiny = int8_t(-5);
  o.small = int16_t(-300);
  o.big = int64_t(1) << 40;
  o.dbl = 2.5;
  o.color = Color::blue;
  o.name = std::string_view("hello");
  o.nums = *sv->value.nums;
  o.inners = std::vector<Inner>{Inner{7, std::nullopt}, Inner{8, std::string_view("x")}};
  o.maybe = Inner{9, std::string_view("maybe")};
  o.later = *sv->value.later;
  o.bits = *sv->value.bits;
  o.far = 99;
  o.marker = nm::empty_struct{};

  std::vector<std::byte> wire;
  nm::thrift_compact_encode(o, wire);
  auto r = nm::thrift_compact<Outer>()(I(wire));
  CHECK(r && r->rest.empty());
  if (!r) { std::puts(r.error().render(I(wire)).c_str()); return; }
  const Outer& d = r->value;
  CHECK(*d.flag && *d.tiny == -5 && *d.small == -300 && *d.big == (int64_t(1) << 40));
  CHECK(*d.dbl == 2.5 && *d.color == Color::blue && *d.name == "hello");
  CHECK(d.nums->size() == 5);
  auto nums = d.nums->to_vector();
  CHECK(nums && *nums == (std::vector<int32_t>{1, -1, 1 << 20, INT32_MIN, INT32_MAX}));
  CHECK(d.nums->at(3) && *d.nums->at(3) == INT32_MIN && !d.nums->at(5));
  CHECK(d.inners->size() == 2 && *(*d.inners)[1].a == 8 && **(*d.inners)[1].s == "x");
  CHECK(d.maybe->has_value() && *(**d.maybe).a == 9);
  auto lz = d.later->decode();
  CHECK(lz && *lz->a == 42 && **lz->s == "lazy");
  auto bits = d.bits->to_vector();
  CHECK(bits && *bits == (std::vector<bool>{true, false, true}));
  CHECK(**d.far == 99 && *d.dflt == 0 && d.marker->has_value());

  // re-encoding the decoded value is byte-identical (lazy members re-emit their exact bytes)
  std::vector<std::byte> again;
  nm::thrift_compact_encode(d, again);
  CHECK(again == wire);

  // for_each early stop
  int seen = 0;
  CHECK(d.nums->for_each([&](int32_t) { return ++seen < 2; }) && seen == 2);
}

static void test_thrift_rejects() {
  // required field missing: Inner without field 1
  auto miss = B({0x28, 0x01, 'z', 0x00});
  auto r = nm::thrift_compact<Inner>()(I(miss));
  CHECK(!r && std::string_view(r.error().expected) == "every required thrift field");
  // wire type mismatch on a REQUIRED field: skipped (Thrift semantics), then the message fails
  // the required-field check
  auto mm = nm::thrift_compact<Inner>()(I(B({0x18, 0x01, 'q', 0x00})));
  CHECK(!mm && std::string_view(mm.error().expected) == "every required thrift field");
  // ... on an OPTIONAL field: skipped, the message decodes, the member stays absent
  auto mo = nm::thrift_compact<Inner>()(I(B({0x15, 0x04, 0x15, 0x06, 0x00})));  // field 2 (string) sent as i32
  CHECK(mo && *mo->value.a == 2 && !mo->value.s->has_value() && mo->rest.empty());
  // i32 member receiving an out-of-range i32 varint (2^31 zigzag-encoded)
  CHECK(!nm::thrift_compact<Inner>()(I(B({0x15, 0x80, 0x80, 0x80, 0x80, 0x10, 0x00}))));
  // truncated string length
  CHECK(!nm::thrift_compact<Inner>()(I(B({0x15, 0x02, 0x28, 0x05, 'a', 0x00}))));
  // missing STOP
  auto nostop = nm::thrift_compact<Inner>()(nm::streaming(I(B({0x15, 0x02}))));
  CHECK(!nostop && nostop.error().kind == nm::errk::incomplete);
  // hostile list count: 2^31 elements announced in 8 bytes — rejected before any allocation
  CHECK(!nm::thrift_compact<Seed>()(I(B({0x89, 0xf5, 0x80, 0x80, 0x80, 0x80, 0x08, 0, 0, 0}))));
  // invalid compact type inside an unknown field
  CHECK(!nm::thrift_compact<Inner>()(I(B({0x15, 0x02, 0x2d, 0x00}))));
  // depth bomb: an unknown field nesting lists 10,000 deep must fail cleanly, not blow the stack
  std::vector<std::byte> bomb = B({0x15, 0x02, 0x39});
  for (int i = 0; i < 10000; ++i) bomb.push_back(std::byte(0x19));
  CHECK(!nm::thrift_compact<Inner>()(I(bomb)));
  // ... and nested structs too
  std::vector<std::byte> sbomb = B({0x15, 0x02});
  for (int i = 0; i < 10000; ++i) sbomb.push_back(std::byte(0x1c));
  CHECK(!nm::thrift_compact<Inner>()(I(sbomb)));
  // bool list element outside {0,1,2}
  std::vector<std::byte> badbool = B({0x89, 0x05, 0x3c, 0x15, 0x00, 0x00, 0x19, 0x11, 0x07, 0x00});
  auto bb = nm::thrift_compact<SeedView>()(I(badbool));
  CHECK(bb.has_value());  // structurally valid (a list<bool> elem is one byte) …
  if (bb) CHECK(!bb->value.bits->to_vector());  // … but decoding the element is rejected
}

// ------------------------------------------------------------------ parquet model
static void test_parquet_model_roundtrip() {
  // a minimal FileMetaData composed with the encoder, then decoded as the zero-copy model
  pq::SchemaElement root;
  root.name = std::string_view("schema");
  root.num_children = 1;
  pq::SchemaElement col;
  col.type = pq::Type::INT64;
  col.repetition_type = pq::FieldRepetitionType::OPTIONAL;
  col.name = std::string_view("ts");

  std::vector<std::byte> footer;
  nm::detail::tc::writer w{footer};
  // FileMetaData by hand-composition: 1:i32 version, 2:list<SchemaElement>, 3:i64 rows, 4:list<RowGroup>
  w.u8(0x15); w.varint(nm::zigzag_encode(int32_t(2)));
  w.u8(0x19); w.list_header(2, 12);
  nm::detail::tc::write_struct(w, root);
  nm::detail::tc::write_struct(w, col);
  w.u8(0x16); w.varint(nm::zigzag_encode(int64_t(3)));
  w.u8(0x19); w.list_header(0, 12);
  w.u8(0x28); w.varint(4); w.raw(reinterpret_cast<const std::byte*>("nmtt"), 4);  // 6: created_by
  w.u8(0x00);

  std::vector<std::byte> file = B({'P', 'A', 'R', '1'});
  file.insert(file.end(), footer.begin(), footer.end());
  const uint32_t len = uint32_t(footer.size());
  for (int i = 0; i < 4; ++i) file.push_back(std::byte(len >> (8 * i)));
  for (char c : std::string_view("PAR1")) file.push_back(std::byte(c));

  auto md = pq::read_file_metadata(I(file));
  CHECK(md.has_value());
  if (!md) { std::puts(md.error().render(I(file)).c_str()); return; }
  CHECK(*md->value.version == 2 && *md->value.num_rows == 3 && md->value.schema->size() == 2);
  CHECK(**md->value.created_by == "nmtt" && md->value.row_groups->empty());
  auto e1 = md->value.schema->at(1);
  CHECK(e1 && *e1->name == "ts" && *e1->type == pq::Type::INT64 &&
        *e1->repetition_type == pq::FieldRepetitionType::OPTIONAL && !e1->logicalType->has_value());

  // footer locator rejects bad magic / oversized length / encrypted footers
  auto bad = file;
  bad.back() = std::byte('X');
  CHECK(!pq::read_file_metadata(I(bad)));
  auto huge = file;
  huge[huge.size() - 5] = std::byte(0x7f);
  CHECK(!pq::read_file_metadata(I(huge)));
  auto enc = file;
  enc[enc.size() - 1] = std::byte('E');
  auto er = pq::read_file_metadata(I(enc));
  CHECK(!er && std::string_view(er.error().expected).find("encrypted") != std::string_view::npos);
}

int main() {
  test_uleb128();
  test_sleb128();
  test_zigzag_varint();
  test_guards_and_le_array();
  test_footer();
  test_thrift_handcoded();
  test_thrift_roundtrip();
  test_thrift_rejects();
  test_parquet_model_roundtrip();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("tagged tests: all passed");
  return 0;
}
