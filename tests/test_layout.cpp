// Tests for nanom/layout.hpp: the JSON reader, the description and enum loaders (incl. malformed
// input with line/column), type classification, name splitting and the name tree, bit-fields in
// both byte orders, sign extension, the stride rule, partial records, projection, the column
// kernels (both schedules) against a bit-by-bit reference, the exporters and the Arrow export.
// tests/layout_oracle.py adds the independent end-to-end check through the CLI.
#include <nanom/layout.hpp>

#include <cstdio>
#include <random>

namespace lay = nanom::layout;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

static std::string line(std::string_view raw, std::string_view name, std::uint64_t off, unsigned w,
                        std::string_view type) {
  return "{\"raw_file\":\"" + std::string(raw) + "\",\"scalar_name\":\"" + std::string(name) +
         "\",\"bit_offset\":" + std::to_string(off) + ",\"bit_width\":" + std::to_string(w) +
         ",\"type\":\"" + std::string(type) + "\"}\n";
}

static const char* kGfi = "/dev/vdiZ/pacemaker/gfi.raw";

static std::string gfi_desc() {
  std::string d;
  for (int k = 0; k < 2; ++k) {
    const unsigned b = 160 * k;
    d += line(kGfi, "GFI.grab_index", b + 0, 32, "UInt");
    d += line(kGfi, "GFI.slow_index", b + 32, 32, "UInt");
    d += line(kGfi, "GFI.tapi_index", b + 64, 32, "UInt");
    d += line(kGfi, "GFI.brain_type", b + 96, 32, "Enum ref = 1");
    d += line(kGfi, "GFI.BlackDummy", b + 128, 8, "Logical*1");
  }
  return d;
}
static const char* kGfiEnums =
    R"({ "/dev/vdiZ/pacemaker/gfi.raw": { "Enum ref = 1": { "-1": "UNDEF", "0": "IMG1", "1": "IMG2",
         "2": "IMG3", "3": "IMG4", "4": "IMG5", "5": "IMG6" } } })";

template <class T>
static void put(std::vector<std::byte>& b, std::size_t at, T v) {
  std::memcpy(b.data() + at, &v, sizeof v);
}

// ------------------------------------------------------------------ JSON reader
static void test_json() {
  auto j = lay::parse_json(R"( {"a": [1, -2.5e3, true, false, null], "s": "x\"\\\/\b\f\n\r\té😀", "o": {}} )");
  CHECK(j.has_value());
  if (j) {
    CHECK(j->is_object());
    const auto* a = j->find("a");
    CHECK(a && a->items.size() == 5 && a->items[0].is_int() && a->items[0].i == 1);
    CHECK(a && a->items[1].t == lay::json::type::real && a->items[1].d == -2500.0);
    CHECK(a && a->items[2].b && !a->items[3].b && a->items[4].t == lay::json::type::null);
    const auto* s = j->find("s");
    CHECK(s && s->s == "x\"\\/\b\f\n\r\t\xc3\xa9\xf0\x9f\x98\x80");
    CHECK(j->find("o") && j->find("o")->members.empty());
    CHECK(j->find("a")->offset == 7);
  }
  // errors carry the offset of the failure
  auto e = lay::parse_json(R"({"a" 1})");
  CHECK(!e && e.error().offset == 5 && e.error().what.find("':'") != std::string::npos);
  e = lay::parse_json(R"({"a":1,})");
  CHECK(!e);
  e = lay::parse_json(R"({"a":"unterminated)");
  CHECK(!e);
  e = lay::parse_json(R"("bad \q escape")");
  CHECK(!e && e.error().offset == 6);
  e = lay::parse_json("\"ctrl \x01 char\"");
  CHECK(!e);
  e = lay::parse_json("{} trailing");
  CHECK(!e && e.error().what.find("after the JSON value") != std::string::npos);
  e = lay::parse_json("[1, 2");
  CHECK(!e);
  e = lay::parse_json("");
  CHECK(!e);
  // depth limit: 64 ok, 65 refused
  CHECK(lay::parse_json(std::string(64, '[') + std::string(64, ']')).has_value());
  CHECK(!lay::parse_json(std::string(65, '[') + std::string(65, ']')).has_value());
  CHECK(!lay::parse_json(std::string(100000, '[')).has_value());  // no stack blow-up
  // lone surrogate -> U+FFFD; integers too big for int64 become reals
  j = lay::parse_json(R"(["\ud800x", 99999999999999999999])");
  CHECK(j && j->items[0].s == "\xef\xbf\xbdx" && j->items[1].t == lay::json::type::real);
}

// ------------------------------------------------------------------ types
static void test_types() {
  using lay::family;
  struct { const char* t; family f; int size; } cases[] = {
      {"UInt", family::unsigned_int, 4},   {"Int", family::signed_int, 4},
      {"ULongLong", family::unsigned_int, 8}, {"UChar", family::unsigned_int, 1},
      {"Char", family::signed_int, 1},     {"SChar", family::signed_int, 1},
      {"Short", family::signed_int, 2},    {"UShort", family::unsigned_int, 2},
      {"Long", family::signed_int, 8},     {"ULong", family::unsigned_int, 8},
      {"LongLong", family::signed_int, 8}, {"unsigned int", family::unsigned_int, 4},
      {"uint8_t", family::unsigned_int, 1}, {"Integer*2", family::signed_int, 2},
      {"Integer*8", family::signed_int, 8}, {"UInteger*4", family::unsigned_int, 4},
      {"Float", family::floating, 4},      {"Double", family::floating, 8},
      {"Real*4", family::floating, 4},     {"Real*8", family::floating, 8},
      {"Logical*1", family::boolean, 1},   {"Logical*4", family::boolean, 4},
      {"Bool", family::boolean, 1},        {"*Void", family::pointer, 0},
      {"*Diagnostics::DeviceStatus", family::pointer, 0}, {"char*", family::pointer, 0},
      {"Enum ref = 161", family::enumeration, 0}, {"Byte", family::unsigned_int, 1},
  };
  for (auto& c : cases) {
    auto ti = lay::classify_type(c.t);
    CHECK(ti && ti->fam == c.f && ti->size == c.size);
    if (!ti || ti->fam != c.f) std::printf("  type %s\n", c.t);
  }
  CHECK(lay::classify_type("Enum ref = 161")->enum_ref == 161);
  CHECK(lay::classify_type("Enum ref = -3")->enum_ref == -3);
  CHECK(!lay::classify_type("Quaternion"));
  CHECK(!lay::classify_type("Real*3"));
  CHECK(!lay::classify_type(""));
}

// ------------------------------------------------------------------ description loader
static std::string err_of(std::string_view text, lay::load_options o = {}) {
  auto d = lay::parse_description(text, o);
  return d ? std::string() : d.error().str();
}

static void test_description() {
  auto d = lay::parse_description(gfi_desc());
  CHECK(d && d->scalars.size() == 10 && d->raw_files.size() == 1);
  // whitespace, key order, extra keys, blank and comment lines, CRLF
  const std::string tolerant =
      "\r\n# comment\n   // another\n"
      "  { \"type\" : \"UInt\", \"bit_width\": 32 , \"extra\": {\"x\": [1, {\"y\": null}]},"
      " \"scalar_name\": \"A.b\", \"bit_offset\": 0, \"raw_file\": \"f\" }  \r\n"
      "{\"raw_file\":\"g\",\"scalar_name\":\"B\",\"bit_offset\":\"8\",\"bit_width\":8.0,\"type\":\"UChar\"}\n";
  d = lay::parse_description(tolerant);
  CHECK(d && d->scalars.size() == 2 && d->scalars[0].line == 4 && d->scalars[1].line == 5);
  CHECK(d && d->raw_files == (std::vector<std::string>{"f", "g"}));
  CHECK(d && d->scalars[1].bit_offset == 8 && d->scalars[1].bit_width == 8);
  // JSON array form
  d = lay::parse_description("[\n" + line("f", "a", 0, 8, "UChar").substr(0, line("f", "a", 0, 8, "UChar").size() - 1) +
                             ",\n" + line("f", "b", 8, 8, "UChar").substr(0, line("f", "a", 0, 8, "UChar").size() - 1) + "]");
  CHECK(d && d->scalars.size() == 2 && d->scalars[1].line == 3);

  // malformed lines: line:column and a useful message
  lay::load_options o;
  o.source = "desc.jsonl";
  std::string e = err_of(line("f", "a", 0, 8, "UChar") + "{\"raw_file\":\"f\" \"x\":1}\n", o);
  CHECK(e.starts_with("desc.jsonl:2:17:"));
  e = err_of("\n\n{\"raw_file\":\"f\",\"scalar_name\":\"a\",\"bit_offset\":0,\"type\":\"Int\"}", o);
  CHECK(e.starts_with("desc.jsonl:3:1:") && e.find("missing key \"bit_width\"") != std::string::npos);
  e = err_of(line("f", "a", 0, 0, "Int"), o);
  CHECK(e.find(":1:62:") != std::string::npos && e.find("bit_width must be 1..64, got 0") != std::string::npos);
  CHECK(err_of(line("f", "a", 0, 65, "Int")).find("1..64, got 65") != std::string::npos);
  CHECK(err_of("{\"raw_file\":\"f\",\"scalar_name\":\"a\",\"bit_offset\":-1,\"bit_width\":8,\"type\":\"Int\"}").find("non-negative") != std::string::npos);
  CHECK(err_of("{\"raw_file\":1,\"scalar_name\":\"a\",\"bit_offset\":0,\"bit_width\":8,\"type\":\"Int\"}").find("must be a string") != std::string::npos);
  CHECK(err_of("[1,2]").find("must be a JSON object") != std::string::npos);
  CHECK(err_of(line("f", "a", std::uint64_t(1) << 40, 8, "Int")).find("record size limit") != std::string::npos);
  CHECK(err_of(line("f", "", 0, 8, "Int")).find("scalar_name is empty") != std::string::npos);
  CHECK(err_of(line("f", "x", 0, 16, "Float")).find("needs bit_width 32") != std::string::npos);
  CHECK(err_of(line("f", "x", 0, 32, "Real*8")).find("needs bit_width 64") != std::string::npos);
  // unknown type: strict error with line, lenient warning + raw
  e = err_of(line("f", "a", 0, 8, "UChar") + line("f", "q", 8, 16, "Quaternion"), o);
  CHECK(e.starts_with("desc.jsonl:2:") && e.find("unknown type \"Quaternion\"") != std::string::npos);
  lay::load_options lenient;
  lenient.strict = false;
  d = lay::parse_description(line("f", "a", 0, 8, "UChar") + line("f", "q", 8, 16, "Quaternion") +
                             line("f", "c", 24, 32, "UChar"), lenient);
  CHECK(d && d->scalars[1].ti.fam == lay::family::raw && !d->scalars[1].known_type && d->warnings.size() == 2);
  // duplicates
  e = err_of(line("f", "a", 0, 8, "UChar") + line("f", "a", 0, 8, "UChar"));
  CHECK(e.find("duplicate scalar") != std::string::npos && e.find("first on line 1") != std::string::npos);
  d = lay::parse_description(line("f", "a", 0, 8, "UChar") + line("f", "a", 0, 8, "UChar"), lenient);
  CHECK(d && d->scalars.size() == 1);
  // file loading
  CHECK(!lay::load_description("/nonexistent/desc.jsonl"));
}

// ------------------------------------------------------------------ enums
static void test_enums() {
  auto c = lay::parse_enums(kGfiEnums);
  CHECK(c && c->size() == 1);
  auto t = c->find(kGfi, 1);
  CHECK(t && t->size() == 7 && t->has_negative());
  CHECK(t && *t->name(-1) == "UNDEF" && *t->name(5) == "IMG6" && !t->name(6) && !t->name(-2));
  CHECK(!c->find(kGfi, 2) && !c->find("other", 1));
  // keys: plain number, hex values, sparse table (binary search path)
  c = lay::parse_enums(R"({"f": {"7": {"0x10": "SIXTEEN", "-5": "M5", "1000000": "BIG"}}})");
  CHECK(c && c->find("f", 7) && *c->find("f", 7)->name(16) == "SIXTEEN" &&
        *c->find("f", 7)->name(1000000) == "BIG" && *c->find("f", 7)->name(-5) == "M5" && !c->find("f", 7)->name(17));
  // errors with line:column
  auto e = lay::parse_enums("{\"f\": {\"Enum ref = 1\": {\n  \"zero\": \"Z\"}}}", "enums.json");
  CHECK(!e && e.error().str().starts_with("enums.json:2:3:") && e.error().message.find("not an integer") != std::string::npos);
  e = lay::parse_enums("{\"f\": {\"Enum ref = 1\": {\"0\": 5}}}");
  CHECK(!e && e.error().message.find("must be a string") != std::string::npos);
  e = lay::parse_enums("{\"f\": {\"Enum thing\": {}}}");
  CHECK(!e && e.error().message.find("Enum ref = <integer>") != std::string::npos);
  e = lay::parse_enums("[]");
  CHECK(!e);
  e = lay::parse_enums("{\"f\": {\"Enum ref = 1\": {\"0\": \"A\",}}}");
  CHECK(!e && e.error().line == 1);
}

// ------------------------------------------------------------------ names and the tree
static std::string json_of(const lay::plan& p, std::span<const std::byte> data, const lay::selection& s) {
  std::string out;
  auto n = lay::export_jsonl(p, data, [&](std::string_view v) { out += v; }, s);
  CHECK(n.has_value());
  return out;
}

static void test_names() {
  auto v = lay::split_name("MEIO::IOAppDevices._board.Diagnostics::DeviceStatus._cslEnabled");
  CHECK(v.size() == 4 && v[0] == "MEIO::IOAppDevices" && v[2] == "Diagnostics::DeviceStatus");
  v = lay::split_name("MEIO::InputFrame.vids.defaultMappedType._value.lastFSTimestamp.long>._M_i");
  CHECK(v.size() == 7 && v[5] == "long>" && v[6] == "_M_i");
  v = lay::split_name("a..b.");
  CHECK(v.size() == 4 && v[1].empty() && v[3].empty());
  CHECK(lay::split_name("x").size() == 1);

  // a tree with ::, atomic internals, 1-based and gappy array_item_N, an implicit array
  const char* f = "/proc/app/devices.raw";
  std::string d;
  d += line(f, "MEIO::IOAppDevices._board.Diagnostics::DeviceStatus._cslEnabled", 0, 8, "Logical*1");
  d += line(f, "MEIO::IOAppDevices._board.Diagnostics::DeviceStatus._state", 32, 32, "Enum ref = 161");
  d += line(f, "MEIO::IOAppDevices._uart.array_item_1._total.int>._M_i", 64, 32, "UInt");
  d += line(f, "MEIO::IOAppDevices._uart.array_item_1._in", 96, 8, "UChar");
  d += line(f, "MEIO::IOAppDevices._uart.array_item_2._total.int>._M_i", 128, 32, "UInt");
  d += line(f, "MEIO::IOAppDevices._uart.array_item_2._in", 160, 8, "UChar");
  d += line(f, "MEIO::IOAppDevices._buf.array_item_0", 168, 8, "UChar");
  d += line(f, "MEIO::IOAppDevices._buf.array_item_2", 176, 8, "UChar");  // gap at 1 -> null
  d += line(f, "MEIO::IOAppDevices.vids._vptr.MapContainer", 192, 64, "*Void");
  d += line(f, "MEIO::IOAppDevices.rep.x", 256, 16, "Short");  // repeated leaf only: "x":[..]
  d += line(f, "MEIO::IOAppDevices.rep.x", 272, 16, "Short");
  d += line(f, "MEIO::IOAppDevices.rep.y", 288, 16, "Short");
  auto desc = lay::parse_description(d);
  CHECK(desc.has_value());
  auto en = lay::parse_enums(R"({"/proc/app/devices.raw": {"Enum ref = 161": {"2": "RUNNING"}}})");
  auto p = lay::plan::compile(*desc, f, &*en);
  CHECK(p.has_value());
  if (!p) return;
  CHECK(p->stride() == 40);  // 38 bytes used, pointer alignment 8
  std::vector<std::byte> rec(40);
  put<std::uint8_t>(rec, 0, 1);
  put<std::int32_t>(rec, 4, 2);
  put<std::uint32_t>(rec, 8, 11);
  put<std::uint8_t>(rec, 12, 12);
  put<std::uint32_t>(rec, 16, 21);
  put<std::uint8_t>(rec, 20, 22);
  put<std::uint8_t>(rec, 21, 7);
  put<std::uint8_t>(rec, 22, 9);
  put<std::uint64_t>(rec, 24, 0xdeadbeef00ull);
  put<std::int16_t>(rec, 32, -1);
  put<std::int16_t>(rec, 34, 3);
  put<std::int16_t>(rec, 36, -300);
  const std::string got = json_of(*p, rec, p->all());
  const std::string want =
      R"({"MEIO::IOAppDevices":{"_board":{"Diagnostics::DeviceStatus":{"_cslEnabled":true,"_state":"RUNNING"}},)"
      R"("_uart":[{"_total":{"int>":{"_M_i":11}},"_in":12},{"_total":{"int>":{"_M_i":21}},"_in":22}],)"
      R"("_buf":[7,null,9],"vids":{"_vptr":{"MapContainer":"0xdeadbeef00"}},"rep":{"x":[-1,3],"y":-300}}})"
      "\n";
  CHECK(got == want);
  if (got != want) std::printf("  got  %s  want %s", got.c_str(), want.c_str());
  CHECK(p->fields()[9].column == "MEIO::IOAppDevices.rep.x[0]" && p->fields()[10].column == "MEIO::IOAppDevices.rep.x[1]");
  CHECK(p->find("MEIO::IOAppDevices.rep.x")->index == 9);  // scalar name -> first occurrence
  // projection keeps array positions up to the last selected element
  auto s = p->select({"MEIO::IOAppDevices._buf.array_item_2"});
  CHECK(s && json_of(*p, rec, *s) == "{\"MEIO::IOAppDevices\":{\"_buf\":[null,null,9]}}\n");
  s = p->select({"MEIO::IOAppDevices._uart.array_item_1"});
  CHECK(s && s->fields.size() == 2 && json_of(*p, rec, *s) ==
                                          "{\"MEIO::IOAppDevices\":{\"_uart\":[{\"_total\":{\"int>\":{\"_M_i\":11}},\"_in\":12}]}}\n");

  // empty components and scalar-vs-struct conflicts: strict errors, lenient tolerates
  auto bad = lay::parse_description(line("f", "a..b", 0, 8, "UChar"));
  CHECK(bad && !lay::plan::compile(*bad, "f"));
  bad = lay::parse_description(line("f", "a.b", 0, 8, "UChar") + line("f", "a.b.c", 8, 8, "UChar"));
  auto bp = lay::plan::compile(*bad, "f");
  CHECK(!bp && bp.error().message.find("both a scalar and the parent") != std::string::npos);
  lay::compile_options lo;
  lo.strict = false;
  bp = lay::plan::compile(*bad, "f", nullptr, lo);
  CHECK(bp.has_value());
  if (bp) {
    std::vector<std::byte> r2{std::byte{5}, std::byte{6}};
    CHECK(json_of(*bp, r2, bp->all()) == "{\"a\":{\"b\":{\"_value\":5,\"c\":6}}}\n");
  }
}

// ------------------------------------------------------------------ GFI end to end
static void test_gfi() {
  auto desc = lay::parse_description(gfi_desc());
  auto en = lay::parse_enums(kGfiEnums);
  auto p = lay::plan::compile(*desc, kGfi, &*en);
  CHECK(p && p->stride() == 40 && p->used_bytes() == 37 && p->alignment() == 4);
  if (!p) return;
  std::vector<std::byte> data(3 * 40);
  for (int r = 0; r < 3; ++r)
    for (int k = 0; k < 2; ++k) {
      const std::size_t b = std::size_t(r) * 40 + std::size_t(k) * 20;
      put<std::uint32_t>(data, b + 0, std::uint32_t(100 * r + 10 * k + 1));
      put<std::uint32_t>(data, b + 4, std::uint32_t(100 * r + 10 * k + 2));
      put<std::uint32_t>(data, b + 8, 0xffffffffu);
      put<std::int32_t>(data, b + 12, r == 0 ? -1 : r == 1 ? 4 : 77);
      put<std::uint8_t>(data, b + 16, std::uint8_t(k));
    }
  const std::string j = json_of(*p, data, p->all());
  CHECK(j.starts_with(
      "{\"GFI\":[{\"grab_index\":1,\"slow_index\":2,\"tapi_index\":4294967295,\"brain_type\":\"UNDEF\",\"BlackDummy\":false},"
      "{\"grab_index\":11,\"slow_index\":12,\"tapi_index\":4294967295,\"brain_type\":\"UNDEF\",\"BlackDummy\":true}]}\n"));
  CHECK(j.find("\"brain_type\":\"IMG5\"") != std::string::npos && j.find("\"brain_type\":77") != std::string::npos);

  // columns
  auto t = lay::decode(*p, data);
  CHECK(t && t->rows() == 3 && t->columns() == 10);
  if (t) {
    auto g1 = t->column<std::uint32_t>("GFI[1].grab_index");
    CHECK(g1.size() == 3 && g1[0] == 11 && g1[2] == 211);
    auto bt = t->column<std::int32_t>("GFI.brain_type");  // scalar name = first occurrence
    CHECK(bt.size() == 3 && bt[0] == -1 && bt[1] == 4);
    CHECK(t->column<std::uint32_t>("GFI.brain_type").empty());  // wrong element type
    auto bd = t->column<bool>("GFI[1].BlackDummy");
    CHECK(bd.size() == 3 && bd[0]);
    CHECK(t->cell(0, 3).enum_name() && *t->cell(0, 3).enum_name() == "UNDEF");
  }
  // random access via handles
  const auto brain = p->find("GFI[1].brain_type").value();
  const auto recs = p->records(data);
  CHECK(recs.size() == 3 && recs.tail_bytes() == 0);
  CHECK(recs[0].get<int>(brain) == -1 && recs[2].get<long>(brain) == 77 && recs[1].get<double>(brain) == 4.0);
  CHECK(recs[0].get<std::uint32_t>(p->find("GFI[0].tapi_index").value()) == 0xffffffffu);
  CHECK(!recs.at(3) && recs.at(2));
  int n = 0;
  for (auto r : recs) n += r.get<int>(p->find("GFI[0].grab_index").value()) % 100 == 1;
  CHECK(n == 3);
  // CSV
  std::string csv;
  CHECK(lay::export_csv(*p, data, [&](std::string_view s) { csv += s; }, p->all()).has_value());
  CHECK(csv.starts_with("GFI[0].grab_index,GFI[0].slow_index,GFI[0].tapi_index,GFI[0].brain_type,GFI[0].BlackDummy,GFI[1].grab_index"));
  CHECK(csv.find("\n1,2,4294967295,UNDEF,false,11,12,4294967295,UNDEF,true\n") != std::string::npos);

  // stride rules: override, per-file override, too small, partial tail
  lay::compile_options o;
  o.stride = 48;
  CHECK(lay::plan::compile(*desc, kGfi, nullptr, o)->stride() == 48);
  o.stride_by_file[kGfi] = 44;
  CHECK(lay::plan::compile(*desc, kGfi, nullptr, o)->stride() == 44);
  o.stride_by_file[kGfi] = 36;
  auto small = lay::plan::compile(*desc, kGfi, nullptr, o);
  CHECK(!small && small.error().message.find("smaller than the 37 bytes") != std::string::npos);
  CHECK(!lay::plan::compile(*desc, "nope"));
  std::vector<std::byte> partial(data.begin(), data.end() - 3);
  CHECK(p->records(partial).size() == 2 && p->records(partial).tail_bytes() == 37);
  auto pt = lay::decode(*p, partial);
  CHECK(!pt && pt.error().message.find("partial record of 37 bytes") != std::string::npos);
  lay::decode_options allow;
  allow.allow_partial = true;
  pt = lay::decode(*p, partial, allow);
  CHECK(pt && pt->rows() == 2 && pt->tail_bytes() == 37);
  // record range
  lay::decode_options range;
  range.first = 1;
  range.count = 5;
  auto rt = lay::decode(*p, data, range);
  CHECK(rt && rt->rows() == 2 && rt->first_record() == 1 && rt->column<std::uint32_t>(0)[0] == 101);
  // caller-provided buffers
  const auto sel = *p->select({"GFI[1].grab_index", "*.BlackDummy"});
  CHECK(sel.fields.size() == 3);
  const lay::decoder dec(*p, sel);
  std::vector<std::uint32_t> a(3);
  std::vector<std::uint8_t> b0(3), b1(3);
  lay::column_out outs[] = {{reinterpret_cast<std::byte*>(b0.data()), 3},
                            {reinterpret_cast<std::byte*>(a.data()), 12},
                            {reinterpret_cast<std::byte*>(b1.data()), 3}};
  auto got = lay::decode_into(dec, *p, data, outs);
  CHECK(got && *got == 3 && a[1] == 111 && b0[0] == 0 && b1[0] == 1);
  outs[1].bytes = 11;
  CHECK(!lay::decode_into(dec, *p, data, outs));
  CHECK(!lay::decode_into(dec, *p, data, std::span(outs, 2)));
  // selection errors
  CHECK(!p->select({"GFI.nope"}));
  CHECK(p->select({"GFI"})->fields.size() == 10);
  CHECK(p->select({"GFI[0]"})->fields.size() == 5);
  CHECK(p->select({"GFI.*_index"})->fields.size() == 6);
  CHECK(p->select({"GFI?1?.slow_index"})->fields.size() == 1);
}

// ------------------------------------------------------------------ bit-fields: reference check
/// Bit-by-bit reference: LSB-first bit numbering over little-endian bytes, or MSB-first over
/// big-endian bytes.
static std::uint64_t ref_bits(std::span<const std::byte> rec, std::uint64_t off, unsigned w, bool be) {
  std::uint64_t v = 0;
  for (unsigned i = 0; i < w; ++i) {
    const std::uint64_t bit = off + i;
    const unsigned byte = unsigned(std::uint8_t(rec[bit / 8]));
    const unsigned b = be ? (byte >> (7 - bit % 8)) & 1 : (byte >> (bit % 8)) & 1;
    if (be) v = (v << 1) | b;
    else v |= std::uint64_t(b) << i;
  }
  return v;
}

static void test_bitfields_random() {
  std::mt19937_64 rng(12345);
  const char* types[] = {"UInt", "Int", "ULongLong", "LongLong", "UChar", "Char", "Logical*4", "*Void", "Enum ref = 2"};
  for (int round = 0; round < 300; ++round) {
    const bool be = round % 2;
    const std::size_t used = 1 + rng() % (round % 5 == 0 ? 7 : 40);  // some records < 8 bytes
    std::string d;
    std::vector<std::pair<std::uint64_t, unsigned>> f;
    std::vector<const char*> ty;
    const int nf = 1 + int(rng() % 12);
    for (int i = 0; i < nf; ++i) {
      unsigned w = 1 + unsigned(rng() % std::min<std::uint64_t>(64, used * 8));
      if (rng() % 3 == 0) w = std::min<unsigned>(unsigned(used * 8), (8u << (rng() % 4)));
      std::uint64_t off = rng() % (used * 8 - w + 1);
      if (rng() % 3 == 0) off &= ~std::uint64_t(7);
      const char* t = types[rng() % std::size(types)];
      if (std::string_view(t) == "Logical*4" || std::string_view(t) == "UChar" || std::string_view(t) == "Char")
        t = w <= 8 ? t : "UInt";
      d += line("r", "s.f" + std::to_string(i), off, w, t);
      f.emplace_back(off, w);
      ty.push_back(t);
    }
    lay::load_options lo;
    lo.strict = false;  // UInt with width > 32 is a warning only
    auto desc = lay::parse_description(d, lo);
    CHECK(desc.has_value());
    if (!desc) continue;
    lay::compile_options co;
    co.order = be ? std::endian::big : std::endian::little;
    auto en = lay::parse_enums(round % 4 < 2 ? R"({"r": {"2": {"-1": "NEG", "1": "ONE"}}})" : R"({"r": {"2": {"1": "ONE"}}})");
    auto p = lay::plan::compile(*desc, "r", &*en, co);
    CHECK(p.has_value());
    if (!p) continue;
    const std::size_t nrec = 1 + rng() % 50;
    std::vector<std::byte> data(nrec * p->stride());
    for (auto& b : data) b = std::byte(rng());
    auto tf = lay::decode(*p, data, {0, std::size_t(-1), false, lay::strategy::field_major});
    auto tr = lay::decode(*p, data, {0, std::size_t(-1), false, lay::strategy::record_major});
    CHECK(tf && tr);
    if (!tf || !tr) continue;
    const auto recs = p->records(data);
    for (std::size_t r = 0; r < nrec; ++r)
      for (std::size_t i = 0; i < f.size(); ++i) {
        const auto& fd = p->fields()[i];
        std::uint64_t want = ref_bits(recs[r].bytes(), f[i].first, f[i].second, be);
        const unsigned w = f[i].second;
        if (fd.acc.sign && w < 64 && (want >> (w - 1)) & 1) want |= ~std::uint64_t(0) << w;
        const auto got = recs[r].value(p->handle(std::uint32_t(i)));
        bool ok = got.bits == want;
        if (fd.st == lay::storage::boolean) ok = (got.bits != 0) == (want != 0);
        // columns hold the value truncated to the column width (or 0/1 for booleans)
        const std::size_t sz = lay::storage_size(fd.st);
        const std::uint64_t mask = sz == 8 ? ~std::uint64_t(0) : (std::uint64_t(1) << (8 * sz)) - 1;
        const std::uint64_t colwant = fd.st == lay::storage::boolean ? (want != 0) : want & mask;
        const auto cf = tf->cell(r, i), cr = tr->cell(r, i);
        ok = ok && (cf.bits & mask) == colwant && (cr.bits & mask) == colwant;
        CHECK(ok);
        if (!ok) {
          std::printf("  round %d rec %zu field %zu off %llu w %u type %s be %d stride %zu: got %llx want %llx\n",
                      round, r, i, (unsigned long long)f[i].first, w, ty[i], be, p->stride(),
                      (unsigned long long)got.bits, (unsigned long long)want);
          return;
        }
      }
  }
}

static void test_sign_and_floats() {
  std::string d;
  d += line("x", "s3", 0, 3, "Int");        // bits 0..2
  d += line("x", "u3", 3, 3, "UInt");       // bits 3..5
  d += line("x", "c", 8, 8, "Char");
  d += line("x", "uc", 8, 8, "UChar");      // union-style overlap with c
  d += line("x", "f", 32, 32, "Real*4");
  d += line("x", "g", 64, 64, "Double");
  d += line("x", "nan", 128, 32, "Float");
  d += line("x", "big", 192, 64, "ULongLong");
  d += line("x", "neg", 256, 64, "LongLong");
  d += line("x", "e3", 320, 3, "Enum ref = 9");  // enum bit-field, no negatives -> unsigned
  d += line("x", "e3n", 323, 3, "Enum ref = 8"); // with negatives -> signed
  auto desc = lay::parse_description(d);
  auto en = lay::parse_enums(R"({"x": {"9": {"7": "SEVEN"}, "8": {"-1": "MINUS"}}})");
  auto p = lay::plan::compile(*desc, "x", &*en);
  CHECK(p.has_value());
  if (!p) return;
  CHECK(p->stride() == 48);
  std::vector<std::byte> r(48);
  put<std::uint8_t>(r, 0, 0b101'110);  // s3 = 110b = -2, u3 = 101b = 5
  put<std::uint8_t>(r, 1, 0xfe);
  put<float>(r, 4, 1.5f);
  put<double>(r, 8, -0.1);
  put<std::uint32_t>(r, 16, 0x7fc00000u);
  put<std::uint64_t>(r, 24, ~std::uint64_t(0));
  put<std::int64_t>(r, 32, std::numeric_limits<std::int64_t>::min());
  put<std::uint8_t>(r, 40, 0b111'111);
  const auto rec = *p->view(r);
  CHECK(rec.get<int>(p->find("s3").value()) == -2 && rec.get<int>(p->find("u3").value()) == 5);
  CHECK(rec.get<int>(p->find("c").value()) == -2 && rec.get<int>(p->find("uc").value()) == 254);
  CHECK(rec.get<float>(p->find("f").value()) == 1.5f && rec.get<double>(p->find("g").value()) == -0.1);
  CHECK(rec.get<std::uint64_t>(p->find("big").value()) == ~std::uint64_t(0));
  CHECK(rec.get<std::int64_t>(p->find("neg").value()) == std::numeric_limits<std::int64_t>::min());
  CHECK(p->fields()[9].st == lay::storage::u8 && p->fields()[10].st == lay::storage::i8);
  CHECK(!p->view(std::span(r).first(47)));
  const std::string j = json_of(*p, r, p->all());
  const std::string jwant = "{\"s3\":-2,\"u3\":5,\"c\":-2,\"uc\":254,\"f\":1.5,\"g\":-0.1,\"nan\":null,\"big\":18446744073709551615,"
             "\"neg\":-9223372036854775808,\"e3\":\"SEVEN\",\"e3n\":\"MINUS\"}\n";
  CHECK(j == jwant);
  if (j != jwant) std::printf("  got %s", j.c_str());
}

// ------------------------------------------------------------------ Arrow
static void test_arrow() {
  auto desc = lay::parse_description(gfi_desc());
  auto p = lay::plan::compile(*desc, kGfi);
  std::vector<std::byte> data(40 * 10);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = std::byte(i % 3 == 0 ? 0 : i);
  auto t = lay::decode(*p, data);
  ArrowSchema s{};
  ArrowArray a{};
  lay::export_arrow(std::move(*t), &s, &a);
  CHECK(std::string_view(s.format) == "+s" && s.n_children == 10 && a.n_children == 10 && a.length == 10);
  CHECK(std::string_view(s.children[0]->format) == "I" && std::string_view(s.children[3]->format) == "i" &&
        std::string_view(s.children[4]->format) == "b");
  CHECK(std::string_view(s.children[5]->name) == "GFI[1].grab_index");
  std::uint32_t v0;
  std::memcpy(&v0, data.data(), 4);
  CHECK(static_cast<const std::uint32_t*>(a.children[0]->buffers[1])[0] == v0);
  const auto* bm = static_cast<const std::uint8_t*>(a.children[4]->buffers[1]);
  for (int r = 0; r < 10; ++r) CHECK(((bm[r / 8] >> (r % 8)) & 1) == (data[std::size_t(r) * 40 + 16] != std::byte{0}));
  // move one child out, release the parent, then the child: no leak, no double free (ASan)
  ArrowArray child = *a.children[2];
  a.children[2]->release = nullptr;
  a.release(&a);
  s.release(&s);
  CHECK(a.release == nullptr && s.release == nullptr);
  CHECK(static_cast<const std::uint32_t*>(child.buffers[1])[1] != 0xdeadbeef || true);
  child.release(&child);
}


// ------------------------------------------------------------------ hostile descriptions
/// Mutated descriptions / enum files must fail cleanly or compile into plans whose decode stays in
/// bounds (ASan/UBSan builds make any slip fatal).
static void test_mutations() {
  std::mt19937 rng(7);
  const std::string base = gfi_desc() + line(kGfi, "GFI.bits.x", 300, 13, "Int") + line(kGfi, "GFI.f", 320, 32, "Float");
  const std::string ebase = kGfiEnums;
  const char junk[] = "{}[]\",:0123456789-+.eE \n\\u\x01\xff*abcnulltrue";
  std::vector<std::byte> data(400);
  for (auto& b : data) b = std::byte(rng());
  int compiled = 0;
  for (int it = 0; it < 3000; ++it) {
    std::string d = base, e = ebase;
    std::string& t = it % 4 == 3 ? e : d;
    for (int m = 1 + int(rng() % 4); m-- > 0;) {
      const std::size_t at = rng() % t.size();
      switch (rng() % 3) {
        case 0: t[at] = junk[rng() % (sizeof junk - 1)]; break;
        case 1: t.erase(at, 1 + rng() % 8); break;
        default: t.insert(at, 1, junk[rng() % (sizeof junk - 1)]); break;
      }
      if (t.empty()) t = "{";
    }
    lay::load_options lo;
    lo.strict = it % 2;
    auto desc = lay::parse_description(d, lo);
    auto en = lay::parse_enums(e);
    if (!desc) { CHECK(!desc.error().message.empty()); continue; }
    for (const auto& rf : desc->raw_files) {
      lay::compile_options co;
      co.strict = lo.strict;
      co.order = it % 3 ? std::endian::little : std::endian::big;
      auto p = lay::plan::compile(*desc, rf, en ? &*en : nullptr, co);
      if (!p) continue;
      ++compiled;
      lay::decode_options o;
      o.allow_partial = true;
      auto t1 = lay::decode(*p, data, o);
      CHECK(t1.has_value());
      std::string out;
      (void)lay::export_jsonl(*p, data, [&](std::string_view v) { out += v; }, p->all(), o);
      (void)lay::export_csv(*p, data, [&](std::string_view v) { out += v; }, p->all(), o);
    }
  }
  CHECK(compiled > 100);
}

int main() {
  test_json();
  test_types();
  test_description();
  test_enums();
  test_names();
  test_gfi();
  test_bitfields_random();
  test_sign_and_floats();
  test_arrow();
  test_mutations();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("layout tests: all passed");
  return 0;
}
