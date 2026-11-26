// Tests for the AUTOSAR parts of nanom/layout.hpp: signal description keys, Intel/Motorola bit
// placement (hand-computed DBC examples), encode (set / set_raw / encode) with range checks and
// rounding, decode(encode(x)) == x over random offsets / widths / byte orders / record sizes
// against a bit-by-bit DBC reference, multiplexing and update bits (nullable columns, JSON nulls,
// Arrow validity), physical columns and metadata, and E2E protect/check (golden vectors produced
// by the independent `autosar-e2e` package; tests/layout_autosar_oracle.py runs the live
// differential against it and against cantools).
#include <nanom/layout.hpp>

#include <cstdio>
#include <random>

namespace lay = nanom::layout;
namespace e2e = nanom::layout::e2e;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

static std::vector<std::byte> hex(std::string_view h) {
  std::vector<std::byte> v(h.size() / 2);
  for (std::size_t i = 0; i < v.size(); ++i) {
    unsigned b = 0;
    std::from_chars(h.data() + 2 * i, h.data() + 2 * i + 2, b, 16);
    v[i] = std::byte(b);
  }
  return v;
}
static std::string tohex(std::span<const std::byte> b) {
  std::string s;
  char t[3];
  for (auto x : b) { std::snprintf(t, sizeof t, "%02x", unsigned(x)); s += t; }
  return s;
}

static lay::plan compile(const std::string& desc, std::string_view raw = "P") {
  auto d = lay::parse_description(desc);
  if (!d) { std::printf("desc: %s\n", d.error().str().c_str()); std::abort(); }
  auto p = lay::plan::compile(*d, raw);
  if (!p) { std::printf("plan: %s\n", p.error().str().c_str()); std::abort(); }
  return std::move(*p);
}
static std::string compile_error(const std::string& desc) {
  auto d = lay::parse_description(desc);
  if (!d) return d.error().str();
  auto p = lay::plan::compile(*d, d->raw_files.at(0));
  return p ? std::string() : p.error().str();
}

// ------------------------------------------------------------------ hand-computed DBC examples
// Sawtooth (DBC) bit numbering, 8-byte PDU:
//
//   byte    0                        1                        2
//   bit     7  6  5  4  3  2  1  0 | 15 14 13 12 11 10  9  8 | 23 22 21 20 19 18 17 16 ...
//
// Intel  (little endian): start bit = LSB; the signal runs upward: bits 12..19 = byte 1 bits 4-7
//         (low nibble of the value), then byte 2 bits 0-3.
// Motorola (big endian):  start bit = MSB; the signal runs right along the row, then continues at
//         bit 7 of the NEXT byte: start 20, 10 bits = byte 2 bits 4..0, then byte 3 bits 7..3.
static void test_dbc_examples() {
  // M8 at start 51 = byte 6 bit 3: byte 6 bits 3..0 then byte 7 bits 7..4.
  const auto p = compile(
      R"({"raw_file":"P","scalar_name":"M16","bit_offset":7,"bit_width":16,"byte_order":"motorola","pdu_length":8}
{"raw_file":"P","scalar_name":"M10","bit_offset":20,"bit_width":10,"byte_order":"big_endian"}
{"raw_file":"P","scalar_name":"I8","bit_offset":36,"bit_width":8,"byte_order":"intel"}
{"raw_file":"P","scalar_name":"M8","bit_offset":51,"bit_width":8,"byte_order":"motorola","signed":true}
{"raw_file":"P","scalar_name":"M10lsb","bit_offset":27,"bit_width":10,"byte_order":"motorola","motorola_start":"lsb"}
)");
  std::vector<std::byte> b(8);
  CHECK(p.set_raw(*p.find("M16"), b, 0x1234).has_value());
  CHECK(p.set_raw(*p.find("M10"), b, 0x201).has_value());
  CHECK(p.set_raw(*p.find("I8"), b, 0xAB).has_value());
  CHECK(p.set_raw(*p.find("M8"), b, -86).has_value());  // 0xAA
  //        M16    M10   I8 (byte4 hi = B, byte5 lo = A)   M8 (byte6 lo = A, byte7 hi = A)
  CHECK(tohex(b) == "12341008b00a0aa0");
  // COM-style LSB start (27 = byte 3 bit 3) names the same bits as MSB start 20.
  const auto& f = p.fields()[4];
  CHECK(f.bit_offset == 20 && f.linear_offset == 19);
  const auto r = *p.view(b);
  CHECK(r.get<int>(*p.find("M10lsb")) == 0x201);
  CHECK(r.get<int>(*p.find("M8")) == -86 && r.get<int>(*p.find("I8")) == 0xAB);
  CHECK(r.get<int>(*p.find("M16")) == 0x1234 && r.get<int>(*p.find("M10")) == 0x201);
  // a Motorola signal that runs past the PDU end is caught at compile time (stride too small)
  CHECK(!compile_error(R"({"raw_file":"P","scalar_name":"X","bit_offset":59,"bit_width":8,"byte_order":"motorola","pdu_length":8})").empty());
}

// ------------------------------------------------------------------ reference + round trips
struct sig {
  bool motorola;
  std::uint64_t start;
  unsigned w;
  bool sign;
};
/// Bit-by-bit DBC reference: write `v` (w bits) into `b`.
static void ref_put(std::vector<std::byte>& b, const sig& s, std::uint64_t v) {
  for (unsigned i = 0; i < s.w; ++i) {
    std::uint64_t byte, bit;
    if (s.motorola) {  // value bit (w-1-i) at linear MSB-first position lin + i
      const std::uint64_t lin = lay::msb_linear(s.start) + i;
      byte = lin / 8; bit = 7 - lin % 8;
      const bool x = (v >> (s.w - 1 - i)) & 1;
      b[byte] = std::byte((std::uint8_t(b[byte]) & ~(1u << bit)) | (unsigned(x) << bit));
    } else {
      byte = (s.start + i) / 8; bit = (s.start + i) % 8;
      const bool x = (v >> i) & 1;
      b[byte] = std::byte((std::uint8_t(b[byte]) & ~(1u << bit)) | (unsigned(x) << bit));
    }
  }
}

static void test_round_trip() {
  std::mt19937_64 rng(42);
  int cases = 0;
  for (int it = 0; it < 4000; ++it) {
    const std::size_t n = 1 + rng() % 20;  // records 1..20 bytes: small, bits64 and bits72 loads
    const unsigned w = 1 + unsigned(rng() % std::min<std::uint64_t>(64, 8 * n));
    sig s{bool(rng() & 1), 0, w, w > 1 && bool(rng() & 1)};
    if (s.motorola) s.start = lay::msb_linear(rng() % (8 * n - w + 1));
    else s.start = rng() % (8 * n - w + 1);
    const bool scaled = rng() % 2;
    std::string d = "{\"raw_file\":\"P\",\"scalar_name\":\"S\",\"bit_offset\":" + std::to_string(s.start) +
                    ",\"bit_width\":" + std::to_string(w) + ",\"byte_order\":\"" +
                    (s.motorola ? "motorola" : "intel") + "\",\"signed\":" + (s.sign ? "true" : "false") +
                    ",\"pdu_length\":" + std::to_string(n) + (scaled ? ",\"factor\":0.25,\"offset\":-3" : "") + "}\n";
    const auto p = compile(d);
    const auto h = *p.find("S");
    std::vector<std::byte> bg(n), mine, want;
    for (auto& x : bg) x = std::byte(rng());
    const std::uint64_t mask = w == 64 ? ~0ull : (1ull << w) - 1;
    const std::uint64_t bits = rng() & mask;
    const std::int64_t val = s.sign && w < 64 && (bits >> (w - 1)) ? std::int64_t(bits | ~mask) : std::int64_t(bits);
    mine = bg;
    want = bg;
    ref_put(want, s, bits);
    bool ok = s.sign || w < 64 || val >= 0 ? p.set_raw(h, mine, val).has_value()
                                            : p.set_raw_unsigned(h, mine, bits).has_value();
    if (!s.sign && w == 64) ok = p.set_raw_unsigned(h, mine = bg, bits).has_value();
    CHECK(ok);
    if (mine != want) {
      ++failures;
      std::printf("FAIL round trip n=%zu %s start=%llu w=%u: %s != ref %s\n", n, s.motorola ? "motorola" : "intel",
                  (unsigned long long)s.start, w, tohex(mine).c_str(), tohex(want).c_str());
      continue;
    }
    // decode: record path and both column schedules
    const auto r = *p.view(mine);
    CHECK(r.value(h).bits == (s.sign ? std::uint64_t(val) : bits));
    for (auto strat : {lay::strategy::field_major, lay::strategy::record_major}) {
      lay::decode_options o;
      o.strat = strat;
      o.physical = true;
      auto t = lay::decode(p, mine, o);
      CHECK(t && t->rows() == 1 && t->cell(0, 0).bits == r.value(h).bits);
      if (t && scaled) CHECK(t->physical(0).size() == 1 && t->physical(0)[0] == r.physical(h));
    }
    // physical round trip (values that are exact: |raw| < 2^50)
    if (scaled && w <= 50) {
      const double phys = double(val) * 0.25 - 3;
      std::vector<std::byte> again = bg;
      CHECK(p.set(h, again, phys).has_value());
      CHECK(again == want);
      CHECK(p.view(again)->physical(h) == phys);
    }
    ++cases;
  }
  CHECK(cases == 4000);
}

static void test_ranges_rounding() {
  const auto p = compile(
      R"({"raw_file":"P","scalar_name":"U","bit_offset":0,"bit_width":4,"byte_order":"intel","pdu_length":8}
{"raw_file":"P","scalar_name":"S","bit_offset":8,"bit_width":4,"byte_order":"intel","signed":true}
{"raw_file":"P","scalar_name":"V","bit_offset":16,"bit_width":8,"byte_order":"intel","factor":0.5,"offset":-10,"min":-10,"max":50,"unit":"km/h"}
{"raw_file":"P","scalar_name":"F","bit_offset":39,"bit_width":32,"type":"Float","byte_order":"motorola","factor":2}
)");
  std::vector<std::byte> b(8);
  const auto U = *p.find("U"), S = *p.find("S"), V = *p.find("V"), F = *p.find("F");
  CHECK(p.set_raw(U, b, 15).has_value() && !p.set_raw(U, b, 16).has_value() && !p.set_raw(U, b, -1).has_value());
  CHECK(p.set_raw(S, b, -8).has_value() && p.set_raw(S, b, 7).has_value());
  CHECK(!p.set_raw(S, b, 8).has_value() && !p.set_raw(S, b, -9).has_value());
  // rounding: nearest, ties away from zero
  CHECK(p.set(U, b, 2.5).has_value() && p.view(b)->get<int>(U) == 3);
  CHECK(p.set(U, b, 2.49).has_value() && p.view(b)->get<int>(U) == 2);
  CHECK(p.set(S, b, -2.5).has_value() && p.view(b)->get<int>(S) == -3);
  CHECK(!p.set(U, b, 15.6).has_value());  // rounds to 16: out of range
  CHECK(p.set(U, b, 15.4).has_value() && p.view(b)->get<int>(U) == 15);
  CHECK(!p.set(U, b, std::nan("")).has_value() && !p.set(U, b, INFINITY).has_value());
  // physical range [min, max] and the raw range
  CHECK(p.set(V, b, 50).has_value() && p.view(b)->get<int>(V) == 120);
  CHECK(!p.set(V, b, 50.5).has_value() && !p.set(V, b, -10.5).has_value());
  auto e = p.set(V, b, 51);
  CHECK(!e && e.error().str().find("outside [-10, 50]") != std::string::npos);
  CHECK(p.set(V, b, 12.3).has_value() && p.view(b)->physical(V) == 12.5);  // raw 44.6 -> 45
  // untouched bits preserved: U, S still hold their values
  CHECK(p.view(b)->get<int>(U) == 15 && p.view(b)->get<int>(S) == -3);
  // IEEE float signal, Motorola: (physical - offset) / factor stored as float
  CHECK(p.set(F, b, 3.0).has_value());
  CHECK(tohex(std::span(b).subspan(4)) == "3fc00000");  // 1.5f big-endian
  CHECK(p.view(b)->physical(F) == 3.0);
  // buffer too short
  std::vector<std::byte> small(4);
  CHECK(!p.set(U, small, 1).has_value() && !p.set_raw(U, small, 1).has_value());
  // encode(): all or nothing
  std::vector<std::byte> c(8, std::byte{0x5A});
  const auto before = c;
  CHECK(!p.encode({{U, 3}, {V, 1000}}, c).has_value() && c == before);
  CHECK(p.encode({{U, 3}, {V, 20}, {S, -4, true}}, c).has_value());
  const auto r = *p.view(c);
  CHECK(r.get<int>(U) == 3 && r.physical(V) == 20 && r.get<int>(S) == -4);
  CHECK((std::uint8_t(c[0]) & 0xF0) == 0x50);  // the other nibble of byte 0 untouched
}

// ------------------------------------------------------------------ mux, update bits, columns
static const char* kMux =
    R"({"raw_file":"P","scalar_name":"Mux","bit_offset":0,"bit_width":4,"byte_order":"intel","multiplexor":true,"pdu_length":8}
{"raw_file":"P","scalar_name":"Speed","bit_offset":8,"bit_width":16,"byte_order":"intel","mux_value":1,"factor":0.01,"unit":"m/s"}
{"raw_file":"P","scalar_name":"Temp","bit_offset":15,"bit_width":12,"byte_order":"motorola","signed":true,"mux_value":[2,3],"factor":0.5,"offset":-40}
{"raw_file":"P","scalar_name":"Always","bit_offset":32,"bit_width":8,"byte_order":"intel","update_bit":40}
{"raw_file":"P","scalar_name":"Plain","bit_offset":48,"bit_width":8,"byte_order":"intel"}
)";

static void test_mux() {
  const auto p = compile(kMux);
  CHECK(p.conditional() && p.scaled() && p.stride() == 8);
  const auto Mux = *p.find("Mux"), Speed = *p.find("Speed"), Temp = *p.find("Temp"), Always = *p.find("Always"),
             Plain = *p.find("Plain");
  CHECK(p.fields()[Speed.index].sig.mux == Mux.index && p.fields()[Temp.index].sig.mux == Mux.index);
  std::vector<std::byte> data(8 * 4);
  auto pdu = [&](std::size_t i) { return std::span<std::byte>(data).subspan(8 * i, 8); };
  // pdu 0: group 1 + update bit; pdu 1: group 2; pdu 2: group 3 (no update); pdu 3: group 7
  CHECK(p.encode({{Mux, 1}, {Speed, 12.34}, {Always, 7}, {Plain, 1}}, pdu(0)).has_value());
  CHECK(p.encode({{Mux, 2}, {Temp, -12.5}, {Plain, 2}}, pdu(1)).has_value());
  CHECK(p.encode({{Mux, 3}, {Temp, 100}, {Plain, 3}}, pdu(2)).has_value());
  CHECK(p.encode({{Mux, 7}, {Plain, 4}}, pdu(3)).has_value());
  // a multiplexed signal of another group is refused (multiplexor given or already in the PDU)
  auto e = p.encode({{Mux, 2}, {Speed, 1}}, pdu(3));
  CHECK(!e && e.error().str().find("selects another signal group") != std::string::npos);
  CHECK(!p.encode({{Speed, 1}}, pdu(3)).has_value());
  CHECK(p.encode({{Temp, 0}}, pdu(1)).has_value() && p.encode({{Temp, -12.5}}, pdu(1)).has_value());
  CHECK(std::uint8_t(data[5]) == 1 && std::uint8_t(data[8 + 5]) == 0);  // update bit 40 set by encode
  const auto r0 = *p.view(pdu(0));
  CHECK(p.valid(r0, Speed) && !p.valid(r0, Temp) && p.valid(r0, Always) && p.valid(r0, Plain));
  CHECK(std::abs(r0.physical(Speed) - 12.34) < 1e-12);

  lay::decode_options o;
  o.physical = true;
  auto t = lay::decode(p, data, o);
  CHECK(t.has_value());
  if (!t) return;
  const auto cs = *t->find("Speed"), ct = *t->find("Temp"), ca = *t->find("Always"), cp = *t->find("Plain");
  CHECK(t->validity(cp).empty() && t->physical(cp).empty() && t->null_count(cp) == 0);
  CHECK(t->null_count(cs) == 3 && t->null_count(ct) == 2 && t->null_count(ca) == 3);
  CHECK(t->valid(0, cs) && !t->valid(1, cs) && t->valid(1, ct) && t->valid(2, ct) && !t->valid(3, ct));
  CHECK(t->physical(ct)[1] == -12.5 && t->physical(ct)[2] == 100);
  // JSON: nulls, physical values
  std::string js;
  lay::text_options to;
  to.physical = true;
  CHECK(lay::export_jsonl(p, data, [&](std::string_view s) { js += s; }, p.all(), {}, to).has_value());
  CHECK(js.find(R"({"Mux":1,"Speed":12.34,"Temp":null,"Always":7,"Plain":1})") == 0);
  CHECK(js.find(R"({"Mux":2,"Speed":null,"Temp":-12.5,"Always":null,"Plain":2})") != std::string::npos);
  std::string raw;
  CHECK(lay::export_jsonl(p, data, [&](std::string_view s) { raw += s; }, p.all()).has_value());
  CHECK(raw.find(R"({"Mux":1,"Speed":1234,"Temp":null,"Always":7,"Plain":1})") == 0);
  // the column path prints the same
  const lay::jsonl_writer w(p, p.all(), to);
  std::string viacols;
  const auto cols = w.bind(*t);
  for (std::size_t r = 0; r < t->rows(); ++r) w.write(viacols, *t, r, cols);
  CHECK(viacols == js);
  std::string csv;
  CHECK(lay::export_csv(p, data, [&](std::string_view s) { csv += s; }, p.all(), {}, to).has_value());
  CHECK(csv.find("Mux,Speed,Temp,Always,Plain\n1,12.34,,7,1\n2,,-12.5,,2\n") == 0);

  // Arrow: physical + raw sibling, nullable with validity bitmaps, signal metadata
  ArrowSchema s{};
  ArrowArray a{};
  lay::export_arrow(std::move(*t), &s, &a);
  CHECK(s.n_children == 7);  // Mux, Speed, Speed#raw, Temp, Temp#raw, Always, Plain
  auto child = [&](std::string_view n) -> int {
    for (int i = 0; i < s.n_children; ++i) if (n == s.children[i]->name) return i;
    return -1;
  };
  const int sp = child("Speed"), spr = child("Speed#raw"), tp = child("Temp"), al = child("Always"), pl = child("Plain");
  CHECK(sp >= 0 && spr >= 0 && tp >= 0 && al >= 0 && pl >= 0);
  if (sp >= 0 && spr >= 0 && al >= 0 && pl >= 0 && tp >= 0) {
    CHECK(std::string_view(s.children[sp]->format) == "g" && std::string_view(s.children[spr]->format) == "S");
    CHECK(s.children[sp]->flags == ARROW_FLAG_NULLABLE && s.children[pl]->flags == 0);
    CHECK(a.children[sp]->null_count == 3 && a.children[tp]->null_count == 2 && a.children[pl]->null_count == 0);
    const auto* vb = static_cast<const std::uint8_t*>(a.children[tp]->buffers[0]);
    CHECK(vb && vb[0] == 0b0110);
    CHECK(a.children[pl]->buffers[0] == nullptr);
    const auto* phys = static_cast<const double*>(a.children[tp]->buffers[1]);
    CHECK(phys[1] == -12.5);
    const auto md = lay::arrow_metadata(s.children[tp]->metadata);
    auto get = [&](std::string_view k) {
      for (auto& [kk, v] : md) if (kk == k) return v;
      return std::string("<none>");
    };
    CHECK(get("nanom.signal.factor") == "0.5" && get("nanom.signal.offset") == "-40");
    CHECK(get("nanom.signal.byte_order") == "motorola" && get("nanom.signal.mux_signal") == "Mux");
    CHECK(get("nanom.signal.mux_values") == "[2,3]" && get("nanom.signal.role") == "physical");
    const auto mds = lay::arrow_metadata(s.children[sp]->metadata);
    bool unit = false;
    for (auto& [k, v] : mds) unit |= k == "nanom.signal.unit" && v == "m/s";
    CHECK(unit);
    const auto mda = lay::arrow_metadata(s.children[al]->metadata);
    bool ub = false;
    for (auto& [k, v] : mda) ub |= k == "nanom.signal.update_bit" && v == "40";
    CHECK(ub);
  }
  a.release(&a);
  s.release(&s);
  // signal_mode::raw keeps one integer column per signal
  auto t2 = lay::decode(p, data, o);
  lay::arrow_options ao;
  ao.signals = lay::signal_mode::raw;
  lay::export_arrow(std::move(*t2), &s, &a, ao);
  CHECK(s.n_children == 5 && std::string_view(s.children[1]->format) == "S");
  a.release(&a);
  s.release(&s);
  // validity off: no nulls anywhere
  lay::decode_options nv;
  nv.validity = false;
  auto t3 = lay::decode(p, data, nv);
  CHECK(t3 && t3->validity(1).empty() && t3->physical(1).empty());
}

static void test_desc_errors() {
  auto err = [](std::string line) { return compile_error(line + "\n"); };
  const std::string head = R"({"raw_file":"P","scalar_name":"A","bit_offset":0,"bit_width":8,)";
  CHECK(err(head + R"("byte_order":"middle"})").find("byte_order") != std::string::npos);
  CHECK(err(head + R"("factor":0})").find("must not be 0") != std::string::npos);
  CHECK(err(head + R"("factor":"x"})").find("finite number") != std::string::npos);
  CHECK(err(head + R"("min":5,"max":1})").find("greater") != std::string::npos);
  CHECK(err(head + R"("mux_value":1})").find("0 multiplexor") != std::string::npos);
  CHECK(err(head + R"("multiplexor":true,"mux_value":1})").find("nested") != std::string::npos);
  CHECK(err(head + R"("mux_value":1,"mux_signal":"Nope"})").find("not a signal") != std::string::npos);
  CHECK(err(head + R"("type":"Float","bit_width":32,"signed":true})").find("does not apply") != std::string::npos);
  CHECK(err(head + R"("type":"Bool","factor":2})").find("do not apply") != std::string::npos);
  CHECK(err(head + R"("motorola_start":"lsb"})").find("needs") != std::string::npos);
  CHECK(err(head + R"("pdu_length":0})").find("pdu_length") != std::string::npos);
  CHECK(err(head + R"("pdu_length":8})" + "\n" +
            R"({"raw_file":"P","scalar_name":"B","bit_offset":8,"bit_width":8,"pdu_length":9})")
            .find("disagrees") != std::string::npos);
  // two multiplexors: mux_signal is required, and then resolves
  const std::string two = R"({"raw_file":"P","scalar_name":"M1","bit_offset":0,"bit_width":4,"multiplexor":true}
{"raw_file":"P","scalar_name":"M2","bit_offset":4,"bit_width":4,"multiplexor":true}
)";
  CHECK(err(two + R"({"raw_file":"P","scalar_name":"X","bit_offset":8,"bit_width":8,"mux_value":1})")
            .find("needs \"mux_signal\"") != std::string::npos);
  CHECK(err(two + R"({"raw_file":"P","scalar_name":"X","bit_offset":8,"bit_width":8,"mux_value":1,"mux_signal":"M2"})").empty());
  // a missing type is fine on signal lines (unsigned / signed by "signed"), not on plain lines
  CHECK(err(R"({"raw_file":"P","scalar_name":"A","bit_offset":0,"bit_width":40,"signed":true})").empty());
  CHECK(!err(R"({"raw_file":"P","scalar_name":"A","bit_offset":0,"bit_width":8})").empty());
  // start_bit alias
  CHECK(err(R"({"raw_file":"P","scalar_name":"A","start_bit":7,"bit_width":8,"byte_order":"motorola"})").empty());
  // a plain layout is untouched: no signal state
  const auto p = compile(R"({"raw_file":"P","scalar_name":"A","bit_offset":3,"bit_width":9,"type":"UInt"})");
  CHECK(!p.has_signals() && !p.conditional() && !p.scaled() && p.stride() == 4);
}

// ------------------------------------------------------------------ E2E
struct golden {
  e2e::profile prof;
  e2e::data_id_mode mode;
  std::uint32_t offset;
  std::uint32_t data_id;
  std::uint32_t counter;
  const char* in;
  const char* out;
};
// Produced by the `autosar-e2e` 1.0.0 Python package (e2e_pXX_protect(..., increment_counter=False,
// offset=offset/8) on the `in` PDU with the counter already in place); P02 data-ID list 0x10..0x1F.
static const golden kGolden[] = {
    {e2e::profile::p01, e2e::data_id_mode::both, 0, 0x1234, 0x3, "a543ca182530bb1d", "2143ca182530bb1d"},
    {e2e::profile::p01, e2e::data_id_mode::both, 24, 0x1234, 0x3, "6d132cded3237b2e", "6d132c00d3237b2e"},
    {e2e::profile::p01, e2e::data_id_mode::alt, 0, 0x1234, 0x3, "d9133f721fcb1971", "6f133f721fcb1971"},
    {e2e::profile::p01, e2e::data_id_mode::alt, 24, 0x1234, 0x3, "174494d6433c9d5c", "17449435433c9d5c"},
    {e2e::profile::p01, e2e::data_id_mode::low, 0, 0x1234, 0x3, "3463be31201e69fe", "d063be31201e69fe"},
    {e2e::profile::p01, e2e::data_id_mode::low, 24, 0x1234, 0x3, "daa0eee8b3997f5c", "daa0eeebb3997f5c"},
    {e2e::profile::p01, e2e::data_id_mode::nibble, 0, 0xa5c, 0x3, "7c2399fdafe59325", "43a399fdafe59325"},
    {e2e::profile::p01, e2e::data_id_mode::nibble, 24, 0xa5c, 0x3, "3cd654af43fad714", "3cd654b1a3fad714"},
    {e2e::profile::p11, e2e::data_id_mode::both, 0, 0x1234, 0x3, "27a3aeb3fee9232f", "a9a3aeb3fee9232f"},
    {e2e::profile::p11, e2e::data_id_mode::both, 24, 0x1234, 0x3, "8af2211f93e491c5", "8af221ff93e491c5"},
    {e2e::profile::p11, e2e::data_id_mode::nibble, 0, 0xa5c, 0x3, "b103ecb5563bfc1e", "43a3ecb5563bfc1e"},
    {e2e::profile::p11, e2e::data_id_mode::nibble, 24, 0xa5c, 0x3, "6f93427ec3c8fe29", "6f93422ea3c8fe29"},
    {e2e::profile::p02, e2e::data_id_mode::both, 0, 0x0, 0x5, "55e5cd8e46dc8ed4", "38e5cd8e46dc8ed4"},
    {e2e::profile::p04, e2e::data_id_mode::both, 0, 0x89abcdef, 0x1234, "b7c212342a5a4d767706f85d8690024ad6bda340", "0014123489abcdefb12fde268690024ad6bda340"},
    {e2e::profile::p04, e2e::data_id_mode::both, 32, 0x89abcdef, 0x1234, "1be9c8cbccc91234cd1f61226ae15338ae1a3400", "1be9c8cb0014123489abcdefef9bff38ae1a3400"},
    {e2e::profile::p05, e2e::data_id_mode::both, 0, 0x4321, 0x42, "4d33420d246ac04c81b1", "8b2c420d246ac04c81b1"},
    {e2e::profile::p05, e2e::data_id_mode::both, 32, 0x4321, 0x42, "baf23e3bf9ee42f79f2b", "baf23e3bd2b442f79f2b"},
    {e2e::profile::p06, e2e::data_id_mode::both, 0, 0x4321, 0x42, "4934af8742520b69b94b", "0c87000a42520b69b94b"},
    {e2e::profile::p06, e2e::data_id_mode::both, 32, 0x4321, 0x42, "0d982e85bb55b6724272", "0d982e858478000a4272"},
    {e2e::profile::p07, e2e::data_id_mode::both, 0, 0x89abcdef, 0x12345678, "637acd7466fcb60e0e8ff18412345678ba29703474f064ac68f700f5", "dcc88c429d3df79d0000001c1234567889abcdef74f064ac68f700f5"},
    {e2e::profile::p07, e2e::data_id_mode::both, 32, 0x89abcdef, 0x12345678, "b02b3dc666f45bdeaa2ccaedcd2b5157123456784af2b34f430a0734", "b02b3dc6eb338f4db2ad26eb0000001c1234567889abcdef430a0734"},
};

static e2e::config cfg_of(const golden& g) {
  e2e::config c;
  c.prof = g.prof;
  c.id_mode = g.mode;
  c.offset = g.offset;
  c.data_id = g.data_id;
  for (int i = 0; i < 16; ++i) c.data_id_list[std::size_t(i)] = std::uint8_t(0x10 + i);
  return c;
}

static void test_e2e() {
  for (const auto& g : kGolden) {
    const auto c = cfg_of(g);
    auto pdu = hex(g.in);
    CHECK(e2e::protect(c, pdu, g.counter));
    if (tohex(pdu) != g.out) {
      ++failures;
      std::printf("FAIL e2e golden profile %d mode %d offset %u: %s != %s\n", int(g.prof), int(g.mode), g.offset,
                  tohex(pdu).c_str(), g.out);
    }
    CHECK(e2e::verify(c, pdu) == e2e::status::ok);
    CHECK(e2e::read_counter(c, pdu) == g.counter);
    pdu.back() ^= std::byte{0x01};
    CHECK(e2e::verify(c, pdu) == e2e::status::wrong_crc);
  }
  // P22 at offset 0 computes exactly P02 (the only check P22 has here: no independent oracle)
  {
    e2e::config c2 = cfg_of(kGolden[12]), c22 = c2;
    c22.prof = e2e::profile::p22;
    auto a = hex(kGolden[12].in), b = a;
    CHECK(e2e::protect(c2, a, 5) && e2e::protect(c22, b, 5) && a == b);
    c22.offset = 16;
    auto d = hex("00112233445566778899");
    CHECK(e2e::protect(c22, d, 9) && e2e::verify(c22, d) == e2e::status::ok && (std::uint8_t(d[3]) & 0xF) == 9);
    CHECK(std::uint8_t(d[0]) == 0x00 && std::uint8_t(d[1]) == 0x11);  // bytes before the header untouched
  }
  // header field errors
  {
    e2e::config c;
    c.prof = e2e::profile::p04;
    c.data_id = 7;
    std::vector<std::byte> p(16);
    CHECK(e2e::protect(c, p, 1));
    std::vector<std::byte> longer = p;
    longer.push_back(std::byte{0});
    CHECK(e2e::verify(c, longer) == e2e::status::wrong_length);  // length field says 16
    c.data_id = 8;
    CHECK(e2e::verify(c, p) == e2e::status::wrong_data_id);
    c.data_id = 7;
    c.min_length = 20;
    CHECK(e2e::verify(c, p) == e2e::status::wrong_length);
    CHECK(e2e::verify(c, std::span(p).first(5)) == e2e::status::wrong_length);
    e2e::config bad = c;
    bad.offset = 3;
    CHECK(e2e::verify(bad, p) == e2e::status::bad_config && !e2e::protect(bad, p, 0));
    e2e::config p11;
    p11.prof = e2e::profile::p11;
    p11.id_mode = e2e::data_id_mode::alt;  // P11 has no alt mode
    CHECK(!e2e::protect(p11, p, 0));
    p11.id_mode = e2e::data_id_mode::nibble;
    p11.data_id = 0x0300;
    CHECK(e2e::protect(p11, p, 2));
    p11.data_id = 0x0400;  // CRC uses only the low byte in nibble mode: the nibble catches this
    CHECK(e2e::verify(p11, p) == e2e::status::wrong_data_id);
    p11.data_id = 0x0300;
    p[1] = std::byte((std::uint8_t(p[1]) & 0xF0) | 0xF);
    CHECK(e2e::verify(p11, p) == e2e::status::bad_counter);
    CHECK(!e2e::protect(p11, p, 15));
  }
  // protector / checker state machine, every profile, including the counter wrap
  for (auto prof : {e2e::profile::p01, e2e::profile::p02, e2e::profile::p04, e2e::profile::p05,
                    e2e::profile::p06, e2e::profile::p07, e2e::profile::p11, e2e::profile::p22}) {
    e2e::config c;
    c.prof = prof;
    c.data_id = 0x0123;
    c.max_delta_counter = 3;
    e2e::protector tx(c);
    e2e::checker rx(c);
    std::vector<std::byte> p(24);
    const std::uint32_t mx = e2e::counter_max(prof);
    if (mx > 300) tx.counter(mx - 5);  // exercise the wrap without 2^32 iterations
    if (mx > 300) {  // first PDU after the jump: wrong_sequence, then in sync
      CHECK(tx.protect(p) && rx.check(p) == e2e::status::wrong_sequence);
    }
    for (int i = 0; i < 40; ++i) {
      CHECK(tx.protect(p));
      CHECK(rx.check(p) == e2e::status::ok);
    }
    CHECK(rx.check(p) == e2e::status::repeated);
    CHECK(rx.check(p, false) == e2e::status::no_new_data);
    CHECK(tx.protect(p) && tx.protect(p) && tx.protect(p));  // lose two
    CHECK(rx.check(p) == e2e::status::ok_some_lost && rx.lost() == 2);
    for (int i = 0; i < 4; ++i) CHECK(tx.protect(p));  // lose three + 1: delta 4 > 3
    CHECK(rx.check(p) == e2e::status::wrong_sequence);
    CHECK(tx.protect(p));
    auto bad = p;
    bad[20] ^= std::byte{0x80};
    CHECK(rx.check(bad) == e2e::status::wrong_crc);
    CHECK(rx.check(p) == e2e::status::ok);  // an error does not move the state
  }
}

int main() {
  test_dbc_examples();
  test_round_trip();
  test_ranges_rounding();
  test_mux();
  test_desc_errors();
  test_e2e();
  if (failures) {
    std::printf("layout autosar tests: %d failure(s)\n", failures);
    return 1;
  }
  std::puts("layout autosar tests: all passed");
  return 0;
}
