// SPDX-License-Identifier: Apache-2.0
// The AUTOSAR I-PDU loop with nanom::layout (docs/LAYOUT_GUIDE.md section 11), as a sender and a
// receiver would write it:
//
//   description (JSON Lines: Intel + Motorola signals, factor/offset, a multiplexor, an update bit)
//     -> plan::compile -> plan.encode / plan.set (physical values into a PDU buffer)
//     -> e2e::protector (AUTOSAR E2E P05 on a CAN FD PDU, P01 on a classic CAN PDU)
//     -> e2e::checker (ok, repeated, wrong_crc) and decode() (physical, nullable columns)
//
// The encoded and protected PDUs are compared with golden bytes from two independent tools:
// cantools 45.2.0 (DBC signal packing) and the autosar-e2e 1.0 Python package (E2E). The DBC and
// the script are in the comment above kGolden*. Built and run by ctest (example_layout_encode_e2e).
#include <nanom/layout.hpp>

#include <array>
#include <cmath>
#include <cstdio>
#include <string_view>
#include <vector>

namespace lay = nanom::layout;
namespace e2e = nanom::layout::e2e;

// Two PDUs in one description. bit_offset is the DBC start bit: the LSB for intel, the MSB
// (sawtooth numbering) for motorola. Bytes 0..2 of VehicleDynamics and 0..1 of BrakeStatus are
// left free for the E2E headers.
static constexpr std::string_view kDescription = R"(
{"raw_file":"VehicleDynamics","scalar_name":"Mux","bit_offset":24,"bit_width":4,"byte_order":"intel","multiplexor":true,"pdu_length":16}
{"raw_file":"VehicleDynamics","scalar_name":"Speed","bit_offset":39,"bit_width":16,"byte_order":"motorola","factor":0.01,"min":0,"max":655.35,"unit":"km/h","mux_value":1}
{"raw_file":"VehicleDynamics","scalar_name":"Temp","bit_offset":48,"bit_width":12,"byte_order":"intel","signed":true,"factor":0.5,"offset":-40,"unit":"degC","mux_value":2}
{"raw_file":"VehicleDynamics","scalar_name":"Torque","bit_offset":64,"bit_width":16,"byte_order":"intel","signed":true,"factor":0.1,"unit":"Nm","update_bit":80}
{"raw_file":"VehicleDynamics","scalar_name":"Accel","bit_offset":103,"bit_width":12,"byte_order":"motorola","signed":true,"factor":0.01,"unit":"m/s2"}
{"raw_file":"BrakeStatus","scalar_name":"BrakePressure","bit_offset":16,"bit_width":12,"byte_order":"intel","factor":0.1,"unit":"bar","pdu_length":8}
{"raw_file":"BrakeStatus","scalar_name":"BrakeActive","bit_offset":28,"bit_width":1,"byte_order":"intel"}
)";

// Golden bytes. The same signals as a DBC (the update bit is a plain 1-bit signal there):
//   BO_ 256 VehicleDynamics: 16 ECU
//    SG_ Mux M : 24|4@1+ (1,0) [0|15] "" ECU
//    SG_ Speed m1 : 39|16@0+ (0.01,0) [0|655.35] "km/h" ECU
//    SG_ Temp m2 : 48|12@1- (0.5,-40) [-1064|983.5] "degC" ECU
//    SG_ Torque : 64|16@1- (0.1,0) [-3276.8|3276.7] "Nm" ECU
//    SG_ TorqueUB : 80|1@1+ (1,0) [0|1] "" ECU
//    SG_ Accel : 103|12@0- (0.01,0) [-20.48|20.47] "m/s2" ECU
//   BO_ 257 BrakeStatus: 8 ECU
//    SG_ BrakePressure : 16|12@1+ (0.1,0) [0|409.5] "bar" ECU
//    SG_ BrakeActive : 28|1@1+ (1,0) [0|1] "" ECU
// cantools: msg.encode(values, strict=False, padding=False).hex(); then the counter byte set and
// e2e.p05.e2e_p05_protect(b, 0x1234, increment_counter=False) /
// e2e.p01.e2e_p01_protect(b, 0x0123, data_id_mode=E2E_P01_DATAID_BOTH, increment_counter=False).
static constexpr std::string_view kSignals0 = "000000012292000085ff0100f6a00000";  // Mux 1, Speed 88.5,
                                                                                    // Torque -12.3, Accel -1.5
static constexpr std::string_view kSignals1 = "0000000200007b000000000001900000";  // Mux 2, Temp 21.5,
                                                                                    // Accel 0.25, no Torque
static constexpr std::string_view kP05Pdu0 = "98a600012292000085ff0100f6a00000";   // counter 0
static constexpr std::string_view kP05Pdu1 = "788d010200007b000000000001900000";   // counter 1
static constexpr std::string_view kBrakeSignals = "0000d21400000000";               // 123.4 bar, active
static constexpr std::string_view kBrakeP01 = "ff00d21400000000";                   // P01, counter 0

static int failures = 0;
#define CHECK(c)                                                    \
  do {                                                              \
    if (!(c)) {                                                     \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);      \
      ++failures;                                                   \
    }                                                               \
  } while (0)

static std::string tohex(std::span<const std::byte> b) {
  static constexpr char d[] = "0123456789abcdef";
  std::string s;
  for (auto x : b) s += {d[unsigned(x) >> 4], d[unsigned(x) & 15]};
  return s;
}
static bool near(double a, double b) { return std::abs(a - b) < 1e-9; }

int main() {
  // 1. Description -> one plan per PDU. Compile once; plans are read-only afterwards. ------------
  auto desc = lay::parse_description(kDescription);  // in real use: lay::load_description(path)
  if (!desc) return std::printf("description: %s\n", desc.error().str().c_str()), 1;
  auto vd = lay::plan::compile(*desc, "VehicleDynamics");
  auto bs = lay::plan::compile(*desc, "BrakeStatus");
  if (!vd || !bs) return std::printf("plan: %s\n", (vd ? bs : vd).error().str().c_str()), 1;
  CHECK(vd->stride() == 16 && bs->stride() == 8);  // pdu_length
  CHECK(vd->has_signals() && vd->conditional() && vd->scaled());

  // Handles once (string lookups happen here, never per PDU). find() is nullopt for a typo.
  const auto vh = [&](const char* n) { return vd->find(n).value_or(lay::field_handle{}); };
  const auto Mux = vh("Mux"), Speed = vh("Speed"), Temp = vh("Temp"), Torque = vh("Torque"), Accel = vh("Accel");
  CHECK(vd->find("Speed") && vd->find("Accel") && !vd->find("Sped"));
  const auto Pressure = bs->find("BrakePressure").value_or(lay::field_handle{}),
             Active = bs->find("BrakeActive").value_or(lay::field_handle{});

  // 2. Encode physical values. encode() validates every value first (range, rounding, the
  //    multiplexor selecting each signal), then writes all of them; untouched bits stay. ---------
  std::vector<std::byte> stream(2 * vd->stride());  // two PDUs back to back, as a capture would hold
  const std::span<std::byte> pdu0 = std::span(stream).first(16), pdu1 = std::span(stream).subspan(16);
  CHECK(vd->encode({{Mux, 1, /*raw=*/true}, {Speed, 88.5}, {Torque, -12.3}, {Accel, -1.5}}, pdu0).has_value());
  CHECK(vd->encode({{Mux, 2, true}, {Temp, 21.5}}, pdu1).has_value());
  CHECK(vd->set(Accel, pdu1, 0.25).has_value());  // one signal at a time works too
  CHECK(tohex(pdu0) == kSignals0);
  CHECK(tohex(pdu1) == kSignals1);  // Torque never written: its update bit (80) stays 0
  // rounding: raw = round((physical - offset) / factor), to nearest, ties away from zero
  auto raw = [&](const lay::field_handle& h, double phys) { auto r = vd->to_raw(h, phys); return r ? *r : ~0ull; };
  CHECK(raw(Accel, 0.256) == 26);
  std::array<std::byte, 16> scratch{};
  const auto scratch_rec = vd->view(scratch);  // nullopt unless the span holds a whole PDU
  CHECK(vd->set(Accel, scratch, -0.256).has_value() && scratch_rec && scratch_rec->get<int>(Accel) == -26);
  CHECK(raw(Temp, -39.75) == 1);  // raw 0.5 -> 1
  // refused, and the PDU left as it was: Temp belongs to the Mux == 2 group, Speed over its max
  const auto before = stream;
  CHECK(!vd->encode({{Mux, 1, true}, {Temp, 0}}, pdu0).has_value());
  CHECK(!vd->set(Speed, pdu0, 700).has_value());
  CHECK(stream == before);

  // 3. E2E protect (sender). One protector per data ID; it keeps the counter. -----------------
  e2e::config p05{.prof = e2e::profile::p05, .data_id = 0x1234};  // header: CRC16 LE, counter
  CHECK(e2e::valid(p05, pdu0.size()) && e2e::required_length(p05) == 3);
  e2e::protector tx(p05);
  CHECK(tx.protect(pdu0) && tx.protect(pdu1) && tx.counter() == 2);
  CHECK(tohex(pdu0) == kP05Pdu0);
  CHECK(tohex(pdu1) == kP05Pdu1);
  CHECK(e2e::read_counter(p05, pdu1) == 1);

  // 4. Receive: E2E check, then decode. ------------------------------------------------------
  e2e::checker rx(p05);
  CHECK(rx.check(pdu0) == e2e::status::ok);
  CHECK(rx.check(pdu1) == e2e::status::ok);
  CHECK(rx.check(pdu1) == e2e::status::repeated);  // the same PDU again
  std::vector<std::byte> corrupt(pdu1.begin(), pdu1.end());
  corrupt[7] ^= std::byte{0x01};
  const e2e::status s = rx.check(corrupt);
  CHECK(s == e2e::status::wrong_crc && !e2e::usable(s));
  CHECK(std::string_view(e2e::status_name(s)) == "wrong_crc");
  CHECK(e2e::verify(p05, pdu0) == e2e::status::ok);  // stateless form

  //    decode(): one column per signal; physical columns; nulls where the multiplexor selects
  //    another group or the update bit is clear.
  lay::decode_options o;
  o.physical = true;
  auto t = lay::decode(*vd, stream, o);
  if (!t) return std::printf("decode: %s\n", t.error().str().c_str()), 1;
  CHECK(t->rows() == 2);
  const auto col = [&](const char* n) { return t->find(n).value_or(t->columns()); };  // column index by name
  const auto cs = col("Speed"), ct = col("Temp"), cq = col("Torque"), ca = col("Accel");
  CHECK(ca < t->columns() && t->columns() == 5);
  CHECK(t->column<std::uint16_t>("Speed")[0] == 8850);  // the raw column
  CHECK(near(t->physical(cs)[0], 88.5) && t->valid(0, cs) && !t->valid(1, cs) && t->null_count(cs) == 1);
  CHECK(t->physical(ct)[1] == 21.5 && !t->valid(0, ct) && t->valid(1, ct));
  CHECK(near(t->physical(cq)[0], -12.3) && t->valid(0, cq) && !t->valid(1, cq));
  CHECK(near(t->physical(ca)[0], -1.5) && near(t->physical(ca)[1], 0.25) && t->null_count(ca) == 0);

  //    The same through records: precomputed handles, no table.
  int seen = 0;
  for (auto rec : vd->records(stream)) {
    if (vd->valid(rec, Speed)) CHECK(near(rec.physical(Speed), 88.5) && rec.get<int>(Mux) == 1);
    if (vd->valid(rec, Temp)) CHECK(rec.physical(Temp) == 21.5 && rec.get<int>(Temp) == 123);
    ++seen;
  }
  CHECK(seen == 2);

  //    And to Arrow: Speed becomes a nullable float64 plus its raw sibling "Speed#raw".
  ArrowSchema schema;
  ArrowArray array;
  lay::export_arrow(std::move(*t), &schema, &array);
  CHECK(array.length == 2 && schema.n_children == 9);  // Mux + 4 x (physical, #raw)
  CHECK(std::string_view(schema.children[1]->name) == "Speed" && std::string_view(schema.children[1]->format) == "g");
  CHECK(array.children[1]->null_count == 1);
  array.release(&array);
  schema.release(&schema);

  // 5. A classic CAN PDU with E2E profile 1: CRC8 in byte 0, counter in the low nibble of byte 1.
  std::array<std::byte, 8> brake{};
  CHECK(bs->encode({{Pressure, 123.4}, {Active, 1, true}}, brake).has_value());
  CHECK(tohex(brake) == kBrakeSignals);
  e2e::config p01{.prof = e2e::profile::p01, .data_id = 0x0123, .id_mode = e2e::data_id_mode::both};
  e2e::protector btx(p01);
  e2e::checker brx(p01);
  CHECK(btx.protect(brake) && tohex(brake) == kBrakeP01);
  CHECK(brx.check(brake) == e2e::status::ok && brx.check(brake) == e2e::status::repeated);
  CHECK(btx.protect(brake) && brx.check(brake) == e2e::status::ok);  // counter 1
  brake[2] ^= std::byte{0x10};
  CHECK(brx.check(brake) == e2e::status::wrong_crc);
  const auto brec = bs->view(brake);
  CHECK(brec && brec->get<int>(Active) == 1 && near(brec->physical(Pressure), 121.8));  // 0x4d2 ^ 0x010

  if (failures) return std::printf("%d failure(s)\n", failures), 1;
  std::printf("layout_encode_e2e: PDUs match cantools + autosar-e2e; checks passed\n");
  return 0;
}
