// SPDX-License-Identifier: Apache-2.0

// reflect26 — nanom with ZERO registration. This is the C++26 showcase: every struct below is
// used with strct<>/overlay<>/soa<>/schema/json/csv purely because it exists — no NANOM_DESCRIBE,
// no adapter, no line of glue anywhere in this file (grep it). P2996 reflection reads the members
// straight off the definitions.
//
// Build (needs a P2996 compiler, e.g. the Bloomberg clang-p2996 fork):
//   clang++ -std=c++26 -freflection-latest -stdlib=libc++ -Inanom/include reflect26.cpp
// or configure nanom with -DNANOM_CXX26_REFLECTION=ON.

#include <nanom/nanom.hpp>

#if !NANOM_HAS_REFLECTION
#error "reflect26.cpp is the C++26 reflection showcase; compile with a P2996 compiler"
#endif

#include <cstdio>
#include <cstring>

namespace nm = nanom;

// A little sensor-record wire format: header + fixed payload. Endianness and bit widths live in
// the field types, the schema lives in the struct — and that is ALL the code there is.
namespace sensors::wire {

struct record_hdr {
  nm::be<std::uint16_t> magic;     // 0xC0DE
  nm::ubits<4> version;            // bit fields pack msb0
  nm::ubits<4> kind;
  std::uint8_t sequence;
};

struct imu_sample {
  record_hdr hdr;                  // nested struct: flattens into dotted columns
  nm::be<std::uint32_t> ts_us;
  std::array<std::uint8_t, 6> mac; // fixed binary -> Arrow "w:6"
  nm::le<std::int16_t> accel_x, accel_y, accel_z;  // little-endian sensor regs
};

}  // namespace sensors::wire

int main() {
  using sensors::wire::imu_sample;

  // Some wire bytes (magic C0DE, ver 2 kind 1, seq 7, ts 1000000, mac, accel -1/2/-3 LE).
  const std::uint8_t wire[] = {0xC0, 0xDE, 0x21, 0x07, 0x00, 0x0F, 0x42, 0x40,
                               0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01, 0xFF, 0xFF,
                               0x02, 0x00, 0xFD, 0xFF};
  static_assert(nm::wire_size_v<imu_sample> == sizeof wire);

  // Parse by value — imu_sample was never registered anywhere.
  auto r = nm::strct<imu_sample>()(nm::from(wire, sizeof wire));
  if (!r) return std::puts(r.error().render(nm::from(wire, sizeof wire)).c_str()), 1;
  std::printf("parsed: seq=%u ts=%u accel=(%d,%d,%d)\n", r->value.hdr.sequence,
              std::uint32_t(r->value.ts_us), std::int16_t(r->value.accel_x),
              std::int16_t(r->value.accel_y), std::int16_t(r->value.accel_z));

  // Zero-copy overlay with compile-time-checked names.
  auto v = nm::overlay<imu_sample>()(nm::from(wire, sizeof wire));
  std::printf("overlay: ts=%u (get<\"ts_us\">)\n", std::uint32_t(v->value.get<"ts_us">()));

  // Columnar storage + Arrow C-Data formats, named from the reflected fields.
  nm::soa<imu_sample> table;
  table.push(r->value);
  std::puts("columns:");
  for (const auto& c : table.columns())
    std::printf("  %-16s arrow=%s\n", c.name.c_str(), c.arrow.c_str());

  // Schemas + debug dumps — record and field names all come from reflection.
  std::printf("avro: %s\n", nm::avro_schema<imu_sample>().c_str());
  std::printf("json: %s\n", nm::to_json(r->value).c_str());
  std::printf("csv:  %s\n      %s\n", nm::csv_header<imu_sample>().c_str(),
              nm::csv_row(r->value).c_str());
  return 0;
}
