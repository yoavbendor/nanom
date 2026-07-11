// SPDX-License-Identifier: Apache-2.0
// Phase 4 tests: the Avro binary field encoder (round-tripped through a small test-only decoder,
// so this has no new test-time dependency) and the Object Container File framing (magic bytes,
// header/first-block sync-marker consistency). Also manually verified in-session against a real
// reader (fastavro) on the gPTP/eth tables -- see the phase summary for those results; that
// verification isn't wired into ctest since it would be the first Python+pip test dependency in
// nanom's own suite (nanoarrow2parquet's check_soa*.py precedent is a different repo/posture).

#include "avro_ocf.hpp"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

int failures = 0;
#define CHECK(cond)                                                \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                                \
  } while (0)

struct Inner {
  std::uint8_t                a;
  std::array<std::uint8_t, 3> tag;
};
struct Row {
  std::int8_t   i8v;
  std::uint16_t u16v;
  std::int32_t  i32v;
  std::uint64_t u64v;
  float         f32v;
  double        f64v;
  bool          flag;
  Inner         inner;
};

}  // namespace

NANOM_DESCRIBE(Inner, a, tag);
NANOM_DESCRIBE(Row, i8v, u16v, i32v, u64v, f32v, f64v, flag, inner);

namespace {

// A minimal test-only decoder, independent of avro_ocf.hpp's own encoder, so this genuinely
// round-trips rather than checking the encoder against itself.
struct Reader {
  const std::byte* p;
  const std::byte* end;

  std::uint64_t varint() {
    std::uint64_t r = 0;
    int shift = 0;
    while (p < end) {
      const std::uint8_t b = std::uint8_t(*p++);
      r |= std::uint64_t(b & 0x7F) << shift;
      if (!(b & 0x80)) break;
      shift += 7;
    }
    return r;
  }
  std::int64_t zigzag() {
    const std::uint64_t z = varint();
    return std::int64_t(z >> 1) ^ -std::int64_t(z & 1);
  }
  float f32() {
    std::uint32_t bits = 0;
    for (int i = 0; i < 4; ++i) bits |= std::uint32_t(std::uint8_t(*p++)) << (8 * i);
    float f;
    std::memcpy(&f, &bits, 4);
    return f;
  }
  double f64() {
    std::uint64_t bits = 0;
    for (int i = 0; i < 8; ++i) bits |= std::uint64_t(std::uint8_t(*p++)) << (8 * i);
    double d;
    std::memcpy(&d, &bits, 8);
    return d;
  }
  void fixed(void* dst, std::size_t n) {
    std::memcpy(dst, p, n);
    p += n;
  }
};

void test_field_encoding_round_trip() {
  const Row row{-1, 40000, -70000, 0xFFFFFFFFFFULL, 3.5f, -2.25, true, Inner{7, {1, 2, 3}}};

  std::vector<std::byte> bytes;
  nano_shark::avro_encode_row(row, bytes);

  Reader r{bytes.data(), bytes.data() + bytes.size()};
  CHECK(r.zigzag() == row.i8v);
  CHECK(r.zigzag() == row.u16v);
  CHECK(r.zigzag() == row.i32v);
  CHECK(std::uint64_t(r.zigzag()) == row.u64v);
  CHECK(r.f32() == row.f32v);
  CHECK(r.f64() == row.f64v);
  CHECK(r.zigzag() == (row.flag ? 1 : 0));
  CHECK(r.zigzag() == row.inner.a);
  std::array<std::uint8_t, 3> tag{};
  r.fixed(tag.data(), 3);
  CHECK(tag == row.inner.tag);
  CHECK(r.p == r.end);  // every byte accounted for, nothing extra
}

void test_varint_known_values() {
  // A handful of hand-computed edge cases: 0, small positive/negative, and values that cross a
  // varint byte boundary, cross-checked against the standard zigzag+base-128 definition directly
  // (not via Reader, so this doesn't just check the encoder against its own decode logic).
  auto encode_one = [](std::int64_t v) {
    std::vector<std::byte> out;
    nano_shark::avro_put_long(out, v);
    return out;
  };
  CHECK(encode_one(0) == std::vector<std::byte>{std::byte{0x00}});
  CHECK(encode_one(-1) == std::vector<std::byte>{std::byte{0x01}});
  CHECK(encode_one(1) == std::vector<std::byte>{std::byte{0x02}});
  CHECK(encode_one(-2) == std::vector<std::byte>{std::byte{0x03}});
  // 300 -> zigzag 600 = 0b100_1011000 -> low7=0x58|cont, next=0x04
  CHECK((encode_one(300) == std::vector<std::byte>{std::byte{0xD8}, std::byte{0x04}}));
}

void test_ocf_framing() {
  const std::string path = "/tmp/nano_shark_test_avro_framing.avro";
  {
    nano_shark::AvroOcfWriter<Row> w(path);
    CHECK(w.ok());
    w.write_row(Row{1, 2, 3, 4, 1.0f, 2.0, false, Inner{5, {6, 7, 8}}});
    w.write_row(Row{-1, 2, -3, 4, 1.0f, 2.0, true, Inner{5, {6, 7, 8}}});
    w.close();
  }

  std::ifstream in(path, std::ios::binary);
  CHECK(bool(in));
  std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::vector<std::byte> data(raw.size());
  std::memcpy(data.data(), raw.data(), raw.size());

  CHECK(data.size() > 20);
  CHECK(std::memcmp(data.data(), "Obj\x01", 4) == 0);

  // avro.schema should mention every field name (a loose but real check that avro_schema<Row>()
  // actually ran and the fields are all present, not just a placeholder).
  const std::string as_text(reinterpret_cast<const char*>(data.data()), data.size());
  for (const char* name : {"i8v", "u16v", "i32v", "u64v", "f32v", "f64v", "flag", "inner", "tag"}) {
    CHECK(as_text.find(name) != std::string::npos);
  }

  // The header's sync marker (the 16 bytes right after the metadata map) must match the 16 bytes
  // at the end of the first data block -- parse the map structurally (count=2, 2 (key,value)
  // byte-string pairs, a terminating 0) rather than guessing a byte offset.
  Reader r{data.data() + 4, data.data() + data.size()};
  CHECK(r.zigzag() == 2);  // metadata block: 2 entries
  auto read_bytes = [&](Reader& rr) {
    const std::size_t n = std::size_t(rr.zigzag());
    std::string s(reinterpret_cast<const char*>(rr.p), n);
    rr.p += n;
    return s;
  };
  const std::string k1 = read_bytes(r), v1 = read_bytes(r);
  const std::string k2 = read_bytes(r), v2 = read_bytes(r);
  (void)v1;
  (void)v2;
  CHECK((k1 == "avro.schema" || k2 == "avro.schema"));
  CHECK(r.zigzag() == 0);  // terminates the metadata map

  std::array<std::byte, 16> sync_in_header{};
  r.fixed(sync_in_header.data(), 16);

  // write_row() flushes one block per call, so the two rows landed in two separate blocks; check
  // the first one's trailing sync marker against the header's.
  CHECK(r.zigzag() == 1);                              // block 1: row count
  const std::size_t block1_bytes = std::size_t(r.zigzag());  // block 1: encoded-bytes size
  r.p += block1_bytes;                                  // skip the encoded row itself
  std::array<std::byte, 16> sync_in_block{};
  r.fixed(sync_in_block.data(), 16);
  CHECK(sync_in_header == sync_in_block);
}

}  // namespace

int main() {
  test_field_encoding_round_trip();
  test_varint_known_values();
  test_ocf_framing();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_avro_tests: OK\n");
  return 0;
}
