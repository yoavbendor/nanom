// Tests for nanom/columnar.hpp (decode kernels), nanom/values.hpp (value kernels),
// nanom/formats/parquet_values.hpp and nanom/codec.hpp (Snappy / LZ4 block).
// Every kernel is checked against a straightforward reference (bit-by-bit unpacking, a reference
// RLE-hybrid / DELTA_BINARY_PACKED encoder) over randomized inputs, plus hostile-input cases.
#include <nanom/columnar.hpp>
#include <nanom/codec.hpp>
#include <nanom/formats/parquet_values.hpp>
#include <nanom/values.hpp>

#include <cstdio>
#include <random>
#include <vector>

namespace nm = nanom;
namespace col = nanom::columnar;
namespace cdc = nanom::codec;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

using bytes_v = std::vector<std::byte>;

// ------------------------------------------------------------------ reference encoders
struct bit_writer {
  bytes_v out;
  std::size_t bit = 0;
  void put(std::uint64_t v, unsigned w) {
    for (unsigned i = 0; i < w; ++i, ++bit) {
      if (bit / 8 >= out.size()) out.push_back(std::byte{0});
      if ((v >> i) & 1) out[bit / 8] |= std::byte(1u << (bit % 8));
    }
  }
};
static void put_uleb(bytes_v& o, std::uint64_t v) {
  std::byte b[10];
  const auto n = nm::uleb128_encode(v, b);
  o.insert(o.end(), b, b + n);
}

/// Reference RLE-hybrid encoder: alternates RLE and bit-packed runs as directed by `plan`.
static bytes_v rle_encode(const std::vector<std::uint32_t>& v, unsigned w, std::mt19937& rng) {
  bytes_v o;
  std::size_t i = 0;
  while (i < v.size()) {
    std::size_t run = 1;
    while (i + run < v.size() && v[i + run] == v[i]) ++run;
    if (run >= 8 || (rng() % 3 == 0 && run >= 1 && i + run == v.size())) {
      put_uleb(o, std::uint64_t(run) << 1);
      for (unsigned b = 0; b < (w + 7) / 8; ++b) o.push_back(std::byte((v[i] >> (8 * b)) & 0xff));
      i += run;
    } else {
      const std::size_t groups = std::min<std::size_t>(1 + rng() % 4, (v.size() - i + 7) / 8);
      put_uleb(o, (std::uint64_t(groups) << 1) | 1);
      bit_writer bw;
      for (std::size_t k = 0; k < groups * 8; ++k) bw.put(i + k < v.size() ? v[i + k] : 0, w);
      bw.out.resize(groups * w);
      o.insert(o.end(), bw.out.begin(), bw.out.end());
      i += groups * 8;
    }
  }
  return o;
}

/// Reference DELTA_BINARY_PACKED encoder (block 128, 4 miniblocks of 32).
template <class T>
static bytes_v dbp_encode(const std::vector<T>& v) {
  using U = std::make_unsigned_t<T>;
  bytes_v o;
  put_uleb(o, 128);
  put_uleb(o, 4);
  put_uleb(o, v.size());
  put_uleb(o, v.empty() ? 0 : nm::zigzag_encode(std::int64_t(v[0])));
  std::size_t i = 1;
  while (i < v.size()) {
    std::vector<U> d;
    for (std::size_t k = 0; k < 128 && i + k < v.size(); ++k)
      d.push_back(U(U(v[i + k]) - U(v[i + k - 1])));
    T min_d = std::bit_cast<T>(d[0]);
    for (U x : d) min_d = std::min(min_d, std::bit_cast<T>(x));
    put_uleb(o, nm::zigzag_encode(std::int64_t(min_d)));
    std::vector<U> rel(128, 0);
    for (std::size_t k = 0; k < d.size(); ++k) rel[k] = U(d[k] - U(min_d));
    unsigned widths[4];
    for (int m = 0; m < 4; ++m) {
      U mx = 0;
      for (int k = 0; k < 32; ++k) mx = std::max(mx, rel[std::size_t(m * 32 + k)]);
      widths[m] = unsigned(std::bit_width(mx));
      o.push_back(std::byte(widths[m]));
    }
    const std::size_t used_minis = (d.size() + 31) / 32;
    for (std::size_t m = 0; m < used_minis; ++m) {
      bit_writer bw;
      for (int k = 0; k < 32; ++k) bw.put(rel[m * 32 + std::size_t(k)], widths[m]);
      bw.out.resize(32 * widths[m] / 8);
      o.insert(o.end(), bw.out.begin(), bw.out.end());
    }
    i += d.size();
  }
  return o;
}

// ------------------------------------------------------------------ tests
static void test_unpack_bits() {
  std::mt19937_64 rng(1);
  for (unsigned w = 0; w <= 64; ++w) {
    for (std::size_t n : {0u, 1u, 7u, 8u, 9u, 63u, 64u, 1000u}) {
      std::vector<std::uint64_t> vals(n);
      bit_writer bw;
      for (auto& x : vals) {
        x = w == 64 ? rng() : (w == 0 ? 0 : rng() & ((std::uint64_t(1) << w) - 1));
        bw.put(x, w);
      }
      bw.out.resize((n * w + 7) / 8);
      std::vector<std::uint64_t> got(n + 1, 0xdead);
      CHECK(col::unpack_bits<std::uint64_t>(bw.out, w, std::span<std::uint64_t>(got), n));
      bool same = true;
      for (std::size_t i = 0; i < n; ++i) same = same && got[i] == vals[i];
      CHECK(same && got[n] == 0xdead);  // exactly n written
      if (w <= 32) {
        std::vector<std::uint32_t> g32(n);
        CHECK(col::unpack_bits<std::uint32_t>(bw.out, w, std::span<std::uint32_t>(g32), n));
        bool s32 = true;
        for (std::size_t i = 0; i < n; ++i) s32 = s32 && g32[i] == vals[i];
        CHECK(s32);
      }
      if (n && w) {  // one byte short -> refused, nothing read past the span
        bytes_v shorter(bw.out.begin(), bw.out.end() - 1);
        CHECK(!col::unpack_bits<std::uint64_t>(shorter, w, std::span<std::uint64_t>(got), n));
      }
    }
  }
  std::vector<std::uint32_t> o(8);
  CHECK(!col::unpack_bits<std::uint32_t>(bytes_v(64), 33, std::span<std::uint32_t>(o), 8));  // width > 32
}

static void test_rle_hybrid() {
  std::mt19937 rng(2);
  for (unsigned w = 0; w <= 32; ++w) {
    for (int trial = 0; trial < 20; ++trial) {
      const std::size_t n = rng() % 3000;
      std::vector<std::uint32_t> v(n);
      const std::uint32_t mask = w == 32 ? ~0u : (w == 0 ? 0 : (1u << w) - 1);
      for (std::size_t i = 0; i < n; ++i)
        v[i] = (i && rng() % 4 != 0) ? v[i - 1] : std::uint32_t(rng()) & mask;  // runs + noise
      const auto enc = rle_encode(v, w, rng);
      col::rle_bp_decoder d(enc, w);
      std::vector<std::uint32_t> got;
      std::uint32_t buf[97];
      while (got.size() < n) {
        const std::size_t want = std::min<std::size_t>(1 + rng() % 97, n - got.size());
        const std::size_t k = d.get(buf, want);
        if (!k) break;
        got.insert(got.end(), buf, buf + k);
      }
      CHECK(d.ok() && got == v);
      // the run view reproduces the same values (expanded here from RLE values / packed bits)
      col::rle_bp_decoder dr(enc, w);
      std::vector<std::uint32_t> via_runs;
      col::rle_bp_decoder::run run;
      while (via_runs.size() < n && dr.next_run(run, std::min<std::size_t>(1 + rng() % 50, n - via_runs.size()))) {
        if (!run.packed) {
          via_runs.insert(via_runs.end(), run.count, run.value);
        } else {
          for (std::size_t k = 0; k < run.count; ++k) {
            std::uint64_t x = 0;
            for (unsigned b = 0; b < w; ++b) {
              const std::size_t bit = run.bit_offset + k * w + b;
              x |= std::uint64_t((std::uint8_t(run.bits[bit / 8]) >> (bit % 8)) & 1) << b;
            }
            via_runs.push_back(std::uint32_t(x));
          }
        }
      }
      CHECK(dr.ok() && via_runs == v);
    }
  }
  // hostile: an RLE run of 2^62 values only yields what is asked for
  bytes_v huge;
  put_uleb(huge, std::uint64_t(1) << 62);
  huge.push_back(std::byte{5});
  col::rle_bp_decoder d(huge, 3);
  std::uint32_t out[16];
  CHECK(d.get(out, 16) == 16 && out[15] == 5);
  // RLE value wider than the bit width is rejected
  bytes_v bad;
  put_uleb(bad, 4 << 1);
  bad.push_back(std::byte{9});
  col::rle_bp_decoder d2(bad, 3);
  CHECK(d2.get(out, 4) == 0 && !d2.ok());
  // bit-packed run header claiming 2^60 groups over 3 bytes: yields only what is present
  bytes_v bp;
  put_uleb(bp, (std::uint64_t(1) << 60) | 1);
  bp.insert(bp.end(), {std::byte{0xff}, std::byte{0xff}, std::byte{0xff}});
  col::rle_bp_decoder d3(bp, 3);
  std::vector<std::uint32_t> many(100);
  CHECK(d3.get(many.data(), 100) == 8);
  CHECK(!col::rle_bp_decoder(bp, 33).ok());
}

template <class T>
static void test_dbp_type() {
  std::mt19937_64 rng(3);
  for (int trial = 0; trial < 60; ++trial) {
    const std::size_t n = trial < 5 ? std::size_t(trial) : rng() % 2000;
    std::vector<T> v(n);
    for (std::size_t i = 0; i < n; ++i) {
      switch (trial % 4) {
        case 0: v[i] = T(i * 3); break;                                    // constant delta
        case 1: v[i] = T(rng()); break;                                    // full range
        case 2: v[i] = T(std::int64_t(rng() % 1000) - 500); break;         // small, signed
        default: v[i] = i % 2 ? std::numeric_limits<T>::max() : std::numeric_limits<T>::min();  // wrap
      }
    }
    const auto enc = dbp_encode(v);
    std::vector<T> got(n);
    auto used = col::delta_binary_packed<T>(enc, std::span<T>(got), n);
    CHECK(used.has_value() && got == v);
    if (used && n) CHECK(*used == enc.size());
  }
  // malformed headers
  std::vector<T> o(4);
  bytes_v bad;
  put_uleb(bad, 100);  // block size not a multiple of 128
  put_uleb(bad, 4); put_uleb(bad, 4); put_uleb(bad, 0);
  CHECK(!col::delta_binary_packed<T>(bad, std::span<T>(o), 4));
  bytes_v few = dbp_encode(std::vector<T>{1, 2});
  CHECK(!col::delta_binary_packed<T>(few, std::span<T>(o), 4));  // declares 2 values, 4 asked
  auto trunc = dbp_encode(std::vector<T>{1, 50, 9000, -3, 7});
  trunc.resize(trunc.size() - 1);
  CHECK(!col::delta_binary_packed<T>(trunc, std::span<T>(o), 4) ||
        col::delta_binary_packed<T>(trunc, std::span<T>(o), 4).value() <= trunc.size());
}

static void test_bss_and_bits() {
  const std::vector<float> f{1.5f, -2.25f, 3.0e10f, 0.0f, -0.0f};
  bytes_v split(f.size() * 4);
  const auto* raw = reinterpret_cast<const std::byte*>(f.data());
  for (std::size_t i = 0; i < f.size(); ++i)
    for (std::size_t b = 0; b < 4; ++b) split[b * f.size() + i] = raw[i * 4 + b];
  std::vector<float> back(f.size());
  CHECK(col::byte_stream_split(split, 4, f.size(), std::as_writable_bytes(std::span<float>(back))));
  CHECK(std::memcmp(back.data(), f.data(), f.size() * 4) == 0);
  CHECK(!col::byte_stream_split(split, 4, f.size() + 1, std::as_writable_bytes(std::span<float>(back))));

  std::mt19937 rng(4);
  for (int t = 0; t < 4000; ++t) {
    // exact-size buffers (no slack) every other round, so ASan catches any over-read or -write
    const std::size_t n = rng() % (t % 4 == 0 ? 3000 : 200), at = rng() % 70;
    bytes_v src((n + 7) / 8);
    for (auto& b : src) b = std::byte(rng());
    bytes_v dst((at + n + 7) / 8 + (t % 2), std::byte{0xa5});
    const bytes_v before = dst;
    CHECK(col::copy_bits(src, n, dst, at));
    bool ok = true;
    for (std::size_t i = 0; i < dst.size() * 8; ++i) {
      const bool got = (std::uint8_t(dst[i / 8]) >> (i % 8)) & 1;
      const bool want = (i >= at && i < at + n) ? ((std::uint8_t(src[(i - at) / 8]) >> ((i - at) % 8)) & 1)
                                                : ((std::uint8_t(before[i / 8]) >> (i % 8)) & 1);
      ok = ok && got == want;
    }
    CHECK(ok);  // the bits around the destination range are untouched
  }
}

static bytes_v Bv(std::initializer_list<int> v) {
  bytes_v o;
  for (int x : v) o.push_back(std::byte(x));
  return o;
}

static bytes_v scratch(std::size_t n) { return bytes_v(n); }

static void test_codecs() {
  // snappy: preamble 9, literal "abc", copy offset 3 length 6 -> "abcabcabc"
  const auto s = Bv({9, 0x08, 'a', 'b', 'c', 0x09, 0x03});  // copy-1: len ((0x09>>2)&7)+4 = 6, off 3
  bytes_v out(9);
  auto r = cdc::snappy_decompress(s, out);
  CHECK(r && *r == 9 && std::memcmp(out.data(), "abcabcabc", 9) == 0);
  { auto o8 = scratch(8); CHECK(!cdc::snappy_decompress(s, o8)); }                           // preamble mismatch
  CHECK(!cdc::snappy_decompress(Bv({9, 0x08, 'a', 'b', 'c', 0x09, 0x04}), out));  // offset > produced
  CHECK(!cdc::snappy_decompress(Bv({9, 0x08, 'a', 'b', 'c', 0x09, 0x00}), out));  // offset 0
  { auto o4 = scratch(4); CHECK(!cdc::snappy_decompress(Bv({4, 0xf0, 0xff}), o4)); }             // truncated length
  { auto o3 = scratch(3); CHECK(!cdc::snappy_decompress(Bv({3, 0x08, 'a', 'b'}), o3)); }        // literal past input

  // lz4: token 0x32 = 3 literals + match len 2+4=6, offset 3; then final literal-only "!"
  const auto l = Bv({0x32, 'a', 'b', 'c', 0x03, 0x00, 0x10, '!'});
  bytes_v lo(10);
  auto lr = cdc::lz4_block_decompress(l, lo);
  CHECK(lr && *lr == 10 && std::memcmp(lo.data(), "abcabcabc!", 10) == 0);
  { auto o9 = scratch(9); CHECK(!cdc::lz4_block_decompress(l, o9)); }                             // overflows output
  CHECK(!cdc::lz4_block_decompress(Bv({0x32, 'a', 'b', 'c', 0x04, 0x00, 0x10, '!'}), lo));  // bad offset
  CHECK(!cdc::lz4_block_decompress(Bv({0xf0, 0xff, 0xff}), lo));               // truncated length
  CHECK(!cdc::lz4_block_decompress({}, lo));
}

// ------------------------------------------------------------------ values.hpp
static bool bit(const std::vector<std::uint8_t>& b, std::size_t i) { return (b[i / 8] >> (i % 8)) & 1; }

static void test_values() {
  std::mt19937 rng(21);
  // bitmaps: set_bits / count_bits against a bool vector
  for (int t = 0; t < 300; ++t) {
    const std::size_t n = 1 + rng() % 700;
    std::vector<std::uint8_t> bm((n + 7) / 8 + 8, 0);
    std::vector<bool> ref(n, false);
    for (int k = 0; k < 4; ++k) {
      const std::size_t a = rng() % n, c = rng() % (n - a + 1);
      col::set_bits(bm.data(), a, c);
      for (std::size_t i = a; i < a + c; ++i) ref[i] = true;
    }
    bool ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && bit(bm, i) == ref[i];
    for (std::size_t i = n; i < bm.size() * 8; ++i) ok = ok && !bit(bm, i);
    CHECK(ok);
    const std::size_t a = rng() % n, c = rng() % (n - a + 1);
    std::size_t want = 0;
    for (std::size_t i = a; i < a + c; ++i) want += ref[i];
    CHECK(col::count_bits(bm.data(), a, c) == want);
  }

  // rle_bitmap: a width-1 stream at a random bit position; neighbours untouched
  for (int t = 0; t < 300; ++t) {
    const std::size_t n = rng() % 900, at = rng() % 40;
    std::vector<std::uint32_t> v(n);
    for (auto& x : v) x = (t % 3 == 0) ? (rng() % 5 != 0) : rng() % 2;
    const auto enc = rle_encode(v, 1, rng);
    bytes_v out((at + n + 7) / 8 + 2, std::byte{0});
    out[0] = std::byte{std::uint8_t((1u << (at % 8)) - 1)};  // bits below `at` in the first byte are set
    col::rle_bp_decoder d(enc, 1);
    CHECK(col::rle_bitmap(d, n, out, at));
    bool ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && (((std::uint8_t(out[(at + i) / 8]) >> ((at + i) % 8)) & 1) == v[i]);
    for (std::size_t i = 0; i < at % 8; ++i) ok = ok && ((std::uint8_t(out[0]) >> i) & 1);
    for (std::size_t i = at + n; i < out.size() * 8; ++i) ok = ok && !((std::uint8_t(out[i / 8]) >> (i % 8)) & 1);
    CHECK(ok);
  }
  {  // a value of 2 in a "bitmap" stream, and a short stream, are errors
    bytes_v two;
    put_uleb(two, 8 << 1);
    two.push_back(std::byte{2});
    bytes_v out(4);
    col::rle_bp_decoder d(two, 2);
    CHECK(!col::rle_bitmap(d, 8, out, 0));  // width 2 is not a bitmap stream
    const bytes_v short_run{std::byte{8 << 1}, std::byte{1}};  // 8 ones, then the data ends
    col::rle_bp_decoder d1(short_run, 1);
    CHECK(!col::rle_bitmap(d1, 20, out, 0));
  }

  // decode_levels: random levels at every width, and the max check
  for (int t = 0; t < 300; ++t) {
    const std::uint16_t maxv = std::uint16_t(1 + rng() % 9);
    const unsigned w = unsigned(std::bit_width(unsigned(maxv)));
    const std::size_t n = rng() % 1500;
    std::vector<std::uint32_t> v(n);
    for (auto& x : v) x = (rng() % 4 == 0) ? 0 : rng() % (maxv + 1u);
    const auto enc = rle_encode(v, w, rng);
    std::vector<std::uint16_t> out(n);
    CHECK(col::decode_levels(enc, maxv, n, out.data()));
    bool ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && out[i] == v[i];
    CHECK(ok);
    if (maxv + 1u < (1u << w) && n) {  // a value above max (but within the bit width) is rejected
      auto bad = v;
      bad[rng() % n] = maxv + 1u;
      const auto e2 = rle_encode(bad, w, rng);
      CHECK(!col::decode_levels(e2, maxv, n, out.data()));
    }
    if (n) CHECK(!col::decode_levels(enc, maxv, n + 9, std::vector<std::uint16_t>(n + 9).data()));  // too short
  }

  // level_slots + struct_slots + list_slots on a hand-built list<int?> column:
  //   rows: [1, null], null, [], [3]   (max_def 3: list present 1, element present 2, value 3)
  {
    const std::uint16_t rep[] = {0, 1, 0, 0, 0};
    const std::uint16_t def[] = {3, 2, 0, 1, 3};
    std::vector<std::uint8_t> bm(8, 0);
    const auto c = col::level_slots(def, 5, 2, 3, bm.data());
    CHECK(c.slots == 3 && c.non_null == 2);
    CHECK(bit(bm, 0) && !bit(bm, 1) && bit(bm, 2));
    col::dremel_node nd{0, 0, 1, 2, 1};
    std::int32_t offs[5];
    std::vector<std::uint8_t> lv(8, 0);
    std::int64_t nulls = 0, elems = 0;
    CHECK(col::list_slots(rep, def, 5, nd, 4, offs, lv.data(), nulls, elems));
    CHECK(nulls == 1 && elems == 3);
    CHECK(offs[0] == 0 && offs[1] == 2 && offs[2] == 2 && offs[3] == 2 && offs[4] == 3);
    CHECK(bit(lv, 0) && !bit(lv, 1) && bit(lv, 2) && bit(lv, 3));
    std::fill(lv.begin(), lv.end(), 0);
    CHECK(!col::list_slots(rep, def, 5, nd, 3, offs, lv.data(), nulls, elems));  // parent promised 3 rows
    const std::uint16_t bad_rep[] = {1, 0};
    const std::uint16_t bad_def[] = {3, 3};
    CHECK(!col::list_slots(bad_rep, bad_def, 2, nd, 1, offs, lv.data(), nulls, elems));  // element before any list
    // the same levels seen by a struct at the top level: 4 slots, one null
    std::fill(lv.begin(), lv.end(), 0);
    col::dremel_node sn{0, 0, 1, 0, 0};
    CHECK(col::struct_slots(rep, def, 5, sn, 4, lv.data(), nulls) && nulls == 1);
    CHECK(!col::struct_slots(rep, def, 5, sn, 5, lv.data(), nulls));
  }

  // utf8
  CHECK(col::valid_utf8("plain ascii, long enough for the word path"));
  CHECK(col::valid_utf8("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80"));
  CHECK(!col::valid_utf8("\xc0\xaf"));          // overlong
  CHECK(!col::valid_utf8("\xed\xa0\x80"));      // surrogate
  CHECK(!col::valid_utf8("\xf4\x90\x80\x80"));  // above U+10FFFF
  CHECK(!col::valid_utf8("abc\xe2\x82"));       // truncated
  {
    const char s[] = "a\xc3\xa9z";
    const std::int32_t good[] = {0, 1, 3}, bad[] = {0, 2};
    CHECK(col::utf8_starts_ok(reinterpret_cast<const std::byte*>(s), 4, good, 3));
    CHECK(!col::utf8_starts_ok(reinterpret_cast<const std::byte*>(s), 4, bad, 2));
  }

  // spread_nulls at every width against a reference, densities 0..1
  for (std::size_t w : {1u, 2u, 4u, 8u, 12u, 16u}) {
    for (int t = 0; t < 60; ++t) {
      const std::size_t n = rng() % 600;
      std::vector<std::uint8_t> vb(((n + 63) / 64) * 8 + 8, 0);
      const unsigned density = rng() % 5;  // 0 = all null .. 4 = all valid
      std::size_t nn = 0;
      for (std::size_t i = 0; i < n; ++i)
        if (density == 4 || (density && rng() % 4 < density)) { vb[i / 8] |= std::uint8_t(1u << (i % 8)); ++nn; }
      bytes_v dense(nn * w), buf(n * w + 1, std::byte{0x77});
      for (auto& b : dense) b = std::byte(rng());
      std::copy(dense.begin(), dense.end(), buf.begin());
      col::spread_nulls(buf.data(), n, nn, w, vb.data());
      bool ok = true;
      std::size_t j = 0;
      for (std::size_t i = 0; i < n; ++i)
        for (std::size_t b = 0; b < w; ++b)
          ok = ok && buf[i * w + b] == (bit(vb, i) ? dense[j * w + b] : std::byte{0}), j += (b + 1 == w && bit(vb, i));
      CHECK(ok && buf[n * w] == std::byte{0x77});
    }
  }

  // widening
  {
    std::byte o[16];
    const std::byte neg[] = {std::byte{0xff}, std::byte{0x85}};  // -123 big-endian
    col::sign_extend_be(neg, 2, o, 16);
    std::int64_t lo, hi;
    std::memcpy(&lo, o, 8);
    std::memcpy(&hi, o + 8, 8);
    CHECK(lo == -123 && hi == -1);
    col::sign_extend_le(std::int32_t(-5), o, 16);
    std::memcpy(&lo, o, 8);
    std::memcpy(&hi, o + 8, 8);
    CHECK(lo == -5 && hi == -1);
    col::sign_extend_le(std::int64_t(7), o, 16);
    std::memcpy(&hi, o + 8, 8);
    CHECK(hi == 0);
    // INT96: Julian day 2440589 (1970-01-02) + 1 ns
    std::byte i96[12]{};
    const std::uint64_t ns = 1;
    const std::uint32_t jd = 2440589;
    std::memcpy(i96, &ns, 8);
    std::memcpy(i96 + 8, &jd, 4);
    CHECK(nanom_formats::parquet::int96_to_unix_nanos(i96) == 86400000000001ll);
  }

  // byte arrays: length-prefixed -> views / offsets, delta-length, delta-prefix, dictionaries
  for (int t = 0; t < 200; ++t) {
    const std::size_t n = rng() % 300;
    std::vector<std::string> vals(n);
    for (auto& v : vals) {
      v.resize(rng() % (t % 2 ? 40 : 6));
      for (auto& c : v) c = char('a' + rng() % 3);
    }
    bytes_v lp;
    for (const auto& v : vals) {
      const std::uint32_t len = std::uint32_t(v.size());
      const auto* b = reinterpret_cast<const std::byte*>(&len);
      lp.insert(lp.end(), b, b + 4);
      for (char c : v) lp.push_back(std::byte(c));
    }
    std::vector<std::string_view> views(n);
    auto used = col::length_prefixed_views(lp, n, views);
    CHECK(used && *used == lp.size());
    bool ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && views[i] == vals[i];
    CHECK(ok);
    if (n) CHECK(!col::length_prefixed_views(std::span<const std::byte>(lp).first(lp.size() - 1), n, views));

    // append_length_prefixed with nulls in the slots
    const std::size_t slots = n + rng() % 50;
    std::vector<std::uint8_t> vb((slots + 7) / 8 + 8, 0);
    {
      std::vector<std::size_t> pos(slots);
      for (std::size_t i = 0; i < slots; ++i) pos[i] = i;
      std::shuffle(pos.begin(), pos.end(), rng);
      for (std::size_t i = 0; i < n; ++i) vb[pos[i] / 8] |= std::uint8_t(1u << (pos[i] % 8));
    }
    bytes_v data(lp.size() + col::kValueSlack + 3);
    std::vector<std::int32_t> offs(slots + 1, -1);
    offs[0] = 3;
    std::int64_t cur = 3;
    CHECK(col::append_length_prefixed(lp, slots, vb.data(), data.data(), cur, offs.data() + 1, INT32_MAX));
    std::size_t j = 0;
    ok = true;
    for (std::size_t r = 0; r < slots; ++r) {
      const std::string_view got(reinterpret_cast<const char*>(data.data()) + offs[r], std::size_t(offs[r + 1] - offs[r]));
      ok = ok && (bit(vb, r) ? got == vals[j++] : got.empty());
    }
    CHECK(ok && j == n);

    // DELTA_LENGTH_BYTE_ARRAY and DELTA_BYTE_ARRAY built with the reference DBP encoder
    std::vector<std::int32_t> lens(n), pre(n), suf(n);
    for (std::size_t i = 0; i < n; ++i) lens[i] = std::int32_t(vals[i].size());
    bytes_v dl = dbp_encode(lens);
    for (const auto& v : vals) for (char c : v) dl.push_back(std::byte(c));
    std::vector<std::int32_t> s1, s2;
    std::vector<std::string_view> v2(n);
    CHECK(col::delta_length_views(dl, n, s1, v2));
    ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && v2[i] == vals[i];
    CHECK(ok);
    bytes_v sfx;
    for (std::size_t i = 0; i < n; ++i) {
      std::size_t p = 0;
      if (i) while (p < vals[i].size() && p < vals[i - 1].size() && vals[i][p] == vals[i - 1][p]) ++p;
      pre[i] = std::int32_t(p);
      suf[i] = std::int32_t(vals[i].size() - p);
      for (std::size_t k = p; k < vals[i].size(); ++k) sfx.push_back(std::byte(vals[i][k]));
    }
    bytes_v db = dbp_encode(pre);
    const bytes_v ds = dbp_encode(suf);
    db.insert(db.end(), ds.begin(), ds.end());
    db.insert(db.end(), sfx.begin(), sfx.end());
    std::vector<char> arena;
    std::vector<std::string_view> v3(n);
    CHECK(col::delta_prefix_views(db, n, s1, s2, arena, v3, 1u << 20));
    ok = true;
    for (std::size_t i = 0; i < n; ++i) ok = ok && v3[i] == vals[i];
    CHECK(ok);
    if (n > 3) CHECK(!col::delta_prefix_views(db, n, s1, s2, arena, v3, 2));  // over the size limit

    // dictionary gather (variable and fixed) through the Parquet index framing
    if (n) {
      std::vector<std::uint32_t> idx(1 + rng() % 400);
      for (auto& x : idx) x = std::uint32_t(rng() % n);
      const unsigned bw = unsigned(std::bit_width(n - 1));
      bytes_v page{std::byte(bw)};
      const auto ri = rle_encode(idx, bw, rng);
      page.insert(page.end(), ri.begin(), ri.end());
      std::vector<std::uint32_t> got(idx.size());
      CHECK(nanom_formats::parquet::dictionary_indices(page, idx.size(), n, got) && got == idx);
      if (n > 1) CHECK(!nanom_formats::parquet::dictionary_indices(page, idx.size(), 1, got));  // out of range
      std::vector<std::size_t> doff(n + 1, 0);
      for (std::size_t i = 0; i < n; ++i) doff[i + 1] = doff[i] + vals[i].size();
      bytes_v dd(doff[n] + col::kValueSlack);
      for (std::size_t i = 0; i < n; ++i)
        for (std::size_t k = 0; k < vals[i].size(); ++k) dd[doff[i] + k] = std::byte(vals[i][k]);
      const auto total = col::gathered_size(doff.data(), std::span<const std::uint32_t>(idx));
      bytes_v out(total + col::kValueSlack);
      std::vector<std::int32_t> o2(idx.size() + 1, 0);
      std::int64_t c2 = 0;
      col::append_gathered(dd.data(), dd.data() + dd.size(), doff.data(), std::span<const std::uint32_t>(idx), idx.size(),
                           nullptr, out.data(), c2, o2.data() + 1);
      ok = std::size_t(c2) == total;
      for (std::size_t i = 0; i < idx.size(); ++i)
        ok = ok && std::string_view(reinterpret_cast<const char*>(out.data()) + o2[i], std::size_t(o2[i + 1] - o2[i])) ==
                       vals[idx[i]];
      CHECK(ok);
      std::vector<std::uint64_t> fd(n), fo(idx.size());
      for (auto& x : fd) x = rng();
      col::gather_fixed(reinterpret_cast<const std::byte*>(fd.data()), 8, std::span<const std::uint32_t>(idx),
                        reinterpret_cast<std::byte*>(fo.data()));
      ok = true;
      for (std::size_t i = 0; i < idx.size(); ++i) ok = ok && fo[i] == fd[idx[i]];
      CHECK(ok);
    }
  }

  // scatter_bits
  for (int t = 0; t < 200; ++t) {
    const std::size_t n = rng() % 500, at = rng() % 30;
    std::vector<std::uint8_t> vb((n + 7) / 8 + 1, 0), dense(n / 8 + 2, 0), out((at + n + 7) / 8 + 1, 0);
    std::size_t nn = 0;
    for (std::size_t i = 0; i < n; ++i) if (rng() % 3) { vb[i / 8] |= std::uint8_t(1u << (i % 8)); ++nn; }
    for (auto& b : dense) b = std::uint8_t(rng());
    col::scatter_bits(dense.data(), vb.data(), n, out.data(), at);
    bool ok = true;
    std::size_t j = 0;
    for (std::size_t r = 0; r < n; ++r) {
      const bool want = bit(vb, r) ? bit(dense, j++) : false;
      ok = ok && bit(out, at + r) == want;
    }
    CHECK(ok && j == nn);
  }
}

int main() {
  test_unpack_bits();
  test_rle_hybrid();
  test_dbp_type<std::int32_t>();
  test_dbp_type<std::int64_t>();
  test_bss_and_bits();
  test_codecs();
  test_values();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("columnar tests: all passed");
  return 0;
}
