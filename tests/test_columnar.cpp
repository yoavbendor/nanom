// Tests for nanom/columnar.hpp (decode kernels) and nanom/codec.hpp (Snappy / LZ4 block).
// Every kernel is checked against a straightforward reference (bit-by-bit unpacking, a reference
// RLE-hybrid / DELTA_BINARY_PACKED encoder) over randomized inputs, plus hostile-input cases.
#include <nanom/columnar.hpp>
#include <nanom/codec.hpp>

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

int main() {
  test_unpack_bits();
  test_rle_hybrid();
  test_dbp_type<std::int32_t>();
  test_dbp_type<std::int64_t>();
  test_bss_and_bits();
  test_codecs();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("columnar tests: all passed");
  return 0;
}
