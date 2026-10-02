// Tests for nanom/columnar_encode.hpp: every encoder round-trips through its decoder.
//
//   pack_bits            -> unpack_bits            every width 0..32 (u32) and 0..64 (u64)
//   rle_hybrid_encode    -> rle_bp_decoder         run-heavy, noisy and mixed data, widths 0..32
//   rle_bitmap_encode    -> rle_bitmap             densities 0 .. 1, any length
//   encode_levels        -> decode_levels
//   delta_binary_packed  -> delta_binary_packed    int32 / int64, extremes, monotonic, constant;
//                                                  the decoder must end exactly at the stream's end
//   byte_stream_split    -> byte_stream_split
//   delta_length / delta_prefix -> delta_length_views / delta_prefix_views
//   dictionaries         indices map back to the values; -0.0 / +0.0 and NaN payloads stay apart
//   statistics           against a naive scan; Parquet's float rules
#include <nanom/columnar_encode.hpp>

#include <cmath>
#include <memory>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

namespace nm = nanom;
namespace col = nanom::columnar;
using bytes_v = std::vector<std::byte>;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

/// Values with runs (long and short) and noise, each < 2^width.
template <class V>
static std::vector<V> runny(std::mt19937_64& rng, std::size_t n, unsigned width) {
  const std::uint64_t mask = width >= 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << width) - 1;
  std::vector<V> v;
  while (v.size() < n) {
    const V x = V(rng() & mask);
    const std::size_t len = rng() % 4 == 0 ? 1 + rng() % 40 : 1;
    for (std::size_t k = 0; k < len && v.size() < n; ++k) v.push_back(x);
  }
  return v;
}

template <class U>
static void test_pack_bits(std::mt19937_64& rng) {
  for (unsigned w = 0; w <= 8 * sizeof(U); ++w) {
    for (int t = 0; t < 30; ++t) {
      const std::size_t n = rng() % 300;
      const std::uint64_t mask = w >= 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << w) - 1;
      std::vector<U> v(n);
      for (auto& x : v) x = U(rng() & mask);
      bytes_v out;
      col::pack_bits<U>(v, w, out);
      CHECK(out.size() == (n * w + 7) / 8);
      std::vector<U> back(n);
      CHECK(col::unpack_bits<U>(out, w, std::span<U>(back), n));
      CHECK(back == v);
    }
  }
}

static void test_rle_hybrid(std::mt19937_64& rng) {
  for (unsigned w = 0; w <= 32; ++w) {
    for (int t = 0; t < 40; ++t) {
      const std::size_t n = rng() % 2000;
      auto v = t % 3 == 0 ? std::vector<std::uint32_t>(n, w ? std::uint32_t(rng() & ((std::uint64_t(1) << w) - 1)) : 0)
                          : runny<std::uint32_t>(rng, n, w);
      bytes_v out;
      col::rle_hybrid_encode<std::uint32_t>(v, w, out);
      col::rle_bp_decoder d(out, w);
      std::vector<std::uint32_t> back(n);
      CHECK(d.get(back.data(), n) == n && d.ok());
      CHECK(back == v);
      // a constant column is one RLE run: header + value
      if (t % 3 == 0 && n >= 8) CHECK(out.size() <= 10 + (w + 7) / 8);
    }
  }
  // runs that straddle group boundaries after a literal: 3 noise values, then a run of 20
  std::vector<std::uint32_t> v = {1, 2, 3};
  v.insert(v.end(), 20, 7u);
  v.push_back(4);
  bytes_v out;
  col::rle_hybrid_encode<std::uint32_t>(v, 3, out);
  col::rle_bp_decoder d(out, 3);
  std::vector<std::uint32_t> back(v.size());
  CHECK(d.get(back.data(), v.size()) == v.size() && back == v);
}

static void test_rle_bitmap(std::mt19937_64& rng) {
  for (int t = 0; t < 400; ++t) {
    const std::size_t n = rng() % 3000;
    const unsigned density = rng() % 6;  // 0: all 0, 5: all 1, else mixed / runny
    std::vector<std::uint8_t> bm((n + 7) / 8 + 1, 0);
    std::vector<std::uint32_t> vals(n);
    bool cur = rng() & 1;
    for (std::size_t i = 0; i < n; ++i) {
      bool b;
      if (density == 0) b = false;
      else if (density == 5) b = true;
      else if (density == 4) { if (rng() % 50 == 0) cur = !cur; b = cur; }  // long runs
      else b = rng() % 4 < density;
      vals[i] = b;
      if (b) bm[i / 8] |= std::uint8_t(1u << (i % 8));
    }
    bytes_v out;
    col::rle_bitmap_encode(bm.data(), n, out);
    // decodes as values …
    col::rle_bp_decoder d(out, 1);
    std::vector<std::uint32_t> back(n);
    CHECK(d.get(back.data(), n) == n && back == vals);
    // … and straight back into a bitmap
    bytes_v bm2((n + 7) / 8 + 1);
    col::rle_bp_decoder d2(out, 1);
    CHECK(col::rle_bitmap(d2, n, bm2, 0));
    bool same = true;
    for (std::size_t i = 0; i < n; ++i) same = same && (((std::uint8_t(bm2[i / 8]) >> (i % 8)) & 1) == vals[i]);
    CHECK(same);
    if ((density == 0 || density == 5) && n >= 64) CHECK(out.size() <= 8);  // one RLE run (+ tail)
  }
}

static void test_levels(std::mt19937_64& rng) {
  for (std::uint16_t maxv = 1; maxv < 12; ++maxv) {
    for (int t = 0; t < 40; ++t) {
      const std::size_t n = rng() % 1500;
      auto v = runny<std::uint16_t>(rng, n, 16);
      for (auto& x : v) x = std::uint16_t(x % (maxv + 1));
      bytes_v out;
      col::encode_levels(v, maxv, out);
      std::vector<std::uint16_t> back(n);
      CHECK(col::decode_levels(out, maxv, n, back.data()));
      CHECK(back == v);
    }
  }
}

template <class T>
static void test_dbp(std::mt19937_64& rng) {
  const T lo = std::numeric_limits<T>::min(), hi = std::numeric_limits<T>::max();
  for (int t = 0; t < 300; ++t) {
    const std::size_t n = t < 6 ? std::size_t(t) : std::size_t(rng() % 1200);
    std::vector<T> v(n);
    const int shape = t % 5;
    for (std::size_t i = 0; i < n; ++i) {
      switch (shape) {
        case 0: v[i] = T(rng()); break;                                  // full range noise
        case 1: v[i] = T(std::int64_t(i) * 3 + 1000); break;             // monotonic
        case 2: v[i] = T(42); break;                                     // constant
        case 3: v[i] = i % 2 ? lo : hi; break;                           // extreme alternation
        default: v[i] = T(std::int64_t(rng() % 1000) - 500); break;      // small values
      }
    }
    bytes_v out;
    col::delta_binary_packed_encode<T>(v, out);
    std::vector<T> back(n);
    auto used = col::delta_binary_packed<T>(out, std::span<T>(back), n);
    CHECK(used.has_value());
    if (used) CHECK(*used == out.size());  // the stream ends exactly where the decoder stops
    CHECK(back == v);
  }
}

static void test_bss(std::mt19937_64& rng) {
  for (std::size_t width : {1u, 2u, 4u, 8u, 12u, 16u}) {
    const std::size_t n = rng() % 500;
    bytes_v in(n * width);
    for (auto& b : in) b = std::byte(rng());
    bytes_v enc;
    col::byte_stream_split_encode(in, width, n, enc);
    bytes_v back(n * width);
    CHECK(enc.size() == n * width);
    CHECK(n == 0 || col::byte_stream_split(enc, width, n, back));
    CHECK(back == in);
  }
}

static void test_byte_arrays(std::mt19937_64& rng) {
  for (int t = 0; t < 200; ++t) {
    const std::size_t n = rng() % 300;
    std::vector<std::string> owned(n);
    std::vector<std::string_view> vals(n);
    const std::string pool[] = {"", "a", "apple", "applesauce", "apply", "banana", "\xff\x00x", std::string(200, 'z')};
    for (std::size_t i = 0; i < n; ++i) {
      owned[i] = pool[rng() % 8];
      if (rng() % 3 == 0) owned[i] += std::to_string(rng() % 100);
      vals[i] = owned[i];
    }
    bytes_v dl;
    CHECK(col::delta_length_encode(vals, dl));
    std::vector<std::int32_t> s1, s2;
    std::vector<std::string_view> back(n);
    CHECK(col::delta_length_views(dl, n, s1, back));
    CHECK(back == vals);
    bytes_v dp;
    CHECK(col::delta_prefix_encode(vals, dp));
    std::vector<char> arena;
    CHECK(col::delta_prefix_views(dp, n, s1, s2, arena, back, 1u << 24));
    CHECK(back == vals);
  }
}

static void test_dictionaries(std::mt19937_64& rng) {
  col::string_dictionary sd;
  std::vector<std::string> owned;
  for (int i = 0; i < 5000; ++i) owned.push_back("k" + std::to_string(rng() % 700));
  std::vector<std::uint32_t> idx;
  for (const auto& s : owned) idx.push_back(sd.index_of(s));
  bool ok = true;
  for (std::size_t i = 0; i < owned.size(); ++i) ok = ok && sd.values()[idx[i]] == owned[i];
  CHECK(ok && sd.size() <= 700);
  std::size_t bytes = 0;
  for (auto v : sd.values()) bytes += v.size();
  CHECK(bytes == sd.bytes());

  // keys of every length 0..80, each in an exact-size allocation (ASan sees any over-read by the hash)
  col::string_dictionary lens;
  std::vector<std::unique_ptr<char[]>> keep;
  for (std::size_t len = 0; len <= 80; ++len) {
    keep.emplace_back(new char[len ? len : 1]);
    for (std::size_t k = 0; k < len; ++k) keep.back()[k] = char('a' + (len + k) % 26);
    const std::string_view key(keep.back().get(), len);
    const auto i = lens.index_of(key);
    CHECK(lens.values()[i] == key && lens.index_of(key) == i);
  }
  CHECK(lens.size() == 81);

  col::fixed_dictionary<double> fd;
  const double vals[] = {0.0, -0.0, std::nan("1"), std::nan("2"), 1.5, 0.0, -0.0, 1.5};
  std::vector<std::uint32_t> di;
  for (double v : vals) di.push_back(fd.index_of(v));
  CHECK(fd.size() == 5);
  CHECK(di[0] == di[5] && di[1] == di[6] && di[0] != di[1] && di[2] != di[3]);
  ok = true;
  for (std::size_t i = 0; i < 8; ++i) ok = ok && std::memcmp(&fd.values()[di[i]], &vals[i], 8) == 0;
  CHECK(ok);
  col::fixed_dictionary<std::int64_t> id;
  for (int i = 0; i < 100000; ++i) (void)id.index_of(std::int64_t(rng() % 20000));
  CHECK(id.size() <= 20000 && id.size() > 19000);
}

static void test_stats(std::mt19937_64& rng) {
  std::vector<std::int32_t> v(1000);
  std::vector<std::uint8_t> valid(125);
  for (auto& x : v) x = std::int32_t(rng());
  for (auto& b : valid) b = std::uint8_t(rng());
  auto s = col::compute_stats<std::int32_t>(v, valid.data(), v.size());
  std::int32_t mn = INT32_MAX, mx = INT32_MIN;
  std::int64_t nulls = 0;
  for (std::size_t i = 0; i < v.size(); ++i) {
    if (!((valid[i / 8] >> (i % 8)) & 1)) { ++nulls; continue; }
    mn = std::min(mn, v[i]);
    mx = std::max(mx, v[i]);
  }
  CHECK(s.has_minmax && s.min == mn && s.max == mx && s.null_count == nulls);
  const double f[] = {std::nan(""), 0.0, -3.0, std::nan("")};
  auto fs = col::compute_stats<double>(f, nullptr, 4);
  CHECK(fs.has_minmax && fs.min == -3.0 && fs.max == 0.0 && !std::signbit(fs.max));
  const double z[] = {0.0, 0.0};
  auto zs = col::compute_stats<double>(z, nullptr, 2);
  CHECK(std::signbit(zs.min) && !std::signbit(zs.max));  // min +0 -> -0, max stays +0
  const double nz[] = {-0.0};
  auto nzs = col::compute_stats<double>(nz, nullptr, 1);
  CHECK(std::signbit(nzs.min) && !std::signbit(nzs.max));  // max -0 -> +0
  const double nan_only[] = {std::nan("")};
  CHECK(!col::compute_stats<double>(nan_only, nullptr, 1).has_minmax);
  const std::string_view sv[] = {"b", "\xff", "a", "ab", ""};
  auto bs = col::compute_binary_stats(sv);
  CHECK(bs.min == "" && bs.max == "\xff");  // unsigned byte order: 0xff sorts last
}

int main() {
  std::mt19937_64 rng(77);
  test_pack_bits<std::uint32_t>(rng);
  test_pack_bits<std::uint64_t>(rng);
  test_rle_hybrid(rng);
  test_rle_bitmap(rng);
  test_levels(rng);
  test_dbp<std::int32_t>(rng);
  test_dbp<std::int64_t>(rng);
  test_bss(rng);
  test_byte_arrays(rng);
  test_dictionaries(rng);
  test_stats(rng);
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("columnar encode tests: all passed");
  return 0;
}
