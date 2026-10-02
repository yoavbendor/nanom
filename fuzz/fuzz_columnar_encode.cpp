// fuzz_columnar_encode — every encoder of nanom/columnar_encode.hpp against its decoder.
//
// The input bytes become values (and a bit width / length taken from the first bytes); each is
// encoded and decoded back, and must come back identical:
//   pack_bits <-> unpack_bits, rle_hybrid_encode <-> rle_bp_decoder, rle_bitmap_encode <->
//   rle_bitmap, delta_binary_packed (int32 / int64, decoder ends at the stream end),
//   byte_stream_split, delta_length / delta_prefix byte arrays, string / fixed dictionaries.
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_columnar_encode.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_columnar_encode_fuzz [iterations] [seed]
#include <nanom/columnar_encode.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <vector>

namespace col = nanom::columnar;

namespace {
[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "fuzz_columnar_encode: %s\n", what);
  __builtin_trap();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  const unsigned w32 = data[0] % 33, w64 = data[0] % 65;
  const std::uint8_t* p = data + 2;
  const std::size_t m = size - 2;
  const std::size_t n = m / 8;

  // values from the input, masked to the width (runs appear when bytes repeat)
  std::vector<std::uint32_t> v32(n);
  std::vector<std::uint64_t> v64(n);
  for (std::size_t i = 0; i < n; ++i) {
    std::uint64_t x;
    std::memcpy(&x, p + 8 * i, 8);
    if (data[1] & 1) x = x % 3;  // run-heavy
    v64[i] = w64 >= 64 ? x : x & ((std::uint64_t(1) << w64) - 1);
    v32[i] = std::uint32_t(w32 >= 32 ? x : x & ((std::uint64_t(1) << w32) - 1));
  }
  {
    std::vector<std::byte> out;
    col::pack_bits<std::uint64_t>(v64, w64, out);
    std::vector<std::uint64_t> back(n);
    if (!col::unpack_bits<std::uint64_t>(out, w64, std::span<std::uint64_t>(back), n) || back != v64)
      die("pack_bits / unpack_bits");
  }
  {
    std::vector<std::byte> out;
    col::rle_hybrid_encode<std::uint32_t>(v32, w32, out);
    col::rle_bp_decoder d(out, w32);
    std::vector<std::uint32_t> back(n);
    if (d.get(back.data(), n) != n || back != v32) die("rle_hybrid_encode / rle_bp_decoder");
  }
  {
    const std::size_t bits = m ? m * 8 - (data[1] % 8) : 0;
    std::vector<std::byte> out;
    col::rle_bitmap_encode(p, bits, out);
    std::vector<std::byte> back(m + 1);
    col::rle_bp_decoder d(out, 1);
    if (!col::rle_bitmap(d, bits, back, 0)) die("rle_bitmap_encode does not decode");
    for (std::size_t i = 0; i < bits; ++i)
      if (((std::uint8_t(back[i / 8]) >> (i % 8)) & 1) != ((p[i / 8] >> (i % 8)) & 1)) die("rle_bitmap round trip");
  }
  {
    std::vector<std::int64_t> s(n);
    std::vector<std::int32_t> s32(n);
    for (std::size_t i = 0; i < n; ++i) {
      s[i] = std::int64_t(v64[i]);
      s32[i] = std::int32_t(v64[i]);
    }
    std::vector<std::byte> o64, o32;
    col::delta_binary_packed_encode<std::int64_t>(s, o64);
    col::delta_binary_packed_encode<std::int32_t>(s32, o32);
    std::vector<std::int64_t> b64(n);
    std::vector<std::int32_t> b32(n);
    auto u64 = col::delta_binary_packed<std::int64_t>(o64, std::span<std::int64_t>(b64), n);
    auto u32 = col::delta_binary_packed<std::int32_t>(o32, std::span<std::int32_t>(b32), n);
    if (!u64 || *u64 != o64.size() || b64 != s) die("delta_binary_packed int64");
    if (!u32 || *u32 != o32.size() || b32 != s32) die("delta_binary_packed int32");
  }
  {
    const std::size_t width = 1 + data[1] % 16, k = m / width;
    std::vector<std::byte> enc, back(k * width);
    const auto in = std::span<const std::byte>(reinterpret_cast<const std::byte*>(p), k * width);
    col::byte_stream_split_encode(in, width, k, enc);
    if (k && (!col::byte_stream_split(enc, width, k, back) || !std::equal(back.begin(), back.end(), in.begin())))
      die("byte_stream_split");
  }
  {
    // byte strings: split the input at bytes equal to data[1]
    std::vector<std::string_view> vals;
    const char* s = reinterpret_cast<const char*>(p);
    std::size_t start = 0;
    for (std::size_t i = 0; i <= m; ++i)
      if (i == m || p[i] == data[1]) {
        vals.emplace_back(s + start, i - start);
        start = i + 1;
      }
    std::vector<std::byte> dl, dp;
    std::vector<std::int32_t> a, b;
    std::vector<std::string_view> back(vals.size());
    std::vector<char> arena;
    if (!col::delta_length_encode(vals, dl) || !col::delta_length_views(dl, vals.size(), a, back) || back != vals)
      die("delta_length");
    if (!col::delta_prefix_encode(vals, dp) || !col::delta_prefix_views(dp, vals.size(), a, b, arena, back, 1u << 24) ||
        back != vals)
      die("delta_prefix");
    col::string_dictionary dict;
    for (auto v : vals) {
      const auto i = dict.index_of(v);  // before values(): adding an entry may reallocate
      if (dict.values()[i] != v) die("string_dictionary");
    }
    col::fixed_dictionary<std::uint64_t> fd;
    for (auto x : v64) {
      const auto i = fd.index_of(x);
      if (fd.values()[i] != x) die("fixed_dictionary");
    }
  }
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20000;
  std::uint64_t s = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull;
  const auto next = [&] { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; };
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    buf.resize(next() % 1200);
    const unsigned alphabet = 1 + unsigned(next() % 256);  // small alphabets make runs and repeats
    for (auto& x : buf) x = std::uint8_t(next() % alphabet);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("nm_columnar_encode_fuzz: %d iterations OK\n", iters);
  return 0;
}
#endif
