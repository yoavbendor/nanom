// fuzz_columnar — robustness fuzzing of the page decode kernels (nanom/columnar.hpp) and the
// dependency-free codecs (nanom/codec.hpp): arbitrary bytes must never crash, read or write out of
// bounds, or loop without making progress (run under ASan/UBSan).
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_columnar.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_columnar_fuzz [iterations] [seed]
#include <nanom/codec.hpp>
#include <nanom/columnar.hpp>
#include <nanom/fastlanes.hpp>
#include <nanom/formats/parquet_values.hpp>
#include <nanom/values.hpp>

#include <array>
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace col = nanom::columnar;
namespace cdc = nanom::codec;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 3) return 0;
  const unsigned width = data[0] % 34;            // includes the invalid 33
  const std::size_t n = std::size_t(data[1]) * 37 + data[2];
  const auto in = std::span<const std::byte>(reinterpret_cast<const std::byte*>(data + 3), size - 3);

  col::rle_bp_decoder d(in, width);
  std::vector<std::uint32_t> out(n);
  std::size_t got = 0;
  while (got < n) {
    const std::size_t k = d.get(out.data() + got, std::min<std::size_t>(n - got, 1 + (got % 61)));
    if (!k) break;
    got += k;
  }
  std::vector<std::uint64_t> u64(n);
  (void)col::unpack_bits<std::uint64_t>(in, data[0] % 66, std::span<std::uint64_t>(u64), n);
  std::vector<std::int32_t> i32(n);
  std::vector<std::int64_t> i64(n);
  (void)col::delta_binary_packed<std::int32_t>(in, std::span<std::int32_t>(i32), n);
  (void)col::delta_binary_packed<std::int64_t>(in, std::span<std::int64_t>(i64), n);
  std::vector<std::byte> raw(n * 8);
  (void)col::byte_stream_split(in, 1 + data[0] % 16, n / 2, raw);
  (void)col::copy_bits(in, n, raw, data[0] % 13);
  // FastLanes blocks from arbitrary bytes, at every width up to one past the word (refused). The
  // packed words are copied into exactly-sized buffers, so ASan sees any read past them.
  {
    const auto block = [&]<class T>(T) {
      constexpr unsigned bits = sizeof(T) * 8;
      const unsigned w = data[1] % (bits + 2);
      std::vector<T> packed(std::min<std::size_t>(in.size() / sizeof(T),
                                                  col::fastlanes::packed_words_1024<T>(bits)));
      if (!packed.empty()) std::memcpy(packed.data(), in.data(), packed.size() * sizeof(T));
      std::array<T, 1024> vals{};
      const bool ok = col::fastlanes::unpack_1024<T>(w, std::span<const T>(packed), vals);
      if (ok != (w <= bits && packed.size() >= col::fastlanes::packed_words_1024<T>(w))) __builtin_trap();
    };
    block(std::uint8_t{});
    block(std::uint16_t{});
    block(std::uint32_t{});
    block(std::uint64_t{});
  }
  std::vector<std::byte> dec(std::size_t(data[1]) * 256 + data[2]);
  (void)cdc::snappy_decompress(in, dec);
  // size the output from the preamble too (exactly: ASan sees any write past it), so random
  // bodies reach the element loop instead of failing the length check
  if (auto want = cdc::snappy_uncompressed_length(in); want && *want <= (1u << 16)) {
    std::vector<std::byte> exact(*want);
    (void)cdc::snappy_decompress(in, exact);
  }
  (void)cdc::lz4_block_decompress(in, dec);

  // values.hpp: every wire-driven kernel on the same bytes, outputs sized exactly
  {
    const std::uint16_t maxv = std::uint16_t(1 + data[0] % 12);
    std::vector<std::uint16_t> lv(n);
    const bool levels_ok = bool(col::decode_levels(in, maxv, n, lv.data()));
    std::vector<std::byte> bm((n + 7) / 8 + 1);
    col::rle_bp_decoder d1(in, 1);
    (void)col::rle_bitmap(d1, n, bm, data[1] % 8);
    if (levels_ok) {
      // the decoded levels as both rep and def of a list / struct (structure checks, no overruns)
      std::vector<std::int32_t> offs(n + 1);
      std::vector<std::uint8_t> vb(n / 8 + 1);
      std::int64_t nulls = 0, elems = 0;
      const col::dremel_node nd{0, 0, std::uint16_t(data[2] % 3), std::uint16_t(1 + data[2] % 3), 1};
      for (std::int64_t expect : {std::int64_t(0), std::int64_t(n / 2), std::int64_t(n)}) {
        std::fill(vb.begin(), vb.end(), 0);
        if (std::size_t(expect) <= n)
          (void)col::list_slots(lv.data(), lv.data(), n, nd, expect, offs.data(), vb.data(), nulls, elems);
        std::fill(vb.begin(), vb.end(), 0);
        (void)col::struct_slots(lv.data(), lv.data(), n, nd, expect, vb.data(), nulls);
      }
      std::vector<std::uint8_t> sv(n / 8 + 1);
      (void)col::level_slots(lv.data(), n, std::uint16_t(data[1] % 4), maxv, sv.data());
    }
    std::vector<std::string_view> views(n);
    (void)col::length_prefixed_views(in, n, views);
    std::vector<std::int32_t> a, b;
    std::vector<char> arena;
    (void)col::delta_length_views(in, n, a, views);
    (void)col::delta_prefix_views(in, n, a, b, arena, views, 1u << 16);
    std::vector<std::uint32_t> idx(n);
    (void)nanom_formats::parquet::dictionary_indices(in, n, 1 + data[0], idx);
    std::vector<std::byte> out(in.size() + col::kValueSlack);
    std::vector<std::int32_t> ends(n);
    std::int64_t cur = 0;
    (void)col::append_length_prefixed(in, n, nullptr, out.data(), cur, ends.data(), INT32_MAX);
    (void)col::valid_utf8(std::string_view(reinterpret_cast<const char*>(in.data()), in.size()));
  }
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20000;
  std::uint64_t s = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull;
  auto next = [&] { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; };
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    buf.resize(3 + next() % 600);
    // skew toward small varints / headers so runs and blocks parse further
    for (auto& b : buf) b = std::uint8_t(next() % 4 == 0 ? next() >> 24 : next() % 16);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("nm_columnar_fuzz: %d iterations OK\n", iters);
  return 0;
}
#endif
