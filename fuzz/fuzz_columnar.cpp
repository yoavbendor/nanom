// fuzz_columnar — robustness fuzzing of the page decode kernels (nanom/columnar.hpp) and the
// dependency-free codecs (nanom/codec.hpp): arbitrary bytes must never crash, read or write out of
// bounds, or loop without making progress (run under ASan/UBSan).
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_columnar.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_columnar_fuzz [iterations] [seed]
#include <nanom/codec.hpp>
#include <nanom/columnar.hpp>

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
  std::vector<std::byte> dec(std::size_t(data[1]) * 256 + data[2]);
  (void)cdc::snappy_decompress(in, dec);
  (void)cdc::lz4_block_decompress(in, dec);
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
