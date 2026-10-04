// codec_check — decompress files listed in a manifest with nanom/codec.hpp and compare them with
// the expected bytes. Driver for tests/codec_differential.py (pyarrow produces the compressed side).
//   codec_check manifest.txt     (lines: "<snappy|lz4_raw> <compressed file> <expected file>")
#include <nanom/codec.hpp>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::vector<std::byte> slurp(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  const std::vector<char> c((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::vector<std::byte> b(c.size());
  if (!c.empty()) std::memcpy(b.data(), c.data(), c.size());
  return b;
}

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  std::ifstream m(argv[1]);
  std::string codec, in, exp;
  int n = 0, bad = 0;
  while (m >> codec >> in >> exp) {
    const auto src = slurp(in), want = slurp(exp);
    std::vector<std::byte> out(want.size());
    nanom::codec::status r = codec == "snappy" ? nanom::codec::snappy_decompress(src, out)
                                               : nanom::codec::lz4_block_decompress(src, out);
    ++n;
    if (!r || *r != want.size() || out != want) {
      ++bad;
      std::printf("MISMATCH %s %s: %s\n", codec.c_str(), in.c_str(), r ? "wrong bytes" : r.error().what);
    }
  }
  std::printf("codec_check: %d buffers, %d mismatches\n", n, bad);
  return bad || n == 0 ? 1 : 0;
}
