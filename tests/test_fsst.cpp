// SPDX-License-Identifier: Apache-2.0
// FSST (nanom/fsst.hpp, nanom/fsst_encode.hpp): trained tables round-trip every value, the decoder
// refuses every malformed table and code, and the encoder's output is pinned to bytes stock Lance
// reads (nanolance's encoder before it moved here; its files are read by pylance).
#include <nanom/fsst_encode.hpp>

#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace fs = nanom::codec::fsst;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

static std::span<const std::byte> bytes_of(const std::string& s) {
  return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

static std::string decode_all(const fs::symbol_table& t, std::span<const std::byte> codes, bool& ok) {
  std::vector<std::byte> out(fs::max_decoded_size(codes.size()));
  const auto n = fs::decode(t, codes, out);
  ok = n.has_value();
  return ok ? std::string(reinterpret_cast<const char*>(out.data()), *n) : std::string();
}

static void test_round_trips(std::mt19937_64& rng) {
  const char* words[] = {"lance", "nano", "parquet", "column", "https://", "example.com/", "user_", "id=", "\x01\x02", "zz"};
  for (int corpus = 0; corpus < 120; ++corpus) {
    std::vector<std::string> owned(1 + rng() % 2000);
    const int shape = corpus % 4;  // random bytes, words, a 4-letter alphabet, tiny values
    for (auto& s : owned) {
      const std::size_t len = shape == 3 ? rng() % 3 : rng() % 60;
      if (shape == 0) for (std::size_t i = 0; i < len; ++i) s += char(rng());
      else if (shape == 1) while (s.size() < len) s += words[rng() % 10];
      else for (std::size_t i = 0; i < len; ++i) s += char('a' + rng() % (shape == 2 ? 4 : 26));
    }
    std::vector<std::span<const std::byte>> values;
    for (const auto& s : owned) values.push_back(bytes_of(s));
    fs::encoder e;
    if (!fs::train(values, e)) continue;
    CHECK(e.symbol_count >= 1 && e.symbol_count <= 255);
    const auto wire = fs::serialize(e);
    fs::symbol_table t;
    CHECK(fs::parse_symbol_table(wire, t).has_value());
    CHECK(!t.passthrough && t.symbol_count == e.symbol_count);
    for (const auto& s : owned) {
      std::vector<std::byte> codes;
      fs::compress(e, bytes_of(s), codes);
      CHECK(codes.size() <= fs::max_compressed_size(s.size()));
      bool ok = false;
      CHECK(decode_all(t, codes, ok) == s && ok);
    }
  }
  fs::encoder none;
  CHECK(!fs::train(std::span<const std::span<const std::byte>>{}, none));  // nothing to learn from
}

// A table built by hand: 3 symbols "abcd", "xy", "pqr".
static std::vector<std::byte> hand_table(std::uint64_t header_low = (std::uint64_t{1} << 24) | 3) {
  std::vector<std::byte> t(fs::kSymbolTableBytes);
  const std::uint64_t header = fs::kMagic | header_low;
  std::memcpy(t.data(), &header, 8);
  std::memcpy(t.data() + 8, "abcd\0\0\0\0xy\0\0\0\0\0\0pqr\0\0\0\0\0", 24);
  t[32] = std::byte{4};
  t[33] = std::byte{2};
  t[34] = std::byte{3};
  return t;
}

static void test_decoder_refusals() {
  fs::symbol_table t;
  CHECK(fs::parse_symbol_table(hand_table(), t).has_value());
  CHECK(t.symbol_count == 3 && t.lengths[0] == 4 && t.lengths[1] == 2 && t.lengths[2] == 3);
  const std::byte codes[] = {std::byte{0}, std::byte{255}, std::byte{'!'}, std::byte{1}, std::byte{2}};
  bool ok = false;
  CHECK(decode_all(t, codes, ok) == "abcd!xypqr" && ok);

  // A refused table leaves the caller's untouched.
  fs::symbol_table kept;
  kept.symbol_count = 0xABCD;
  auto bad = hand_table();
  bad.pop_back();
  CHECK(!fs::parse_symbol_table(bad, kept) && kept.symbol_count == 0xABCD);    // wrong size
  bad = hand_table();
  bad[7] = std::byte{0};
  CHECK(!fs::parse_symbol_table(bad, kept) && kept.symbol_count == 0xABCD);    // wrong magic
  for (const int len : {0, 9}) {
    bad = hand_table();
    bad[33] = std::byte(len);
    const auto r = fs::parse_symbol_table(bad, kept);
    CHECK(!r && r.error().at == 33 && kept.symbol_count == 0xABCD);             // length outside 1..8
  }

  std::vector<std::byte> room(fs::max_decoded_size(2));
  const std::byte unknown[] = {std::byte{0}, std::byte{3}};                     // code 3: undeclared
  auto r = fs::decode(t, unknown, room);
  CHECK(!r && r.error().at == 1);
  const std::byte dangling[] = {std::byte{1}, std::byte{255}};                  // escape, no byte
  r = fs::decode(t, dangling, room);
  CHECK(!r && r.error().at == 1);
  std::vector<std::byte> small(fs::max_decoded_size(2) - 1);                    // output under the bound
  CHECK(!fs::decode(t, unknown, small));

  // The unchecked form leaves dst where it was on a refusal.
  std::vector<std::byte> buf(64);
  std::byte* dst = buf.data();
  nanom::codec::codec_error why;
  CHECK(!fs::decode_unchecked(t, unknown, dst, &why) && dst == buf.data() && why.at == 1);

  // encoder_switch clear: the values are stored as they are and copied through.
  fs::symbol_table pass;
  CHECK(fs::parse_symbol_table(hand_table(0), pass).has_value() && pass.passthrough && pass.symbol_count == 0);
  const std::string raw = "\xff\xff stored verbatim";
  CHECK(decode_all(pass, bytes_of(raw), ok) == raw && ok);
}

// nanolance's encoder, before it moved here, on this corpus: 218 symbols and these hashes.
static void test_golden() {
  const char* w[] = {"https://", "example.com/", "user_", "id=", "lance", "/path/", "?q=", "&x="};
  std::uint64_t s = 0x1234567;
  auto next = [&] {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  };
  std::vector<std::string> owned(3000);
  for (auto& x : owned) {
    while (x.size() < 10 + next() % 50) x += w[next() % 8];
    x += std::to_string(next() % 100000);
  }
  std::vector<std::span<const std::byte>> values;
  for (const auto& x : owned) values.push_back(bytes_of(x));
  fs::encoder e;
  CHECK(fs::train(values, e));
  const auto fnv = [](const std::byte* p, std::size_t n, unsigned long long h) {
    for (std::size_t i = 0; i < n; ++i) h = (h ^ std::uint8_t(p[i])) * 1099511628211ull;
    return h;
  };
  const auto table = fs::serialize(e);
  unsigned long long codes_hash = 1469598103934665603ull;
  std::size_t total = 0;
  for (const auto& v : values) {
    std::vector<std::byte> c;
    fs::compress(e, v, c);
    codes_hash = fnv(c.data(), c.size(), codes_hash);
    total += c.size();
  }
  CHECK(e.symbol_count == 218);
  CHECK(fnv(table.data(), table.size(), 1469598103934665603ull) == 0x2e0a9ee7c5ed67f9ull);
  CHECK(codes_hash == 0x54f168575a0cf4dfull && total == 25620);
}

int main() {
  std::mt19937_64 rng(20261004);
  test_round_trips(rng);
  test_decoder_refusals();
  test_golden();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("fsst tests: all passed\n");
  return 0;
}
