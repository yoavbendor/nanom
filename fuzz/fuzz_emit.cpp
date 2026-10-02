// fuzz_emit — writing fixed-layout structs (nanom/emit.hpp) against reading them (strct<T>()).
//
// Properties checked on every input, for several layouts (bytes and big/little default order):
//   1. emit(strct<T>(b)) == b: every bit read is written back in place (bit fields of both orders,
//      signed fields, be / le / plain scalars, arrays, nesting);
//   2. a header written with computed fields (IPv4 total length + checksum over a payload taken
//      from the input) passes verify_computed, and fails it once any header byte is flipped.
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_emit.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_emit_fuzz [iterations] [seed]
#include <nanom/emit.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;

struct ipv4 {
  nm::ubits<4> version, ihl;
  nm::ubits<6> dscp;
  nm::ubits<2> ecn;
  nm::be<u16> total_len, ident;
  nm::ubits<3> flags;
  nm::ubits<13> frag_off;
  u8 ttl, proto;
  nm::be<u16> checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum, src, dst);
struct regs {  // lsb0 register layout + signed fields + plain scalars
  nm::ubits<3, nm::bit_order::lsb0> mode;
  nm::ibits<5, nm::bit_order::lsb0> trim;
  nm::ibits<12> offset;
  nm::ubits<4> gain;
  std::int32_t raw;
  float scale;
  std::array<nm::le<u16>, 3> taps;
};
NANOM_DESCRIBE(regs, mode, trim, offset, gain, raw, scale, taps);
struct framed {
  ipv4 ip;
  regs r;
  nm::be<double> t;
};
NANOM_DESCRIBE(framed, ip, r, t);

inline u16 csum(std::span<const std::byte> b) {
  u32 s = 0;
  for (std::size_t i = 0; i + 1 < b.size(); i += 2) s += u32(u8(b[i])) << 8 | u8(b[i + 1]);
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return u16(~s);
}
template <>
struct nm::computed<ipv4> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_len">([](const ipv4& h, const nm::emit_ctx& c) { return 4 * h.ihl.v + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h, const nm::emit_ctx&) { return csum(h); }),
  };
};

namespace {
[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "fuzz_emit: %s\n", what);
  __builtin_trap();
}

template <class T>
void byte_roundtrip(const std::uint8_t* data, std::size_t size, std::endian order) {
  if (size < nm::wire_size_v<T>) return;
  const auto in = std::span<const std::byte>(reinterpret_cast<const std::byte*>(data), nm::wire_size_v<T>);
  auto v = nm::strct<T>(order)(nm::from(in));
  if (!v) die("strct failed on enough bytes");
  std::vector<std::byte> out(nm::wire_size_v<T>);  // exact size
  if constexpr (!std::is_same_v<T, ipv4>) {  // ipv4 has computed fields: covered below
    auto n = nm::emit(v->value, out, {}, order);
    if (!n || !std::equal(out.begin(), out.end(), in.begin())) die("emit(strct(b)) != b");
  }
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  for (auto order : {std::endian::little, std::endian::big}) {
    byte_roundtrip<regs>(data, size, order);
    byte_roundtrip<framed>(data, size, order);
  }
  // computed fields: header from the input, payload = the rest of the input
  if (size >= nm::wire_size_v<ipv4>) {
    auto h = nm::strct<ipv4>()(nm::from(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data), size)));
    if (!h) die("strct<ipv4> failed");
    h->value.ihl.v = 5;
    const auto payload = std::span<const std::byte>(reinterpret_cast<const std::byte*>(data) + 20, size - 20);
    auto b = nm::to_bytes(h->value, nm::emit_ctx{payload});
    if (b) {
      if (!nm::verify_computed<ipv4>(*b, nm::emit_ctx{payload})) die("emitted header fails verify_computed");
      auto t = *b;
      t[data[0] % 20] ^= std::byte{std::uint8_t(1 + data[1] % 255)};
      if (nm::verify_computed<ipv4>(t, nm::emit_ctx{payload})) die("a corrupted header passes verify_computed");
    } else if (20 + payload.size() <= 0xffff) {
      die("emit failed for a payload that fits");
    }
  }
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20000;
  std::uint64_t s = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull;
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    buf.resize(s % 200);
    for (auto& x : buf) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; x = std::uint8_t(s >> 24); }
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("nm_emit_fuzz: %d iterations OK\n", iters);
  return 0;
}
#endif
