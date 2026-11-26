// Tests for nanom/checksum.hpp.
//
//   * Internet checksum: the fast (8 bytes at a time) path against a byte-pair RFC 1071 reference
//     over random lengths 0..2100 at every start alignment 0..7, scatter/gather over random splits
//     (odd-length parts included), textbook headers, pseudo-headers, RFC 1624 incremental update
//     against a full recompute, and constant evaluation;
//   * CRCs: the AUTOSAR SWS_Crc check values ("123456789") in static_asserts, the slicing-by-8
//     tables against a bit-at-a-time Rocksoft reference on random data, streaming over random
//     splits, and AUTOSAR start-value chaining (resume);
//   * emit computed fields: an IPv4 header checksum, a UDP checksum over its pseudo-header and an
//     E2E-style CRC8 over a protected payload (both through a custom emit context carrying the
//     bytes the checksum covers but the struct does not write).
#include <nanom/checksum.hpp>
#include <nanom/emit.hpp>

#include <cstdio>
#include <random>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

using bspan = std::span<const std::byte>;

// ------------------------------------------------------------------ references
static u16 ref_inet(const std::vector<std::byte>& b) {
  u32 s = 0;
  for (std::size_t i = 0; i < b.size(); i += 2) {
    u32 w = u32(u8(b[i])) << 8;
    if (i + 1 < b.size()) w |= u8(b[i + 1]);
    s += w;
    s = (s & 0xffff) + (s >> 16);
  }
  return u16(~s);
}

template <class P>
static typename P::type ref_crc(bspan b) {
  using T = typename P::type;
  constexpr unsigned W = P::width;
  const T top = T(T(1) << (W - 1));
  auto refl = [](u64 v, unsigned n) {
    u64 r = 0;
    for (unsigned i = 0; i < n; ++i) r |= ((v >> i) & 1) << (n - 1 - i);
    return r;
  };
  T reg = P::init;
  for (std::byte by : b) {
    u8 x = u8(by);
    if (P::reflected) x = u8(refl(x, 8));
    for (int i = 7; i >= 0; --i) {
      const bool bit = ((x >> i) & 1) != 0;
      const bool msb = (reg & top) != 0;
      reg = T(reg << 1);
      if (bit != msb) reg = T(reg ^ P::poly);
    }
  }
  if (P::reflected) reg = T(refl(reg, W));
  return T(reg ^ P::xorout);
}

static std::vector<std::byte> random_bytes(std::mt19937_64& rng, std::size_t n) {
  std::vector<std::byte> v(n);
  for (auto& b : v) b = std::byte(rng());
  return v;
}

// ------------------------------------------------------------------ compile time
constexpr std::array<std::byte, 20> kIpv4Hdr = [] {
  // the classic example header: 45 00 00 73 00 00 40 00 40 11 [b8 61] c0 a8 00 01 c0 a8 00 c7
  constexpr u8 raw[20] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                          0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
  std::array<std::byte, 20> a{};
  for (int i = 0; i < 20; ++i) a[i] = std::byte(raw[i]);
  return a;
}();
static_assert(nm::inet::checksum(bspan(kIpv4Hdr)) == 0xb861);
static_assert(nm::inet::checksum(std::string_view("\x01\x02\x03")) == u16(~u16(0x0102 + 0x0300)));
static_assert(nm::inet::update16(0xb861, 0x4011, 0x3f11) == u16(0xb961));  // TTL 64 -> 63

static_assert(nm::crc8_sae_j1850::compute(std::string_view("123456789")) == 0x4B);
static_assert(nm::crc8_h2f::compute(std::string_view("123456789")) == 0xDF);
static_assert(nm::crc16_ccitt_false::compute(std::string_view("123456789")) == 0x29B1);
static_assert(nm::crc16_arc::compute(std::string_view("123456789")) == 0xBB3D);
static_assert(nm::crc32::compute(std::string_view("123456789")) == 0xCBF43926u);
static_assert(nm::crc32_p4::compute(std::string_view("123456789")) == 0x1697D06Au);
static_assert(nm::crc64::compute(std::string_view("123456789")) == 0x995DC9BBDF1939FAull);
// a run long enough to take the 8-byte slicing path in constant evaluation too
static_assert(nm::crc32::compute(std::string_view("The quick brown fox jumps over the lazy dog")) ==
              0x414FA339u);

// ------------------------------------------------------------------ Internet checksum
static void test_inet(std::mt19937_64& rng) {
  // every alignment x many lengths, fast path vs reference
  std::vector<std::byte> big = random_bytes(rng, 2200 + 8);
  for (std::size_t align = 0; align < 8; ++align)
    for (std::size_t n = 0; n < 2100; n += (n < 80 ? 1 : 37)) {
      const bspan s(big.data() + align, n);
      const std::vector<std::byte> v(s.begin(), s.end());
      CHECK(nm::inet::checksum(s) == ref_inet(v));
    }
  // scatter/gather: random splits, odd parts included
  for (int iter = 0; iter < 3000; ++iter) {
    const std::size_t n = rng() % 600;
    auto v = random_bytes(rng, n);
    nm::inet::sum s;
    std::vector<bspan> parts;
    for (std::size_t at = 0; at < n;) {
      const std::size_t take = std::min<std::size_t>(n - at, rng() % 23);
      parts.emplace_back(v.data() + at, take);
      s.add(parts.back());
      at += take;
    }
    const u16 want = ref_inet(v);
    CHECK(s.checksum() == want);
    CHECK(nm::inet::checksum(std::span<const bspan>(parts)) == want);
  }
  // verify(): a buffer carrying its own correct checksum sums to all ones
  {
    auto h = kIpv4Hdr;
    const u16 c = nm::inet::checksum(bspan(h));
    h[10] = std::byte(c >> 8);
    h[11] = std::byte(c);
    CHECK(nm::inet::verify(bspan(h)));
    h[3] = std::byte(0x74);
    CHECK(!nm::inet::verify(bspan(h)));
  }
  // RFC 1624 incremental update == full recompute
  for (int iter = 0; iter < 2000; ++iter) {
    auto v = random_bytes(rng, 2 * (2 + rng() % 30));
    const u16 c0 = nm::inet::checksum(bspan(v));
    const std::size_t w = 2 * (rng() % (v.size() / 2 - 1));
    const u16 old16 = u16(u8(v[w]) << 8 | u8(v[w + 1]));
    const u32 old32 = u32(old16) << 16 | u32(u8(v[w + 2]) << 8 | u8(v[w + 3]));
    const u32 nw = u32(rng());
    if (iter & 1) {
      v[w] = std::byte(nw >> 8);
      v[w + 1] = std::byte(nw);
      CHECK(nm::inet::update16(c0, old16, u16(nw)) == nm::inet::checksum(bspan(v)));
    } else {
      for (int k = 0; k < 4; ++k) v[w + k] = std::byte(nw >> (24 - 8 * k));
      CHECK(nm::inet::update32(c0, old32, nw) == nm::inet::checksum(bspan(v)));
    }
  }
  // pseudo-headers: the UDP checksum over pseudo-header + header + payload verifies, v4 and v6
  {
    const std::array<u8, 4> src{10, 0, 0, 1}, dst{10, 0, 0, 2};
    std::vector<std::byte> udp = random_bytes(rng, 8 + 37);
    udp[4] = std::byte(0);
    udp[5] = std::byte(udp.size());
    udp[6] = udp[7] = std::byte(0);
    const auto ph = nm::inet::pseudo_header_v4(src, dst, 17, u16(udp.size()));
    const u16 c = nm::inet::udp_checksum({ph, udp});
    std::vector<std::byte> joined(ph.begin(), ph.end());
    joined.insert(joined.end(), udp.begin(), udp.end());
    CHECK(c == (ref_inet(joined) == 0 ? 0xffff : ref_inet(joined)));
    udp[6] = std::byte(c >> 8);
    udp[7] = std::byte(c);
    CHECK(nm::inet::verify({ph, udp}));

    std::array<u8, 16> s6{}, d6{};
    s6[0] = d6[0] = 0xfd;
    s6[15] = 1;
    d6[15] = 2;
    const auto ph6 = nm::inet::pseudo_header_v6(s6, d6, u32(udp.size()), 17);
    CHECK(ph6.size() == 40 && ph6[35] == std::byte(udp.size()) && ph6[39] == std::byte(17));
    udp[6] = udp[7] = std::byte(0);
    const u16 c6 = nm::inet::udp_checksum({ph6, udp});
    udp[6] = std::byte(c6 >> 8);
    udp[7] = std::byte(c6);
    CHECK(nm::inet::verify({ph6, udp}));
  }
  // a long buffer (exercises the folded multi-block accumulator)
  {
    auto v = random_bytes(rng, (1 << 20) + 3);
    CHECK(nm::inet::checksum(bspan(v)) == ref_inet(v));
  }
  // add_folded after an odd-length span must NOT byte-swap the pre-folded word-aligned partial sum
  {
    const std::array<u8, 4> sa{10, 0, 0, 1}, da{10, 0, 0, 2};
    const std::array<std::byte, 5> odd_pay{std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
                                           std::byte{0x44}, std::byte{0x55}};
    const auto ph = nm::inet::pseudo_header_v4(sa, da, 17, 13);
    const u16 ph_folded = nm::inet::sum{}.add(ph).folded();
    const u16 before = nm::inet::sum{}.add_folded(ph_folded).add(bspan(odd_pay)).checksum();
    const u16 after  = nm::inet::sum{}.add(bspan(odd_pay)).add_folded(ph_folded).checksum();
    const u16 direct = nm::inet::checksum({ph, odd_pay});
    CHECK(before == direct);
    CHECK(after == direct);
  }
}

// ------------------------------------------------------------------ CRCs
template <class C>
static void test_crc(const char* name, std::mt19937_64& rng) {
  using P = typename C::params;
  int before = failures;
  CHECK(C::compute(std::string_view("123456789")) == P::check);
  for (int iter = 0; iter < 400; ++iter) {
    const std::size_t n = rng() % 300;
    auto v = random_bytes(rng, n + 8);
    const std::size_t align = rng() % 8;
    const bspan s(v.data() + align, n);
    const auto want = ref_crc<P>(s);
    CHECK(C::compute(s) == want);
    // streaming over random splits
    C c;
    C chained = C::resume(C{}.value());  // resume from the CRC of nothing == a fresh start
    for (std::size_t at = 0; at < n;) {
      const std::size_t take = std::min<std::size_t>(n - at, rng() % 19);
      c.update(s.subspan(at, take));
      // AUTOSAR chaining: each call starts from the previous call's FINAL value
      chained = C::resume(chained.update(s.subspan(at, take)).value());
      at += take;
    }
    CHECK(c.value() == want);
    CHECK(chained.value() == want);
    // uint8_t spans and single bytes are accepted too
    std::vector<u8> u(n);
    for (std::size_t i = 0; i < n; ++i) u[i] = u8(s[i]);
    CHECK(C::compute(std::span<const u8>(u)) == want);
  }
  if (failures != before) std::printf("  (in %s)\n", name);
}

// ------------------------------------------------------------------ emit integration
struct ipv4_hdr {
  nm::ubits<4>      version;
  nm::ubits<4>      ihl;
  u8                tos;
  nm::be<u16>       total_len;
  nm::be<u16>       ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl;
  u8                proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_hdr, version, ihl, tos, total_len, ident, flags, frag_off, ttl, proto, checksum, src, dst);
struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);
/// A custom emit context: the payload after the struct, plus bytes the checksum covers that are
/// not written with the struct at all (a UDP pseudo-header, an E2E Data ID).
struct covered_ctx {
  bspan payload{};
  bspan prefix{};
};
/// An E2E-protected message in the spirit of AUTOSAR E2E Profile 1/11: CRC8 SAE-J1850 over the
/// Data ID (not transmitted: covered_ctx::prefix), the counter and the payload.
struct e2e_msg {
  u8           crc;
  nm::ubits<4> data_id_nibble;
  nm::ubits<4> counter;
};
NANOM_DESCRIBE(e2e_msg, crc, data_id_nibble, counter);

template <>
struct nm::computed<ipv4_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_len">([](const ipv4_hdr&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](bspan h, const nm::emit_ctx&) { return nm::inet::checksum(h); })};
};
template <>
struct nm::computed<udp_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const udp_hdr&, const covered_ctx& c) { return 8 + c.payload.size(); }),
      // pseudo-header (prefix) + this header (checksum zeroed) + payload, in one scatter/gather sum
      nm::checksum<"checksum">([](bspan h, const covered_ctx& c) { return nm::inet::udp_checksum({c.prefix, h, c.payload}); })};
};
template <>
struct nm::computed<e2e_msg> {
  static constexpr auto fields = std::tuple{nm::checksum<"crc">([](bspan h, const covered_ctx& c) {
    // the CRC byte itself is zeroed in h; skip it, cover data id, the rest of the header, payload
    return nm::crc8_sae_j1850{}.update(c.prefix).update(h.subspan(1)).update(c.payload).value();
  })};
};

static void test_emit_integration(std::mt19937_64& rng) {
  // IPv4: the computed header checksum matches the textbook value
  {
    ipv4_hdr ip{};
    ip.version = 4;
    ip.ihl = 5;
    ip.flags = 2;
    ip.ttl = 64;
    ip.proto = 17;
    ip.src = {0xc0, 0xa8, 0x00, 0x01};
    ip.dst = {0xc0, 0xa8, 0x00, 0xc7};
    std::vector<std::byte> payload(0x73 - 20);
    auto b = nm::to_bytes(ip, nm::emit_ctx{payload});
    CHECK(b.has_value());
    if (b) {
      CHECK((*b)[10] == std::byte{0xb8} && (*b)[11] == std::byte{0x61});
      CHECK(nm::verify_computed<ipv4_hdr>(*b, nm::emit_ctx{payload}));
    }
  }
  // UDP over IPv4 with the pseudo-header carried in the context: the datagram verifies
  {
    auto payload = random_bytes(rng, 33);
    udp_hdr u{};
    u.src_port = 30501;
    u.dst_port = 30501;
    const auto ph = nm::inet::pseudo_header_v4({10, 0, 0, 1}, {10, 0, 0, 2}, 17, u16(8 + payload.size()));
    auto b = nm::to_bytes(u, covered_ctx{payload, ph});
    CHECK(b.has_value());
    if (b) CHECK(nm::inet::verify({ph, *b, payload}));
  }
  // E2E: CRC8 over data id + header + payload; a flipped payload bit is detected
  {
    const std::array<std::byte, 2> data_id{std::byte{0x12}, std::byte{0x34}};
    auto payload = random_bytes(rng, 6);
    e2e_msg m{};
    m.data_id_nibble = 0x4;
    m.counter = 7;
    auto b = nm::to_bytes(m, covered_ctx{payload, data_id});
    CHECK(b.has_value());
    if (b) {
      std::vector<std::byte> all(data_id.begin(), data_id.end());
      all.push_back((*b)[1]);
      all.insert(all.end(), payload.begin(), payload.end());
      CHECK(u8((*b)[0]) == nm::crc8_sae_j1850::compute(bspan(all)));
      CHECK(nm::verify_computed<e2e_msg>(*b, covered_ctx{payload, data_id}));
      payload[2] ^= std::byte{0x10};
      CHECK(!nm::verify_computed<e2e_msg>(*b, covered_ctx{payload, data_id}));
    }
  }
}

int main() {
  std::mt19937_64 rng(1624);
  test_inet(rng);
  test_crc<nm::crc8_sae_j1850>("crc8_sae_j1850", rng);
  test_crc<nm::crc8_h2f>("crc8_h2f", rng);
  test_crc<nm::crc16_ccitt_false>("crc16_ccitt_false", rng);
  test_crc<nm::crc16_arc>("crc16_arc", rng);
  test_crc<nm::crc32>("crc32", rng);
  test_crc<nm::crc32_p4>("crc32_p4", rng);
  test_crc<nm::crc64>("crc64", rng);
  test_emit_integration(rng);
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("checksum tests: all passed");
  return 0;
}
