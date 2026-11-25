// SPDX-License-Identifier: Apache-2.0
// Tests for nanom/craft.hpp: composable crafting combinators (`nanom::craft` / `nc::`),
// compile-time parser/crafter cross-contamination rejection, multi-layer Eth/VLAN/IPv4/UDP/TLV
// round-trip with RFC 768 UDP pseudo-header checksum, exact span_sink bounds (ASan), and zero
// heap allocations on span_sink.
#include <nanom/craft.hpp>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

namespace nm = nanom;
namespace nc = nanom::craft;

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

#if defined(__SANITIZE_ADDRESS__)
#  define NANOM_TEST_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define NANOM_TEST_ASAN 1
#  else
#    define NANOM_TEST_ASAN 0
#  endif
#else
#  define NANOM_TEST_ASAN 0
#endif

// Track heap allocations during span_sink crafting to prove zero-allocation execution.
static std::atomic<std::size_t> g_alloc_count{0};
static std::atomic<bool>        g_track_allocs{false};

#if !NANOM_TEST_ASAN
void* operator new(std::size_t n) {
  if (g_track_allocs.load(std::memory_order_relaxed))
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
#endif

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

// ------------------------------------------------------------------ wire structs
struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16>       eth_type;
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);

struct vlan_hdr {
  nm::ubits<3>  pcp;
  nm::ubits<1>  dei;
  nm::ubits<12> vid;
  nm::be<u16>   eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);

struct ipv4_hdr {
  nm::ubits<4>      version;
  nm::ubits<4>      ihl;
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_len;
  nm::be<u16>       ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl;
  u8                proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_hdr, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum,
               src, dst);

struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);

struct udp_ipv4_ctx {
  std::span<const std::byte> payload{};
  std::array<u8, 4>          src{};
  std::array<u8, 4>          dst{};
};

inline u32 sum16_words(std::span<const std::byte> b) {
  u32 sum = 0;
  for (std::size_t i = 0; i + 1 < b.size(); i += 2)
    sum += (u32(u8(b[i])) << 8) | u8(b[i + 1]);
  if (b.size() % 2) sum += u32(u8(b.back())) << 8;
  return sum;
}
inline u16 fold16(u32 sum) {
  while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
  return u16(~sum);
}

template <>
struct nm::computed<ipv4_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"ihl">([](const ipv4_hdr&) { return 5; }),
      nm::calc<"total_len">([](const ipv4_hdr&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h) { return fold16(sum16_words(h)); }),
  };
};

template <>
struct nm::computed<udp_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const udp_hdr&, const udp_ipv4_ctx& c) { return 8 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h, const udp_ipv4_ctx& c) {
        const u16 ulen = u16(h.size() + c.payload.size());
        u32 sum = 0;
        // RFC 768 IPv4 pseudo-header: src(4) + dst(4) + zero(1) + proto(17) + udp_len(2)
        sum += (u32(c.src[0]) << 8) | c.src[1];
        sum += (u32(c.src[2]) << 8) | c.src[3];
        sum += (u32(c.dst[0]) << 8) | c.dst[1];
        sum += (u32(c.dst[2]) << 8) | c.dst[3];
        sum += 17u;
        sum += ulen;
        sum += sum16_words(h);
        sum += sum16_words(c.payload);
        const u16 cs = fold16(sum);
        return cs == 0 ? u16(0xffff) : cs;
      }),
  };
};

// ------------------------------------------------------------------ compile-time separation proofs
namespace compile_time_checks {
using PutU8 = decltype(nc::put_u8(1));
static_assert(nc::Crafter<PutU8>);
static_assert(!nm::Parser<PutU8>);
static_assert(nm::Parser<decltype(nm::u8)>);
static_assert(!nc::Crafter<decltype(nm::u8)>);

// Mixing parsers and crafters with `+` or `|` MUST NOT compile!
template <class A, class B>
concept can_add = requires(A a, B b) { a + b; };
template <class A, class B>
concept can_pipe = requires(A a, B b) { a | b; };

static_assert(can_add<PutU8, PutU8>);
static_assert(!can_add<decltype(nm::u8), PutU8>);
static_assert(!can_add<PutU8, decltype(nm::u8)>);
static_assert(!can_add<decltype(nm::u8), decltype(nm::u8)>);

using ParseCtx  = decltype(nm::context("x"));
using CraftFrm  = decltype(nc::framed_by(eth_hdr{}));
static_assert(can_pipe<decltype(nm::u8), ParseCtx>);
static_assert(can_pipe<PutU8, CraftFrm>);
static_assert(!can_pipe<PutU8, ParseCtx>);
static_assert(!can_pipe<decltype(nm::u8), CraftFrm>);
static_assert(!can_pipe<ParseCtx, CraftFrm>);
static_assert(!can_pipe<CraftFrm, ParseCtx>);
}  // namespace compile_time_checks

struct tlv_item {
  u8                  type;
  std::array<u8, 4>   data;
  u8                  len;
};

static void test_full_stack_roundtrip(bool with_vlan) {
  const std::array<u8, 4> src_ip{10, 0, 0, 1};
  const std::array<u8, 4> dst_ip{10, 0, 0, 2};

  eth_hdr eth{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
              {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
              u16(with_vlan ? 0x8100 : 0x0800)};
  vlan_hdr vlan{.pcp = 5, .dei = 0, .vid = 42, .eth_type = 0x0800};
  ipv4_hdr ip{};
  ip.version = 4;
  ip.flags = 2;
  ip.ttl = 64;
  ip.proto = 17;
  ip.src = src_ip;
  ip.dst = dst_ip;

  udp_hdr udp{};
  udp.src_port = 5000;
  udp.dst_port = 53;

  const std::array<tlv_item, 2> tlvs = {{
      {0x01, {0xde, 0xad, 0xbe, 0xef}, 4},
      {0x02, {0xca, 0xfe, 0x00, 0x00}, 2},
  }};

  udp_ipv4_ctx uctx{{}, src_ip, dst_ip};

  auto tlv_list = nc::each(tlvs, [](const tlv_item& t) {
    return nc::put_u8(t.type)
         + (nc::put_bytes(std::span<const u8>(t.data.data(), t.len)) | nc::prefixed_with(nc::put_u8));
  });

  // Pad TLV payload to 4-byte boundary, wrap in UDP (pseudo-header checksum!), IPv4, optional VLAN, Eth.
  auto l3_l4 = (tlv_list | nc::padded_to(4))
             | nc::framed_by(udp, uctx)
             | nc::framed_by(ip);
  auto pkt = (nc::when(with_vlan, nc::put_struct(vlan)) + l3_l4)
           | nc::framed_by(eth);

  const auto expected_sz = nc::size_of(pkt);
  CHECK(expected_sz.has_value());
  // TLV1(1+1+4=6) + TLV2(1+1+2=4) = 10 -> padded to 12; + UDP(8) + IPv4(20) + Eth(14) + optional VLAN(4)
  const std::size_t want_sz = 14 + (with_vlan ? 4 : 0) + 20 + 8 + 12;
  CHECK(*expected_sz == want_sz);

  // 1. Craft into span_sink with ZERO heap allocations!
  std::array<std::byte, 128> fixed_buf{};
  nm::span_sink ss{std::span<std::byte>(fixed_buf).first(want_sz)};
  g_alloc_count.store(0, std::memory_order_relaxed);
  g_track_allocs.store(true, std::memory_order_relaxed);
  auto n_span = nc::write(pkt, ss);
  g_track_allocs.store(false, std::memory_order_relaxed);
  CHECK(n_span && *n_span == want_sz && ss.used == want_sz);
  CHECK(g_alloc_count.load(std::memory_order_relaxed) == 0);

  // 2. Craft into vector_sink and verify byte-identical output!
  auto vec = nc::to_vector(pkt);
  CHECK(vec && vec->size() == want_sz);
  CHECK(std::equal(vec->begin(), vec->end(), ss.written().begin()));

  // 3. Every smaller span_sink fails cleanly without writing past bounds (ASan checks exact allocation!)
  for (std::size_t cap = 0; cap < want_sz; ++cap) {
    std::vector<std::byte> exact(cap);
    nm::span_sink small{exact};
    auto fail_r = nc::write(pkt, small);
    CHECK(!fail_r && small.used <= cap);
  }

  // 4. Parse back with nanom:: (`nm::`) and verify every layer + checksums!
  nm::cursor cur{nm::from(std::span<const std::byte>(*vec))};
  auto p_eth = cur.next(nm::strct<eth_hdr>());
  CHECK(cur && p_eth.eth_type == u16(with_vlan ? 0x8100 : 0x0800));
  if (with_vlan) {
    auto p_vlan = cur.next(nm::strct<vlan_hdr>());
    CHECK(cur && p_vlan.pcp == 5 && p_vlan.vid == 42 && p_vlan.eth_type == 0x0800);
  }
  const std::span<const std::byte> ip_start = cur.rest().span();
  auto p_ip = cur.next(nm::strct<ipv4_hdr>());
  CHECK(cur && p_ip.version == 4 && p_ip.ihl == 5 && p_ip.total_len == 40u);
  const std::span<const std::byte> ip_payload = cur.rest().span();
  CHECK(nm::verify_computed<ipv4_hdr>(ip_start.first(20), nm::emit_ctx{ip_payload}));

  const std::span<const std::byte> udp_start = cur.rest().span();
  auto p_udp = cur.next(nm::strct<udp_hdr>());
  CHECK(cur && p_udp.src_port == 5000u && p_udp.dst_port == 53u && p_udp.length == 20u);
  const std::span<const std::byte> udp_payload = cur.rest().span();
  CHECK(udp_payload.size() == 12);
  CHECK(nm::verify_computed<udp_hdr>(udp_start.first(8), udp_ipv4_ctx{udp_payload, src_ip, dst_ip}));

  // Parse back the two TLVs + 2-byte zero pad
  auto t1_type = cur.next(nm::u8);
  auto t1_val  = cur.next(nm::length_data(nm::u8));
  auto t2_type = cur.next(nm::u8);
  auto t2_val  = cur.next(nm::length_data(nm::u8));
  auto pad     = cur.take(2);
  CHECK(cur && cur.empty());
  CHECK(t1_type == 0x01 && t1_val.size() == 4 && u8(t1_val[0]) == 0xde && u8(t1_val[3]) == 0xef);
  CHECK(t2_type == 0x02 && t2_val.size() == 2 && u8(t2_val[0]) == 0xca && u8(t2_val[1]) == 0xfe);
  CHECK(pad.size() == 2 && u8(pad[0]) == 0 && u8(pad[1]) == 0);
}

static void test_primitives_and_errors() {
  // All integer widths + uleb128 + lit + pad + composed craft_adaptors
  auto c = nc::put_u8(0x12)
         + nc::put_be16(0x3456)
         + nc::put_be24(0x789abc)
         + nc::put_be32(0x11223344)
         + nc::put_be48(0x010203040506ULL)
         + nc::put_le16(0xabcd)
         + nc::put_le24(0x123456)
         + nc::put_le48(0x0a0b0c0d0e0fULL)
         + nc::put_uleb128(300)
         + (nc::put_lit("hi") | nc::prefixed_with(nc::put_uleb128))
         + nc::put_pad(3, std::byte{0xee});

  auto v = nc::to_vector(c);
  CHECK(v.has_value());
  auto sz = nc::size_of(c);
  CHECK(sz && *sz == v->size());

  nm::cursor cur{nm::from(std::span<const std::byte>(*v))};
  CHECK(cur.next(nm::u8) == 0x12);
  CHECK(cur.next(nm::be_u16) == 0x3456);
  CHECK(cur.next(nm::be_u24) == 0x789abc);
  CHECK(cur.next(nm::be_u32) == 0x11223344);
  CHECK(cur.next(nm::be_u48) == 0x010203040506ULL);
  CHECK(cur.next(nm::le_u16) == 0xabcd);
  CHECK(cur.next(nm::le_u24) == 0x123456);
  CHECK(cur.next(nm::le_u48) == 0x0a0b0c0d0e0fULL);
  CHECK(cur.next(nm::varint_u64) == 300u);
  auto hi = cur.next(nm::length_data(nm::varint_u64));
  CHECK(nm::as_str(hi) == "hi");
  auto pad = cur.take(3);
  CHECK(cur && cur.empty() && u8(pad[0]) == 0xee && u8(pad[2]) == 0xee);

  // Length-prefix overflow (300 bytes cannot fit in put_u8!)
  std::vector<std::byte> big(300, std::byte{0x42});
  auto bad_len = nc::put_bytes(big) | nc::prefixed_with(nc::put_u8);
  CHECK(!nc::to_vector(bad_len));

  // Reusable composed craft_adaptor stage
  auto wrap = nc::padded_to(4) | nc::prefixed_with(nc::put_be16);
  auto framed = nc::put_lit("abc") | wrap;
  auto fv = nc::to_vector(framed);
  CHECK(fv && fv->size() == 6 && u8((*fv)[0]) == 0 && u8((*fv)[1]) == 4 &&
        char((*fv)[2]) == 'a' && u8((*fv)[5]) == 0);
}

int main() {
  test_full_stack_roundtrip(false);
  test_full_stack_roundtrip(true);
  test_primitives_and_errors();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("craft tests: all passed");
  return 0;
}
